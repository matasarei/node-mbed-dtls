'use strict';

const dgram = require('dgram');
const fs = require('fs');
const EventEmitter = require('events').EventEmitter;

const DtlsSocket = require('./socket');
const mbed = require('bindings')('node_mbed_dtls.node');

const ALERT_CONTENT_TYPE = 21;
const APPLICATION_DATA_CONTENT_TYPE = 23;
const IP_CHANGE_CONTENT_TYPE = 254;
const DUMB_PING_CONTENT_TYPE = 112;

class DtlsServer extends EventEmitter {
	constructor(options) {
		super();
		this.options = options = Object.assign({
			sendClose: true
		}, options);
		this.sockets = {};
		this.proxyClients = {};
		this.dgramSocket = dgram.createSocket('udp4');
		this._onMessage = this._onMessage.bind(this);
		this.listening = false;

		this.dgramSocket.on('message', this._onMessage);
		this.dgramSocket.once('listening', () => {
			this.listening = true;
			this.emit('listening');
		});
		this.dgramSocket.once('error', err => {
			this.emit('error', err);
			this._closeSocket();
		});
		this.dgramSocket.once('close', () => {
			this._socketClosed();
		});

		let key = Buffer.isBuffer(options.key) ? options.key : fs.readFileSync(options.key);
		// likely a PEM encoded key, add null terminating byte
		// 0x2d = '-'
		if (key[0] === 0x2d && key[key.length - 1] !== 0) {
			key = Buffer.concat([key, Buffer.from([0])]);
		}

		if (
			options.identityPskCallback
			&& typeof options.identityPskCallback !== 'function'
		) {
			throw new Error('identityPskCallback must be a callback, function(id): string');
		}

		this.mbedServer = new mbed.DtlsServer(
			key,
			options.identityPskCallback,
			0//options.debug ?? 0
		);
		if (options.handshakeTimeoutMin) {
			this.mbedServer.handshakeTimeoutMin = options.handshakeTimeoutMin;
		}
		if (options.handshakeTimeoutMax) {
			this.mbedServer.handshakeTimeoutMax = options.handshakeTimeoutMax;
		}

		this.on('forceDeviceRehandshake', (rinfo, deviceId) => {
			this._forceDeviceRehandshake(rinfo, deviceId);
		})
	}

	listen(port, hostname, callback) {
		this.dgramSocket.bind(port, hostname, callback);
	}

	close(callback) {
		if (callback) {
			this.once('close', callback);
		}
		this._closing = true;
		this._closeSocket();
	}

	address() {
		return this.dgramSocket.address();
	}

	getConnections(callback) {
		const numConnections = Object.keys(this.sockets).filter(skey => {
			return this.sockets[skey] && this.sockets[skey].connected;
		}).length;
		process.nextTick(() => callback(numConnections));
	}

	resumeSocket(rinfo, session) {
		const key = `${rinfo.address}:${rinfo.port}`;
		let client = this.sockets[key];
		if (client) {
			return false;
		}

		this.sockets[key] = client = this._createSocket(rinfo, true);
		if (client.resumeSession(session)) {
			this.emit('secureConnection', client, session);
			return true;
		}
		return false;
	}

	_debug() {
		if (this.options.debug) {
			console.log(...arguments);
		}
	}

	_handleIpChange(msg, key, rinfo, deviceId) {
		const lookedUp = this.emit('lookupKey', deviceId, (err, oldRinfo) => {
			if (!err && oldRinfo) {
				if (rinfo.address === oldRinfo.address && rinfo.port === oldRinfo.port) {
					// The IP and port have not changed.
					// The device just thought they might have.
					// The extra DTLS option has been stripped already,
					// handle the message as normal using the client we already had.
					this._debug(`handleIpChange: ignoring ip change because address did not change ip=${key}, deviceID=${deviceId}`);
					this._onMessage(msg, rinfo, (client, received) => {
						// 'received' is true or false based on whether the message is pushed into the stream
						if (!received) {
							this.emit('forceDeviceRehandshake', rinfo, deviceId);
						}
					});

					return;
				}
				// The IP and/or port have changed
				// Attempt to send to oldRinfo which will
				// a) attempt session resumption (if the client with old address and port doesnt exist yet)
				// b) attempt to send the message to the old address and port
				this._onMessage(msg, oldRinfo, (client, received) =>
					new Promise((resolve, reject) => {
						const oldKey = `${oldRinfo.address}:${oldRinfo.port}`;
						// if the message went through OK
						if (received) {
							this._debug(`handleIpChange: message successfully received, changing ip address fromip=${oldKey}, toip=${key}, deviceID=${deviceId}`);
							// change IP
							client.remoteAddress = rinfo.address;
							client.remotePort = rinfo.port;
							// move in lookup table
							this.sockets[key] = client;
							if (this.sockets[oldKey]) {
								delete this.sockets[oldKey];
							}
							client.emit('ipChanged', oldRinfo, () => {
								resolve(true);
							}, err => {
								if (err) {
									this.emit('forceDeviceRehandshake', rinfo, deviceId);
									reject(err);
								}
								reject();
							});
						} else {
							this._debug(`handleIpChange: message not successfully received, NOT changing ip address fromip=${oldKey}, toip=${key}, deviceID=${deviceId}`);
							this.emit('forceDeviceRehandshake', rinfo, deviceId);
						}}
					)
				);
			} else {
				// In May 2019 some devices were stuck with bad sessions, never handshaking.
				// https://app.clubhouse.io/particle/milestone/32301/manage-next-steps-associated-with-device-connectivity-issues-starting-may-2nd-2019
				// This cloud-side solution was discovered by Eli Thomas which caused
				// mbedTLS to fail a socket read and initiate a handshake.
				this._debug(`Device in 'move session' lock state attempting to force it to re-handshake deviceID=${deviceId}`, key);
				//Always EMIT this event instead of calling _forceDeviceRehandshake internally this allows the DS to device wether to send the packet or not to the device
				this.emit('forceDeviceRehandshake', rinfo, deviceId);
			}
		});
		return lookedUp;
	}

	_forceDeviceRehandshake(rinfo, deviceId){
		this._debug(`Attempting force re-handshake by sending malformed hello request packet to ${deviceId} socket ${rinfo.port} ${rinfo.address}`);

		// Construct the 'session killing' Avada Kedavra packet
		const malformedHelloRequest = Buffer.from([
			0x16,                                 // Handshake message type 22
			0xfe, 0xfd,                           // DTLS 1.2
			0x00, 0x01,                           // Epoch
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Sequence number, works when set to anything, therefore chose 0x00
			0x00, 0x10,                           // Data length, this has to be >= 16 (minumum) (deliberatly set to 0x10 (16) which is > the data length (2) that follows to force an mbed error on the device
			0x00,                                 // HandshakeType hello_request
			0x00                                  // Handshake body, intentionally too short at a single byte
		]);

		// Sending the malformed hello request back over the raw UDP socket
		this.dgramSocket.send(malformedHelloRequest, rinfo.port, rinfo.address);
	}

	/**
	 * This function attempts to resume a session for a client.
	 * If the session cannot be resumed, it ends the client and removes it from the sockets list.
	 * @param {Object} client - The client to attempt to resume the session for.
	 * @param {Buffer} msg - The message received from the client.
	 * @param {string} key - The key of the client in the sockets list.
	 * @param {Function} cb - A callback function to be called after attempting to resume the session.
	 */
	_attemptResume(client, msg, key, cb) {
		const lcb = cb || (() => {});

		this._debug('_attemptResume', key, lcb);

		const called = this.emit('resumeSession', key, client, async (session) => {
			this._debug('resumeSession (callback)', session, cb);

			if (session) {
				const resumed = client.resumeSession(session);
				if (resumed) {
					client.cork();
					let received;
					if (msg.length === 1 && msg[0] === DUMB_PING_CONTENT_TYPE) {
						received = true;
					} else {
						received = client.receive(msg);
					}
					// callback before secureConnection so
					// IP can be changed
					if (cb) {
						try {
							await lcb(client, received);
						} catch(err) {
							this.emit('forceDeviceRehandshake', { address: client.remoteAddress, port: client.remotePort });
						}
					}
					if (received) {
						this.emit('secureConnection', client, session);
					}

					client.uncork();
					return;
				}
			}
			// client.receive(msg); // removed because it generates
			// clientError: SSL - Processing of the ClientHello handshake message failed
			// Socket error: -30976 sessionKey=127.0.0.1=61109
			if (this.sockets[key]) {
				this.sockets[key].end();
			 	delete this.sockets[key];
			}
			if (cb) {
				lcb(null, false);
			} else {
				this.emit('forceDeviceRehandshake', { address: client.remoteAddress, port: client.remotePort });
			}
		});

		// if somebody was listening, session will attempt to be resumed
		// do not process with receive until resume finishes
		return called;
	}

	_onMessage(msg, rinfo, cb) {
		const key = `${rinfo.address}:${rinfo.port}`;
		let clientId = key;

		if (this.options.proxyProtocol) {
			const PROXY_PROTOCOL_SIGNATURE = Buffer.from('50524f5859', 'hex');
			const PROXY_PROTOCOL_SPECIAL_BYTES = [
				0x0A, // LF
				0x0D, // CR
				0x20  // Space
			];

			// Check if the message starts with the Proxy Protocol signature
			if (msg.slice(0, 5).equals(PROXY_PROTOCOL_SIGNATURE)) {
				this._debug('PROXY protocol V1', rinfo, msg);

				const header = [];
				let buffer = [];
				let headerPointer = 0;
				let stopBytes = 0;

				while (stopBytes < 2 && headerPointer < msg.length) {
					const byte = msg.readUInt8(headerPointer);

					if (PROXY_PROTOCOL_SPECIAL_BYTES.includes(byte)) {
						if (byte === 0x0A || byte === 0x0D) {
							stopBytes++;
						}

						const buf = Buffer.from(buffer);
						header.push(buf);
						buffer = [];
					} else {
						buffer.push(byte);
					}

					headerPointer++;
				}

				const clientAddress = header[3].toString('ascii');
				const clientPort = header[4].readUInt16BE(0);

				clientId = `${clientAddress}:${clientPort}`;

				this.proxyClients[key] = clientId;

				// Remove the Proxy Protocol header from the message
				msg = msg.slice(headerPointer);
			}

			if (this.proxyClients[key]) {
				clientId = this.proxyClients[key];

				if (this.sockets[clientId]) {
					this._debug(`PROXY client address updated`, clientId, this.sockets[clientId].remoteAddress, rinfo.address);
					this._debug(`PROXY client port updated`, clientId, this.sockets[clientId].remotePort, rinfo.port);

					this.sockets[clientId].remotePort = rinfo.port;
					this.sockets[clientId].remoteAddress = rinfo.address;
				}

				this._debug(`PROXY client: ${key} => ${clientId}`);
			}
		}

		this._debug('_onMessage', clientId, msg);
		// special IP changed content type
		if (msg.length > 0 && msg[0] === IP_CHANGE_CONTENT_TYPE) {
			this._debug("IP_CHANGE_CONTENT_TYPE");
			const idLen = msg[msg.length - 1];
			const idStartIndex = msg.length - idLen - 1;
			const deviceId = msg.slice(idStartIndex, idStartIndex + idLen).toString('hex').toLowerCase();
			// handle special case of ip change (with tinydtls trackle lib 2.0)
			if (msg[1] === DUMB_PING_CONTENT_TYPE) {
				this._debug("type DUMB_PING_CONTENT_TYPE");
				// return content type to DumbPing
				msg = [DUMB_PING_CONTENT_TYPE];
			} else {
				this._debug("type APPLICATION_DATA_CONTENT_TYPE");
				// slice off id and length, return content type to ApplicationData
				msg = msg.slice(0, idStartIndex);
				msg[0] = APPLICATION_DATA_CONTENT_TYPE;
			}
			this._debug(`received ip change ip=${clientId}, deviceID=${deviceId}`);
			if (this._handleIpChange(msg, clientId, rinfo, deviceId)) {
				return;
			}
		}

		let client = this.sockets[clientId];
		if (!client) {
			this._debug("Unknown client, creating new one", clientId);
			this.sockets[clientId] = client = this._createSocket(clientId, rinfo.address, rinfo.port);
			if ((msg.length > 0 && msg[0] === APPLICATION_DATA_CONTENT_TYPE) || (msg.length === 1 && msg[0] === DUMB_PING_CONTENT_TYPE)) {
				if (this._attemptResume(client, msg, clientId, cb)) {
					return;
				}
			}
		}

		if (msg.length > 0 && msg[0] === ALERT_CONTENT_TYPE) {
			this._debug("ALERT_CONTENT_TYPE", clientId);
			if(client) {
				client.end();
				delete this.sockets[clientId];
				delete this.proxyClients[key];
			}
		}

		if (msg.length === 1 && msg[0] === DUMB_PING_CONTENT_TYPE) {
			this._debug("DUMB_PING_CONTENT_TYPE");
			client.emit("dumbPing");
			if (cb) {
				cb(client, true);
			}
			return;
		}

		if (cb) {
			this._debug("Processing new message with a callback...". msg, cb);
			// we cork because we want the callback to happen
			// before the implications of the message do
			client.cork();
			const received = client.receive(msg);
			cb(client, received);
			client.uncork();
		} else {
			client.receive(msg);
		}

		Object.keys(this.sockets).forEach(key => {
			this._debug('Connected client: ', key, this.sockets[key].remoteAddress, this.sockets[key].remotePort);
		});
	}

	_createSocket(clientId, address, port) {
		this._debug("_createSocket", clientId, address, port);
		const client = new DtlsSocket(this, clientId, address, port);
		client.sendClose = this.options.sendClose;
		this._attachToSocket(client);
		return client;
	}

	_attachToSocket(client) {
		const clientId = client.clientId;

		client.once('error', (code, err) => {
			delete this.sockets[clientId];
			if (!client.connected) {
				this.emit('clientError', err, client);
			}
		});
		client.once('close', () => {
			this.emit('endSession', clientId);
			delete this.sockets[clientId];
			client = null;
			if (this._closing && Object.keys(this.sockets).length === 0) {
				this._closeSocket();
			}
		});
		client.once('reconnect', socket => {
			// treat like a brand-new connection
			socket.reset();
			this._attachToSocket(socket);
			this.sockets[clientId] = socket;
		});

		client.once('secureConnect', () => {
			this.emit('newSession', clientId, client.session);
			this.emit('secureConnection', client);
		});

		this.emit('connection', client);
	}

	_endSockets() {
		if (this.dgramSocket) {
			this.dgramSocket.removeListener('message', this._onMessage);
		}
		this.dgramSocket = null;
		const sockets = Object.keys(this.sockets);
		sockets.forEach(skey => {
			const s = this.sockets[skey];
			if (s) {
				s.end();
			}
		});
		this.sockets = {};
	}

	_socketClosed() {
		this.listening = false;
		this._endSockets();
		this.emit('close');
		this.removeAllListeners();
	}

	_closeSocket() {
		if (!this.listening) {
			process.nextTick(() => {
				this._socketClosed();
			});
			return;
		}

		if (this.dgramSocket) {
			this.dgramSocket.close();
		}
	}
}

module.exports = DtlsServer;
