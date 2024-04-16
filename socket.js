'use strict';

const stream = require('stream');

var mbed = require('bindings')('node_mbed_dtls.node');

const HANDSHAKE_TIMEOUT_MAX = 60000; // ms

const MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY = -0x7880;
const MBEDTLS_ERR_SSL_CLIENT_RECONNECT = -0x6780;

class DtlsSocket extends stream.Duplex {
	constructor(server, clientId, address, port) {
		super({ allowHalfOpen: false });
		this.server = server;
		this.dgramSocket = server.dgramSocket;
		this.remoteAddress = address;
		this.remotePort = port;
		this.clientId = clientId;
		this._hadError = false;
		this._sendClose = true;
		this._handshakeLoop;
		this._handshakeLoopTimeout = new Date().getTime();

		try {
			this.mbedSocket = new mbed.DtlsSocket(server.mbedServer, clientId,
				this._sendEncrypted.bind(this),
				this._handshakeComplete.bind(this),
				this._error.bind(this),
				this._renegotiate.bind(this));

			// handshake control loop: it calls the mbedtls receiveData like a loop in order to:
			// 1) increase dtls timeout counters for packet retransmission
			// 2) close socket after handshake max timeout if something goes wrong
			this._handshakeLoop = setImmediate(() => {
				this.mbedSocket.receiveData("");
				if (new Date().getTime() - this._handshakeLoopTimeout >= HANDSHAKE_TIMEOUT_MAX) {
					this._end();
				}
			});
		} catch (error) {
			// Don't _error() here because that method assumues we've had
			// an active socket at some point which is not the case here.
			this.emit('error', 0, error.message);
			if(this._handshakeLoop) {
				clearImmediate(this._handshakeLoop);
			}
		}
	}

	get publicKey() {
		return (this.mbedSocket && this.mbedSocket.publicKey) || Buffer.alloc(0);
	}
	get publicKeyPEM() {
		return (this.mbedSocket && this.mbedSocket.publicKeyPEM) || Buffer.alloc(0);
	}
	get outCounter() {
		return this.mbedSocket && this.mbedSocket.outCounter;
	}
	get session() {
		return this.mbedSocket && this.mbedSocket.session;
	}

	get sendClose() {
		return this._sendClose;
	}
	set sendClose(value) {
		this._sendClose = value;
	}

	resumeSession(session) {
		if (!session || !this.mbedSocket) {
			return false;
		}

		const s = new mbed.SessionWrap();
		s.restore(session);

		const success = this.mbedSocket.resumeSession(s);
		if (success) {
			this.connected = true;
			this.resumed = true;
		}
		if (this._handshakeLoop) {
			clearImmediate(this._handshakeLoop);
		}
		return success;
	}

	_read() {
		// @TODO implement way to stop/start reading?
		// do nothing since chunk pushing is async
	}

	_write(chunk, encoding, callback) {
		if (!this.mbedSocket) {
			return callback(new Error('no mbed socket'));
		}

		this._sendCallback = callback;

		try {
			this.mbedSocket.send(chunk);
		} catch (error) {
			return callback(error);
		}
	}

	_sendEncrypted(msg) {
		// store the callback here because '_write' might be called
		// again before the underlying socket finishes sending
		const sendCb = this._sendCallback;
		this._sendCallback = null;
		const sendFinished = (err) => {
			if (sendCb) {
				sendCb(err);
			}
			if (this._clientEnd) {
				this._finishEnd();
			}
		};

		// make absolutely sure the socket will let us send
		if (!this.dgramSocket) {
			process.nextTick(() => {
				sendFinished(new Error('no underlying socket'));
			});
			return;
		}

		this.emit('send', msg.length);
		this.dgramSocket.send(msg, 0, msg.length, this.remotePort, this.remoteAddress, sendFinished);
	}

	_handshakeComplete() {
		this.connected = true;
		this.emit('secureConnect');
		if (this._handshakeLoop) {
			clearImmediate(this._handshakeLoop);
		}
	}

	_error(code, msg) {
		if (code === MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			this._end();
			return;
		}

		if (code === MBEDTLS_ERR_SSL_CLIENT_RECONNECT) {
			this.emit('reconnect', this);
			process.nextTick(() => {
				this.receive();
			});
			return;
		}

		this._hadError = true;

		if (this._sendCallback) {
			this._sendCallback(code);
			this._sendCallback = null;
		} else {
			this.emit('error', code, msg);
		}

		this._end();
	}

	_renegotiate(sessionId) {
		const done = this._renegotiateCallback.bind(this);

		if (!this.server.emit('renegotiate', sessionId.toString('hex'), this, done)) {
			process.nextTick(done);
		}
	}

	_renegotiateCallback(err, data) {
		let s;

		if (!err && data) {
			s = new mbed.SessionWrap();
			err = s.restore(data);
		}

		if (err) {
			this._end();
			return;
		}

		this.mbedSocket.renegotiate(s || undefined);
		this.resumed = true;
		if (this._handshakeLoop) {
			clearImmediate(this._handshakeLoop);
		}
	}

	receive(msg) {
		if (!this.mbedSocket) {
			return false;
		}

		if (msg && msg.length < 4) {
			return false;
		}

		this.emit('receive', (msg && msg.length) || 0);
		let data;

		try {
			// We keep getting an 'unknown error' thrown from this call,
			// but we cannot figure out where in the native code it is
			// coming from.
			data = this.mbedSocket.receiveData(msg);
		} catch (error) {
			// based on DTLS debug logs, this error is what mbed-tls should be giving us
			// @TODO find a way to get this message from mbed-tls
			this.server.emit('clientError', 'SSL - Verification of the message MAC failed', this);
			this._hadError = true;
			this._end();
		}

		if (data) {
			this.push(data);

			return true;
		}

		return false;
	}

	end() {
		if (this._resetting) {
			return;
		}
		this._clientEnd = true;
		this._end();
	}

	reset() {
		this._resetting = true;
		this.emit('close', false);
		this.removeAllListeners();
		this._resetting = false;
		this.resumed = false;
		this.connected = false;

		if (this._handshakeLoop) {
			clearImmediate(this._handshakeLoop);
		}
	}

	_end() {
		if (this._ending) {
			return;
		}
		this._ending = true;

		super.end();
		this.push(null);

		let noSend = true;

		try {
			noSend = !this._sendClose || (this.connected && this.mbedSocket.close());
		} catch (error) {
			this.emit('error', 0, error.message);
		}

		this.emit('closing');
		this.mbedSocket = null;

		if (this._handshakeLoop) {
			clearImmediate(this._handshakeLoop);
		}

		if (noSend || !this._clientEnd) {
			this._finishEnd();
		}
	}

	_finishEnd() {
		this.dgramSocket = null;
		this.server = null;
		this.emit('close', this._hadError);
		this.removeAllListeners();
	}
}

module.exports = DtlsSocket;
