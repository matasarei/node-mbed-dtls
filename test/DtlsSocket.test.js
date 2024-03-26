'use strict';

const chai = require('chai')
const fs = require('fs');
const path = require('path');
const sinon = require('sinon');

const expect = chai.expect;

const { DtlsSocket, DtlsServer } = require('bindings')('node_mbed_dtls.node');

const keyFilename = path.join(__dirname, 'key.pem');
const key = Buffer.concat([
	fs.readFileSync(keyFilename),
	Buffer.from([0])] // null terminating byte
);

describe('DtlsSocket', function() {
	describe('exports', function () {
		it('should exist', function () {
			expect(DtlsSocket).to.be.a('function');
		});

		it('should be named correctly', function () {
			expect(DtlsSocket.name).to.equal('DtlsSocket');
		});
	});

	describe('constructor', function () {
		let server;
		let sendCb;
		let handshakeCb;
		let errorCb;
		let sessResumeCb;

		beforeEach(function () {
			server = new DtlsServer(key);
			sendCb = sinon.stub();
			handshakeCb = sinon.stub();
			errorCb = sinon.stub();
			sessResumeCb = sinon.stub();
		});

		it('should throw if constructed with no arguments', function () {
			expect(() => { new DtlsSocket() }).to.throw();
		});

		it('should throw if called as a function', function () {
			expect(() => { DtlsSocket(key) }).to.throw();
		});

		it('should construct correctly given all arguments', function () {
			expect(new DtlsSocket(server, '127.0.0.1', sendCb, handshakeCb, errorCb, sessResumeCb)).to.be.instanceOf(DtlsSocket);
		});
	});
});
