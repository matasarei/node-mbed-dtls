/**
 * Use the client-side echo example from the `node-mbed-dtls-client` repository:
 * https://github.com/matasarei/node-mbed-dtls-client/blob/master/examples/echo.js
 */

'use strict';

const path = require('path');
const dtls = require('../index');
const sessions = new Map();

/**
 * @param {Buffer} identity
 * @param {Buffer} sessionId
 * @returns {string}
 */
function identityPskCallback(identity, sessionId) {
  let psk = '';

  console.log('identity received: ', identity);
  console.log('session id: ', sessionId.toString('hex'));
  console.log('looking up pre-shared key...');

  switch (identity.toString('utf8'))  {
    case 'foo':
      psk = 'asdasdadasd';
      break;
    case '32323232-3232-3232-3232-323232323232':
      psk = 'AAAAAAAAAAAAAAAA';
      break;
    default:
      psk = 'q2w3e4r5t6';
      break;
  }

  console.log('pre-shared key: ', psk);

  return psk;
}

const opts = {
  key: path.join(__dirname, '../test/key.pem'),
  identityPskCallback: identityPskCallback,
  debug: 4,
  handshakeTimeoutMin: 3000,
  proxyProtocol: true,
};

const dtlsserver = dtls.createServer(opts, (socket) => {
  const session = socket.session;
  const clientId = `${socket.remoteAddress}:${socket.remotePort}`;
  console.log(`secure connection from ${clientId}, session id: ${session.id.toString('hex')}`);

  socket.on('data', msg => {
    socket.write(msg);
    if (msg.toString('utf8').indexOf('close') === 0) {
      console.log('closing');
      dtlsserver.close();
    }
  });
  socket.once('error', (err) => {
    console.error(`socket error on ${clientId}: ${err}`);
  });
  socket.once('close', () => {
    console.log(`closing socket from ${clientId}`);
  });
});

dtlsserver.on('clientError', err => {
  console.error(`clientError: ${err}`);
});

dtlsserver.on('error', err => {
  console.error(`server error: ${err}`);
});

dtlsserver.on('listening', () => {
  const addr = dtlsserver.address();
  console.log(`dtls listening on ${addr.address}:${addr.port}`);
});

dtlsserver.on('newSession', (clientId, session) => {
  console.log('newSession: ', clientId, session.id.toString('hex'));
  sessions.set(clientId, session);
});

dtlsserver.on('resumeSession', (clientId, socket, resumeCallback) => {
  console.log('resumeSession: ', clientId);

  process.nextTick(() => {
    resumeCallback(sessions.get(clientId));
  });

  return true;
});

dtlsserver.on('endSession', (clientId) => {
  console.log('endSession: ', clientId);
  sessions.delete(clientId);
});

dtlsserver.listen(5683);
