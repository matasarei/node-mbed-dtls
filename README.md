# node-mbed-dtls-server

Node DTLS server wrapping [mbedtls](https://github.com/Mbed-TLS/mbedtls).

Changes made to the fork:
* Merged changes from a fork, [node-mbed-dtls-modified](https://www.npmjs.com/package/node-mbed-dtls-modified), including Node.js 12 support;
* Merged changes from a fork, [node-mbed-dtls](https://www.npmjs.com/package/node-mbed-dtls), including N-API migration;
* Removed the client part of the library, which is now available as a separate package:
[node-mbed-dtls-client](https://github.com/matasarei/node-mbed-dtls-client).

## Setup & Build
```bash
git submodule update --init mbedtls
npm i
```

## DTLS Server API:

```javascript
// Key is the only required option. The rest are optional.
const options = {
  key:                '...',  // Path to the server's private key.
  identityPskCallback: null,  // Callback. PSK resolver, if we're using PSK.
  handshakeTimeoutMin: 3000,  // How many milliseconds can a handshake subtend before being dropped?
  proxyProtocol:       false, // Whether to use the PROXY protocol.
  debug:               0      // How chatty is the library? Larger values generate more log.
};

const dtlsserver = dtls.createServer(opts, socket => {
  // socket is a duplex stream.
  socket.on('data', data => {
    // Handle incoming data.
  });
});
```

### Events

`error` when the server has a problem.
```javascript
// err: Error string/code.
server.on('error', (err) => {});
```

`close` when the server stops listening.
```javascript
// No arguments to callback.
server.on('error', (err) => {});
```

`listening` when the server setup completes without problems.
```javascript
// No arguments to callback.
server.on('listening', () => {});
````
