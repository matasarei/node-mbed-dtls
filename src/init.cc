#include <napi.h>

#include "Constants.h"
#include "DtlsServer.h"
#include "DtlsSocket.h"
#include "SessionWrap.h"

Napi::Object init(Napi::Env env, Napi::Object exports) {
	Constants::Initialize(env, exports);
	DtlsServer::Initialize(env, exports);
	DtlsSocket::Initialize(env, exports);
	SessionWrap::Initialize(env, exports);
	return exports;
}

NODE_API_MODULE(node_mbed_dtls, init);
