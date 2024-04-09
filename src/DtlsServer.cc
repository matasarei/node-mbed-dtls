#include "DtlsServer.h"
#include <stdio.h>

#if defined(_WIN32)
#include <chrono>

#if 0
typedef struct timeval {
    long tv_sec;
    long tv_usec;
} timeval;
#endif

int gettimeofday(struct timeval* tp, struct timezone* tzp) {
    namespace sc = std::chrono;
    sc::system_clock::duration d = sc::system_clock::now().time_since_epoch();
    sc::seconds s = sc::duration_cast<sc::seconds>(d);
    tp->tv_sec = s.count();
    tp->tv_usec = sc::duration_cast<sc::microseconds>(d - s).count();

    return 0;
}
#else
#include <sys/time.h>
#endif // _WIN32

#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf

void throwMbedTlsError(Napi::Env& env, int error) {
	char buf[256] = {};
	mbedtls_strerror(error, buf, sizeof(buf));
	Napi::Error::New(env, buf).ThrowAsJavaScriptException();
}

static void my_debug(void *ctx, int level,
					 const char *file, int line,
                     const char *str ) {
	((void) level);

	struct timeval tp;
	gettimeofday(&tp, NULL);
	long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;

	mbedtls_fprintf((FILE *) ctx, "%013ld:%s:%04d: %s", ms, file, line, str);
	fflush((FILE *) ctx);
}

int psk_callback(void *parameter, mbedtls_ssl_context *ssl, const unsigned char *psk_identity, size_t identity_len) {
    char *pskIdentity = (char *)malloc(sizeof(char) * (identity_len + 1));
    strncpy(pskIdentity, (char*)psk_identity, identity_len);
    pskIdentity[identity_len]='\0';

    size_t session_id_len = ssl->session_negotiate->id_len;
    char *sessionId = (char *)malloc(sizeof(char) * (session_id_len + 1));
    strncpy(sessionId, (char*)ssl->session_negotiate->id, session_id_len);

    DtlsServer *dtlsServer = (DtlsServer *)parameter;

    char *psk;
    psk = dtlsServer->getPskFromIdentity(pskIdentity, sessionId);

    free(pskIdentity);
    free(sessionId);

    if (!psk) {
        return 1;
    }

    mbedtls_ssl_set_hs_psk(ssl, (const unsigned char*)psk, strlen(psk));
    free(psk);

    return 0;
}

Napi::FunctionReference DtlsServer::constructor;

Napi::Object DtlsServer::Initialize(Napi::Env env, Napi::Object exports) {
	Napi::HandleScope scope(env);

	Napi::Function func = DefineClass(env, "DtlsServer", {
		InstanceAccessor("handshakeTimeoutMin", &DtlsServer::GetHandshakeTimeoutMin, &DtlsServer::SetHandshakeTimeoutMin),
		InstanceAccessor("handshakeTimeoutMax", &DtlsServer::GetHandshakeTimeoutMax, &DtlsServer::SetHandshakeTimeoutMax),
	});

	constructor = Napi::Persistent(func);
	constructor.SuppressDestruct();

	exports.Set("DtlsServer", func);

	return exports;
}

DtlsServer::DtlsServer(const Napi::CallbackInfo& info) : Napi::ObjectWrap<DtlsServer>(info) {
	Napi::Env env = info.Env();
	Napi::HandleScope scope(env);

	const char *pers = "dtls_server";
	mbedtls_ssl_config_init(&conf);
	mbedtls_ssl_cookie_init(&cookie_ctx);
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_init(&cache);
#endif
	mbedtls_x509_crt_init(&srvcert);
	mbedtls_pk_init(&pkey);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	if (info.Length() < 1 || !info[0].IsBuffer()) {
		Napi::TypeError::New(env, "Expecting first parameter (key) to be a buffer").ThrowAsJavaScriptException();
		return;
	}

	Napi::Buffer<unsigned char> key_buffer = info[0].As<Napi::Buffer<unsigned char>>();
	size_t key_len = key_buffer.Length();
	unsigned char * key = key_buffer.Data();

    if (info.Length() > 1 && info[1].ToBoolean().Value()) {
        if (!info[1].IsFunction()) {
            Napi::TypeError::New(env, "Expecting second parameter (identityPskCallback) to be a function").ThrowAsJavaScriptException();
            return;
        }

        get_psk = Napi::Persistent(info[1].As<Napi::Function>());
    }

    if (get_psk != nullptr) {
        mbedtls_ssl_conf_psk_cb(&conf, psk_callback, this);
    }

#if defined(MBEDTLS_DEBUG_C)
	int debug_level = 0;

    if (info.Length() > 2) {
        debug_level = info[2].ToNumber().Uint32Value();
    }

	mbedtls_debug_set_threshold(debug_level);
#endif
	int parse_key_result = mbedtls_pk_parse_key(&pkey, key, key_len, NULL, 0);
	CHECK_MBEDTLS(parse_key_result);

	CHECK_MBEDTLS(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers)));
	CHECK_MBEDTLS(mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT));

  // @TODO: probably define allowed cipher suites based on provided config
  // static int allowed_ciphersuites[] = {MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256, MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256, 0};
  // mbedtls_ssl_conf_ciphersuites(&conf, allowed_ciphersuites);

	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

	CHECK_MBEDTLS(mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey));
	CHECK_MBEDTLS(mbedtls_ssl_cookie_setup(&cookie_ctx, mbedtls_ctr_drbg_random, &ctr_drbg));

	mbedtls_ssl_conf_dtls_cookies(&conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &cookie_ctx);
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
}

char *DtlsServer::getPskFromIdentity(char *identity, char *sessionId) {
    char *psk = NULL;

    if (get_psk != nullptr)
    {
        napi_env env = get_psk.Env();
        napi_value global;
        napi_get_global(env, &global);

        napi_value jsIdentity;
        napi_create_buffer_copy(env, strlen(identity), identity, NULL, &jsIdentity);

        napi_value jsSessionId;
        napi_create_buffer_copy(env, strlen(sessionId), sessionId, NULL, &jsSessionId);

        napi_value args[2];
        args[0] = jsIdentity;
        args[1] = jsSessionId;

        napi_value jsPsk;
        napi_call_function(env, global, get_psk.Value(), 2, args, &jsPsk);

        size_t pskLen;
        napi_get_value_string_utf8(env, jsPsk, NULL, 0, &pskLen);

        if (pskLen > 0) {
            psk = (char *)malloc(sizeof(char)*(pskLen+1));
            napi_get_value_string_utf8(env, jsPsk, psk, pskLen+1, &pskLen);
        }
    }

    return psk;
}

DtlsServer::~DtlsServer() {
	mbedtls_x509_crt_free( &srvcert );
	mbedtls_pk_free( &pkey );
	mbedtls_ssl_config_free( &conf );
	mbedtls_ssl_cookie_free( &cookie_ctx );
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_free( &cache );
#endif
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
}

Napi::Value DtlsServer::GetHandshakeTimeoutMin(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	return Napi::Number::New(env, this->config()->hs_timeout_min);
}

Napi::Value DtlsServer::GetHandshakeTimeoutMax(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	return Napi::Number::New(env, this->config()->hs_timeout_max);
}

void DtlsServer::SetHandshakeTimeoutMin(const Napi::CallbackInfo& info, const Napi::Value& value) {
	uint32_t hs_timeout_min = value.As<Napi::Number>().Uint32Value();
	mbedtls_ssl_conf_handshake_timeout(this->config(), hs_timeout_min, this->config()->hs_timeout_max);
}

void DtlsServer::SetHandshakeTimeoutMax(const Napi::CallbackInfo& info, const Napi::Value& value) {
	uint32_t hs_timeout_max = value.As<Napi::Number>().Uint32Value();
	mbedtls_ssl_conf_handshake_timeout(this->config(), this->config()->hs_timeout_min, hs_timeout_max);
}
