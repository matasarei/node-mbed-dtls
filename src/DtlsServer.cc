
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

static int allowed_ciphersuites[] = {MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256, 0};

#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf

using namespace node;

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
  ((void) level);

  struct timeval tp;
  gettimeofday(&tp, NULL);
  long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;

  mbedtls_fprintf((FILE *) ctx, "%013ld:%s:%04d: %s", ms, file, line, str);
  fflush((FILE *) ctx);
}


/*
 * Callback to get PSK given identity. Use the js callback to get the key.
 */
int fetchPSKGivenID(void *parameter, mbedtls_ssl_context *ssl, const unsigned char *psk_identity, size_t identity_len) {
  int status = 1;
  char *psk;
  char *pskIdentity = (char *)malloc(sizeof(char) * (identity_len+1));
  DtlsServer *dtlsServer = (DtlsServer *)parameter;

  strncpy(pskIdentity,(char*)psk_identity,identity_len);
  pskIdentity[identity_len]='\0';

  psk = dtlsServer->getPskFromIdentity(pskIdentity);

  if (!psk) {
    goto clean_and_exit;
  }

  mbedtls_ssl_set_hs_psk(ssl, (const unsigned char*)psk, strlen(psk));
  status = 0;

clean_and_exit:
  free(psk);
  free(pskIdentity);
  return status;
}


Nan::Persistent<v8::FunctionTemplate> DtlsServer::constructor;

void DtlsServer::Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target) {
  Nan::HandleScope scope;

  // Constructor
  v8::Local<v8::FunctionTemplate> ctor = Nan::New<v8::FunctionTemplate>(DtlsServer::New);
  constructor.Reset(ctor);
  v8::Local<v8::ObjectTemplate>  ctorInst = ctor->InstanceTemplate();
  ctorInst->SetInternalFieldCount(1);
  ctor->SetClassName(Nan::New("DtlsServer").ToLocalChecked());

  Nan::SetAccessor(ctorInst, Nan::New("handshakeTimeoutMin").ToLocalChecked(), 0, SetHandshakeTimeoutMin);

  v8::Local<v8::Context> context = Nan::GetCurrentContext();
  Nan::Set(target, Nan::New("DtlsServer").ToLocalChecked(), ctor->GetFunction(context).ToLocalChecked());
}

void DtlsServer::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  if (info.Length() < 4) {
    return Nan::ThrowTypeError("Expecting at least 4 parameters");
  }

  size_t key_len = info[0]->IsNull() ? 0 : Buffer::Length(info[0]);
  size_t crt_len = info[1]->IsNull() ? 0 : Buffer::Length(info[1]);
  bool psk_callback_is_null = info[2]->IsNull();
  size_t ca_crt_len = info[3]->IsNull() ? 0 : Buffer::Length(info[3]);
  v8::Local<v8::Context> context = Nan::GetCurrentContext();
  int ca_verify_mode = info[4]->IsNull() ? MBEDTLS_SSL_VERIFY_OPTIONAL : info[4]->IntegerValue(context).ToChecked();

  // needs to be a Buffer or false
  if ( key_len && !Buffer::HasInstance(info[0])) {
    return Nan::ThrowTypeError("Expecting key to be a buffer");
  }

  // needs to be a Buffer or false
  if ( crt_len && !Buffer::HasInstance(info[1]) ) {
    return Nan::ThrowTypeError("Expecting crt to be a buffer");
  }

  if ( !psk_callback_is_null && info[2]->IsFunction() == false) {
   return Nan::ThrowTypeError("Expecting param 2 to be a function (or null)");
  }

  // needs to be a Buffer or false
  if ( ca_crt_len && !Buffer::HasInstance(info[3]) ) {
    return Nan::ThrowTypeError("Expecting ca_crt to be a buffer");
  }

  printf("Verify mode: %i", ca_verify_mode);

  if ( ca_verify_mode < 0 || ca_verify_mode > 2 )
  {
    if( crt_len > 0 )
      ca_verify_mode = MBEDTLS_SSL_VERIFY_OPTIONAL;
    else
      ca_verify_mode = MBEDTLS_SSL_VERIFY_NONE;
  }

  const unsigned char *key = nullptr;
  if( key_len )
    key = (const unsigned char *)Buffer::Data(info[0]);

  const unsigned char *crt = nullptr;
  if( crt_len )
    crt = (const unsigned char *)Buffer::Data(info[1]);

  Nan::Callback* get_psk = nullptr;
  if( !psk_callback_is_null )
    get_psk = new Nan::Callback(info[2].As<v8::Function>());

  const unsigned char *ca_crt = nullptr;
  if( ca_crt_len )
    ca_crt = (const unsigned char *)Buffer::Data(info[3]);

  int debug_level = 0;
  if (info.Length() > 5) {
    debug_level = info[5]->Uint32Value(context).ToChecked();
  }

  DtlsServer *server = new DtlsServer(key, key_len,
                                      crt, crt_len,
                                      ca_crt, ca_crt_len,
                                      ca_verify_mode,
                                      get_psk,
                                      debug_level);
  server->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

DtlsServer::DtlsServer(const unsigned char *srv_key,
                       size_t srv_key_len,
                       const unsigned char *srv_crt,
                       size_t srv_crt_len,
                       const unsigned char *ca_crt,
                       size_t ca_crt_len,
                       int ca_verify_mode,
                       Nan::Callback* get_psk_cb,
                       int debug_level)
    : Nan::ObjectWrap() {
  int ret;

  get_psk = get_psk_cb;

  const char *pers = "dtls_server";
  mbedtls_ssl_config_init(&conf);
  mbedtls_ssl_cookie_init(&cookie_ctx);
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_init(&cache);
#endif
  mbedtls_x509_crt_init(&srvcert);
  mbedtls_pk_init(&pkey);

  mbedtls_x509_crt_init(&ca_chain);
  mbedtls_x509_crl_init(&ca_crl);

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_ssl_conf_ciphersuites(&conf, allowed_ciphersuites);

#if defined(MBEDTLS_DEBUG_C)
  mbedtls_debug_set_threshold(debug_level);
#endif

  // PSK: register psk callback if present
  if( get_psk != nullptr )
    mbedtls_ssl_conf_psk_cb( &conf, fetchPSKGivenID, this );

  // crt is optional
  if( srv_crt && srv_crt_len )
  {
    ret = mbedtls_x509_crt_parse(&srvcert,
                (const unsigned char *)srv_crt,
                srv_crt_len);
    if (ret != 0) goto exit;
  }

  // key is optional when using PSK only
  if( srv_key && srv_key_len )
  {
    ret = mbedtls_pk_parse_key(&pkey,
                (const unsigned char *)srv_key,
                srv_key_len,
                NULL,
                0);
    if (ret != 0) goto exit;

    if( debug_level > 1 )
    {
      printf( "private key loaded: %s-%zu type: %i\n", mbedtls_pk_get_name(&pkey), mbedtls_pk_get_bitlen(&pkey), mbedtls_pk_get_type(&pkey) );
    }

    // Since this library is exclusively for datagram (UDP) connections
    // if using a key, it must meet the CoAP Specification
    // https://tools.ietf.org/html/rfc7252#section-9.1.3.3
    // required is an Elliptic Curve key with 256 bits 'secp256r1' (aka 'prime256v1' in OpenSSL)
    // TODO: - either pass validating the key into a separate function that can be called from node OR
    //       - make an enum with operating modes that gets passed in and we can evaluate here

    //DE_Hayden: We want to allow for RSA certificates on the server side for performance reasons
    /*if( mbedtls_pk_get_type(&pkey) != MBEDTLS_PK_ECKEY &&
        mbedtls_pk_get_bitlen(&pkey) != 256 )
    {
      Nan::ThrowError( "private key must be Elliptic-Curve type for DTLS and CoAP (see https://tools.ietf.org/html/rfc7252#section-9.1.3.3)" );
      return;
    }*/
  }

  if( ca_crt && ca_crt_len )
  {
    ret = mbedtls_x509_crt_parse( &ca_chain, (const unsigned char *) ca_crt, ca_crt_len );
    if (ret != 0) goto exit;
  }

  mbedtls_ssl_conf_authmode( &conf, ca_verify_mode );
  mbedtls_ssl_conf_ca_chain( &conf, &ca_chain, NULL );

  // TODO re-use node entropy and randomness
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                  mbedtls_entropy_func,
                  &entropy,
                  (const unsigned char *) pers,
                  strlen(pers));
  if (ret != 0) goto exit;

  ret = mbedtls_ssl_config_defaults(&conf,
                  MBEDTLS_SSL_IS_SERVER,
                  MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                  MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) goto exit;

  mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

  // TODO use node random number generator?
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

  ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
  if (ret != 0) goto exit;

  ret = mbedtls_ssl_cookie_setup(&cookie_ctx,
                                 mbedtls_ctr_drbg_random,
                                 &ctr_drbg);
  if (ret != 0) goto exit;
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY)
  mbedtls_ssl_conf_dtls_cookies(&conf,
                                mbedtls_ssl_cookie_write,
                                mbedtls_ssl_cookie_check,
                                &cookie_ctx);
#endif
  return;
exit:
  throwError(ret);
  return;
}

NAN_SETTER(DtlsServer::SetHandshakeTimeoutMin) {
  DtlsServer *server = Nan::ObjectWrap::Unwrap<DtlsServer>(info.This());
  v8::Local<v8::Context> context = Nan::GetCurrentContext();
  mbedtls_ssl_conf_handshake_timeout(server->config(), value->Uint32Value(context).ToChecked(), server->config()->hs_timeout_max);
}

char *DtlsServer::getPskFromIdentity(char *identity) {
  char *psk = NULL;

  if( get_psk != nullptr  )
  {

    v8::Local<v8::Value> argv[] = {
      Nan::New(identity).ToLocalChecked()
    };
    v8::Local<v8::Context> context = Nan::GetCurrentContext();
    v8::Local<v8::Function> getPskCallback = get_psk->GetFunction();
    v8::Local<v8::Value> jsPsk = getPskCallback->Call(context, Nan::GetCurrentContext()->Global(), 1, argv).ToLocalChecked();

    Nan::Utf8String jsUtf8Psk(jsPsk->ToString(context).ToLocalChecked());
    int pskLen = jsUtf8Psk.length();
    if (pskLen > 0) {
      psk = (char *)malloc(sizeof(char)*(pskLen+1));
      strcpy(psk,*jsUtf8Psk);
    }
  }

  return psk;
}

void DtlsServer::throwError(int ret) {
  char error_buf[100];
  mbedtls_strerror(ret, error_buf, 100);
  Nan::ThrowError(error_buf);
}

DtlsServer::~DtlsServer() {
  mbedtls_x509_crt_free( &srvcert );
  mbedtls_pk_free( &pkey );
  mbedtls_x509_crt_free( &ca_chain );
  mbedtls_x509_crl_free( &ca_crl );
  mbedtls_ssl_config_free( &conf );
  mbedtls_ssl_cookie_free( &cookie_ctx );
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_free( &cache );
#endif
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );
}
