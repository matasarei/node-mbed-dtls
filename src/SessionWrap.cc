#include "SessionWrap.h"
#include <stdlib.h>

Napi::FunctionReference SessionWrap::constructor;

Napi::Object SessionWrap::Initialize(Napi::Env& env, Napi::Object& exports) {
	Napi::HandleScope scope(env);

	Napi::Function func = DefineClass(env, "SessionWrap", {
		InstanceMethod("restore", &SessionWrap::Restore),
		InstanceAccessor("ciphersuite", &SessionWrap::GetCiphersuite, &SessionWrap::SetCiphersuite),
		InstanceAccessor("randbytes", &SessionWrap::GetRandomBytes, &SessionWrap::SetRandomBytes),
		InstanceAccessor("id", &SessionWrap::GetId, &SessionWrap::SetId),
		InstanceAccessor("master", &SessionWrap::GetMaster, &SessionWrap::SetMaster),
		InstanceAccessor("in_epoch", &SessionWrap::GetInEpoch, &SessionWrap::SetInEpoch),
		InstanceAccessor("out_ctr", &SessionWrap::GetOutCounter, &SessionWrap::SetOutCounter),
	});

	constructor = Napi::Persistent(func);
	constructor.SuppressDestruct();

	exports.Set("SessionWrap", func);
	return exports;
}

Napi::Object SessionWrap::CreateFromContext(Napi::Env env, mbedtls_ssl_context *ssl, uint8_t *random) {
	Napi::EscapableHandleScope scope(env);
	Napi::Object instance = constructor.New({ });

	SessionWrap *news = Napi::ObjectWrap<SessionWrap>::Unwrap(instance);
	news->ciphersuite = ssl->session->ciphersuite;
	memcpy(news->randbytes, random, RANDBYTES_LENGTH);
	memcpy(news->id, ssl->session->id, ssl->session->id_len);
	news->id_len = ssl->session->id_len;
	memcpy(news->master, ssl->session->master, MASTER_LENGTH);
	news->in_epoch = ssl->in_epoch;
	memcpy(news->out_ctr, ssl->cur_out_ctr, OUT_CR_LENGTH);

	return scope.Escape(instance).As<Napi::Object>();
}

Napi::Value SessionWrap::Restore(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());

	Napi::Object object = info[0].ToObject();
	session->ciphersuite = object.Get("ciphersuite").As<Napi::Number>().Uint32Value();

	Napi::Object rbv = object.Get("randbytes").ToObject();
	size_t rbv_length = rbv.As<Napi::Buffer<char>>().Length();
	if (rbv_length > RANDBYTES_LENGTH) {
		return Napi::String::New(env, "SessionWrap::Restore: random bytes value length greater than allowed");
	}
	memcpy(session->randbytes, (rbv).As<Napi::Buffer<char>>().Data(), rbv_length);

	Napi::Object idv = object.Get("id").ToObject();
	size_t idv_length = idv.As<Napi::Buffer<char>>().Length();
	if (idv_length > ID_LENGTH) {
		return Napi::String::New(env, "SessionWrap::Restore: id value length greater than allowed");
	}
	memcpy(session->id, idv.As<Napi::Buffer<char>>().Data(), idv_length);
	session->id_len = idv_length;

	Napi::Object masterv = object.Get("master").ToObject();
	size_t masterv_length = masterv.As<Napi::Buffer<char>>().Length();
	if (masterv_length > MASTER_LENGTH) {
		return Napi::String::New(env, "SessionWrap::Restore: master value length greater than allowed");
	}
	memcpy(session->master, masterv.As<Napi::Buffer<char>>().Data(), masterv_length);
	session->in_epoch = object.Get("in_epoch").As<Napi::Number>().Uint32Value();

	Napi::Object out_ctrv = object.Get("out_ctr").ToObject();
	size_t out_ctrv_length = out_ctrv.As<Napi::Buffer<char>>().Length();
	if (out_ctrv_length > OUT_CR_LENGTH) {
		return Napi::String::New(env, "SessionWrap::Restore: out_ctr value length greater than allowed");
	}
	memcpy(session->out_ctr, out_ctrv.As<Napi::Buffer<char>>().Data(), out_ctrv_length);

	return env.Undefined();
}

Napi::Value SessionWrap::GetCiphersuite(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	return Napi::Number::New(env, session->ciphersuite);
}

void SessionWrap::SetCiphersuite(const Napi::CallbackInfo& info, const Napi::Value& value) {
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	session->ciphersuite = value.As<Napi::Number>().Uint32Value();
}


Napi::Value SessionWrap::GetRandomBytes(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	return Napi::Buffer<char>::Copy(env, (char *)session->randbytes, RANDBYTES_LENGTH);
}

void SessionWrap::SetRandomBytes(const Napi::CallbackInfo& info, const Napi::Value& value) {
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	memcpy(session->randbytes,
		value.As<Napi::Buffer<unsigned char>>().Data(),
		value.As<Napi::Buffer<unsigned char>>().Length());
}


Napi::Value SessionWrap::GetId(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	return Napi::Buffer<char>::Copy(env, (char *)session->id, session->id_len);
}

void SessionWrap::SetId(const Napi::CallbackInfo& info, const Napi::Value& value) {
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	memcpy(session->id,
		value.As<Napi::Buffer<unsigned char>>().Data(),
		value.As<Napi::Buffer<unsigned char>>().Length());
	session->id_len = value.As<Napi::Buffer<unsigned char>>().Length();
}


Napi::Value SessionWrap::GetMaster(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	return Napi::Buffer<char>::Copy(env, (char *)session->master, MASTER_LENGTH);
}

void SessionWrap::SetMaster(const Napi::CallbackInfo& info, const Napi::Value& value) {
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	memcpy(session->master,
		value.As<Napi::Buffer<unsigned char>>().Data(),
		value.As<Napi::Buffer<unsigned char>>().Length());
}


Napi::Value SessionWrap::GetInEpoch(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	return Napi::Number::New(env, session->in_epoch);
}

void SessionWrap::SetInEpoch(const Napi::CallbackInfo& info, const Napi::Value& value) {
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	session->in_epoch = value.As<Napi::Number>().Uint32Value();
}


Napi::Value SessionWrap::GetOutCounter(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	return Napi::Buffer<char>::Copy(env, (char *)session->out_ctr, OUT_CR_LENGTH);
}

void SessionWrap::SetOutCounter(const Napi::CallbackInfo& info, const Napi::Value& value) {
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	memcpy(session->out_ctr,
		value.As<Napi::Buffer<unsigned char>>().Data(),
		value.As<Napi::Buffer<unsigned char>>().Length());
}

SessionWrap::SessionWrap(const Napi::CallbackInfo& info) : Napi::ObjectWrap<SessionWrap>(info) {
	Napi::Env env = info.Env();
	Napi::HandleScope scope(env);
}

SessionWrap::~SessionWrap() {
}
