#include <node.h>
#include <nan.h>
#include <v8.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>

using namespace v8;
using namespace node;

static RSA *generateKey(int num, unsigned long e) {
#if OPENSSL_VERSION_NUMBER < 0x009080001
    return RSA_generate_key(num, e, NULL, NULL);
#else
    BIGNUM *eBig = BN_new();

    if (eBig == NULL) {
        return NULL;
    }

    if (!BN_set_word(eBig, e)) {
        BN_free(eBig);
        return NULL;
    }

    RSA *result = RSA_new();

    if (result == NULL) {
        BN_free(eBig);
        return NULL;
    }

    if (RSA_generate_key_ex(result, num, eBig, NULL) < 0) {
        RSA_free(result);
        result = NULL;
    }

    BN_free(eBig);

    return result;
#endif
}

static Nan::MaybeLocal<Object> toBuffer(BIO *bio) {
    char *data;
    long length = BIO_get_mem_data(bio, &data);

	return Nan::CopyBuffer(data, length);
}

void Generate(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	Nan::HandleScope scope;
	
	int modulusBits = 2048;
	int exponent = 65537;

	if (info[0]->IsInt32()) {
		modulusBits = info[0]->ToInt32()->Value();
	}

	if (info[1]->IsInt32()) {
		exponent = info[1]->ToInt32()->Value();
	}

	if (modulusBits < 512) {
		Nan::ThrowTypeError("Expected modulus bit count bigger than 512.");
		return;
	}

	if (exponent < 0) {
		Nan::ThrowTypeError("Expected positive exponent.");
		return;
	}

	if ((exponent & 1) == 0) {
		Nan::ThrowTypeError("Expected odd exponent.");
		return;
	}

	RSA *rsa = generateKey(modulusBits, (unsigned int)exponent);

	if (!rsa) {
		Nan::ThrowError("Failed creating RSA context.");
		return;
	}

	BIO *publicBio = BIO_new(BIO_s_mem());
	BIO *privateBio = BIO_new(BIO_s_mem());

	if (!publicBio || !privateBio) {
		if (publicBio) {
			BIO_vfree(publicBio);
		}

		if (privateBio) {
			BIO_vfree(privateBio);
		}

		RSA_free(rsa);

		Nan::ThrowError("Failed to allocate OpenSSL buffers.");
		return;
	}

	if (!PEM_write_bio_RSA_PUBKEY(publicBio, rsa)) {
		BIO_vfree(publicBio);
		BIO_vfree(privateBio);
		RSA_free(rsa);

		Nan::ThrowError("Failed exporting public key.");
		return;
	}

	if (!PEM_write_bio_RSAPrivateKey(privateBio, rsa, NULL, NULL, 0, NULL, NULL)) {
		BIO_vfree(publicBio);
		BIO_vfree(privateBio);
		RSA_free(rsa);

		Nan::ThrowError("Failed exporting private key.");
		return;
	}

	Nan::MaybeLocal<Object> publicKey = toBuffer(publicBio);
	Nan::MaybeLocal<Object> privateKey = toBuffer(privateBio);

	BIO_vfree(publicBio);
	BIO_vfree(privateBio);
	RSA_free(rsa);

	Local<Object> result = Nan::New<Object>();

	Nan::Set(result, Nan::New<String>("public_key").ToLocalChecked(), publicKey.ToLocalChecked());
	Nan::Set(result, Nan::New<String>("private_key").ToLocalChecked(), privateKey.ToLocalChecked());

	info.GetReturnValue().Set(result);
}

void InitAll(Handle<Object> exports) {
	Nan::Set(exports, Nan::New<String>("generate").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(Generate)).ToLocalChecked());
}

NODE_MODULE(rsa_keygen, InitAll)

