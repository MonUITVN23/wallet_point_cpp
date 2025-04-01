#include "otp_utils.h"
#include <openssl/hmac.h>
#include <chrono>
#include <cstring>

#include "cotp.hpp"

extern "C"
{
#include <openssl/evp.h>
}

using namespace std;

static const int32_t SHA1_BYTES = 160 / 8;

int hmac_algo_sha1(const char* key, int key_length, const char* input, char* output) {
    unsigned int len = SHA1_BYTES; // SHA1 produces a 20-byte hash

	unsigned char* result = HMAC(
		EVP_sha1(),							// algorithm
		(unsigned char*)key, key_length,	// key
		(unsigned char*)input, 8,		// data
		(unsigned char*)output,				// output
		&len								// output length
	);

	// Return the HMAC success
	return result == 0 ? 0 : len;
}

uint64_t getCurrentTime() {
	using namespace chrono;

	auto now = system_clock::now();
	auto dur = now.time_since_epoch();

	return duration_cast<chrono::seconds>(dur).count();
}