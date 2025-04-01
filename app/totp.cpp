#include <cstdlib>
#include <iostream>
#include <cstring>
#include <chrono>

#include "cotp.hpp"

extern "C"
{
#include <openssl/evp.h>
#include <openssl/hmac.h>
}


using namespace std;
using namespace COTP;

static const int32_t SHA1_BYTES = 160 / 8;	// 20

int hmac_algo_sha1(const char* byte_secret, int key_length, const char* byte_string, char* out)
{
	// Output len
	unsigned int len = SHA1_BYTES;

	unsigned char* result = HMAC(
		EVP_sha1(),							// algorithm
		(unsigned char*)byte_secret, key_length,	// key
		(unsigned char*)byte_string, 8,		// data
		(unsigned char*)out,				// output
		&len								// output length
	);

	// Return the HMAC success
	return result == 0 ? 0 : len;
}

uint64_t get_current_time()
{
	using namespace std::chrono;

	auto now = system_clock::now();
	auto dur = now.time_since_epoch();

	return duration_cast<chrono::seconds>(dur).count();
}

int main(int argc, char** argv)
{
	////////////////////////////////////////////////////////////////
	// Initialization Stuff                                       //
	////////////////////////////////////////////////////////////////

	const int INTERVAL = 30;
	const int DIGITS = 6;


	// Base32 secret to utilize
	const char BASE32_SECRET[] = "JBSWY3DPEHPK3PXP";


	OTPData odata1;
	memset(&odata1, 0, sizeof(OTPData));

	class TOTP tdata
	{
			&odata1,
			BASE32_SECRET,
			hmac_algo_sha1,
			get_current_time,
			DIGITS,
			INTERVAL
	};

}