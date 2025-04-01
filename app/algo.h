#pragma once

#include "cotp.hpp"

#include <iostream>
#include <cotp.h>
#include <chrono>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
using namespace std;

class Algorithm {
public:
	virtual int hmac_algo_sha1(const char* key, int key_length, const char* input, char* output) = 0;
	virtual uint64_t getCurrentTime() = 0;
};