#pragma once

#ifndef OTP_H
#define OTP_H

#include <string>
#include <cstdint>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <ctime>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>

class OTP {
public:
    static std::string generateTOTP(const std::string& secret, uint64_t timeStep = 30, int digits = 6);
    static std::string generateHOTP(const std::string& secret, uint64_t counter, int digits = 6);
    static bool verifyTOTP(const std::string& secret, const std::string& otp, uint64_t timeStep = 30, int window = 1);
    static bool verifyHOTP(const std::string& secret, const std::string& otp, uint64_t counter);

private:
    static std::string base32Decode(const std::string& encoded);
    static std::string hmacSHA1(const std::string& key, const std::string& data);
    static uint32_t dynamicTruncate(const std::string& hmacResult);
};

#endif // OTP_H
