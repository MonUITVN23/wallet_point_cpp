#include "otp.h"


std::string OTP::generateTOTP(const std::string& secret, uint64_t timeStep, int digits) {
    uint64_t counter = std::time(nullptr) / timeStep;
    return generateHOTP(secret, counter, digits);
}

std::string OTP::generateHOTP(const std::string& secret, uint64_t counter, int digits) {
    std::string key = base32Decode(secret);
    std::string counterStr(reinterpret_cast<const char*>(&counter), sizeof(counter));
    std::string hmacResult = hmacSHA1(key, counterStr);
    uint32_t otp = dynamicTruncate(hmacResult) % static_cast<uint32_t>(std::pow(10, digits));

    std::ostringstream oss;
    oss << std::setw(digits) << std::setfill('0') << otp;
    return oss.str();
}

bool OTP::verifyTOTP(const std::string& secret, const std::string& otp, uint64_t timeStep, int window) {
    uint64_t currentCounter = std::time(nullptr) / timeStep;
    for (int i = -window; i <= window; i++) {
        if (generateHOTP(secret, currentCounter + i) == otp) {
            return true;
        }
    }
    return false;
}

bool OTP::verifyHOTP(const std::string& secret, const std::string& otp, uint64_t counter) {
    return generateHOTP(secret, counter) == otp;
}

// Hàm hỗ trợ: Giải mã base32
std::string OTP::base32Decode(const std::string& encoded) {
    // Thực hiện giải mã Base32 (để xử lý khóa bí mật)
    // Placeholder - Cần triển khai hoặc sử dụng thư viện bên ngoài
    return encoded;
}

// Hàm hỗ trợ: Tính HMAC-SHA1
std::string OTP::hmacSHA1(const std::string& key, const std::string& data) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    HMAC(EVP_sha1(), key.c_str(), key.size(), reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash, nullptr);
    return std::string(reinterpret_cast<char*>(hash), SHA_DIGEST_LENGTH);
}

// Hàm hỗ trợ: Truncate động từ kết quả HMAC
uint32_t OTP::dynamicTruncate(const std::string& hmacResult) {
    int offset = hmacResult.back() & 0xF;
    return ((hmacResult[offset] & 0x7F) << 24) |
        ((hmacResult[offset + 1] & 0xFF) << 16) |
        ((hmacResult[offset + 2] & 0xFF) << 8) |
        (hmacResult[offset + 3] & 0xFF);
}
