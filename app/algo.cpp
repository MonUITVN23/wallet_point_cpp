#include "algo.h"
#include <cstdlib>

static const int32_t SHA1_BYTES = 160 / 8;

#include "algo.h"

class AlgorithmImpl : public Algorithm {
public:
    int hmac_algo_sha1(const char* key, int key_length, const char* input, char* output) override {
        unsigned int len = SHA1_BYTES;  // 20 bytes
        unsigned char* result = HMAC(
            EVP_sha1(),                     // Sử dụng SHA-1
            (unsigned char*)key, key_length, // Khóa HMAC
            (unsigned char*)input, 8,        // Dữ liệu input
            (unsigned char*)output,          // Kết quả đầu ra
            &len
        );
        return result == nullptr ? 0 : len;
    }

    uint64_t getCurrentTime() override {
        using namespace std::chrono;
        auto now = system_clock::now();
        return duration_cast<seconds>(now.time_since_epoch()).count();
    }
};
