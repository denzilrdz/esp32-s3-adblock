#pragma once
// SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104) and PBKDF2-HMAC-SHA256 (RFC 8018).
// Portable so password hashing is testable natively; only used for the dashboard
// password, never on the DNS path.

#include <cstddef>
#include <cstdint>

namespace util {

constexpr size_t kSha256Size = 32;

class Sha256 {
 public:
  Sha256() { reset(); }
  void reset();
  void update(const uint8_t* data, size_t len);
  void finish(uint8_t out[kSha256Size]);

 private:
  void block(const uint8_t* p);
  uint32_t h_[8];
  uint8_t buf_[64];
  size_t bufLen_ = 0;
  uint64_t total_ = 0;
};

void sha256(const uint8_t* data, size_t len, uint8_t out[kSha256Size]);
void hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t out[kSha256Size]);
void pbkdf2Sha256(const uint8_t* password, size_t passwordLen, const uint8_t* salt, size_t saltLen,
                  uint32_t iterations, uint8_t* out, size_t outLen);

// Constant-time comparison (no early exit on the first difference).
bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t len);

}  // namespace util
