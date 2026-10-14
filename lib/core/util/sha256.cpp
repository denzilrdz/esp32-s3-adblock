#include "util/sha256.h"

#include <cstring>

#include "util/bytes.h"

namespace util {

namespace {

constexpr uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

}  // namespace

void Sha256::reset() {
  static const uint32_t kInit[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  memcpy(h_, kInit, sizeof(h_));
  bufLen_ = 0;
  total_ = 0;
}

void Sha256::block(const uint8_t* p) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++) w[i] = readU32Be(p + 4 * i);
  for (int i = 16; i < 64; i++) {
    const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
  for (int i = 0; i < 64; i++) {
    const uint32_t t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + kK[i] + w[i];
    const uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  h_[0] += a;
  h_[1] += b;
  h_[2] += c;
  h_[3] += d;
  h_[4] += e;
  h_[5] += f;
  h_[6] += g;
  h_[7] += h;
}

void Sha256::update(const uint8_t* data, size_t len) {
  total_ += len;
  while (len > 0) {
    const size_t n = len < 64 - bufLen_ ? len : 64 - bufLen_;
    memcpy(buf_ + bufLen_, data, n);
    bufLen_ += n;
    data += n;
    len -= n;
    if (bufLen_ == 64) {
      block(buf_);
      bufLen_ = 0;
    }
  }
}

void Sha256::finish(uint8_t out[kSha256Size]) {
  const uint64_t bits = total_ * 8;
  const uint8_t one = 0x80;
  update(&one, 1);
  const uint8_t zero = 0;
  while (bufLen_ != 56) update(&zero, 1);
  uint8_t len[8];
  writeU32Be(len, static_cast<uint32_t>(bits >> 32));
  writeU32Be(len + 4, static_cast<uint32_t>(bits));
  update(len, 8);
  for (int i = 0; i < 8; i++) writeU32Be(out + 4 * i, h_[i]);
  reset();
}

void sha256(const uint8_t* data, size_t len, uint8_t out[kSha256Size]) {
  Sha256 s;
  s.update(data, len);
  s.finish(out);
}

void hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t out[kSha256Size]) {
  uint8_t k[64] = {0};
  if (keyLen > 64) sha256(key, keyLen, k);
  else memcpy(k, key, keyLen);
  uint8_t pad[64];
  Sha256 s;
  for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
  s.update(pad, 64);
  s.update(msg, msgLen);
  uint8_t inner[kSha256Size];
  s.finish(inner);
  for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
  s.update(pad, 64);
  s.update(inner, sizeof(inner));
  s.finish(out);
}

void pbkdf2Sha256(const uint8_t* password, size_t passwordLen, const uint8_t* salt, size_t saltLen,
                  uint32_t iterations, uint8_t* out, size_t outLen) {
  uint8_t msg[128];
  const size_t s = saltLen > sizeof(msg) - 4 ? sizeof(msg) - 4 : saltLen;
  memcpy(msg, salt, s);
  for (uint32_t blockIndex = 1; outLen > 0; blockIndex++) {
    writeU32Be(msg + s, blockIndex);
    uint8_t u[kSha256Size], t[kSha256Size];
    hmacSha256(password, passwordLen, msg, s + 4, u);
    memcpy(t, u, sizeof(t));
    for (uint32_t i = 1; i < iterations; i++) {
      hmacSha256(password, passwordLen, u, sizeof(u), u);
      for (size_t j = 0; j < sizeof(t); j++) t[j] ^= u[j];
    }
    const size_t n = outLen < sizeof(t) ? outLen : sizeof(t);
    memcpy(out, t, n);
    out += n;
    outLen -= n;
  }
}

bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t len) {
  uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
  return diff == 0;
}

}  // namespace util
