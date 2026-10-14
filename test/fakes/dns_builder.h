#pragma once
// Builds DNS packets for tests so they don't need hand-typed hex (except for
// deliberately malformed cases).

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace testdns {

using Bytes = std::vector<uint8_t>;

inline void put16(Bytes& b, uint16_t v) {
  b.push_back(static_cast<uint8_t>(v >> 8));
  b.push_back(static_cast<uint8_t>(v));
}
inline void put32(Bytes& b, uint32_t v) {
  put16(b, static_cast<uint16_t>(v >> 16));
  put16(b, static_cast<uint16_t>(v));
}
inline uint16_t get16(const Bytes& b, size_t off) {
  return static_cast<uint16_t>((b[off] << 8) | b[off + 1]);
}
inline uint16_t get16(const uint8_t* b, size_t off) {
  return static_cast<uint16_t>((b[off] << 8) | b[off + 1]);
}
inline uint32_t get32(const uint8_t* b, size_t off) {
  return (static_cast<uint32_t>(get16(b, off)) << 16) | get16(b, off + 2);
}

// "ads.Example.com" -> 3ads7Example3com0 (case preserved). "" or "." -> root.
inline void putName(Bytes& b, const std::string& name) {
  size_t start = 0;
  while (start < name.size()) {
    size_t dot = name.find('.', start);
    if (dot == std::string::npos) dot = name.size();
    b.push_back(static_cast<uint8_t>(dot - start));
    for (size_t i = start; i < dot; i++) b.push_back(static_cast<uint8_t>(name[i]));
    start = dot + 1;
  }
  b.push_back(0);
}

struct QueryOpts {
  uint16_t id = 0x1234;
  uint16_t flags = 0x0100;  // RD
  uint16_t qclass = 1;
  bool edns = false;
  uint16_t udpSize = 1232;
  bool dnssecOk = false;
  uint8_t version = 0;
};

inline Bytes makeQuery(const std::string& name, uint16_t qtype, const QueryOpts& o = {}) {
  Bytes b;
  put16(b, o.id);
  put16(b, o.flags);
  put16(b, 1);
  put16(b, 0);
  put16(b, 0);
  put16(b, o.edns ? 1 : 0);
  putName(b, name);
  put16(b, qtype);
  put16(b, o.qclass);
  if (o.edns) {
    b.push_back(0);
    put16(b, 41);
    put16(b, o.udpSize);
    b.push_back(0);
    b.push_back(o.version);
    put16(b, o.dnssecOk ? 0x8000 : 0);
    put16(b, 0);
  }
  return b;
}

// Upstream-style response builder: question, then records added in order.
class ResponseBuilder {
 public:
  ResponseBuilder(uint16_t id, const std::string& qname, uint16_t qtype, uint16_t flags = 0x8180) {
    put16(b_, id);
    put16(b_, flags);
    put16(b_, 1);
    put16(b_, 0);
    put16(b_, 0);
    put16(b_, 0);
    putName(b_, qname);
    put16(b_, qtype);
    put16(b_, 1);
  }
  // Record owned by the question name (compression pointer to offset 12).
  ResponseBuilder& answerA(uint32_t ttl, uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    rr(6, 1, ttl, {a, b, c, d});
    return *this;
  }
  ResponseBuilder& answerTxt(uint32_t ttl, size_t textLen) {
    Bytes rd;
    while (textLen > 0) {
      size_t chunk = textLen > 255 ? 255 : textLen;
      rd.push_back(static_cast<uint8_t>(chunk));
      rd.insert(rd.end(), chunk, 'x');
      textLen -= chunk;
    }
    rr(6, 16, ttl, rd);
    return *this;
  }
  ResponseBuilder& authoritySoa(uint32_t ttl, uint32_t minimum) {
    Bytes rd;
    putName(rd, "ns.example");
    putName(rd, "admin.example");
    put32(rd, 1);
    put32(rd, 3600);
    put32(rd, 600);
    put32(rd, 86400);
    put32(rd, minimum);
    rr(8, 6, ttl, rd);
    return *this;
  }
  ResponseBuilder& opt(uint16_t udpSize = 1232, size_t paddingLen = 0) {
    b_.push_back(0);
    put16(b_, 41);
    put16(b_, udpSize);
    put32(b_, 0);
    if (paddingLen) {
      put16(b_, static_cast<uint16_t>(4 + paddingLen));
      put16(b_, 12);
      put16(b_, static_cast<uint16_t>(paddingLen));
      b_.insert(b_.end(), paddingLen, 0);
    } else {
      put16(b_, 0);
    }
    bump(10);
    return *this;
  }
  Bytes build() const { return b_; }

 private:
  void bump(size_t countOff) {
    uint16_t v = get16(b_, countOff) + 1;
    b_[countOff] = static_cast<uint8_t>(v >> 8);
    b_[countOff + 1] = static_cast<uint8_t>(v);
  }
  void rr(size_t countOff, uint16_t type, uint32_t ttl, const Bytes& rdata) {
    put16(b_, 0xC00C);
    put16(b_, type);
    put16(b_, 1);
    put32(b_, ttl);
    put16(b_, static_cast<uint16_t>(rdata.size()));
    b_.insert(b_.end(), rdata.begin(), rdata.end());
    bump(countOff);
  }
  Bytes b_;
};

}  // namespace testdns
