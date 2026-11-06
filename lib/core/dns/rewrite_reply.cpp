#include "dns/rewrite_reply.h"

#include <cstring>

#include "util/bytes.h"

namespace dns {

using util::readU16Be;
using util::readU32Be;
using util::writeU16Be;
using util::writeU32Be;

namespace {

constexpr size_t kRrFixed = 10;  // type, class, ttl, rdlength

// RDATA that may hold compressed names (RFC 3597 §4 and the types it says receivers
// should decompress): `pre` fixed bytes, `names` names, then exactly `post` bytes. They
// are rewritten uncompressed; every other type is copied as it is (no compression).
struct Layout {
  uint16_t type;
  uint8_t pre;
  uint8_t names;
  uint8_t post;
};
constexpr Layout kLayouts[] = {
    {2, 0, 1, 0},                                               // NS
    {3, 0, 1, 0},                                               // MD
    {4, 0, 1, 0},                                               // MF
    {kTypeCname, 0, 1, 0}, {kTypeSoa, 0, 2, 20}, {7, 0, 1, 0},  // MB
    {8, 0, 1, 0},                                               // MG
    {9, 0, 1, 0},                                               // MR
    {kTypePtr, 0, 1, 0},   {14, 0, 2, 0},                       // MINFO
    {15, 2, 1, 0},                                              // MX
    {17, 0, 2, 0},                                              // RP
    {18, 2, 1, 0},                                              // AFSDB
    {21, 2, 1, 0},                                              // RT
    {26, 2, 2, 0},                                              // PX
    {33, 6, 1, 0},                                              // SRV
    {36, 2, 1, 0},                                              // KX
    {39, 0, 1, 0},                                              // DNAME
};

const Layout* layoutFor(uint16_t type) {
  for (const Layout& l : kLayouts)
    if (l.type == type) return &l;
  return nullptr;
}

class Out {
 public:
  Out(uint8_t* buf, size_t cap) : buf_(buf), cap_(cap) {}
  bool put(const uint8_t* p, size_t n) {
    if (!room(n)) return false;
    memcpy(buf_ + pos_, p, n);
    pos_ += n;
    return true;
  }
  bool put16(uint16_t v) {
    if (!room(2)) return false;
    writeU16Be(buf_ + pos_, v);
    pos_ += 2;
    return true;
  }
  bool put32(uint32_t v) {
    if (!room(4)) return false;
    writeU32Be(buf_ + pos_, v);
    pos_ += 4;
    return true;
  }
  void set16(size_t at, uint16_t v) { writeU16Be(buf_ + at, v); }
  size_t pos() const { return pos_; }
  bool failed() const { return failed_; }

 private:
  bool room(size_t n) {
    if (failed_ || pos_ + n > cap_) failed_ = true;
    return !failed_;
  }
  uint8_t* buf_;
  size_t cap_;
  size_t pos_ = 0;
  bool failed_ = false;
};

uint32_t capTtl(uint32_t ttl, uint32_t cap) {
  if (ttl > 0x7FFFFFFFu) ttl = 0;  // RFC 2181 §8
  return ttl < cap ? ttl : cap;
}

// Owner name given as a compression pointer to an earlier name in our own reply.
void rrHeader(Out& o, uint16_t ownerPtr, uint16_t type, uint32_t ttl, uint16_t rdlen) {
  o.put16(static_cast<uint16_t>(0xC000 | ownerPtr));
  o.put16(type);
  o.put16(kClassIn);
  o.put32(ttl);
  o.put16(rdlen);
}

enum class Copy { kWritten, kSkipped, kBad, kOverflow };

// Copies the record at src[off] with every name decompressed. `next` = past it.
Copy copyRecord(const uint8_t* src, size_t len, size_t off, uint32_t ttlCap, Out& o, size_t& next) {
  uint8_t name[kMaxNameWire];
  size_t nameLen = 0;
  const size_t p = readName(src, len, off, name, nameLen);
  if (p == 0 || p + kRrFixed > len) return Copy::kBad;
  const uint16_t type = readU16Be(src + p);
  const uint16_t cls = readU16Be(src + p + 2);
  const uint32_t ttl = readU32Be(src + p + 4);
  const size_t rd = p + kRrFixed;
  const size_t rdlen = readU16Be(src + p + 8);
  if (rd + rdlen > len) return Copy::kBad;
  next = rd + rdlen;
  if (type == kTypeOpt) return Copy::kSkipped;  // hop-by-hop; never outside the additional section

  o.put(name, nameLen);
  o.put16(type);
  o.put16(cls);
  o.put32(capTtl(ttl, ttlCap));
  const size_t rdlenAt = o.pos();
  o.put16(0);
  const size_t start = o.pos();
  const Layout* l = layoutFor(type);
  if (!l) {
    o.put(src + rd, rdlen);
  } else {
    size_t at = rd;
    if (l->pre > rdlen) return Copy::kBad;
    o.put(src + at, l->pre);
    at += l->pre;
    for (uint8_t k = 0; k < l->names; k++) {
      const size_t end = readName(src, len, at, name, nameLen);
      if (end == 0 || end > rd + rdlen) return Copy::kBad;
      o.put(name, nameLen);
      at = end;
    }
    if (at + l->post != rd + rdlen) return Copy::kBad;  // trailing garbage or short
    o.put(src + at, l->post);
  }
  if (o.failed()) return Copy::kOverflow;
  const size_t newLen = o.pos() - start;
  if (newLen > 0xFFFF) return Copy::kBad;
  o.set16(rdlenAt, static_cast<uint16_t>(newLen));
  return Copy::kWritten;
}

size_t servfail(const Query& q, uint8_t* out, size_t cap) {
  return buildErrorReply(q, Rcode::kServFail, out, cap);
}

}  // namespace

void RewriteAnswer::clear() {
  end = End::kAddress;
  ttl = kRewriteMaxTtl;
  hops = 0;
  nameOff[0] = 0;
  hasV4 = hasV6 = false;
}

bool RewriteAnswer::addHop(const uint8_t* wire, size_t len) {
  if (hops >= kMaxRewriteHops || len == 0 || nameOff[hops] + len > sizeof(chain)) return false;
  memcpy(chain + nameOff[hops], wire, len);
  nameOff[hops + 1] = static_cast<uint16_t>(nameOff[hops] + len);
  hops++;
  return true;
}

bool rewriteTargetQuery(const Query& q, const RewriteAnswer& rw, Query& out) {
  if (rw.hops == 0) return false;
  size_t len;
  const uint8_t* wire = rw.hop(rw.hops - 1, len);
  out = q;
  const NameParse np = parseUncompressedName(wire, len, 0, out.qnameWire, out.qname);
  if (!np.ok || np.end != len || np.wireLen <= 1) return false;  // never the root
  out.qnameWireLen = np.wireLen;
  out.qnameLen = np.textLen;
  return true;
}

size_t buildRewriteReply(const Query& q, const RewriteAnswer& rw, const uint8_t* target, size_t targetLen,
                         size_t sizeLimit, uint8_t* out, size_t cap) {
  if (!q.hasQuestion || rw.end == RewriteAnswer::End::kLoop) return servfail(q, out, cap);

  // The upstream/cached answer for the last hop.
  const bool useTarget = rw.end == RewriteAnswer::End::kForward && target;
  uint16_t rcode = 0, tc = 0, an = 0, ns = 0;
  size_t at = 0;
  if (useTarget) {
    if (targetLen < kHeaderSize) return servfail(q, out, cap);
    const uint16_t f = readU16Be(target + 2);
    rcode = f & flag::kRcodeMask;
    tc = f & flag::kTc;
    if ((f & flag::kQr) == 0 || (rcode != 0 && rcode != static_cast<uint16_t>(Rcode::kNxDomain)) ||
        readU16Be(target + 4) != 1)
      return servfail(q, out, cap);
    an = readU16Be(target + 6);
    ns = readU16Be(target + 8);
    at = skipName(target, targetLen, kHeaderSize);
    if (at == 0 || at + 4 > targetLen) return servfail(q, out, cap);
    at += 4;
  }

  Out o(out, cap);
  o.put16(q.id);
  o.put16(static_cast<uint16_t>(flag::kQr | flag::kRa | tc | rcode));
  o.put16(1);
  o.put16(0);  // ANCOUNT, NSCOUNT, ARCOUNT: filled in below
  o.put16(0);
  o.put16(0);
  o.put(q.qnameWire, q.qnameWireLen);
  o.put16(q.qtype);
  o.put16(q.qclass);
  if (o.failed()) return servfail(q, out, cap);
  const size_t questionEnd = o.pos();

  uint16_t anCount = 0, nsCount = 0;
  size_t owner = kHeaderSize;  // the question name, then each CNAME target in turn
  for (uint8_t i = 0; i < rw.hops; i++) {
    size_t len;
    const uint8_t* wire = rw.hop(i, len);
    rrHeader(o, static_cast<uint16_t>(owner), kTypeCname, rw.ttl, static_cast<uint16_t>(len));
    owner = o.pos();  // < 0x3FFF: question + at most kRewriteChainBytes of names
    o.put(wire, len);
    anCount++;
  }

  if (rw.end == RewriteAnswer::End::kAddress) {
    bool answered = q.qtype == kTypeCname && rw.hops > 0;
    if (q.qtype == kTypeA && rw.hasV4) {
      rrHeader(o, static_cast<uint16_t>(owner), kTypeA, rw.ttl, 4);
      o.put(rw.v4, 4);
      anCount++;
      answered = true;
    } else if (q.qtype == kTypeAaaa && rw.hasV6) {
      rrHeader(o, static_cast<uint16_t>(owner), kTypeAaaa, rw.ttl, 16);
      o.put(rw.v6, 16);
      anCount++;
      answered = true;
    }
    if (!answered) {
      // NODATA for this type, with a synthetic SOA so clients cache it for `ttl`.
      rrHeader(o, static_cast<uint16_t>(owner), kTypeSoa, rw.ttl, 22);
      const uint8_t roots[2] = {0, 0};  // MNAME, RNAME
      o.put(roots, 2);
      o.put32(1);
      o.put32(3600);
      o.put32(600);
      o.put32(86400);
      o.put32(rw.ttl);
      nsCount++;
    }
  } else if (useTarget) {
    for (uint32_t i = 0; i < static_cast<uint32_t>(an) + ns; i++) {
      size_t next = 0;
      const Copy c = copyRecord(target, targetLen, at, rw.ttl, o, next);
      if (c == Copy::kBad) return servfail(q, out, cap);
      if (c == Copy::kOverflow) break;
      if (c == Copy::kWritten) (i < an ? anCount : nsCount)++;
      at = next;
    }
  }
  size_t len = o.pos();
  if (o.failed()) {
    // Doesn't fit the buffer: header + question with TC=1, so the client retries over TCP.
    o.set16(2, static_cast<uint16_t>(flag::kQr | flag::kRa | flag::kTc | rcode));
    anCount = nsCount = 0;
    len = questionEnd;
  }
  o.set16(6, anCount);
  o.set16(8, nsCount);

  ClientReplyOptions co;
  co.authenticatedUpstream = false;  // synthesized: never AD
  co.sizeLimit = sizeLimit;
  const size_t n = finalizeForClient(out, len, q, co, out, cap);
  return n ? n : servfail(q, out, cap);
}

}  // namespace dns
