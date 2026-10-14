#include "dns/message.h"

#include <cstring>

#include "util/bytes.h"

namespace dns {

using util::readU16Be;
using util::readU32Be;
using util::writeU16Be;
using util::writeU32Be;

namespace {

constexpr size_t kRrFixed = 10;   // type, class, ttl, rdlength
constexpr size_t kOptFixed = 11;  // root name + kRrFixed
constexpr size_t kEdeOptLen = 6;  // code(2) len(2) info-code(2)
constexpr uint16_t kDoBit = 0x8000;

uint32_t normalizeTtl(uint32_t ttl) {
  return ttl > 0x7FFFFFFFu ? 0 : ttl;
}

// One resource record located inside a message.
struct Rr {
  size_t start;
  size_t fixed;  // offset of the type field
  uint16_t type;
  uint32_t ttl;
  size_t rdata;
  uint16_t rdlen;
  size_t end;
};

bool readRr(const uint8_t* msg, size_t len, size_t off, Rr& rr) {
  const size_t nameEnd = skipName(msg, len, off);
  if (nameEnd == 0 || nameEnd + kRrFixed > len) return false;
  rr.start = off;
  rr.fixed = nameEnd;
  rr.type = readU16Be(msg + nameEnd);
  rr.ttl = readU32Be(msg + nameEnd + 4);
  rr.rdlen = readU16Be(msg + nameEnd + 8);
  rr.rdata = nameEnd + kRrFixed;
  rr.end = rr.rdata + rr.rdlen;
  return rr.end <= len;
}

// Offset just past the (single) question, or 0 if malformed.
size_t questionEnd(const uint8_t* msg, size_t len) {
  const size_t nameEnd = skipName(msg, len, kHeaderSize);
  if (nameEnd == 0 || nameEnd + 4 > len) return 0;
  return nameEnd + 4;
}

void writeOpt(uint8_t* p, uint16_t udpSize, uint8_t extRcode, bool dnssecOk, uint16_t rdlen) {
  p[0] = 0;  // root owner name
  writeU16Be(p + 1, kTypeOpt);
  writeU16Be(p + 3, udpSize);
  p[5] = extRcode;
  p[6] = 0;  // EDNS version
  writeU16Be(p + 7, dnssecOk ? kDoBit : 0);
  writeU16Be(p + 9, rdlen);
}

}  // namespace

size_t Query::udpReplyLimit() const {
  if (!edns.present) return kMinUdpPayload;
  if (edns.udpSize < kMinUdpPayload) return kMinUdpPayload;
  if (edns.udpSize > kMaxUdpPayload) return kMaxUdpPayload;
  return edns.udpSize;
}

ParseStatus parseQuery(const uint8_t* pkt, size_t len, Query& out) {
  out = Query{};
  if (len < kHeaderSize) return ParseStatus::kDrop;
  out.id = readU16Be(pkt);
  out.flags = readU16Be(pkt + 2);
  if (out.flags & flag::kQr) return ParseStatus::kDrop;  // never answer responses
  if (out.flags & flag::kOpcodeMask) return ParseStatus::kNotImp;

  const uint16_t qd = readU16Be(pkt + 4);
  const uint16_t an = readU16Be(pkt + 6);
  const uint16_t ns = readU16Be(pkt + 8);
  const uint16_t ar = readU16Be(pkt + 10);
  if (qd != 1) return ParseStatus::kFormErr;

  const NameParse np = parseUncompressedName(pkt, len, kHeaderSize, out.qnameWire, out.qname);
  if (!np.ok || np.end + 4 > len) return ParseStatus::kFormErr;
  out.qnameWireLen = np.wireLen;
  out.qnameLen = np.textLen;
  out.qtype = readU16Be(pkt + np.end);
  out.qclass = readU16Be(pkt + np.end + 2);
  out.hasQuestion = true;

  if (an != 0 || ns != 0) return ParseStatus::kFormErr;

  size_t pos = np.end + 4;
  for (uint16_t i = 0; i < ar; i++) {
    Rr rr;
    if (!readRr(pkt, len, pos, rr)) return ParseStatus::kFormErr;
    if (rr.type == kTypeOpt) {
      if (out.edns.present) return ParseStatus::kFormErr;  // at most one OPT
      if (rr.fixed != rr.start + 1 || pkt[rr.start] != 0) return ParseStatus::kFormErr;
      // Options must tile the RDATA exactly.
      size_t o = rr.rdata;
      while (o < rr.end) {
        if (o + 4 > rr.end) return ParseStatus::kFormErr;
        const size_t olen = readU16Be(pkt + o + 2);
        if (o + 4 + olen > rr.end) return ParseStatus::kFormErr;
        o += 4 + olen;
      }
      out.edns.present = true;
      out.edns.udpSize = readU16Be(pkt + rr.fixed + 2);
      out.edns.version = pkt[rr.fixed + 5];
      out.edns.dnssecOk = readU16Be(pkt + rr.fixed + 6) & kDoBit;
    }
    pos = rr.end;
  }
  // Trailing bytes after the last record are ignored (lenient, like most servers).

  if (out.edns.present && out.edns.version > 0) return ParseStatus::kBadVers;
  if (out.qclass != kClassIn) return ParseStatus::kRefused;
  return ParseStatus::kOk;
}

// ---------------------------------------------------------------------------
// ReplyWriter

bool ReplyWriter::reserve(size_t n) {
  if (failed_ || pos_ + n > cap_) {
    failed_ = true;
    return false;
  }
  return true;
}

bool ReplyWriter::enter(Section s) {
  if (!begun_ || failed_ || s < section_) {
    failed_ = true;
    return false;
  }
  section_ = s;
  return true;
}

bool ReplyWriter::begin(const Query& q, Rcode rc) {
  pos_ = 0;
  failed_ = false;
  an_ = ns_ = ar_ = 0;
  section_ = Section::kAnswer;
  hasQuestion_ = q.hasQuestion;
  rcode_ = static_cast<uint16_t>(rc);
  const size_t qlen = q.hasQuestion ? q.qnameWireLen + 4u : 0u;
  if (!reserve(kHeaderSize + qlen)) return false;
  const uint16_t flags = flag::kQr | flag::kRa | (q.flags & (flag::kOpcodeMask | flag::kRd | flag::kCd)) |
                         (rcode_ & flag::kRcodeMask);
  writeU16Be(buf_, q.id);
  writeU16Be(buf_ + 2, flags);
  writeU16Be(buf_ + 4, q.hasQuestion ? 1 : 0);
  memset(buf_ + 6, 0, 6);
  pos_ = kHeaderSize;
  if (q.hasQuestion) {
    memcpy(buf_ + pos_, q.qnameWire, q.qnameWireLen);
    pos_ += q.qnameWireLen;
    writeU16Be(buf_ + pos_, q.qtype);
    writeU16Be(buf_ + pos_ + 2, q.qclass);
    pos_ += 4;
  }
  begun_ = true;
  return true;
}

bool ReplyWriter::addAnswerA(uint32_t ttl, const uint8_t addr[4]) {
  if (!enter(Section::kAnswer) || !hasQuestion_ || !reserve(2 + kRrFixed + 4)) return false;
  uint8_t* p = buf_ + pos_;
  writeU16Be(p, 0xC000 | kHeaderSize);  // owner = the question name
  writeU16Be(p + 2, kTypeA);
  writeU16Be(p + 4, kClassIn);
  writeU32Be(p + 6, ttl);
  writeU16Be(p + 10, 4);
  memcpy(p + 12, addr, 4);
  pos_ += 16;
  an_++;
  return true;
}

bool ReplyWriter::addAnswerAaaa(uint32_t ttl, const uint8_t addr[16]) {
  if (!enter(Section::kAnswer) || !hasQuestion_ || !reserve(2 + kRrFixed + 16)) return false;
  uint8_t* p = buf_ + pos_;
  writeU16Be(p, 0xC000 | kHeaderSize);
  writeU16Be(p + 2, kTypeAaaa);
  writeU16Be(p + 4, kClassIn);
  writeU32Be(p + 6, ttl);
  writeU16Be(p + 10, 16);
  memcpy(p + 12, addr, 16);
  pos_ += 28;
  an_++;
  return true;
}

bool ReplyWriter::addAuthoritySoa(uint32_t ttl) {
  // Owner = question name; MNAME and RNAME = root; serial 1, then refresh, retry,
  // expire, and MINIMUM = ttl so the negative answer is cached for `ttl` seconds.
  constexpr uint16_t kRdlen = 1 + 1 + 20;
  if (!enter(Section::kAuthority) || !hasQuestion_ || !reserve(2 + kRrFixed + kRdlen)) return false;
  uint8_t* p = buf_ + pos_;
  writeU16Be(p, 0xC000 | kHeaderSize);
  writeU16Be(p + 2, kTypeSoa);
  writeU16Be(p + 4, kClassIn);
  writeU32Be(p + 6, ttl);
  writeU16Be(p + 10, kRdlen);
  p[12] = 0;                  // MNAME
  p[13] = 0;                  // RNAME
  writeU32Be(p + 14, 1);      // serial
  writeU32Be(p + 18, 3600);   // refresh
  writeU32Be(p + 22, 600);    // retry
  writeU32Be(p + 26, 86400);  // expire
  writeU32Be(p + 30, ttl);    // minimum
  pos_ += 2 + kRrFixed + kRdlen;
  ns_++;
  return true;
}

bool ReplyWriter::addOpt(uint16_t udpSize, bool dnssecOk, uint16_t ede) {
  const uint16_t rdlen = ede == kEdeNone ? 0 : kEdeOptLen;
  if (!enter(Section::kAdditional) || !reserve(kOptFixed + rdlen)) return false;
  uint8_t* p = buf_ + pos_;
  writeOpt(p, udpSize, static_cast<uint8_t>(rcode_ >> 4), dnssecOk, rdlen);
  if (rdlen) {
    writeU16Be(p + kOptFixed, kOptEde);
    writeU16Be(p + kOptFixed + 2, 2);
    writeU16Be(p + kOptFixed + 4, ede);
  }
  pos_ += kOptFixed + rdlen;
  ar_++;
  return true;
}

size_t ReplyWriter::finish() {
  if (!begun_ || failed_) return 0;
  writeU16Be(buf_ + 6, an_);
  writeU16Be(buf_ + 8, ns_);
  writeU16Be(buf_ + 10, ar_);
  return pos_;
}

// ---------------------------------------------------------------------------
// Synthesized replies

size_t buildBlockedReply(const Query& q, const BlockedReplyOptions& opt, uint8_t* out, size_t cap) {
  static const uint8_t kZero[16] = {0};
  if (!q.hasQuestion) return 0;
  ReplyWriter w(out, cap);
  w.begin(q, Rcode::kNoError);
  if (q.qtype == kTypeA)
    w.addAnswerA(opt.ttl, kZero);
  else if (q.qtype == kTypeAaaa)
    w.addAnswerAaaa(opt.ttl, kZero);
  else
    w.addAuthoritySoa(opt.ttl);  // HTTPS/SVCB/etc: NODATA, never NXDOMAIN
  if (q.edns.present) w.addOpt(kMaxUdpPayload, q.edns.dnssecOk, opt.ede);
  return w.finish();
}

size_t buildAddressReply(const Query& q, const uint8_t* v4, const uint8_t* v6, uint32_t ttl, uint8_t* out,
                         size_t cap) {
  if (!q.hasQuestion) return 0;
  ReplyWriter w(out, cap);
  w.begin(q, Rcode::kNoError);
  if (q.qtype == kTypeA && v4)
    w.addAnswerA(ttl, v4);
  else if (q.qtype == kTypeAaaa && v6)
    w.addAnswerAaaa(ttl, v6);
  else
    w.addAuthoritySoa(ttl);
  if (q.edns.present) w.addOpt(kMaxUdpPayload, q.edns.dnssecOk, kEdeNone);
  return w.finish();
}

size_t buildNegativeReply(const Query& q, Rcode rc, uint32_t ttl, uint8_t* out, size_t cap) {
  if (!q.hasQuestion) return 0;
  ReplyWriter w(out, cap);
  w.begin(q, rc);
  w.addAuthoritySoa(ttl);
  if (q.edns.present) w.addOpt(kMaxUdpPayload, q.edns.dnssecOk, kEdeNone);
  return w.finish();
}

size_t buildErrorReply(const Query& q, Rcode rc, uint8_t* out, size_t cap) {
  ReplyWriter w(out, cap);
  w.begin(q, rc);
  if (q.edns.present) w.addOpt(kMaxUdpPayload, q.edns.dnssecOk, kEdeNone);
  return w.finish();
}

// ---------------------------------------------------------------------------
// Forwarding

size_t buildUpstreamQuery(const Query& q, uint16_t id, const UpstreamQueryOptions& opt, uint8_t* out,
                          size_t cap) {
  if (!q.hasQuestion) return 0;
  const size_t base = kHeaderSize + q.qnameWireLen + 4 + kOptFixed;
  size_t pad = 0;
  size_t rdlen = 0;
  if (opt.padding) {
    const size_t unpadded = base + 4;  // padding option header
    pad = (kPaddingBlock - unpadded % kPaddingBlock) % kPaddingBlock;
    rdlen = 4 + pad;
  }
  const size_t total = base + rdlen;
  if (total > cap) return 0;

  uint16_t flags = flag::kRd | (q.flags & flag::kCd);
  if (opt.requestAd) flags |= flag::kAd;
  writeU16Be(out, id);
  writeU16Be(out + 2, flags);
  writeU16Be(out + 4, 1);
  writeU16Be(out + 6, 0);
  writeU16Be(out + 8, 0);
  writeU16Be(out + 10, 1);
  size_t pos = kHeaderSize;
  memcpy(out + pos, q.qnameWire, q.qnameWireLen);
  pos += q.qnameWireLen;
  writeU16Be(out + pos, q.qtype);
  writeU16Be(out + pos + 2, q.qclass);
  pos += 4;
  writeOpt(out + pos, kMaxUdpPayload, 0, q.edns.dnssecOk, static_cast<uint16_t>(rdlen));
  pos += kOptFixed;
  if (opt.padding) {
    writeU16Be(out + pos, kOptPadding);
    writeU16Be(out + pos + 2, static_cast<uint16_t>(pad));
    memset(out + pos + 4, 0, pad);
    pos += 4 + pad;
  }
  return pos;
}

bool inspectResponse(const uint8_t* msg, size_t len, ResponseInfo& info) {
  info = ResponseInfo{};
  if (len < kHeaderSize) return false;
  info.id = readU16Be(msg);
  info.flags = readU16Be(msg + 2);
  info.rcode = info.flags & flag::kRcodeMask;
  if (!(info.flags & flag::kQr) || readU16Be(msg + 4) != 1) return false;
  info.an = readU16Be(msg + 6);
  info.ns = readU16Be(msg + 8);
  info.ar = readU16Be(msg + 10);
  info.questionEnd = questionEnd(msg, len);
  if (info.questionEnd == 0) return false;

  const uint32_t total = static_cast<uint32_t>(info.an) + info.ns + info.ar;
  size_t pos = info.questionEnd;
  bool haveTtl = false;
  for (uint32_t i = 0; i < total; i++) {
    Rr rr;
    if (!readRr(msg, len, pos, rr)) return false;
    const bool inAuthority = i >= info.an && i < static_cast<uint32_t>(info.an) + info.ns;
    if (rr.type == kTypeOpt) {
      if (info.hasOpt || i < static_cast<uint32_t>(info.an) + info.ns) return false;
      info.hasOpt = true;
      info.optOffset = rr.start;
      info.optIsLast = (i + 1 == total);
    } else {
      const uint32_t ttl = normalizeTtl(rr.ttl);
      info.hasRecords = true;
      if (!haveTtl || ttl < info.minTtl) info.minTtl = ttl;
      haveTtl = true;
      if (inAuthority && rr.type == kTypeSoa) {
        const size_t mEnd = skipName(msg, rr.end, rr.rdata);
        const size_t rEnd = mEnd ? skipName(msg, rr.end, mEnd) : 0;
        if (rEnd == 0 || rEnd + 20 != rr.end) return false;
        const uint32_t minimum = normalizeTtl(readU32Be(msg + rEnd + 16));
        const uint32_t neg = ttl < minimum ? ttl : minimum;
        if (!info.hasSoa || neg < info.negativeTtl) info.negativeTtl = neg;
        info.hasSoa = true;
      }
    }
    pos = rr.end;
  }
  return true;
}

bool responseMatches(const uint8_t* msg, size_t len, uint16_t id, const Query& q) {
  if (len < kHeaderSize || !q.hasQuestion) return false;
  if (readU16Be(msg) != id) return false;
  if (!(readU16Be(msg + 2) & flag::kQr) || readU16Be(msg + 4) != 1) return false;
  const size_t qEnd = questionEnd(msg, len);
  if (qEnd == 0) return false;
  if (!nameEquals(msg, len, kHeaderSize, q.qnameWire, q.qnameWireLen)) return false;
  return readU16Be(msg + qEnd - 4) == q.qtype && readU16Be(msg + qEnd - 2) == q.qclass;
}

size_t stripTrailingOpt(uint8_t* msg, size_t len, const ResponseInfo& info) {
  if (!info.hasOpt || !info.optIsLast || info.optOffset > len || info.ar == 0) return 0;
  writeU16Be(msg + 10, static_cast<uint16_t>(info.ar - 1));
  return info.optOffset;
}

bool ageTtls(uint8_t* msg, size_t len, uint32_t elapsed) {
  if (len < kHeaderSize) return false;
  const uint32_t total = static_cast<uint32_t>(readU16Be(msg + 6)) + readU16Be(msg + 8) + readU16Be(msg + 10);
  size_t pos = questionEnd(msg, len);
  if (pos == 0) return false;
  for (uint32_t i = 0; i < total; i++) {
    Rr rr;
    if (!readRr(msg, len, pos, rr)) return false;
    if (rr.type != kTypeOpt) {
      const uint32_t ttl = normalizeTtl(rr.ttl);
      writeU32Be(msg + rr.fixed + 4, ttl > elapsed ? ttl - elapsed : 0);
    }
    pos = rr.end;
  }
  return true;
}

size_t finalizeForClient(const uint8_t* answer, size_t len, const Query& q, const ClientReplyOptions& opt,
                         uint8_t* out, size_t cap) {
  if (len < kHeaderSize) return 0;
  const size_t optLen = q.edns.present ? kOptFixed : 0;
  const size_t limit = opt.sizeLimit < cap ? opt.sizeLimit : cap;
  const uint16_t upFlags = readU16Be(answer + 2);

  size_t body;
  bool truncated = false;
  if (len + optLen <= limit) {
    memcpy(out, answer, len);
    body = len;
  } else {
    const size_t qEnd = questionEnd(answer, len);
    if (qEnd == 0 || qEnd + optLen > cap) return 0;
    memcpy(out, answer, qEnd);
    writeU16Be(out + 6, 0);
    writeU16Be(out + 8, 0);
    writeU16Be(out + 10, 0);
    body = qEnd;
    truncated = true;
  }

  uint16_t flags = upFlags & ~(flag::kRd | flag::kCd | flag::kAd | flag::kTc);
  flags |= flag::kRa | (q.flags & (flag::kRd | flag::kCd));
  if ((upFlags & flag::kAd) && opt.authenticatedUpstream && q.wantsAd()) flags |= flag::kAd;
  if (truncated || (upFlags & flag::kTc)) flags |= flag::kTc;
  writeU16Be(out, q.id);
  writeU16Be(out + 2, flags);

  if (q.edns.present) {
    writeOpt(out + body, kMaxUdpPayload, 0, q.edns.dnssecOk, 0);
    writeU16Be(out + 10, static_cast<uint16_t>(readU16Be(out + 10) + 1));
    body += kOptFixed;
  }
  return body;
}

}  // namespace dns
