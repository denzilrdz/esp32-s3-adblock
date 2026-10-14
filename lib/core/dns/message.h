#pragma once
// DNS message parsing and building for the forwarder (RFC 1035, 6891, 8914, 7830).
// No allocation: every function works on caller-provided buffers and is
// bounds-checked. See .claude/skills/dns-protocol/SKILL.md for the rules.

#include <cstddef>
#include <cstdint>

#include "dns/name.h"

namespace dns {

constexpr size_t kHeaderSize = 12;
constexpr uint16_t kMinUdpPayload = 512;
constexpr uint16_t kMaxUdpPayload = 1232;  // DNS Flag Day 2020
constexpr size_t kPaddingBlock = 128;      // RFC 8467 query block length

// RR types / classes.
constexpr uint16_t kTypeA = 1;
constexpr uint16_t kTypeNs = 2;
constexpr uint16_t kTypeCname = 5;
constexpr uint16_t kTypeSoa = 6;
constexpr uint16_t kTypePtr = 12;
constexpr uint16_t kTypeTxt = 16;
constexpr uint16_t kTypeAaaa = 28;
constexpr uint16_t kTypeOpt = 41;
constexpr uint16_t kTypeSvcb = 64;
constexpr uint16_t kTypeHttps = 65;
constexpr uint16_t kTypeAny = 255;
constexpr uint16_t kClassIn = 1;

// EDNS option codes and Extended DNS Error info-codes.
constexpr uint16_t kOptPadding = 12;
constexpr uint16_t kOptEde = 15;
constexpr uint16_t kEdeNone = 0xFFFF;
constexpr uint16_t kEdeBlocked = 15;
constexpr uint16_t kEdeFiltered = 17;

// Header flag bits (second 16-bit word).
namespace flag {
constexpr uint16_t kQr = 0x8000;
constexpr uint16_t kOpcodeMask = 0x7800;
constexpr uint16_t kAa = 0x0400;
constexpr uint16_t kTc = 0x0200;
constexpr uint16_t kRd = 0x0100;
constexpr uint16_t kRa = 0x0080;
constexpr uint16_t kAd = 0x0020;
constexpr uint16_t kCd = 0x0010;
constexpr uint16_t kRcodeMask = 0x000F;
}  // namespace flag

// Full 12-bit RCODE (low 4 bits in the header, high 8 in the OPT TTL field).
enum class Rcode : uint16_t {
  kNoError = 0,
  kFormErr = 1,
  kServFail = 2,
  kNxDomain = 3,
  kNotImp = 4,
  kRefused = 5,
  kBadVers = 16,
};

struct Edns {
  bool present = false;
  uint16_t udpSize = 0;
  uint8_t version = 0;
  bool dnssecOk = false;
};

// A validated client query.
struct Query {
  uint16_t id = 0;
  uint16_t flags = 0;
  bool hasQuestion = false;  // false when parsing failed before/inside the question
  uint16_t qtype = 0;
  uint16_t qclass = 0;
  uint8_t qnameWire[kMaxNameWire] = {0};  // lowercased, uncompressed
  uint8_t qnameWireLen = 0;
  char qname[kMaxNameText + 1] = {0};     // lowercased dotted text, no trailing dot
  uint8_t qnameLen = 0;
  Edns edns;

  bool rd() const { return flags & flag::kRd; }
  bool cd() const { return flags & flag::kCd; }
  bool ad() const { return flags & flag::kAd; }
  // RFC 6840 §5.7: only clients that signal AD or DO get the AD bit back.
  bool wantsAd() const { return ad() || edns.dnssecOk; }
  // Largest UDP reply this client accepts.
  size_t udpReplyLimit() const;
};

enum class ParseStatus {
  kOk,
  kDrop,      // not worth answering (too short, or a response): silently ignore
  kFormErr,
  kNotImp,    // opcode other than QUERY
  kRefused,   // class other than IN
  kBadVers,   // EDNS version > 0
};

// Validates and parses a client query. On any status other than kOk/kDrop, the
// fields that could be parsed are filled so an error reply can be built.
ParseStatus parseQuery(const uint8_t* pkt, size_t len, Query& out);

// ---------------------------------------------------------------------------
// Building replies we synthesize (blocked, local, errors).

// Writes header, question, records and OPT in RFC order into a caller buffer.
// Any write that would overflow marks the writer failed; finish() then returns 0.
class ReplyWriter {
 public:
  ReplyWriter(uint8_t* buf, size_t cap) : buf_(buf), cap_(cap) {}

  // Header (QR=1, RA=1, ID/RD/CD copied, AA=0, AD=0) + the echoed question if parsed.
  bool begin(const Query& q, Rcode rc);
  bool addAnswerA(uint32_t ttl, const uint8_t addr[4]);
  bool addAnswerAaaa(uint32_t ttl, const uint8_t addr[16]);
  // Synthetic SOA in the authority section so the negative answer is cached for `ttl`.
  bool addAuthoritySoa(uint32_t ttl);
  // OPT record; `ede` = kEdeNone for no Extended DNS Error option.
  bool addOpt(uint16_t udpSize, bool dnssecOk, uint16_t ede);
  size_t finish();  // final length, or 0 on overflow / misuse

 private:
  enum class Section { kAnswer, kAuthority, kAdditional };
  bool reserve(size_t n);
  bool enter(Section s);

  uint8_t* buf_;
  size_t cap_;
  size_t pos_ = 0;
  bool failed_ = false;
  bool begun_ = false;
  bool hasQuestion_ = false;
  Section section_ = Section::kAnswer;
  uint16_t rcode_ = 0;
  uint16_t an_ = 0, ns_ = 0, ar_ = 0;
};

struct BlockedReplyOptions {
  uint32_t ttl = 10;
  uint16_t ede = kEdeBlocked;  // kEdeFiltered for a banned client
};

// A -> 0.0.0.0, AAAA -> ::, anything else -> NOERROR/NODATA + SOA (never NXDOMAIN).
size_t buildBlockedReply(const Query& q, const BlockedReplyOptions& opt, uint8_t* out, size_t cap);

// Local answer: A/AAAA get the given address (null = NODATA), other types NODATA.
size_t buildAddressReply(const Query& q, const uint8_t* v4, const uint8_t* v6, uint32_t ttl,
                         uint8_t* out, size_t cap);

// NXDOMAIN (or NODATA with kNoError) with a synthetic SOA, for local zones.
size_t buildNegativeReply(const Query& q, Rcode rc, uint32_t ttl, uint8_t* out, size_t cap);

// Error reply (FORMERR, SERVFAIL, NOTIMP, REFUSED, BADVERS). Echoes the question when
// it was parsed and adds an OPT when the query carried one (mandatory for BADVERS).
// parseQuery() fills id/flags for every status except kDrop, so `q` is always usable.
size_t buildErrorReply(const Query& q, Rcode rc, uint8_t* out, size_t cap);

// ---------------------------------------------------------------------------
// Forwarding.

struct UpstreamQueryOptions {
  bool padding = true;    // RFC 7830/8467: pad to a multiple of 128 bytes
  bool requestAd = true;  // set AD=1 so a validating upstream reports AD
};

// Re-encodes the client's question for an upstream with a fresh ID, RD=1, the
// client's CD and DO bits, and our own OPT (1232 bytes, optional padding).
size_t buildUpstreamQuery(const Query& q, uint16_t id, const UpstreamQueryOptions& opt,
                          uint8_t* out, size_t cap);

// Facts about an upstream response gathered in one bounds-checked walk.
struct ResponseInfo {
  uint16_t id = 0;
  uint16_t flags = 0;
  uint16_t rcode = 0;  // low 4 bits only (extended bits live in the stripped OPT)
  uint16_t an = 0, ns = 0, ar = 0;
  size_t questionEnd = 0;
  bool hasOpt = false;
  bool optIsLast = false;
  size_t optOffset = 0;   // start of the OPT RR
  uint32_t minTtl = 0;    // over all non-OPT RRs (0 if none)
  bool hasRecords = false;
  bool hasSoa = false;
  uint32_t negativeTtl = 0;  // min(SOA TTL, SOA MINIMUM) from the authority section
};

// Walks a response; false if it is malformed, not a response, or QDCOUNT != 1.
bool inspectResponse(const uint8_t* msg, size_t len, ResponseInfo& info);

// True if `msg` is a response to `q` sent with upstream ID `id` (ID + question match).
bool responseMatches(const uint8_t* msg, size_t len, uint16_t id, const Query& q);

// Removes a trailing OPT RR in place. Returns the new length, or 0 if the OPT is
// not the last record (cannot be removed safely because of compression pointers).
size_t stripTrailingOpt(uint8_t* msg, size_t len, const ResponseInfo& info);

// Subtracts `elapsed` seconds from every non-OPT RR TTL (floor 0). TTLs above
// 2^31-1 are treated as 0 (RFC 2181 §8). False if the message is malformed.
bool ageTtls(uint8_t* msg, size_t len, uint32_t elapsed);

struct ClientReplyOptions {
  bool authenticatedUpstream = true;  // DoT/DoH with a verified certificate
  size_t sizeLimit = kMinUdpPayload;  // q.udpReplyLimit() for UDP, 65535 for TCP
};

// Turns an upstream/cached answer (without OPT) into the reply for this client:
// client ID, RD from the query, RA=1, AD only if authenticated and wanted, our own
// OPT if the client used EDNS, and TC=1 with empty sections if it does not fit.
size_t finalizeForClient(const uint8_t* answer, size_t len, const Query& q,
                         const ClientReplyOptions& opt, uint8_t* out, size_t cap);

}  // namespace dns
