#pragma once
// Temporary DNS rewrites (dashboard "Rewrites", ARCHITECTURE.md §5.7): answer a name with
// a fixed IPv4/IPv6 address or alias it to another name, for 1 minute to 24 hours.
//
//  - Domain: an exact name ("nas", "app.example.com") or a wildcard "*.example.com"
//    that covers every subdomain but not example.com itself. An exact entry wins over
//    any wildcard; among wildcards the longest (most specific) wins.
//  - Per name: one IPv4 and/or one IPv6, or one alias (CNAME), never both (RFC 1034
//    §3.6.2). Adding the same name and kind again replaces its answer and time.
//  - Names answered locally anyway (localhost, private reverse zones, .local, the
//    Firefox/iCloud canaries) can't be rewritten or be alias targets.
//  - Times are monotonic milliseconds, so a wall-clock jump never ends a rewrite early.
//    The file stores absolute Unix expiry times; entries loaded from it wait ("pending")
//    until the clock is synced, then get their remaining time back or are dropped.
//
// Not thread-safe: the owner (src/app/rewrites) locks around every call. resolve() is
// allocation-free (DNS hot path).

#include <cstddef>
#include <cstdint>

#include "dns/rewrite_reply.h"

namespace rules {

enum class TargetKind : uint8_t { kIpv4, kIpv6, kName };

enum class RewriteStatus {
  kAdded,
  kUpdated,  // same name and kind: answer/time replaced
  kRemoved,
  kBadDomain,
  kLocalName,  // answered locally (localhost, .local, private reverse, canaries)
  kBadTarget,
  kSelfTarget,
  kLoop,  // the alias would loop or make a chain longer than dns::kMaxRewriteHops
  kBadDuration,
  kConflict,  // address and alias for the same name
  kFull,
  kNotFound,
};

const char* rewriteStatusMessage(RewriteStatus s);
inline bool rewriteOk(RewriteStatus s) {
  return s == RewriteStatus::kAdded || s == RewriteStatus::kUpdated || s == RewriteStatus::kRemoved;
}

constexpr size_t kRewriteTextMax = 253;  // dotted name without trailing dot

// One row for the dashboard.
struct RewriteView {
  char domain[kRewriteTextMax + 3] = {0};  // with "*." for a wildcard
  char target[kRewriteTextMax + 1] = {0};  // canonical IP text or name
  TargetKind kind = TargetKind::kIpv4;
  bool pending = false;      // loaded from flash, waiting for the clock
  uint32_t secondsLeft = 0;  // rounded up; 0 while pending
};

class RewriteTable {
 public:
  static constexpr size_t kMax = 64;
  static constexpr uint32_t kMaxMinutes = 24 * 60;
  // One line per entry: "<domain> <target> <unix expiry>\n".
  static constexpr size_t kMaxTextBytes = kMax * (kRewriteTextMax + 2 + 1 + kRewriteTextMax + 1 + 20 + 1);
  // A loaded entry with more time left than this has a bad clock behind it: dropped.
  static constexpr int64_t kMaxLoadSeconds = static_cast<int64_t>(kMaxMinutes) * 60 + 60;

  RewriteStatus add(const char* domain, const char* target, uint32_t minutes, uint64_t nowMs);
  RewriteStatus remove(const char* domain, const char* target);
  void clear() { count_ = 0; }

  // `qname`: lowercase, no trailing dot (dns::Query::qname). Follows aliases through
  // the table (up to dns::kMaxRewriteHops). False if no active rewrite matches.
  bool resolve(const char* qname, size_t len, uint64_t nowMs, dns::RewriteAnswer& out) const;

  // Maintenance. Drops expired entries; returns how many.
  size_t purgeExpired(uint64_t nowMs);
  // Gives pending entries their remaining time once the clock is synced; drops those
  // already expired or impossibly far away. Returns how many were dropped.
  size_t activate(uint64_t nowMs, int64_t unixNow);
  bool hasPending() const;

  // Whole lines only. False (nothing written) if an active entry exists and the clock
  // is not synced: its absolute expiry is unknown. Expired entries are left out.
  bool serialize(char* out, size_t cap, size_t& written, uint64_t nowMs, bool synced, int64_t unixNow) const;
  // Replaces the table with the file's valid lines, all pending. Malformed, duplicate,
  // conflicting and excess lines are skipped. Returns the number loaded.
  size_t parse(const char* text, size_t len);

  size_t list(RewriteView* out, size_t max, uint64_t nowMs) const;
  size_t size() const { return count_; }

 private:
  struct Entry {
    char domain[kRewriteTextMax + 1];  // without "*."
    uint8_t domainLen;
    bool wildcard;
    TargetKind kind;
    char target[kRewriteTextMax + 1];  // canonical text
    uint8_t targetLen;
    uint8_t addr[16];
    bool pending;
    uint64_t expiresMs;   // active entries
    int64_t expiresUnix;  // pending entries
  };

  bool active(const Entry& e, uint64_t nowMs) const { return !e.pending && nowMs < e.expiresMs; }
  // Finds the rewrite group for `name` (exact first, then the longest wildcard).
  // Fills the indices of its IPv4/IPv6/alias entries (-1 = none); false if none.
  bool findGroup(const char* name, size_t len, uint64_t nowMs, int& v4, int& v6, int& alias) const;
  int find(const char* domain, size_t len, bool wildcard, TargetKind kind) const;  // any state
  RewriteStatus insert(const Entry& e);  // after validation: duplicate/conflict/full checks
  void erase(size_t i);

  Entry entries_[kMax];
  size_t count_ = 0;
};

// Input parsing (exposed for tests and the dashboard).
// Lowercases and trims; strips one trailing dot; "*." prefix -> wildcard (if allowed).
RewriteStatus parseRewriteDomain(const char* in, char* out, uint8_t& outLen, bool& wildcard);
// IP (dotted IPv4 without leading zeros, or IPv6 incl. "::" and an embedded IPv4) or a
// name. `text` gets the canonical form (RFC 5952 for IPv6).
RewriteStatus parseRewriteTarget(const char* in, TargetKind& kind, uint8_t addr[16], char* text,
                                 uint8_t& textLen);
bool parseIpv4Strict(const char* s, size_t len, uint8_t out[4]);
bool parseIpv6(const char* s, size_t len, uint8_t out[16]);
size_t formatIpv6(const uint8_t a[16], char* out, size_t cap);  // RFC 5952

}  // namespace rules
