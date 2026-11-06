#include "rules/rewrites.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "dns/local_zones.h"
#include "dns/name.h"

namespace rules {

namespace {

bool isSpace(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

bool isHostChar(char c) {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

// Trims and lowercases `in` into `out` (cap bytes incl. NUL). False if too long.
bool trimLower(const char* in, char* out, size_t cap, size_t& len) {
  while (*in && isSpace(*in)) in++;
  size_t n = strlen(in);
  while (n && isSpace(in[n - 1])) n--;
  if (n + 1 > cap) return false;
  for (size_t i = 0; i < n; i++) {
    const char c = in[i];
    out[i] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
  }
  out[n] = 0;
  len = n;
  return true;
}

// A host name: labels of 1-63 [a-z0-9-_] chars, at most 253 chars, and a last label
// that isn't all digits (so "1.2.3" is never taken for a name).
bool validHostName(const char* s, size_t len, size_t& labels) {
  labels = 0;
  if (len == 0 || len > kRewriteTextMax) return false;
  size_t start = 0;
  bool allDigits = true;
  for (size_t i = 0; i <= len; i++) {
    if (i == len || s[i] == '.') {
      const size_t l = i - start;
      if (l == 0 || l > dns::kMaxLabel) return false;
      labels++;
      if (i == len) break;
      start = i + 1;
      allDigits = true;
      continue;
    }
    if (!isHostChar(s[i])) return false;
    // RFC 1123: no hyphen at either end of a label.
    if (s[i] == '-' && (i == start || i + 1 == len || s[i + 1] == '.')) return false;
    if (s[i] < '0' || s[i] > '9') allDigits = false;
  }
  return !allDigits;
}

// Names the DNS service answers itself before any rewrite is consulted (every
// optional local zone counted as on, so a rewrite never silently stops working when
// a setting changes).
bool isLocalName(const char* name, size_t len) {
  dns::LocalZoneOptions all;
  all.firefoxCanary = all.icloudPrivateRelay = all.privateReverse = true;
  return dns::classifyLocal(name, len, all) != dns::LocalAnswer::kNone;
}

uint32_t secondsLeft(uint64_t expiresMs, uint64_t nowMs) {
  if (nowMs >= expiresMs) return 0;
  const uint64_t s = (expiresMs - nowMs + 999) / 1000;
  return s > 0xFFFFFFFFu ? 0xFFFFFFFFu : static_cast<uint32_t>(s);
}

int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

const char* rewriteStatusMessage(RewriteStatus s) {
  switch (s) {
    case RewriteStatus::kAdded: return "rewrite added";
    case RewriteStatus::kUpdated: return "rewrite updated";
    case RewriteStatus::kRemoved: return "rewrite removed";
    case RewriteStatus::kBadDomain:
      return "invalid domain (use a name like nas.home or *.example.com for its subdomains)";
    case RewriteStatus::kLocalName:
      return "that name is always answered by the device itself (localhost, .local, private reverse "
             "lookups, Firefox/iCloud canaries)";
    case RewriteStatus::kBadTarget: return "answer must be an IPv4 address, an IPv6 address or a domain name";
    case RewriteStatus::kSelfTarget: return "a domain can't be an alias of itself";
    case RewriteStatus::kLoop: return "that alias would loop or chain more than 8 names";
    case RewriteStatus::kBadDuration: return "duration must be 1 to 1440 minutes (24 h)";
    case RewriteStatus::kConflict:
      return "this name already has a rewrite of the other kind (a name gets addresses or an alias, not "
             "both): remove it first";
    case RewriteStatus::kFull: return "rewrite list full (64): remove one first";
    case RewriteStatus::kNotFound: return "no such rewrite";
  }
  return "?";
}

// ---------------------------------------------------------------------------
// Input parsing

bool parseIpv4Strict(const char* s, size_t len, uint8_t out[4]) {
  size_t i = 0;
  for (int part = 0; part < 4; part++) {
    unsigned v = 0;
    size_t digits = 0;
    const size_t first = i;
    while (i < len && s[i] >= '0' && s[i] <= '9') {
      v = v * 10 + static_cast<unsigned>(s[i++] - '0');
      if (++digits > 3 || v > 255) return false;
    }
    if (digits == 0 || (digits > 1 && s[first] == '0')) return false;  // no octal look-alikes
    out[part] = static_cast<uint8_t>(v);
    if (part < 3) {
      if (i >= len || s[i] != '.') return false;
      i++;
    }
  }
  return i == len;
}

bool parseIpv6(const char* s, size_t len, uint8_t out[16]) {
  uint16_t groups[8] = {0};
  int n = 0;     // groups written
  int gap = -1;  // index where "::" sits
  size_t i = 0;
  if (len < 2) return false;
  if (s[0] == ':') {
    if (s[1] != ':') return false;
    gap = 0;
    i = 2;
    if (i == len) {
      memset(out, 0, 16);
      return true;
    }
  }
  while (i < len) {
    if (n == 8) return false;
    // An embedded IPv4 in the last 32 bits ("::ffff:192.0.2.1").
    size_t end = i;
    while (end < len && s[end] != ':') end++;
    bool dotted = false;
    for (size_t k = i; k < end; k++)
      if (s[k] == '.') dotted = true;
    if (dotted) {
      uint8_t v4[4];
      if (end != len || n > 6 || !parseIpv4Strict(s + i, end - i, v4)) return false;
      groups[n++] = static_cast<uint16_t>(v4[0] << 8 | v4[1]);
      groups[n++] = static_cast<uint16_t>(v4[2] << 8 | v4[3]);
      break;  // the IPv4 part is always last (end == len)
    }
    if (end == i || end - i > 4) return false;
    unsigned v = 0;
    for (size_t k = i; k < end; k++) {
      const int h = hexVal(s[k]);
      if (h < 0) return false;
      v = v << 4 | static_cast<unsigned>(h);
    }
    groups[n++] = static_cast<uint16_t>(v);
    i = end;
    if (i == len) break;
    i++;                         // ':'
    if (i == len) return false;  // trailing single ':'
    if (s[i] == ':') {
      if (gap >= 0) return false;  // a second "::"
      gap = n;
      i++;
    }
  }
  if (gap < 0 && n != 8) return false;
  if (gap >= 0 && n > 7) return false;  // "::" must stand for at least one group
  uint16_t full[8] = {0};
  if (gap < 0) {
    memcpy(full, groups, sizeof(full));
  } else {
    const int tail = n - gap;
    for (int k = 0; k < gap; k++) full[k] = groups[k];
    for (int k = 0; k < tail; k++) full[8 - tail + k] = groups[gap + k];
  }
  for (int k = 0; k < 8; k++) {
    out[2 * k] = static_cast<uint8_t>(full[k] >> 8);
    out[2 * k + 1] = static_cast<uint8_t>(full[k]);
  }
  return true;
}

size_t formatIpv6(const uint8_t a[16], char* out, size_t cap) {
  uint16_t g[8];
  for (int k = 0; k < 8; k++) g[k] = static_cast<uint16_t>(a[2 * k] << 8 | a[2 * k + 1]);
  // RFC 5952 §4.2: the longest run of 2+ zero groups (the first on a tie) becomes "::".
  int best = -1, bestLen = 1;
  for (int k = 0; k < 8;) {
    if (g[k]) {
      k++;
      continue;
    }
    int e = k;
    while (e < 8 && !g[e]) e++;
    if (e - k > bestLen) {
      best = k;
      bestLen = e - k;
    }
    k = e;
  }
  char buf[48];
  size_t n = 0;
  for (int k = 0; k < 8; k++) {
    if (k == best) {
      buf[n++] = ':';
      if (k == 0) buf[n++] = ':';
      k += bestLen - 1;
      continue;
    }
    n += static_cast<size_t>(snprintf(buf + n, sizeof(buf) - n, "%x", g[k]));
    if (k < 7) buf[n++] = ':';
  }
  buf[n] = 0;
  if (n + 1 > cap) return 0;
  memcpy(out, buf, n + 1);
  return n;
}

RewriteStatus parseRewriteDomain(const char* in, char* out, uint8_t& outLen, bool& wildcard) {
  char buf[kRewriteTextMax + 8];
  size_t len;
  wildcard = false;
  if (!in || !trimLower(in, buf, sizeof(buf), len)) return RewriteStatus::kBadDomain;
  const char* p = buf;
  if (len >= 2 && p[0] == '*' && p[1] == '.') {
    wildcard = true;
    p += 2;
    len -= 2;
  }
  if (len && p[len - 1] == '.') len--;
  size_t labels;
  if (!validHostName(p, len, labels)) return RewriteStatus::kBadDomain;
  if (wildcard && labels < 2) return RewriteStatus::kBadDomain;  // never a whole TLD
  // A wildcard covers names below `p`: check one of them as well as `p` itself.
  char probe[kRewriteTextMax + 4];
  if (isLocalName(p, len)) return RewriteStatus::kLocalName;
  if (wildcard) {
    const int n = snprintf(probe, sizeof(probe), "x.%.*s", static_cast<int>(len), p);
    if (n > 0 && isLocalName(probe, static_cast<size_t>(n))) return RewriteStatus::kLocalName;
  }
  memcpy(out, p, len);
  out[len] = 0;
  outLen = static_cast<uint8_t>(len);
  return RewriteStatus::kAdded;
}

RewriteStatus parseRewriteTarget(const char* in, TargetKind& kind, uint8_t addr[16], char* text,
                                 uint8_t& textLen) {
  char buf[kRewriteTextMax + 8];
  size_t len;
  if (!in || !trimLower(in, buf, sizeof(buf), len) || len == 0) return RewriteStatus::kBadTarget;
  memset(addr, 0, 16);
  if (strchr(buf, ':')) {
    if (!parseIpv6(buf, len, addr)) return RewriteStatus::kBadTarget;
    kind = TargetKind::kIpv6;
    textLen = static_cast<uint8_t>(formatIpv6(addr, text, kRewriteTextMax + 1));
    return RewriteStatus::kAdded;
  }
  bool numeric = true;
  for (size_t i = 0; i < len; i++)
    if (!((buf[i] >= '0' && buf[i] <= '9') || buf[i] == '.')) numeric = false;
  if (numeric) {
    if (!parseIpv4Strict(buf, len, addr)) return RewriteStatus::kBadTarget;
    kind = TargetKind::kIpv4;
    textLen = static_cast<uint8_t>(
        snprintf(text, kRewriteTextMax + 1, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]));
    return RewriteStatus::kAdded;
  }
  if (len && buf[len - 1] == '.') len--;
  size_t labels;
  if (buf[0] == '*' || !validHostName(buf, len, labels)) return RewriteStatus::kBadTarget;
  if (isLocalName(buf, len)) return RewriteStatus::kLocalName;
  kind = TargetKind::kName;
  memcpy(text, buf, len);
  text[len] = 0;
  textLen = static_cast<uint8_t>(len);
  return RewriteStatus::kAdded;
}

// ---------------------------------------------------------------------------
// Table

int RewriteTable::find(const char* domain, size_t len, bool wildcard, TargetKind kind) const {
  for (size_t i = 0; i < count_; i++) {
    const Entry& e = entries_[i];
    if (e.wildcard == wildcard && e.kind == kind && e.domainLen == len && memcmp(e.domain, domain, len) == 0)
      return static_cast<int>(i);
  }
  return -1;
}

void RewriteTable::erase(size_t i) {
  for (size_t k = i + 1; k < count_; k++) entries_[k - 1] = entries_[k];
  count_--;
}

RewriteStatus RewriteTable::insert(const Entry& e) {
  const int same = find(e.domain, e.domainLen, e.wildcard, e.kind);
  if (same >= 0) {
    entries_[same] = e;
    return RewriteStatus::kUpdated;
  }
  // Addresses and an alias never share a name.
  const bool isAlias = e.kind == TargetKind::kName;
  const TargetKind others[2] = {isAlias ? TargetKind::kIpv4 : TargetKind::kName, TargetKind::kIpv6};
  for (int k = 0; k < (isAlias ? 2 : 1); k++)
    if (find(e.domain, e.domainLen, e.wildcard, others[k]) >= 0) return RewriteStatus::kConflict;
  if (count_ >= kMax) return RewriteStatus::kFull;
  entries_[count_++] = e;
  return RewriteStatus::kAdded;
}

RewriteStatus RewriteTable::add(const char* domain, const char* target, uint32_t minutes, uint64_t nowMs) {
  Entry e;
  memset(&e, 0, sizeof(e));
  RewriteStatus st = parseRewriteDomain(domain, e.domain, e.domainLen, e.wildcard);
  if (st != RewriteStatus::kAdded) return st;
  st = parseRewriteTarget(target, e.kind, e.addr, e.target, e.targetLen);
  if (st != RewriteStatus::kAdded) return st;
  if (minutes < 1 || minutes > kMaxMinutes) return RewriteStatus::kBadDuration;
  if (e.kind == TargetKind::kName && !e.wildcard && e.targetLen == e.domainLen &&
      memcmp(e.target, e.domain, e.domainLen) == 0)
    return RewriteStatus::kSelfTarget;
  e.pending = false;
  e.expiresMs = nowMs + static_cast<uint64_t>(minutes) * 60000;
  purgeExpired(nowMs);

  // Keep a copy so a rejected alias (loop) leaves the table exactly as it was.
  const int prevIdx = find(e.domain, e.domainLen, e.wildcard, e.kind);
  Entry prev;
  if (prevIdx >= 0) prev = entries_[prevIdx];
  st = insert(e);
  if (!rewriteOk(st) || e.kind != TargetKind::kName) return st;

  // Every alias chain (not just the new one: it may extend another chain) must end
  // within dns::kMaxRewriteHops. Wildcards are followed from a name under them.
  bool loops = false;
  dns::RewriteAnswer probe;
  for (size_t i = 0; i < count_ && !loops; i++) {
    const Entry& a = entries_[i];
    if (a.kind != TargetKind::kName || !active(a, nowMs)) continue;
    char name[kRewriteTextMax + 4];
    const int n = snprintf(name, sizeof(name), "%s%s", a.wildcard ? "x." : "", a.domain);
    if (n > 0 && static_cast<size_t>(n) <= kRewriteTextMax &&
        resolve(name, static_cast<size_t>(n), nowMs, probe) && probe.end == dns::RewriteAnswer::End::kLoop)
      loops = true;
  }
  if (loops) {
    const int idx = find(e.domain, e.domainLen, e.wildcard, e.kind);
    if (prevIdx >= 0)
      entries_[idx] = prev;
    else
      erase(static_cast<size_t>(idx));
    return RewriteStatus::kLoop;
  }
  return st;
}

RewriteStatus RewriteTable::remove(const char* domain, const char* target) {
  char d[kRewriteTextMax + 1], t[kRewriteTextMax + 1];
  uint8_t dLen, tLen;
  bool wildcard;
  TargetKind kind;
  uint8_t addr[16];
  if (parseRewriteDomain(domain, d, dLen, wildcard) != RewriteStatus::kAdded) return RewriteStatus::kNotFound;
  if (parseRewriteTarget(target, kind, addr, t, tLen) != RewriteStatus::kAdded)
    return RewriteStatus::kNotFound;
  const int i = find(d, dLen, wildcard, kind);
  if (i < 0 || entries_[i].targetLen != tLen || memcmp(entries_[i].target, t, tLen) != 0)
    return RewriteStatus::kNotFound;
  erase(static_cast<size_t>(i));
  return RewriteStatus::kRemoved;
}

bool RewriteTable::findGroup(const char* name, size_t len, uint64_t nowMs, int& v4, int& v6,
                             int& alias) const {
  v4 = v6 = alias = -1;
  // Exact names first.
  for (size_t i = 0; i < count_; i++) {
    const Entry& e = entries_[i];
    if (e.wildcard || e.domainLen != len || !active(e, nowMs) || memcmp(e.domain, name, len) != 0) continue;
    (e.kind == TargetKind::kIpv4 ? v4 : e.kind == TargetKind::kIpv6 ? v6 : alias) = static_cast<int>(i);
  }
  if (v4 >= 0 || v6 >= 0 || alias >= 0) return true;
  // Then the most specific wildcard: "*.b.c" matches "a.b.c" and "x.a.b.c", not "b.c".
  size_t bestLen = 0;
  for (size_t i = 0; i < count_; i++) {
    const Entry& e = entries_[i];
    if (!e.wildcard || !active(e, nowMs) || len < e.domainLen + 2u || e.domainLen < bestLen) continue;
    if (name[len - e.domainLen - 1] != '.' || memcmp(name + len - e.domainLen, e.domain, e.domainLen) != 0)
      continue;
    if (e.domainLen > bestLen) {
      bestLen = e.domainLen;
      v4 = v6 = alias = -1;
    }
    (e.kind == TargetKind::kIpv4 ? v4 : e.kind == TargetKind::kIpv6 ? v6 : alias) = static_cast<int>(i);
  }
  return v4 >= 0 || v6 >= 0 || alias >= 0;
}

bool RewriteTable::resolve(const char* qname, size_t len, uint64_t nowMs, dns::RewriteAnswer& out) const {
  out.clear();
  const char* name = qname;
  size_t nameLen = len;
  while (true) {
    int v4, v6, alias;
    if (!findGroup(name, nameLen, nowMs, v4, v6, alias)) {
      if (out.hops == 0) return false;
      out.end = dns::RewriteAnswer::End::kForward;  // the last alias target goes upstream
      return true;
    }
    const int group[3] = {v4, v6, alias};
    for (int idx : group) {
      if (idx < 0) continue;
      const uint32_t left = secondsLeft(entries_[idx].expiresMs, nowMs);
      if (left < out.ttl) out.ttl = left;
    }
    if (alias >= 0) {
      const Entry& e = entries_[alias];
      uint8_t wire[dns::kMaxNameWire];
      const size_t wl = dns::encodeName(e.target, e.targetLen, wire, sizeof(wire));
      if (wl == 0 || !out.addHop(wire, wl)) {
        out.end = dns::RewriteAnswer::End::kLoop;
        return true;
      }
      name = e.target;
      nameLen = e.targetLen;
      continue;
    }
    if (v4 >= 0) {
      out.hasV4 = true;
      memcpy(out.v4, entries_[v4].addr, 4);
    }
    if (v6 >= 0) {
      out.hasV6 = true;
      memcpy(out.v6, entries_[v6].addr, 16);
    }
    out.end = dns::RewriteAnswer::End::kAddress;
    return true;
  }
}

size_t RewriteTable::purgeExpired(uint64_t nowMs) {
  size_t dropped = 0;
  for (size_t i = count_; i-- > 0;)
    if (!entries_[i].pending && nowMs >= entries_[i].expiresMs) {
      erase(i);
      dropped++;
    }
  return dropped;
}

size_t RewriteTable::activate(uint64_t nowMs, int64_t unixNow) {
  size_t dropped = 0;
  for (size_t i = count_; i-- > 0;) {
    Entry& e = entries_[i];
    if (!e.pending) continue;
    const int64_t left = e.expiresUnix - unixNow;
    if (left <= 0 || left > kMaxLoadSeconds) {
      erase(i);
      dropped++;
      continue;
    }
    e.pending = false;
    e.expiresMs = nowMs + static_cast<uint64_t>(left) * 1000;
  }
  return dropped;
}

bool RewriteTable::hasPending() const {
  for (size_t i = 0; i < count_; i++)
    if (entries_[i].pending) return true;
  return false;
}

bool RewriteTable::serialize(char* out, size_t cap, size_t& written, uint64_t nowMs, bool synced,
                             int64_t unixNow) const {
  written = 0;
  for (size_t i = 0; i < count_; i++)
    if (!synced && !entries_[i].pending && nowMs < entries_[i].expiresMs) return false;
  for (size_t i = 0; i < count_; i++) {
    const Entry& e = entries_[i];
    int64_t expiry;
    if (e.pending) {
      expiry = e.expiresUnix;
    } else if (nowMs < e.expiresMs) {
      expiry = unixNow + static_cast<int64_t>(secondsLeft(e.expiresMs, nowMs));
    } else {
      continue;  // expired
    }
    char line[2 * kRewriteTextMax + 40];
    const int n = snprintf(line, sizeof(line), "%s%s %s %lld\n", e.wildcard ? "*." : "", e.domain, e.target,
                           static_cast<long long>(expiry));
    if (n <= 0 || written + static_cast<size_t>(n) > cap) break;
    memcpy(out + written, line, static_cast<size_t>(n));
    written += static_cast<size_t>(n);
  }
  return true;
}

size_t RewriteTable::parse(const char* text, size_t len) {
  count_ = 0;
  size_t loaded = 0;
  size_t start = 0;
  while (start < len) {
    size_t end = start;
    while (end < len && text[end] != '\n') end++;
    // Split into three space-separated fields.
    char fields[3][kRewriteTextMax + 24];
    int nf = 0;
    size_t i = start;
    bool bad = false;
    while (i < end && !bad) {
      while (i < end && isSpace(text[i])) i++;
      if (i >= end) break;
      size_t j = i;
      while (j < end && !isSpace(text[j])) j++;
      if (nf == 3 || j - i >= sizeof(fields[0])) {
        bad = true;
        break;
      }
      memcpy(fields[nf], text + i, j - i);
      fields[nf][j - i] = 0;
      nf++;
      i = j;
    }
    start = end + 1;
    if (bad || nf != 3) continue;
    char* stop = nullptr;
    const long long expiry = strtoll(fields[2], &stop, 10);
    if (!stop || *stop || expiry <= 0) continue;
    Entry e;
    memset(&e, 0, sizeof(e));
    if (parseRewriteDomain(fields[0], e.domain, e.domainLen, e.wildcard) != RewriteStatus::kAdded ||
        parseRewriteTarget(fields[1], e.kind, e.addr, e.target, e.targetLen) != RewriteStatus::kAdded)
      continue;
    if (e.kind == TargetKind::kName && !e.wildcard && e.targetLen == e.domainLen &&
        memcmp(e.target, e.domain, e.domainLen) == 0)
      continue;
    e.pending = true;
    e.expiresUnix = expiry;
    if (find(e.domain, e.domainLen, e.wildcard, e.kind) >= 0) continue;  // first line wins
    if (insert(e) == RewriteStatus::kAdded) loaded++;
  }
  return loaded;
}

size_t RewriteTable::list(RewriteView* out, size_t max, uint64_t nowMs) const {
  size_t n = 0;
  for (size_t i = 0; i < count_ && n < max; i++) {
    const Entry& e = entries_[i];
    if (!e.pending && nowMs >= e.expiresMs) continue;
    RewriteView& v = out[n++];
    snprintf(v.domain, sizeof(v.domain), "%s%s", e.wildcard ? "*." : "", e.domain);
    memcpy(v.target, e.target, e.targetLen);
    v.target[e.targetLen] = 0;
    v.kind = e.kind;
    v.pending = e.pending;
    v.secondsLeft = e.pending ? 0 : secondsLeft(e.expiresMs, nowMs);
  }
  return n;
}

}  // namespace rules
