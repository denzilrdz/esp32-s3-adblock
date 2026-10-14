#include "config/config.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>

namespace config {

namespace {

constexpr uint32_t kSchemaVersion = 1;

struct ProviderInfo {
  const char* name;
  const char* verifyName;
  const char* ip1;
  const char* ip2;
  bool doh;
};

// Hard-coded IPs: no plaintext bootstrap lookup. Quad9's DoH needs HTTP/2, which
// this platform lacks, so Quad9 is DoT only (ARCHITECTURE.md §7.1).
const ProviderInfo kCloudflare = {"cloudflare", "cloudflare-dns.com", "1.1.1.1", "1.0.0.1", true};
const ProviderInfo kQuad9 = {"quad9", "dns.quad9.net", "9.9.9.9", "149.112.112.112", false};

bool parseBool(const char* v, bool& out) {
  if (!strcmp(v, "1") || !strcmp(v, "true") || !strcmp(v, "on")) return out = true, true;
  if (!strcmp(v, "0") || !strcmp(v, "false") || !strcmp(v, "off")) return out = false, true;
  return false;
}

bool parseU32(const char* v, uint32_t min, uint32_t max, uint32_t& out) {
  if (!*v) return false;
  char* end = nullptr;
  const unsigned long n = strtoul(v, &end, 10);
  if (*end || n < min || n > max) return false;
  out = static_cast<uint32_t>(n);
  return true;
}

bool validIpv4(const char* v) {
  int parts = 0;
  const char* p = v;
  while (*p) {
    int n = 0, digits = 0;
    while (*p >= '0' && *p <= '9') {
      n = n * 10 + (*p++ - '0');
      if (++digits > 3) return false;
    }
    if (!digits || n > 255) return false;
    parts++;
    if (*p == '.')
      p++;
    else if (*p)
      return false;
  }
  return parts == 4 && v[strlen(v) - 1] != '.';
}

bool validHostname(const char* v) {
  const size_t n = strlen(v);
  if (n < 3 || n > 63 || !strchr(v, '.') || v[0] == '.' || v[n - 1] == '.') return false;
  for (const char* p = v; *p; p++)
    if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '-' || *p == '.')) return false;
  return !strstr(v, "..");
}

bool validTimezone(const char* v) {
  const size_t n = strlen(v);
  if (n < 3 || n > 47) return false;
  for (const char* p = v; *p; p++) {
    const char c = *p;
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
          strchr("+-:,./<>", c)))
      return false;
  }
  return true;
}

template <size_t N>
bool copyIf(char (&dst)[N], const char* v, bool ok) {
  if (!ok || strlen(v) >= N) return false;
  snprintf(dst, N, "%s", v);
  return true;
}

const ProviderInfo* info(Provider p) {
  switch (p) {
    case Provider::kCloudflare: return &kCloudflare;
    case Provider::kQuad9: return &kQuad9;
    default: return nullptr;
  }
}

}  // namespace

const char* providerName(Provider p) {
  switch (p) {
    case Provider::kCloudflare: return "cloudflare";
    case Provider::kQuad9: return "quad9";
    case Provider::kCustom: return "custom";
    case Provider::kNone: return "none";
  }
  return "none";
}

bool parseProvider(const char* s, Provider& out) {
  for (Provider p : {Provider::kCloudflare, Provider::kQuad9, Provider::kCustom, Provider::kNone})
    if (!strcmp(s, providerName(p))) return out = p, true;
  return false;
}

SetResult setField(AppConfig& c, const char* key, const char* v) {
  if (!key || !v) return SetResult::kInvalid;
  bool ok = false;
  uint32_t n = 0;
  if (!strcmp(key, "up_pri"))
    ok = parseProvider(v, c.primary);
  else if (!strcmp(key, "up_sec"))
    ok = parseProvider(v, c.secondary);
  else if (!strcmp(key, "up_doh"))
    ok = parseBool(v, c.dohFallback);
  else if (!strcmp(key, "up_plain"))
    ok = parseBool(v, c.plainFallback);
  else if (!strcmp(key, "up_cip"))
    ok = copyIf(c.customIp, v, !*v || validIpv4(v));
  else if (!strcmp(key, "up_cip2"))
    ok = copyIf(c.customIp2, v, !*v || validIpv4(v));
  else if (!strcmp(key, "up_cname"))
    ok = copyIf(c.customName, v, !*v || validHostname(v));
  else if (!strcmp(key, "up_cdoh"))
    ok = parseBool(v, c.customDoh);
  else if (!strcmp(key, "pad"))
    ok = parseBool(v, c.padding);
  else if (!strcmp(key, "ad"))
    ok = parseBool(v, c.passAd);
  else if (!strcmp(key, "blk_ttl"))
    ok = parseU32(v, 0, 3600, c.blockedTtl);
  else if (!strcmp(key, "ff_canary"))
    ok = parseBool(v, c.firefoxCanary);
  else if (!strcmp(key, "icloud"))
    ok = parseBool(v, c.icloudRelay);
  else if (!strcmp(key, "priv_rev"))
    ok = parseBool(v, c.privateReverse);
  else if (!strcmp(key, "tz"))
    ok = copyIf(c.timezone, v, validTimezone(v));
  else if (!strcmp(key, "log")) {
    ok = parseU32(v, 0, 3, n);
    if (ok) c.logLevel = static_cast<uint8_t>(n);
  } else {
    return SetResult::kUnknownKey;
  }
  return ok ? SetResult::kOk : SetResult::kInvalid;
}

bool validate(const AppConfig& c, const char** why) {
  const char* reason = nullptr;
  if (c.primary == Provider::kNone)
    reason = "a primary upstream is required";
  else if (c.primary == c.secondary)
    reason = "primary and secondary upstream must differ";
  else if ((c.primary == Provider::kCustom || c.secondary == Provider::kCustom) &&
           (!*c.customIp || !*c.customName))
    reason = "custom upstream needs an IP and a TLS name";
  if (reason && why) *why = reason;
  return !reason;
}

bool load(const hal::IKeyValueStore& kv, AppConfig& c) {
  uint32_t ver = 0;
  if (!kv.getU32("cfg_ver", ver)) return true;  // nothing saved yet: defaults
  if (ver > kSchemaVersion) return false;       // written by newer firmware: keep defaults
  char buf[64];
  const char* textKeys[] = {"up_pri", "up_sec", "up_cip", "up_cip2", "up_cname", "tz"};
  for (const char* k : textKeys)
    if (kv.getString(k, buf, sizeof(buf))) setField(c, k, buf);
  const char* u32Keys[] = {"up_doh",  "up_plain",  "up_cdoh", "pad",      "ad",
                           "blk_ttl", "ff_canary", "icloud",  "priv_rev", "log"};
  for (const char* k : u32Keys) {
    uint32_t v;
    if (kv.getU32(k, v)) {
      snprintf(buf, sizeof(buf), "%u", static_cast<unsigned>(v));
      setField(c, k, buf);
    }
  }
  const char* why = nullptr;
  if (!validate(c, &why)) c = AppConfig{};  // corrupt combination: fall back to defaults
  return true;
}

bool save(hal::IKeyValueStore& kv, const AppConfig& c) {
  bool ok = kv.setString("up_pri", providerName(c.primary)) &&
            kv.setString("up_sec", providerName(c.secondary)) && kv.setString("up_cip", c.customIp) &&
            kv.setString("up_cip2", c.customIp2) && kv.setString("up_cname", c.customName) &&
            kv.setString("tz", c.timezone) && kv.setU32("up_doh", c.dohFallback) &&
            kv.setU32("up_plain", c.plainFallback) && kv.setU32("up_cdoh", c.customDoh) &&
            kv.setU32("pad", c.padding) && kv.setU32("ad", c.passAd) && kv.setU32("blk_ttl", c.blockedTtl) &&
            kv.setU32("ff_canary", c.firefoxCanary) && kv.setU32("icloud", c.icloudRelay) &&
            kv.setU32("priv_rev", c.privateReverse) && kv.setU32("log", c.logLevel);
  return ok && kv.setU32("cfg_ver", kSchemaVersion);
}

bool requiresRestart(const AppConfig& a, const AppConfig& b) {
  return a.primary != b.primary || a.secondary != b.secondary || a.dohFallback != b.dohFallback ||
         a.plainFallback != b.plainFallback || strcmp(a.customIp, b.customIp) ||
         strcmp(a.customIp2, b.customIp2) || strcmp(a.customName, b.customName) ||
         a.customDoh != b.customDoh || a.padding != b.padding || a.passAd != b.passAd ||
         a.blockedTtl != b.blockedTtl || a.firefoxCanary != b.firefoxCanary ||
         a.icloudRelay != b.icloudRelay || a.privateReverse != b.privateReverse;
}

size_t buildChain(const AppConfig& c, Endpoint* out, size_t max) {
  size_t n = 0;
  auto add = [&](upstream::TransportKind kind, const char* name, const char* ip, const char* verify,
                 uint16_t port) {
    if (n >= max || !ip || !*ip) return;
    Endpoint& e = out[n++];
    e.kind = kind;
    snprintf(e.name, sizeof(e.name), "%s", name);
    snprintf(e.ip, sizeof(e.ip), "%s", ip);
    snprintf(e.verifyName, sizeof(e.verifyName), "%s", verify ? verify : "");
    e.port = port;
  };
  struct Resolved {
    const char* label;
    const char* verify;
    const char* ip1;
    const char* ip2;
    bool doh;
  };
  Resolved list[2];
  size_t count = 0;
  for (Provider p : {c.primary, c.secondary}) {
    if (p == Provider::kNone) continue;
    if (p == Provider::kCustom) {
      list[count++] = {"custom", c.customName, c.customIp, c.customIp2, c.customDoh};
    } else {
      const ProviderInfo* pi = info(p);
      list[count++] = {pi->name, pi->verifyName, pi->ip1, pi->ip2, pi->doh};
    }
  }
  char name[24];
  for (size_t i = 0; i < count; i++) {
    snprintf(name, sizeof(name), "%s-dot", list[i].label);
    add(upstream::TransportKind::kDoT, name, list[i].ip1, list[i].verify, 853);
    snprintf(name, sizeof(name), "%s-dot-2", list[i].label);
    add(upstream::TransportKind::kDoT, name, list[i].ip2, list[i].verify, 853);
  }
  if (c.dohFallback)
    for (size_t i = 0; i < count; i++) {
      if (!list[i].doh) continue;
      snprintf(name, sizeof(name), "%s-doh", list[i].label);
      add(upstream::TransportKind::kDoH, name, list[i].ip1, list[i].verify, 443);
      snprintf(name, sizeof(name), "%s-doh-2", list[i].label);
      add(upstream::TransportKind::kDoH, name, list[i].ip2, list[i].verify, 443);
    }
  if (c.plainFallback)
    for (size_t i = 0; i < count; i++) {
      snprintf(name, sizeof(name), "%s-udp", list[i].label);
      add(upstream::TransportKind::kUdp, name, list[i].ip1, nullptr, 53);
    }
  return n;
}

}  // namespace config
