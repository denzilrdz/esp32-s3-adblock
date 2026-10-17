#pragma once
// User-facing settings (ARCHITECTURE.md §8): validated, stored in NVS through
// IKeyValueStore, edited from the dashboard as key=value form fields. Blocklist URL
// and update time are owned by the blocklist manager (its own NVS keys).

#include <cstddef>
#include <cstdint>

#include "hal/kv_store.h"
#include "upstream/transport.h"

namespace config {

enum class Provider : uint8_t { kCloudflare, kQuad9, kCustom, kNone };

const char* providerName(Provider p);
bool parseProvider(const char* s, Provider& out);

struct AppConfig {
  Provider primary = Provider::kCloudflare;
  Provider secondary = Provider::kQuad9;
  bool dohFallback = true;    // DNS-over-HTTPS when port 853 is blocked
  bool plainFallback = true;  // plain DNS when every encrypted upstream is down
  char customIp[16] = "";     // custom DoT provider
  char customIp2[16] = "";
  char customName[64] = "";  // TLS name to verify, e.g. dns.example.net
  bool customDoh = false;    // custom provider also serves DoH at /dns-query
  bool padding = true;       // RFC 7830/8467 query padding
  bool passAd = true;        // pass the DNSSEC AD bit from encrypted upstreams
  uint32_t blockedTtl = 10;
  bool firefoxCanary = true;
  bool icloudRelay = false;
  bool privateReverse = true;
  char timezone[48] = "UTC0";
  uint8_t logLevel = 2;  // 0 error .. 3 debug
};

enum class SetResult { kOk, kUnknownKey, kInvalid };

// Sets one field from text (dashboard form). Keys are the NVS keys below.
SetResult setField(AppConfig& cfg, const char* key, const char* value);
// Cross-field checks after a batch of setField() calls. `why` gets a reason.
bool validate(const AppConfig& cfg, const char** why);

bool load(const hal::IKeyValueStore& kv, AppConfig& out);  // missing keys keep defaults
bool save(hal::IKeyValueStore& kv, const AppConfig& cfg);

// Upstream changes rebuild the transports, which needs a restart.
bool requiresRestart(const AppConfig& before, const AppConfig& after);

struct Endpoint {
  upstream::TransportKind kind = upstream::TransportKind::kDoT;
  char name[24] = "";
  char ip[16] = "";
  char verifyName[64] = "";
  uint16_t port = 0;
};

// Ordered upstream chain for the forwarder: DoT (primary, secondary), then DoH,
// then plain UDP if allowed. Returns the number written (<= max).
size_t buildChain(const AppConfig& cfg, Endpoint* out, size_t max);

}  // namespace config
