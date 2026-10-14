#pragma once
// Hardware RNG. esp_random() is cryptographically secure while Wi-Fi/BT is running,
// which is always the case once the DNS service starts.

#include <esp_system.h>

#include "hal/random.h"

namespace platform {

class EspRandom final : public hal::IRandom {
 public:
  uint32_t next32() override { return esp_random(); }
};

}  // namespace platform
