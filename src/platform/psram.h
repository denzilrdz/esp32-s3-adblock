#pragma once
// Large buffers live in PSRAM only (never internal RAM, which TLS and Wi-Fi need).
// Never use these for task stacks, DMA, or data touched with the flash cache off.

#include <esp_heap_caps.h>

#include <cstddef>
#include <memory>

namespace platform {

inline void* allocLarge(size_t bytes) {
  return heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
}

struct LargeFree {
  void operator()(void* p) const { heap_caps_free(p); }
};

// RAII owner for allocLarge() memory.
using LargeBuffer = std::unique_ptr<uint8_t, LargeFree>;

inline LargeBuffer makeLargeBuffer(size_t bytes) {
  return LargeBuffer(static_cast<uint8_t*>(allocLarge(bytes)));
}

inline bool havePsram() {
  return heap_caps_get_total_size(MALLOC_CAP_SPIRAM) > 0;
}

}  // namespace platform
