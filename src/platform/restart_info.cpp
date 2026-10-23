#include "platform/restart_info.h"

#include <esp_attr.h>
#include <esp_core_dump.h>
#include <esp_system.h>

#include <cstring>

#include "util/crc32.h"

namespace platform {

namespace {

static_assert(ESP_RST_POWERON == static_cast<int>(diag::ResetCause::kPowerOn), "esp_reset_reason_t changed");
static_assert(ESP_RST_BROWNOUT == static_cast<int>(diag::ResetCause::kBrownout),
              "esp_reset_reason_t changed");
static_assert(ESP_RST_CPU_LOCKUP == static_cast<int>(diag::ResetCause::kCpuLockup),
              "esp_reset_reason_t changed");

constexpr uint32_t kNoteMagic = 0x52535421;  // "RST!"

struct Note {
  uint32_t magic;
  char why[sizeof(diag::RestartInfo::note)];
  uint32_t crc;
};

// Not cleared at boot: holds garbage after a power cut, hence magic + CRC.
RTC_NOINIT_ATTR Note gNote;

uint32_t noteCrc(const Note& n) {
  return util::crc32(reinterpret_cast<const uint8_t*>(n.why), sizeof(n.why));
}

}  // namespace

void noteRestart(const char* why) {
  memset(gNote.why, 0, sizeof(gNote.why));
  strncpy(gNote.why, why ? why : "", sizeof(gNote.why) - 1);
  gNote.crc = noteCrc(gNote);
  gNote.magic = kNoteMagic;
}

void restart(const char* why) {
  noteRestart(why);
  esp_restart();
}

diag::RestartInfo readRestartInfo() {
  diag::RestartInfo info;
  info.cause = diag::resetCauseFromIdf(static_cast<int>(esp_reset_reason()));
  if (info.cause == diag::ResetCause::kSoftware && gNote.magic == kNoteMagic && gNote.crc == noteCrc(gNote)) {
    memcpy(info.note, gNote.why, sizeof(info.note));
    info.note[sizeof(info.note) - 1] = 0;
  }
  gNote.magic = 0;  // a later reset without a note must not reuse this one

  if (esp_core_dump_image_check() == ESP_OK) {
    esp_core_dump_summary_t s;  // ~200 B, once at boot on the 16 KB loop task stack
    if (esp_core_dump_get_summary(&s) == ESP_OK) {
      diag::CrashRecord& c = info.crash;
      c.present = true;
      strncpy(c.task, s.exc_task, sizeof(c.task) - 1);  // exc_task may lack a NUL
      c.pc = s.exc_pc;
      const uint32_t depth =
          s.exc_bt_info.depth < diag::kMaxBacktrace ? s.exc_bt_info.depth : diag::kMaxBacktrace;
      memcpy(c.backtrace, s.exc_bt_info.bt, depth * sizeof(uint32_t));
      c.depth = static_cast<uint8_t>(depth);
      c.corrupted = s.exc_bt_info.corrupted;
      const size_t sha = strnlen(reinterpret_cast<const char*>(s.app_elf_sha256), sizeof(s.app_elf_sha256));
      memcpy(c.elfSha, s.app_elf_sha256, sha < sizeof(c.elfSha) - 1 ? sha : sizeof(c.elfSha) - 1);
      if (esp_core_dump_get_panic_reason(c.reason, sizeof(c.reason)) != ESP_OK) c.reason[0] = 0;
    }
  }
  return info;
}

}  // namespace platform
