#pragma once
// Feeds the task watchdog only if the calling task is subscribed to it. ESP-IDF 5 logs
// "esp_task_wdt_reset: task not found" for unsubscribed callers (4.4 returned an error
// silently), and some shared code (blocklist load at boot, TLS and HTTP clients) runs
// both in watched tasks and before setup() subscribes the Arduino loop task.

#include <esp_task_wdt.h>

namespace platform {

inline void feedWatchdog() {
  if (esp_task_wdt_status(nullptr) == ESP_OK) esp_task_wdt_reset();
}

}  // namespace platform
