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

// Takes the calling task off the task watchdog for one scope whose blocking calls are
// bounded by their own timeouts but can't feed it in between (esp_http_client's
// connect + TLS handshake + redirect can exceed 5 s on a slow network). Use only with
// an overall deadline in that scope.
class WatchdogPause {
 public:
  WatchdogPause() : watched_(esp_task_wdt_status(nullptr) == ESP_OK) {
    if (watched_) esp_task_wdt_delete(nullptr);
  }
  ~WatchdogPause() {
    if (watched_) esp_task_wdt_add(nullptr);
  }
  WatchdogPause(const WatchdogPause&) = delete;
  WatchdogPause& operator=(const WatchdogPause&) = delete;

 private:
  bool watched_;
};

}  // namespace platform
