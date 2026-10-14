#pragma once
// Small RAII wrappers over FreeRTOS primitives.

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

namespace platform {

class Mutex {
 public:
  Mutex() : handle_(xSemaphoreCreateMutex()) {}
  ~Mutex() {
    if (handle_) vSemaphoreDelete(handle_);
  }
  Mutex(const Mutex&) = delete;
  Mutex& operator=(const Mutex&) = delete;

  void lock() { xSemaphoreTake(handle_, portMAX_DELAY); }
  void unlock() { xSemaphoreGive(handle_); }

 private:
  SemaphoreHandle_t handle_;
};

class LockGuard {
 public:
  explicit LockGuard(Mutex& m) : m_(m) { m_.lock(); }
  ~LockGuard() { m_.unlock(); }
  LockGuard(const LockGuard&) = delete;
  LockGuard& operator=(const LockGuard&) = delete;

 private:
  Mutex& m_;
};

}  // namespace platform
