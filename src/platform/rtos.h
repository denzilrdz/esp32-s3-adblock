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
  bool tryLock(uint32_t timeoutMs) { return xSemaphoreTake(handle_, pdMS_TO_TICKS(timeoutMs)) == pdTRUE; }
  void unlock() { xSemaphoreGive(handle_); }

 private:
  SemaphoreHandle_t handle_;
};

// Recursive mutex for legacy code paths whose helpers call each other while locked.
class RecursiveMutex {
 public:
  RecursiveMutex() : handle_(xSemaphoreCreateRecursiveMutex()) {}
  ~RecursiveMutex() {
    if (handle_) vSemaphoreDelete(handle_);
  }
  RecursiveMutex(const RecursiveMutex&) = delete;
  RecursiveMutex& operator=(const RecursiveMutex&) = delete;

  void lock() { xSemaphoreTakeRecursive(handle_, portMAX_DELAY); }
  void unlock() { xSemaphoreGiveRecursive(handle_); }

 private:
  SemaphoreHandle_t handle_;
};

template <typename M>
class BasicLockGuard {
 public:
  explicit BasicLockGuard(M& m) : m_(m) { m_.lock(); }
  ~BasicLockGuard() { m_.unlock(); }
  BasicLockGuard(const BasicLockGuard&) = delete;
  BasicLockGuard& operator=(const BasicLockGuard&) = delete;

 private:
  M& m_;
};

using RecursiveLockGuard = BasicLockGuard<RecursiveMutex>;

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
