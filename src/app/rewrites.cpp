#include "app/rewrites.h"

#include <memory>
#include <new>

#include "platform/psram.h"

namespace app {

using hal::LogLevel;

namespace {

constexpr const char* kTag = "rw";
constexpr const char* kPath = "/rewrites.txt";
constexpr const char* kTmpPath = "/rewrites.tmp";

}  // namespace

bool RewriteManager::begin() {
  void* mem = platform::allocLarge(sizeof(rules::RewriteTable));
  if (!mem) {
    log_.log(LogLevel::kError, kTag, "out of memory for DNS rewrites");
    return false;
  }
  table_ = new (mem) rules::RewriteTable();

  // save() writes the temp file, deletes the live one, then renames: a temp file alone
  // is complete (the live one is only deleted after it was closed); both = interrupted
  // write, keep the old live file.
  if (fs_.exists(kPath)) {
    fs_.remove(kTmpPath);
  } else if (fs_.exists(kTmpPath)) {
    fs_.rename(kTmpPath, kPath);
  }
  auto f = fs_.open(kPath, hal::FileMode::kRead);
  if (!f) return true;
  const size_t size = f->size();
  if (size > rules::RewriteTable::kMaxTextBytes) {
    log_.log(LogLevel::kWarn, kTag, "%s too large (%u bytes): ignored", kPath, static_cast<unsigned>(size));
    return true;
  }
  std::unique_ptr<char[]> buf(new (std::nothrow) char[size + 1]);
  if (!buf) return true;
  const size_t got = f->read(reinterpret_cast<uint8_t*>(buf.get()), size);
  platform::LockGuard g(mutex_);
  const size_t n = table_->parse(buf.get(), got);
  count_ = table_->size();
  if (n) log_.log(LogLevel::kInfo, kTag, "%u saved rewrite(s) wait for the clock", static_cast<unsigned>(n));
  return true;
}

bool RewriteManager::resolve(const dns::Query& q, dns::RewriteAnswer& out) {
  if (!table_ || count_.load(std::memory_order_relaxed) == 0) return false;
  platform::LockGuard g(mutex_);
  return table_->resolve(q.qname, q.qnameLen, clock_.monotonicMs(), out);
}

rules::RewriteStatus RewriteManager::add(const String& domain, const String& target, uint32_t minutes) {
  if (!table_) return rules::RewriteStatus::kFull;
  rules::RewriteStatus st;
  {
    platform::LockGuard g(mutex_);
    st = addLocked(domain, target, minutes);
    retryAtMs_ = 0;  // a fresh change retries a failed save at once
  }
  save();
  return st;
}

rules::RewriteStatus RewriteManager::addLocked(const String& domain, const String& target, uint32_t minutes) {
  const rules::RewriteStatus st = table_->add(domain.c_str(), target.c_str(), minutes, clock_.monotonicMs());
  count_ = table_->size();
  if (rules::rewriteOk(st)) {
    log_.log(LogLevel::kInfo, kTag, "%s -> %s for %u min", domain.c_str(), target.c_str(),
             static_cast<unsigned>(minutes));
    changes_++;
  }
  return st;
}

rules::RewriteStatus RewriteManager::remove(const String& domain, const String& target) {
  if (!table_) return rules::RewriteStatus::kNotFound;
  rules::RewriteStatus st;
  {
    platform::LockGuard g(mutex_);
    st = table_->remove(domain.c_str(), target.c_str());
    count_ = table_->size();
    if (st == rules::RewriteStatus::kRemoved) changes_++;
    retryAtMs_ = 0;
  }
  save();
  return st;
}

std::vector<rules::RewriteView> RewriteManager::list() {
  std::vector<rules::RewriteView> v;
  if (!table_) return v;
  platform::LockGuard g(mutex_);
  v.resize(table_->size());
  v.resize(table_->list(v.data(), v.size(), clock_.monotonicMs()));
  return v;
}

void RewriteManager::tick() {
  if (!table_) return;
  {
    platform::LockGuard g(mutex_);
    const uint64_t now = clock_.monotonicMs();
    table_->purgeExpired(now);  // the file keeps them until the next save: dropped at load
    if (clock_.wallClockSynced() && table_->hasPending()) {
      const size_t dropped = table_->activate(now, clock_.unixTime());
      log_.log(LogLevel::kInfo, kTag, "clock synced: %u saved rewrite(s) active, %u expired",
               static_cast<unsigned>(table_->size()), static_cast<unsigned>(dropped));
      if (dropped) changes_++;
    }
    count_ = table_->size();
  }
  save();
}

bool RewriteManager::save() {
  platform::LockGuard file(fileMutex_);
  std::unique_ptr<char[]> buf;
  size_t n = 0;
  uint32_t gen;
  {
    platform::LockGuard g(mutex_);
    if (changes_ == saved_) return true;
    const uint64_t now = clock_.monotonicMs();
    if (retryAtMs_ && now < retryAtMs_) return false;
    buf.reset(new (std::nothrow) char[rules::RewriteTable::kMaxTextBytes]);
    if (!buf) return false;
    const bool synced = clock_.wallClockSynced();
    if (!table_->serialize(buf.get(), rules::RewriteTable::kMaxTextBytes, n, now, synced,
                           synced ? clock_.unixTime() : 0))
      return false;  // expiry times unknown until the clock syncs: tick() retries
    gen = changes_;
  }
  bool ok;
  {
    auto f = fs_.open(kTmpPath, hal::FileMode::kWrite);
    ok = f && f->write(reinterpret_cast<const uint8_t*>(buf.get()), n) == n && f->flush();
  }
  if (ok) {
    fs_.remove(kPath);
    ok = fs_.rename(kTmpPath, kPath);
  } else {
    fs_.remove(kTmpPath);
  }
  platform::LockGuard g(mutex_);
  if (!ok) {
    log_.log(LogLevel::kError, kTag, "cannot save %s (retrying in a minute)", kPath);
    retryAtMs_ = clock_.monotonicMs() + 60000;
    return false;
  }
  retryAtMs_ = 0;
  saved_ = gen;  // a change made meanwhile keeps changes_ != saved_: saved next time
  return true;
}

}  // namespace app
