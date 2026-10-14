#include "app/clients.h"

#include <LittleFS.h>
#include <lwip/etharp.h>
#include <lwip/netif.h>
#include <lwip/tcpip.h>

#include <cstring>

namespace app {

namespace {

constexpr const char* kBanFile = "/banned.txt";

// ARP lookups must run inside lwIP's thread (tcpip_callback); results are copied
// back by the maintenance task. No application lock is taken in the lwIP thread.
struct MacJob {
  int n = 0;
  uint32_t ip[8] = {0};
  uint8_t mac[8][6] = {{0}};
  bool found[8] = {false};
  SemaphoreHandle_t done = nullptr;
};

void macJobInLwip(void* ctx) {
  MacJob* job = static_cast<MacJob*>(ctx);
  for (int k = 0; k < job->n; k++) {
    ip4_addr_t ipa;
    ipa.addr = job->ip[k];
    struct eth_addr* eth = nullptr;
    const ip4_addr_t* ipret = nullptr;
    job->found[k] = false;
    for (struct netif* nif = netif_list; nif && !job->found[k]; nif = nif->next)
      if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) {
        memcpy(job->mac[k], eth->addr, 6);
        job->found[k] = true;
      }
  }
  xSemaphoreGive(job->done);
}

}  // namespace

ClientTable::Entry* ClientTable::find(uint32_t ip, bool create) {
  for (int i = 0; i < count_; i++)
    if (entries_[i].info.ip == ip) return &entries_[i];
  if (!create || count_ >= kMaxClients) return nullptr;
  Entry& e = entries_[count_++];
  e = Entry{};
  e.info.ip = ip;
  e.info.banned = isBanListed(ip);
  e.macPending = true;
  return &e;
}

bool ClientTable::isBanListed(uint32_t ip) const {
  for (int i = 0; i < banCount_; i++)
    if (bans_[i] == ip) return true;
  return false;
}

void ClientTable::loadBans() {
  platform::LockGuard g(mutex_);
  banCount_ = 0;
  File f = LittleFS.open(kBanFile, "r");
  if (!f) return;
  while (f.available() && banCount_ < kMaxBans) {
    String l = f.readStringUntil('\n');
    l.trim();
    IPAddress ip;
    if (l.length() && ip.fromString(l)) bans_[banCount_++] = static_cast<uint32_t>(ip);
  }
  f.close();
}

void ClientTable::saveBans() {
  banCount_ = 0;
  for (int i = 0; i < count_ && banCount_ < kMaxBans; i++)
    if (entries_[i].info.banned) bans_[banCount_++] = entries_[i].info.ip;
  File f = LittleFS.open(kBanFile, "w");
  if (!f) return;
  for (int i = 0; i < banCount_; i++) f.println(IPAddress(bans_[i]).toString());
  f.close();
}

bool ClientTable::checkBanned(uint32_t ip) {
  platform::LockGuard g(mutex_);
  Entry* e = find(ip, true);
  if (!e) return false;
  e->info.lastSeenMs = millis();
  if (e->info.banned) {
    e->info.blocked++;
    totalBlocked_++;
  }
  return e->info.banned;
}

void ClientTable::record(uint32_t ip, bool blocked) {
  platform::LockGuard g(mutex_);
  Entry* e = find(ip, true);
  if (blocked) {
    totalBlocked_++;
    if (e) e->info.blocked++;
  } else {
    totalAllowed_++;
    if (e) e->info.allowed++;
  }
}

bool ClientTable::blockingOn() {
  platform::LockGuard g(mutex_);
  return blockingOn_;
}

bool ClientTable::toggleBan(uint32_t ip) {
  platform::LockGuard g(mutex_);
  Entry* e = find(ip, true);
  if (!e) return false;
  e->info.banned = !e->info.banned;
  saveBans();
  return e->info.banned;
}

void ClientTable::pause(uint32_t seconds) {
  platform::LockGuard g(mutex_);
  blockingOn_ = false;
  resumeAt_ = seconds ? (millis() + seconds * 1000UL) | 1 : 0;
}

void ClientTable::resume() {
  platform::LockGuard g(mutex_);
  blockingOn_ = true;
  resumeAt_ = 0;
}

uint32_t ClientTable::resumeInSeconds() {
  platform::LockGuard g(mutex_);
  if (blockingOn_ || !resumeAt_) return 0;
  const int32_t left = static_cast<int32_t>(resumeAt_ - millis());
  return left > 0 ? static_cast<uint32_t>(left) / 1000 : 0;
}

void ClientTable::tick() {
  platform::LockGuard g(mutex_);
  if (!blockingOn_ && resumeAt_ && static_cast<int32_t>(millis() - resumeAt_) >= 0) {
    blockingOn_ = true;
    resumeAt_ = 0;
  }
}

void ClientTable::resolvePendingMacs() {
  static MacJob job;
  static bool inFlight = false;
  if (!job.done) job.done = xSemaphoreCreateBinary();
  if (inFlight && xSemaphoreTake(job.done, 0) != pdTRUE) return;  // previous job still queued
  inFlight = false;
  job.n = 0;
  {
    platform::LockGuard g(mutex_);
    for (int i = 0; i < count_ && job.n < 8; i++)
      if (entries_[i].macPending && (ntohl(entries_[i].info.ip) >> 24) != 127)
        job.ip[job.n++] = entries_[i].info.ip;
  }
  if (!job.n || tcpip_callback(macJobInLwip, &job) != ERR_OK) return;
  inFlight = true;
  if (xSemaphoreTake(job.done, pdMS_TO_TICKS(500)) != pdTRUE) return;  // collect next time
  inFlight = false;
  platform::LockGuard g(mutex_);
  for (int k = 0; k < job.n; k++) {
    Entry* e = find(job.ip[k], false);
    if (!e || !e->macPending) continue;
    if (job.found[k]) {
      memcpy(e->info.mac, job.mac[k], 6);
      e->macPending = false;
    } else if (++e->macTries >= 10) {
      e->macPending = false;  // give up quietly
    }
  }
}

std::vector<ClientInfo> ClientTable::snapshot() {
  platform::LockGuard g(mutex_);
  std::vector<ClientInfo> v;
  v.reserve(count_);
  for (int i = 0; i < count_; i++) v.push_back(entries_[i].info);
  return v;
}

uint32_t ClientTable::totalBlocked() {
  platform::LockGuard g(mutex_);
  return totalBlocked_;
}

uint32_t ClientTable::totalAllowed() {
  platform::LockGuard g(mutex_);
  return totalAllowed_;
}

}  // namespace app
