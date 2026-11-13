#include "app/clients.h"

#include <LittleFS.h>
#include <esp_timer.h>
#include <lwip/etharp.h>
#include <lwip/netif.h>
#include <lwip/tcpip.h>

#include <cstring>

namespace app {

namespace {

constexpr const char* kBanFile = "/banned.txt";

uint64_t nowMs() {
  return static_cast<uint64_t>(esp_timer_get_time() / 1000);
}

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

clients::ClientEntry& ClientTable::obtain(uint32_t ip) {
  bool created = false;
  clients::ClientEntry& e = dir_.obtain(ip, millis(), &created);
  if (created) e.info.banned = bans_.contains(ip);
  return e;
}

void ClientTable::loadBans() {
  platform::LockGuard f(fileMutex_);
  char buf[clients::BanList::kMaxTextBytes + 64];  // a little slack for CR/spaces
  File file = LittleFS.open(kBanFile, "r");
  if (!file) return;
  const size_t n = file.read(reinterpret_cast<uint8_t*>(buf), sizeof(buf));
  file.close();
  platform::LockGuard g(mutex_);
  bans_.parse(buf, n);
  for (int i = 0; i < dir_.count(); i++) dir_.at(i).info.banned = bans_.contains(dir_.at(i).info.ip);
}

void ClientTable::saveBans() {
  // Serialise under mutex_ (brief), write with only fileMutex_ held: a LittleFS write
  // can take tens of ms (much longer on a nearly full filesystem), and both DNS tasks
  // take mutex_ for every query; holding it here dropped queries (audit 2026-11).
  char buf[clients::BanList::kMaxTextBytes];
  size_t n;
  {
    platform::LockGuard g(mutex_);
    n = bans_.serialize(buf, sizeof(buf));
  }
  File file = LittleFS.open(kBanFile, "w");
  if (!file) return;
  file.write(reinterpret_cast<const uint8_t*>(buf), n);
  file.close();
}

bool ClientTable::checkBanned(uint32_t ip) {
  platform::LockGuard g(mutex_);
  const bool banned = bans_.contains(ip);
  clients::ClientEntry& e = obtain(ip);
  e.info.lastSeenMs = millis();
  e.info.banned = banned;
  if (banned) {
    e.info.blocked++;
    totalBlocked_++;
  }
  return banned;
}

void ClientTable::record(uint32_t ip, bool blocked) {
  platform::LockGuard g(mutex_);
  clients::ClientEntry& e = obtain(ip);
  if (blocked) {
    totalBlocked_++;
    e.info.blocked++;
  } else {
    totalAllowed_++;
    e.info.allowed++;
  }
}

bool ClientTable::blockingOn() {
  platform::LockGuard g(mutex_);
  return pause_.blockingOn(nowMs());
}

ClientTable::BanResult ClientTable::toggleBan(uint32_t ip) {
  platform::LockGuard f(fileMutex_);  // keeps saves in the order of the changes
  bool ban;
  {
    platform::LockGuard g(mutex_);
    ban = !bans_.contains(ip);
    if (ban && !bans_.add(ip)) return BanResult::kListFull;
    if (!ban) bans_.remove(ip);
    if (clients::ClientEntry* e = dir_.find(ip)) e->info.banned = ban;
  }
  saveBans();
  return ban ? BanResult::kBanned : BanResult::kUnbanned;
}

clients::BanList ClientTable::bans() {
  platform::LockGuard g(mutex_);
  return bans_;
}

void ClientTable::replaceBans(const clients::BanList& list) {
  platform::LockGuard f(fileMutex_);
  {
    platform::LockGuard g(mutex_);
    bans_ = list;
    for (int i = 0; i < dir_.count(); i++) dir_.at(i).info.banned = bans_.contains(dir_.at(i).info.ip);
  }
  saveBans();
}

void ClientTable::pause(uint32_t seconds) {
  platform::LockGuard g(mutex_);
  pause_.pause(nowMs(), seconds);
}

void ClientTable::resume() {
  platform::LockGuard g(mutex_);
  pause_.resume();
}

uint32_t ClientTable::resumeInSeconds() {
  platform::LockGuard g(mutex_);
  return pause_.resumeInSeconds(nowMs());
}

void ClientTable::tick() {
  platform::LockGuard g(mutex_);
  pause_.blockingOn(nowMs());  // ends a timed pause that is due
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
    for (int i = 0; i < dir_.count() && job.n < 8; i++)
      if (dir_.at(i).macPending && (ntohl(dir_.at(i).info.ip) >> 24) != 127)
        job.ip[job.n++] = dir_.at(i).info.ip;
  }
  if (!job.n || tcpip_callback(macJobInLwip, &job) != ERR_OK) return;
  inFlight = true;
  if (xSemaphoreTake(job.done, pdMS_TO_TICKS(500)) != pdTRUE) return;  // collect next time
  inFlight = false;
  platform::LockGuard g(mutex_);
  for (int k = 0; k < job.n; k++) {
    clients::ClientEntry* e = dir_.find(job.ip[k]);
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
  v.reserve(dir_.count());
  for (int i = 0; i < dir_.count(); i++) v.push_back(dir_.at(i).info);
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
