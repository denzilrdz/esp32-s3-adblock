#include "platform/tls_stream.h"

#include "platform/watchdog.h"

#include <esp_crt_bundle.h>

#include <esp_err.h>
#include <esp_system.h>
#include <esp_task_wdt.h>
#include <esp_timer.h>
#include <lwip/netdb.h>
#include <lwip/sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>

#include <cerrno>
#include <cstring>

namespace platform {

namespace {

uint64_t nowMs() {
  return static_cast<uint64_t>(esp_timer_get_time() / 1000);
}

// Hardware RNG as the mbedTLS random source (secure while Wi-Fi is on).
int hardwareRng(void*, unsigned char* out, size_t len) {
  esp_fill_random(out, len);
  return 0;
}

void setSocketTimeout(int fd, uint32_t ms) {
  struct timeval tv;
  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

// Waits until fd is readable; returns 1 readable, 0 timeout, -1 error.
int waitReadable(int fd, uint32_t timeoutMs) {
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);
  struct timeval tv;
  tv.tv_sec = timeoutMs / 1000;
  tv.tv_usec = (timeoutMs % 1000) * 1000;
  const int r = select(fd + 1, &rfds, nullptr, nullptr, &tv);
  return r > 0 ? 1 : (r == 0 ? 0 : -1);
}

constexpr uint32_t kIoSliceMs = 1000;  // per-syscall timeout; lets us reset the watchdog

}  // namespace

TlsStream::TlsStream(const char* ipv4, uint16_t port, const char* verifyName)
    : port_(port), verifyName_(verifyName) {
  strncpy(ip_, ipv4, sizeof(ip_) - 1);
  ip_[sizeof(ip_) - 1] = 0;
  mbedtls_ssl_config_init(&conf_);
  mbedtls_ssl_init(&ssl_);
  mbedtls_ssl_session_init(&session_);
}

TlsStream::~TlsStream() {
  close();
  mbedtls_ssl_session_free(&session_);
  mbedtls_ssl_config_free(&conf_);
}

bool TlsStream::setupConfig() {
  if (confReady_) return true;
  int rc = mbedtls_ssl_config_defaults(&conf_, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT);
  if (rc != 0) {
    lastError_ = rc;
    return false;
  }
  mbedtls_ssl_conf_authmode(&conf_, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_min_tls_version(&conf_, MBEDTLS_SSL_VERSION_TLS1_2);
  mbedtls_ssl_conf_rng(&conf_, hardwareRng, nullptr);
  mbedtls_ssl_conf_session_tickets(&conf_, MBEDTLS_SSL_SESSION_TICKETS_ENABLED);
  if (esp_crt_bundle_attach(&conf_) != ESP_OK) {
    lastError_ = -1;
    return false;
  }
  confReady_ = true;
  return true;
}

bool TlsStream::openSocket(uint32_t timeoutMs) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port_);
  if (inet_pton(AF_INET, ip_, &addr.sin_addr) != 1) return false;

  fd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd_ < 0) return false;
  int one = 1;
  setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

  // Non-blocking connect so the timeout is ours, then back to blocking with slices.
  const int flags = fcntl(fd_, F_GETFL, 0);
  fcntl(fd_, F_SETFL, flags | O_NONBLOCK);
  int rc = ::connect(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
  if (rc != 0 && errno != EINPROGRESS) {
    closeSocket();
    return false;
  }
  if (rc != 0) {
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd_, &wfds);
    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    if (select(fd_ + 1, nullptr, &wfds, nullptr, &tv) <= 0) {
      closeSocket();
      return false;
    }
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) {
      closeSocket();
      return false;
    }
  }
  fcntl(fd_, F_SETFL, flags & ~O_NONBLOCK);
  setSocketTimeout(fd_, kIoSliceMs);
  return true;
}

int TlsStream::bioSend(void* ctx, const unsigned char* buf, size_t len) {
  auto* self = static_cast<TlsStream*>(ctx);
  const int n = ::send(self->fd_, buf, len, 0);
  if (n >= 0) return n;
  if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_WRITE;
  if (errno == EPIPE || errno == ECONNRESET) return MBEDTLS_ERR_NET_CONN_RESET;
  return MBEDTLS_ERR_NET_SEND_FAILED;
}

int TlsStream::bioRecv(void* ctx, unsigned char* buf, size_t len) {
  auto* self = static_cast<TlsStream*>(ctx);
  const int n = ::recv(self->fd_, buf, len, 0);
  if (n >= 0) return n;  // 0 = peer closed
  if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_READ;
  if (errno == EPIPE || errno == ECONNRESET) return MBEDTLS_ERR_NET_CONN_RESET;
  return MBEDTLS_ERR_NET_RECV_FAILED;
}

bool TlsStream::connect(uint32_t timeoutMs) {
  close();
  const uint64_t start = nowMs();
  const uint64_t deadline = start + timeoutMs;
  if (!setupConfig() || !openSocket(timeoutMs)) return false;

  int rc = mbedtls_ssl_setup(&ssl_, &conf_);
  if (rc != 0) {
    lastError_ = rc;
    mbedtls_ssl_free(&ssl_);
    mbedtls_ssl_init(&ssl_);
    closeSocket();
    return false;
  }
  sslReady_ = true;
  mbedtls_ssl_set_hostname(&ssl_, verifyName_);
  mbedtls_ssl_set_bio(&ssl_, this, bioSend, bioRecv, nullptr);
  if (haveSession_) mbedtls_ssl_set_session(&ssl_, &session_);

  while ((rc = mbedtls_ssl_handshake(&ssl_)) != 0) {
    if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) break;
    if (nowMs() >= deadline) break;
    feedWatchdog();  // only if this task is watched
  }
  if (rc != 0) {
    lastError_ = rc;
    // A rejected resumption must not poison later attempts.
    if (haveSession_) {
      mbedtls_ssl_session_free(&session_);
      mbedtls_ssl_session_init(&session_);
      haveSession_ = false;
    }
    close();
    return false;
  }
  lastHandshakeMs_ = static_cast<uint32_t>(nowMs() - start);

  // Keep the session (ticket) for resumption on the next connect.
  mbedtls_ssl_session_free(&session_);
  mbedtls_ssl_session_init(&session_);
  haveSession_ = mbedtls_ssl_get_session(&ssl_, &session_) == 0;
  return true;
}

StreamStatus TlsStream::writeAll(const uint8_t* data, size_t len, uint32_t timeoutMs) {
  if (!sslReady_) return StreamStatus::kError;
  const uint64_t deadline = nowMs() + timeoutMs;
  size_t done = 0;
  while (done < len) {
    const int rc = mbedtls_ssl_write(&ssl_, data + done, len - done);
    if (rc > 0) {
      done += static_cast<size_t>(rc);
      continue;
    }
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
      if (nowMs() >= deadline) return StreamStatus::kTimeout;
      continue;
    }
    lastError_ = rc;
    return StreamStatus::kError;
  }
  return StreamStatus::kOk;
}

StreamStatus TlsStream::read(uint8_t* buf, size_t cap, size_t& got, uint32_t timeoutMs) {
  got = 0;
  if (!sslReady_) return StreamStatus::kError;
  if (mbedtls_ssl_get_bytes_avail(&ssl_) == 0) {
    const int r = waitReadable(fd_, timeoutMs);
    if (r == 0) return StreamStatus::kTimeout;
    if (r < 0) return StreamStatus::kError;
  }
  const int rc = mbedtls_ssl_read(&ssl_, buf, cap);
  if (rc > 0) {
    got = static_cast<size_t>(rc);
    return StreamStatus::kOk;
  }
  if (rc == 0 || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || rc == MBEDTLS_ERR_NET_CONN_RESET)
    return StreamStatus::kClosed;
  if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) return StreamStatus::kTimeout;
  lastError_ = rc;
  return StreamStatus::kError;
}

void TlsStream::closeSocket() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

void TlsStream::close() {
  if (sslReady_) {
    mbedtls_ssl_close_notify(&ssl_);
    mbedtls_ssl_free(&ssl_);
    mbedtls_ssl_init(&ssl_);
    sslReady_ = false;
  }
  closeSocket();
}

}  // namespace platform
