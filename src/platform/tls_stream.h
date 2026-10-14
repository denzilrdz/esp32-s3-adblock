#pragma once
// RAII TLS client over an lwIP socket using mbedTLS directly (not esp_tls), because
// the prebuilt esp_tls has no client session API and we want TLS session resumption:
// DoT servers drop idle connections after ~10 s, and a resumed handshake skips the
// ECDHE + certificate-chain cost of a full one.
//
// The server certificate is verified against the ESP-IDF CA bundle, and the name is
// always checked (mbedTLS 2.28 does not match IP SANs, so we connect to an IP but
// verify the provider's hostname).

#include <mbedtls/ssl.h>

#include <cstddef>
#include <cstdint>

namespace platform {

enum class StreamStatus { kOk, kTimeout, kClosed, kError };

class TlsStream {
 public:
  // `ipv4` like "1.1.1.1"; `verifyName` like "cloudflare-dns.com" (must outlive us).
  TlsStream(const char* ipv4, uint16_t port, const char* verifyName);
  ~TlsStream();
  TlsStream(const TlsStream&) = delete;
  TlsStream& operator=(const TlsStream&) = delete;

  // TCP connect + TLS handshake within timeoutMs. Reuses the saved session if any.
  bool connect(uint32_t timeoutMs);
  bool connected() const { return sslReady_; }
  // Writes everything or fails.
  StreamStatus writeAll(const uint8_t* data, size_t len, uint32_t timeoutMs);
  // Reads whatever is available (at least 1 byte) within timeoutMs.
  StreamStatus read(uint8_t* buf, size_t cap, size_t& got, uint32_t timeoutMs);
  // Sends close_notify (best effort) and frees the connection; keeps the session.
  void close();

  uint32_t lastHandshakeMs() const { return lastHandshakeMs_; }
  int lastError() const { return lastError_; }

 private:
  static int bioSend(void* ctx, const unsigned char* buf, size_t len);
  static int bioRecv(void* ctx, unsigned char* buf, size_t len);
  bool openSocket(uint32_t timeoutMs);
  bool setupConfig();
  void closeSocket();

  char ip_[16];
  uint16_t port_;
  const char* verifyName_;
  int fd_ = -1;
  bool confReady_ = false;
  bool sslReady_ = false;
  bool haveSession_ = false;
  uint32_t lastHandshakeMs_ = 0;
  int lastError_ = 0;
  mbedtls_ssl_config conf_;
  mbedtls_ssl_context ssl_;
  mbedtls_ssl_session session_;
};

}  // namespace platform
