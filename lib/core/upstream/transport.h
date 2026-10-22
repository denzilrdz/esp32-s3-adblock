#pragma once
// Strategy interface for one upstream resolver connection (DoT, DoH or plain UDP).
// Implementations live in src/platform/; tests use FakeTransport.

#include <cstddef>
#include <cstdint>

namespace upstream {

enum class TransportKind { kDoT, kDoH, kUdp };

enum class IoStatus {
  kOk,
  kTimeout,  // nothing arrived within the timeout (not an error)
  kClosed,   // peer closed the connection
  kError,    // connect/TLS/IO failure
};

class ITransport {
 public:
  virtual ~ITransport() = default;

  virtual const char* name() const = 0;  // e.g. "cloudflare-dot"
  virtual TransportKind kind() const = 0;
  // True if answers arrive over an authenticated channel (TLS with a verified cert).
  virtual bool authenticated() const = 0;
  // True if several queries may be outstanding at once (DoT, UDP). DoH over
  // HTTP/1.1 is one request at a time.
  virtual bool pipelined() const = 0;

  virtual bool connected() const = 0;
  // Opens the connection (TCP + TLS handshake) if needed. Blocks up to timeoutMs.
  virtual IoStatus connect(uint32_t timeoutMs) = 0;
  // Sends one complete DNS message (framing is the transport's job).
  virtual IoStatus send(const uint8_t* msg, size_t len) = 0;
  // Receives one complete DNS message. Blocks up to timeoutMs (0 = poll).
  virtual IoStatus receive(uint8_t* buf, size_t cap, size_t& len, uint32_t timeoutMs) = 0;
  virtual void close() = 0;
  // Error code of the last failed TLS step (mbedTLS, negative), 0 if none or not TLS.
  virtual int lastError() const { return 0; }
};

}  // namespace upstream
