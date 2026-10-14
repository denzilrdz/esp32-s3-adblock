#pragma once
// Scriptable ITransport. By default it answers every query with an A record for the
// asked name (echoing the upstream ID). Tests switch behaviour to simulate refused
// connections, silence, closed connections, and malformed or forged replies.

#include <deque>
#include <functional>
#include <string>
#include <vector>

#include "dns/message.h"
#include "fakes/dns_builder.h"
#include "upstream/transport.h"

class FakeTransport final : public upstream::ITransport {
 public:
  enum class Mode {
    kAnswer,          // reply to each query (queued, delivered by receive)
    kSilent,          // accept queries, never reply
    kRefuseConnect,   // connect() fails
    kFailSend,        // send() fails
    kCloseAfterSend,  // receive() reports the peer closed the connection
  };
  using Responder = std::function<testdns::Bytes(const testdns::Bytes& query)>;

  FakeTransport(const char* name, upstream::TransportKind kind, bool authenticated, bool pipelined)
      : name_(name), kind_(kind), authenticated_(authenticated), pipelined_(pipelined) {}

  const char* name() const override { return name_; }
  upstream::TransportKind kind() const override { return kind_; }
  bool authenticated() const override { return authenticated_; }
  bool pipelined() const override { return pipelined_; }
  bool connected() const override { return connected_; }

  upstream::IoStatus connect(uint32_t) override {
    connects++;
    if (onConnect) onConnect();  // e.g. advance a FakeClock to simulate a slow handshake
    if (mode == Mode::kRefuseConnect) return upstream::IoStatus::kError;
    connected_ = true;
    return upstream::IoStatus::kOk;
  }
  upstream::IoStatus send(const uint8_t* msg, size_t len) override {
    if (!connected_ || mode == Mode::kFailSend) return upstream::IoStatus::kError;
    testdns::Bytes q(msg, msg + len);
    sent.push_back(q);
    if (mode == Mode::kAnswer) {
      testdns::Bytes r = responder ? responder(q) : defaultAnswer(q);
      if (!r.empty()) (holdReplies ? held : inbox).push_back(r);
    }
    return upstream::IoStatus::kOk;
  }
  upstream::IoStatus receive(uint8_t* buf, size_t cap, size_t& len, uint32_t) override {
    if (mode == Mode::kCloseAfterSend && !sent.empty()) {
      connected_ = false;
      return upstream::IoStatus::kClosed;
    }
    if (inbox.empty()) return upstream::IoStatus::kTimeout;
    testdns::Bytes r = inbox.front();
    inbox.pop_front();
    if (r.size() > cap) return upstream::IoStatus::kError;
    memcpy(buf, r.data(), r.size());
    len = r.size();
    return upstream::IoStatus::kOk;
  }
  void close() override {
    if (connected_) closes++;
    connected_ = false;
  }

  // Delivers replies held back with holdReplies, newest first if reversed.
  void release(bool reversed = false) {
    while (!held.empty()) {
      if (reversed) {
        inbox.push_back(held.back());
        held.pop_back();
      } else {
        inbox.push_back(held.front());
        held.pop_front();
      }
    }
  }

  static testdns::Bytes defaultAnswer(const testdns::Bytes& q) {
    dns::Query parsed;
    if (dns::parseQuery(q.data(), q.size(), parsed) != dns::ParseStatus::kOk) return {};
    const uint16_t id = testdns::get16(q, 0);
    return testdns::ResponseBuilder(id, parsed.qname, parsed.qtype, 0x81A0)  // QR RD RA AD
        .answerA(300, 10, 0, 0, 1)
        .opt(1232, 0)
        .build();
  }

  Mode mode = Mode::kAnswer;
  bool holdReplies = false;
  Responder responder;
  std::function<void()> onConnect;
  std::vector<testdns::Bytes> sent;
  std::deque<testdns::Bytes> inbox;
  std::deque<testdns::Bytes> held;
  int connects = 0;
  int closes = 0;

 private:
  const char* name_;
  upstream::TransportKind kind_;
  bool authenticated_;
  bool pipelined_;
  bool connected_ = false;
};
