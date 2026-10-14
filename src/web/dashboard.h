#pragma once
// Dashboard + REST API (runs in the web task). Security (ARCHITECTURE.md §9):
//  - every request: Host must be the device IP or <hostname>[.local] (DNS rebinding)
//  - GET is read-only and public on the LAN (as upstream): /, /api/stats, /api/config
//  - every change is POST and needs: X-Requested-With: adblock, a same-origin
//    Origin/Referer (CSRF), Basic Auth checked against the PBKDF2 hash, and no
//    active login lockout. While the setup code is required, only /api/password works.

#include <WebServer.h>

#include <functional>

#include "app/blocklist_manager.h"
#include "app/clients.h"
#include "auth/auth.h"
#include "config/config.h"
#include "hal/kv_store.h"
#include "hal/logger.h"
#include "tasks/dns_service.h"

namespace web {

struct DashboardContext {
  WebServer* server = nullptr;
  app::ClientTable* clients = nullptr;
  app::BlocklistManager* blocklist = nullptr;
  app::DnsService* dns = nullptr;
  auth::PasswordStore* passwords = nullptr;
  auth::LoginGuard* logins = nullptr;
  config::AppConfig* config = nullptr;
  hal::IKeyValueStore* kv = nullptr;
  hal::ILogger* log = nullptr;
  const char* hostname = "";
  const char* version = "";
  std::function<void(const config::AppConfig&)> applyLive;  // timezone, log level
};

class Dashboard {
 public:
  explicit Dashboard(const DashboardContext& ctx) : ctx_(ctx) {}
  void begin();

 private:
  enum class Access { kPublic, kAuth, kAuthDuringSetup };
  struct Check {
    bool ok;
    int code;
    const char* message;
    bool askCredentials;
  };

  Check check(Access access);
  bool guard(Access access);  // sends the error response itself
  void sendText(int code, const String& text);

  void handleStats();
  void handleGetConfig();
  void handleSetConfig();
  void handlePassword();
  void handleRule(bool add);
  void handleBan();
  void handlePause();
  void handleBlocklistSettings();
  void handleListUpload();
  void handleListUploadDone();
  void handleFirmwareUpload();
  void handleFirmwareUploadDone();

  DashboardContext ctx_;
  bool uploadAuthorized_ = false;
  String uploadResult_;
};

}  // namespace web
