#pragma once
// Dashboard + REST API (runs in the web task). Security (ARCHITECTURE.md §9):
//  - every request: Host must be the device IP or <hostname>[.local] (DNS rebinding)
//  - only the page shell (/) is public: it holds no data and opens on a login form
//  - /api/login checks the password (PBKDF2 hash, per-client lockout) and sets an
//    HttpOnly, SameSite=Strict session cookie; every other /api route needs that
//    session (or Basic Auth, for scripts). No WWW-Authenticate challenge, so browsers
//    never pop up their own login box.
//  - every change is POST and also needs: X-Requested-With: adblock and a same-origin
//    Origin/Referer (CSRF). While the setup code is required, the data reads and
//    /api/password work, nothing else.

#include <WebServer.h>

#include <functional>

#include "app/blocklist_manager.h"
#include "app/clients.h"
#include "app/rewrites.h"
#include "auth/auth.h"
#include "config/backup.h"
#include "config/config.h"
#include "diag/restart.h"
#include "hal/clock.h"
#include "hal/kv_store.h"
#include "hal/logger.h"
#include "platform/psram.h"
#include "tasks/dns_service.h"

namespace web {

struct DashboardContext {
  WebServer* server = nullptr;
  app::ClientTable* clients = nullptr;
  app::BlocklistManager* blocklist = nullptr;
  app::RewriteManager* rewrites = nullptr;
  app::DnsService* dns = nullptr;
  auth::PasswordStore* passwords = nullptr;
  auth::LoginGuard* logins = nullptr;
  auth::SessionStore* sessions = nullptr;
  const diag::RestartInfo* restart = nullptr;  // read once at boot
  config::AppConfig* config = nullptr;
  hal::IKeyValueStore* kv = nullptr;
  hal::ILogger* log = nullptr;
  const hal::IClock* clock = nullptr;
  const char* hostname = "";
  const char* version = "";
  std::function<void(const config::AppConfig&)> applyLive;  // timezone, log level
  std::function<void()> alive;  // web task progress during long uploads (software watchdog)
  std::function<bool(util::CivilTime&)> nextReboot;  // scheduled reboot, local time
#ifdef ADBLOCK_SELFTEST
  std::function<void(const String&)> selftest;  // POST /api/selftest?hang=<what>
#endif
};

class Dashboard {
 public:
  explicit Dashboard(const DashboardContext& ctx) : ctx_(ctx) {}
  void begin();

 private:
  // kRead: logged in, any method, also during setup (GET /api/stats, /api/config).
  // kAuth / kAuthDuringSetup: logged in, POST + CSRF checks; only the latter during setup.
  enum class Access { kPublic, kRead, kAuth, kAuthDuringSetup };
  struct Check {
    bool ok;
    int code;
    const char* message;
  };

  Check check(Access access);
  Check postChecks();                                            // POST, CSRF header, Origin/Referer
  Check verifyPassword(const String& user, const String& pass);  // lockout + PBKDF2
  bool hasSession();
  bool guard(Access access);   // sends the error response itself
  bool reply(const Check& c);  // false: sent c's error response (with Retry-After on 429)
  // A multipart "done" handler: the upload callback checked auth at UPLOAD_FILE_START,
  // but only runs for requests that carry a file part, so a stale flag from an earlier
  // upload must never stand in for this request's own check. Consumes the flag.
  bool uploadDoneAllowed();
  // Registers a route that refuses oversized bodies (web/bounded_route.h).
  void route(const char* uri, HTTPMethod method, std::function<void()> fn,
             std::function<void()> upload = nullptr);
  void sendText(int code, const String& text);
  void uploadProgress();  // feeds both watchdogs while one upload runs in handleClient()
  // Sends a body in TCP-sized pieces under one deadline (slow clients can't hold the task).
  void sendBody(const char* data, size_t len, const char* type, bool progmem);

  void handleStats();
  void handleGetConfig();
  void handleSetConfig();
  void handleLogin();
  void handleLogout();
  void handlePassword();
  void handleRule(bool add);
  void handleRewrite(bool add);
  void handleBan();
  void handlePause();
  void handleBlocklistSettings();
  void handleListUpload();
  void handleListUploadDone();
  void handleFirmwareUpload();
  void handleFirmwareUploadDone();
  void handleExport();
  void handleImportUpload();
  void handleImportDone();

  DashboardContext ctx_;
  bool uploadAuthorized_ = false;
  String uploadResult_;
  platform::LargeBuffer importBuf_;  // settings file being uploaded (PSRAM)
  size_t importCap_ = 0, importLen_ = 0;
  const char* importError_ = nullptr;  // set when the upload can't be kept...
  int importErrorCode_ = 400;          // ...with this HTTP status
};

}  // namespace web
