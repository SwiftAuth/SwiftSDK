#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace swiftauth {

// ── Error ───────────────────────────────────────────────────────────

struct Error {
    std::string code;
    std::string message;

    explicit operator bool() const { return !code.empty(); }
};

class Exception : public std::exception {
public:
    std::string code;
    std::string msg;

    Exception(std::string c, std::string m) : code(std::move(c)), msg(std::move(m)) {}
    const char* what() const noexcept override { return msg.c_str(); }
};

// ── Data Types ──────────────────────────────────────────────────────

struct AppInfo {
    std::string name;
    std::string version;
    bool anti_debug  = false;
    bool anti_vm     = false;
    bool lock_hwid   = false;
    bool lock_ip     = false;
    bool lock_pcname = false;
};

struct UserData {
    std::string key;
    std::string username;
    std::string email;
    int         level = 0;
    std::string expires_at;
};

struct Variable {
    std::string key;
    std::string value;
    std::string type;
};

struct UserVariable {
    std::string key;
    std::string value;
};

struct UpdateCheck {
    bool        update_available = false;
    std::string latest_version;
    std::string current_version;
};

struct InitResult {
    std::string session_token;
    AppInfo     app;
    std::string expires_at;
    bool        resumed = false;
};

struct LoginResult {
    UserData    user;
    bool        license_activated = false;
    std::vector<std::string> warnings;
};

struct LicenseResult {
    UserData    user;
    bool        returning = false;
    std::vector<std::string> warnings;
};

// ── WebSocket Event ─────────────────────────────────────────────────

struct WsEvent {
    std::string type;
    std::string raw_data;
};

using WsCallback = std::function<void(const WsEvent&)>;

// ── JSON Helpers (minimal, header-only) ─────────────────────────────
// These operate on raw JSON strings to avoid external dependencies.

namespace json {
    std::string get_string(const std::string& json, const std::string& key);
    bool        get_bool(const std::string& json, const std::string& key);
    int         get_int(const std::string& json, const std::string& key);
    std::string get_object(const std::string& json, const std::string& key);
    std::string serialize(const std::map<std::string, std::string>& kv);
    std::vector<std::string> split_array(const std::string& arr);
}

// ── HTTP Transport ──────────────────────────────────────────────────

namespace http {
    struct Response {
        int         status = 0;
        std::string body;
        std::map<std::string, std::string> response_headers;
    };

    Response post(const std::string& url, const std::string& json_body,
                  const std::map<std::string, std::string>& headers = {});
}

// ── File Decryption (requires OpenSSL) ──────────────────────────────
namespace file_crypto {
    std::string decrypt_file_bytes(const std::string& data, const std::string& app_secret,
                                    const std::string& session_token, const std::string& nonce_hex);
}

// ── Client ──────────────────────────────────────────────────────────

class Client {
public:
    Client(const std::string& base_url,
           const std::string& app_secret,
           const std::string& app_version = "1.0.0",
           const std::string& hwid = "");

    ~Client();

    // Non-copyable
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    // State
    bool is_initialized() const { return !session_token_.empty(); }
    const std::string& session_token() const { return session_token_; }
    const AppInfo& app() const { return app_; }
    const UserData& user() const { return user_; }

    // ── Core API ────────────────────────────────────────────────────
    InitResult    init();
    LoginResult   login(const std::string& username, const std::string& password,
                        const std::string& license_key = "", const std::string& pc_name = "");
    LoginResult   register_user(const std::string& username, const std::string& password,
                                const std::string& email = "", const std::string& display_name = "",
                                const std::string& license_key = "", const std::string& pc_name = "");
    LicenseResult license_login(const std::string& license_key, const std::string& pc_name = "");
    void          activate(const std::string& license_key);
    bool          validate_token(const std::string& token);

    // ── Variables ───────────────────────────────────────────────────
    Variable              get_variable(const std::string& key);
    std::vector<Variable> get_all_variables();
    UserVariable              get_user_variable(const std::string& key);
    std::vector<UserVariable> get_all_user_variables();
    UserVariable              set_user_variable(const std::string& key, const std::string& value);
    void                      delete_user_variable(const std::string& key);

    // ── Files ───────────────────────────────────────────────────────
    std::string download_file(const std::string& name);
    UpdateCheck check_update(const std::string& current_version, const std::string& file_name = "");

    // ── Session ─────────────────────────────────────────────────────
    std::string heartbeat();
    bool        check_session();
    void        end_session();

    // ── User ────────────────────────────────────────────────────────
    UserData    get_user();
    void        change_password(const std::string& current_pw, const std::string& new_pw);
    void        request_reset();

    // ── Logging ─────────────────────────────────────────────────────
    void        log(const std::string& message, const std::string& level = "INFO");

    // ── WebSocket ───────────────────────────────────────────────────
    // Note: WebSocket requires linking against a WS library (e.g. libwebsockets, Beast).
    // This SDK provides the interface; implementation depends on your platform.
    void on_ws_event(const std::string& event_type, WsCallback cb);
    void ws_send(const std::string& json_message);
    void ws_ping();
    void ws_set_status(const std::string& status);
    void ws_send_chat(const std::string& message);
    void ws_set_typing(bool typing);

private:
    std::string base_url_;
    std::string secret_;
    std::string version_;
    std::string hwid_;
    std::string session_token_;
    std::string nonce_;

    AppInfo  app_;
    UserData user_;

    std::map<std::string, std::vector<WsCallback>> ws_handlers_;
    std::mutex ws_mutex_;

    void require_init() const;
    std::string fetch_nonce();
    std::string api_post(const std::string& path, const std::string& json_body);
    std::string api_post_nonce(const std::string& path, const std::string& json_body);
    std::string parse_response(const std::string& body);

    static std::string default_hwid();
};

} // namespace swiftauth
