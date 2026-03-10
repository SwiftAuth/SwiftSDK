#include "swiftauth/swiftauth.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>
#include <stdexcept>

#ifdef _WIN32
    #include <windows.h>
    #include <winhttp.h>
    #pragma comment(lib, "winhttp.lib")
#else
    #include <curl/curl.h>
#endif

// OpenSSL + zlib for file decryption
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <zlib.h>

namespace swiftauth {

// ─── JSON Helpers (minimal parser for flat objects) ──────────────────

namespace json {

static std::string find_value(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return "";
    pos++;

    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r'))
        pos++;

    if (pos >= json.size()) return "";

    if (json[pos] == '"') {
        auto end = json.find('"', pos + 1);
        while (end != std::string::npos && json[end - 1] == '\\')
            end = json.find('"', end + 1);
        return (end != std::string::npos) ? json.substr(pos + 1, end - pos - 1) : "";
    }

    if (json[pos] == '{') {
        int depth = 1;
        size_t start = pos;
        pos++;
        while (pos < json.size() && depth > 0) {
            if (json[pos] == '{') depth++;
            else if (json[pos] == '}') depth--;
            pos++;
        }
        return json.substr(start, pos - start);
    }

    if (json[pos] == '[') {
        int depth = 1;
        size_t start = pos;
        pos++;
        while (pos < json.size() && depth > 0) {
            if (json[pos] == '[') depth++;
            else if (json[pos] == ']') depth--;
            pos++;
        }
        return json.substr(start, pos - start);
    }

    size_t start = pos;
    while (pos < json.size() && json[pos] != ',' && json[pos] != '}' && json[pos] != ']')
        pos++;
    std::string val = json.substr(start, pos - start);
    while (!val.empty() && (val.back() == ' ' || val.back() == '\n' || val.back() == '\r'))
        val.pop_back();
    return val;
}

std::string get_string(const std::string& json, const std::string& key) {
    return find_value(json, key);
}

bool get_bool(const std::string& json, const std::string& key) {
    return find_value(json, key) == "true";
}

int get_int(const std::string& json, const std::string& key) {
    auto val = find_value(json, key);
    return val.empty() ? 0 : std::stoi(val);
}

std::string get_object(const std::string& json, const std::string& key) {
    return find_value(json, key);
}

static std::string escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;
        }
    }
    return out;
}

std::string serialize(const std::map<std::string, std::string>& kv) {
    std::ostringstream ss;
    ss << "{";
    bool first = true;
    for (auto& [k, v] : kv) {
        if (!first) ss << ",";
        ss << "\"" << escape(k) << "\":\"" << escape(v) << "\"";
        first = false;
    }
    ss << "}";
    return ss.str();
}

// Split a JSON array string into its top-level element strings
std::vector<std::string> split_array(const std::string& arr) {
    std::vector<std::string> items;
    if (arr.empty() || arr.front() != '[') return items;
    size_t pos = 1; // skip '['
    while (pos < arr.size()) {
        // skip whitespace
        while (pos < arr.size() && (arr[pos] == ' ' || arr[pos] == '\n' || arr[pos] == '\r' || arr[pos] == '\t'))
            pos++;
        if (pos >= arr.size() || arr[pos] == ']') break;

        size_t start = pos;
        int depth = 0;
        bool in_str = false;
        while (pos < arr.size()) {
            char c = arr[pos];
            if (in_str) {
                if (c == '\\') { pos++; } // skip escaped char
                else if (c == '"') { in_str = false; }
            } else {
                if (c == '"') { in_str = true; }
                else if (c == '{' || c == '[') { depth++; }
                else if (c == '}' || c == ']') {
                    if (depth == 0) break;
                    depth--;
                }
                else if (c == ',' && depth == 0) break;
            }
            pos++;
        }
        std::string item = arr.substr(start, pos - start);
        // Trim trailing whitespace
        while (!item.empty() && (item.back() == ' ' || item.back() == '\n' || item.back() == '\r'))
            item.pop_back();
        if (!item.empty()) items.push_back(item);
        if (pos < arr.size() && arr[pos] == ',') pos++;
    }
    return items;
}

} // namespace json

// ─── HTTP (platform-specific) ───────────────────────────────────────

#ifndef _WIN32
namespace http {

static size_t write_cb(void* ptr, size_t size, size_t nmemb, std::string* out) {
    out->append(static_cast<char*>(ptr), size * nmemb);
    return size * nmemb;
}

static size_t header_cb(char* buffer, size_t size, size_t nitems, std::map<std::string, std::string>* hdrs) {
    size_t total = size * nitems;
    std::string line(buffer, total);
    auto colon = line.find(':');
    if (colon != std::string::npos) {
        std::string key = line.substr(0, colon);
        std::string val = line.substr(colon + 1);
        // Trim whitespace
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.erase(val.begin());
        while (!val.empty() && (val.back() == '\r' || val.back() == '\n')) val.pop_back();
        // Lowercase key for consistent lookup
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        (*hdrs)[key] = val;
    }
    return total;
}

Response post(const std::string& url, const std::string& json_body,
              const std::map<std::string, std::string>& headers) {
    Response resp;
    CURL* curl = curl_easy_init();
    if (!curl) {
        resp.status = -1;
        resp.body = "Failed to initialize HTTP client";
        return resp;
    }

    struct curl_slist* hdr_list = nullptr;
    hdr_list = curl_slist_append(hdr_list, "Content-Type: application/json");
    hdr_list = curl_slist_append(hdr_list, "Accept: application/json");
    for (auto& [k, v] : headers) {
        hdr_list = curl_slist_append(hdr_list, (k + ": " + v).c_str());
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdr_list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &resp.response_headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        long code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        resp.status = static_cast<int>(code);
    } else {
        resp.status = -1;
        resp.body = curl_easy_strerror(res);
    }

    curl_slist_free_all(hdr_list);
    curl_easy_cleanup(curl);
    return resp;
}

} // namespace http
#else
namespace http {

static std::wstring to_wide(const std::string& s) {
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], len);
    return w;
}

Response post(const std::string& url, const std::string& json_body,
              const std::map<std::string, std::string>& headers) {
    Response resp;

    // Parse URL components
    URL_COMPONENTSW uc = {};
    uc.dwStructSize = sizeof(uc);
    uc.dwSchemeLength = (DWORD)-1;
    uc.dwHostNameLength = (DWORD)-1;
    uc.dwUrlPathLength = (DWORD)-1;

    std::wstring wurl = to_wide(url);
    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.size(), 0, &uc)) {
        resp.status = -1;
        resp.body = "Failed to parse URL";
        return resp;
    }

    std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
    std::wstring path(uc.lpszUrlPath, uc.dwUrlPathLength);
    bool useSSL = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    INTERNET_PORT port = uc.nPort;

    HINTERNET hSession = WinHttpOpen(L"SwiftAuth-CPP/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        resp.status = -1;
        resp.body = "WinHttpOpen failed";
        return resp;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        resp.status = -1;
        resp.body = "WinHttpConnect failed";
        return resp;
    }

    DWORD flags = useSSL ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(),
                                             nullptr, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        resp.status = -1;
        resp.body = "WinHttpOpenRequest failed";
        return resp;
    }

    // Build headers string
    std::wstring hdrs = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    for (auto& [k, v] : headers) {
        hdrs += to_wide(k) + L": " + to_wide(v) + L"\r\n";
    }

    BOOL sent = WinHttpSendRequest(hRequest, hdrs.c_str(), (DWORD)hdrs.size(),
                                    (LPVOID)json_body.data(), (DWORD)json_body.size(),
                                    (DWORD)json_body.size(), 0);
    if (!sent || !WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        resp.status = -1;
        resp.body = "HTTP request failed";
        return resp;
    }

    // Read status code
    DWORD statusCode = 0, statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
    resp.status = (int)statusCode;

    // Read response headers for file decryption
    DWORD hdrBufSize = 0;
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
                        nullptr, &hdrBufSize, WINHTTP_NO_HEADER_INDEX);
    if (hdrBufSize > 0) {
        std::wstring rawHdrs(hdrBufSize / sizeof(wchar_t), 0);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
                            &rawHdrs[0], &hdrBufSize, WINHTTP_NO_HEADER_INDEX);
        // Parse headers line by line
        std::wstring line;
        for (size_t i = 0; i < rawHdrs.size(); i++) {
            if (rawHdrs[i] == L'\r' && i + 1 < rawHdrs.size() && rawHdrs[i + 1] == L'\n') {
                auto colon = line.find(L':');
                if (colon != std::wstring::npos) {
                    std::wstring wkey = line.substr(0, colon);
                    std::wstring wval = line.substr(colon + 1);
                    while (!wval.empty() && (wval.front() == L' ' || wval.front() == L'\t')) wval.erase(wval.begin());
                    // Convert to narrow and lowercase key
                    std::string nkey(wkey.begin(), wkey.end());
                    std::transform(nkey.begin(), nkey.end(), nkey.begin(), ::tolower);
                    std::string nval(wval.begin(), wval.end());
                    resp.response_headers[nkey] = nval;
                }
                line.clear();
                i++; // skip \n
            } else {
                line += rawHdrs[i];
            }
        }
    }

    // Read response body
    DWORD bytesAvailable, bytesRead;
    do {
        bytesAvailable = 0;
        WinHttpQueryDataAvailable(hRequest, &bytesAvailable);
        if (bytesAvailable == 0) break;
        std::string chunk(bytesAvailable, 0);
        WinHttpReadData(hRequest, &chunk[0], bytesAvailable, &bytesRead);
        resp.body.append(chunk.data(), bytesRead);
    } while (bytesAvailable > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return resp;
}

} // namespace http
#endif

// ─── Client Implementation ──────────────────────────────────────────

Client::Client(const std::string& base_url,
               const std::string& app_secret,
               const std::string& app_version,
               const std::string& hwid)
    : base_url_(base_url)
    , secret_(app_secret)
    , version_(app_version)
    , hwid_(hwid.empty() ? default_hwid() : hwid) {
    // Strip trailing slashes
    while (!base_url_.empty() && base_url_.back() == '/')
        base_url_.pop_back();
}

Client::~Client() = default;

void Client::require_init() const {
    if (session_token_.empty())
        throw Exception("NOT_INITIALIZED", "Call init() before using other methods.");
}

std::string Client::default_hwid() {
    char hostname[256] = {};
    #ifdef _WIN32
        DWORD size = sizeof(hostname);
        GetComputerNameA(hostname, &size);
    #else
        gethostname(hostname, sizeof(hostname));
    #endif
    return std::string(hostname) + "-client";
}

std::string Client::parse_response(const std::string& body) {
    auto success = json::get_string(body, "success");
    if (success != "true" && success != "1") {
        auto err = json::get_object(body, "error");
        auto code = json::get_string(err, "code");
        auto msg = json::get_string(err, "message");
        if (code.empty()) code = "UNKNOWN";
        if (msg.empty()) msg = "Request failed";
        throw Exception(code, msg);
    }
    return json::get_object(body, "data");
}

std::string Client::api_post(const std::string& path, const std::string& json_body) {
    auto resp = http::post(base_url_ + path, json_body);
    return parse_response(resp.body);
}

std::string Client::api_post_nonce(const std::string& path, const std::string& json_body) {
    std::map<std::string, std::string> headers = { {"X-Nonce", nonce_} };
    auto resp = http::post(base_url_ + path, json_body, headers);
    return parse_response(resp.body);
}

std::string Client::fetch_nonce() {
    auto body = json::serialize({{"sessionToken", session_token_}});
    auto data = api_post("/api/client/nonce", body);
    nonce_ = json::get_string(data, "nonce");
    return nonce_;
}

// ── Core API ────────────────────────────────────────────────────────

InitResult Client::init() {
    std::map<std::string, std::string> payload = {
        {"secret", secret_},
        {"version", version_},
        {"hwid", hwid_},
    };
    auto data = api_post("/api/client/init", json::serialize(payload));

    session_token_ = json::get_string(data, "sessionToken");
    app_.name       = json::get_string(data, "appName");
    app_.version    = json::get_string(data, "appVersion");
    app_.anti_debug = json::get_bool(data, "antiDebug");
    app_.anti_vm    = json::get_bool(data, "antiVM");
    app_.lock_hwid  = json::get_bool(data, "lockHwid");
    app_.lock_ip    = json::get_bool(data, "lockIp");
    app_.lock_pcname = json::get_bool(data, "lockPcName");

    InitResult result;
    result.session_token = session_token_;
    result.app = app_;
    result.expires_at = json::get_string(data, "expiresAt");
    result.resumed = json::get_bool(data, "resumed");
    return result;
}

LoginResult Client::login(const std::string& username, const std::string& password,
                           const std::string& license_key, const std::string& pc_name) {
    require_init();
    fetch_nonce();

    std::map<std::string, std::string> payload = {
        {"sessionToken", session_token_},
        {"username", username},
        {"password", password},
        {"licenseKey", license_key},
        {"hwid", hwid_},
        {"pcName", pc_name},
    };
    auto data = api_post_nonce("/api/client/login", json::serialize(payload));

    user_.key       = json::get_string(data, "key");
    user_.username  = json::get_string(data, "username");
    user_.email     = json::get_string(data, "email");
    user_.level     = json::get_int(data, "level");
    user_.expires_at = json::get_string(data, "expiresAt");

    LoginResult result;
    result.user = user_;
    result.license_activated = json::get_bool(data, "licenseActivated");
    return result;
}

LoginResult Client::register_user(const std::string& username, const std::string& password,
                                    const std::string& email, const std::string& display_name,
                                    const std::string& license_key, const std::string& pc_name) {
    require_init();
    fetch_nonce();

    std::map<std::string, std::string> payload = {
        {"sessionToken", session_token_},
        {"username", username},
        {"password", password},
        {"email", email},
        {"displayName", display_name},
        {"licenseKey", license_key},
        {"hwid", hwid_},
        {"pcName", pc_name},
    };
    auto data = api_post_nonce("/api/client/register", json::serialize(payload));

    user_.key       = json::get_string(data, "key");
    user_.username  = json::get_string(data, "username");
    user_.email     = json::get_string(data, "email");
    user_.level     = json::get_int(data, "level");
    user_.expires_at = json::get_string(data, "expiresAt");

    LoginResult result;
    result.user = user_;
    return result;
}

LicenseResult Client::license_login(const std::string& license_key, const std::string& pc_name) {
    require_init();
    fetch_nonce();

    std::map<std::string, std::string> payload = {
        {"sessionToken", session_token_},
        {"licenseKey", license_key},
        {"hwid", hwid_},
        {"pcName", pc_name},
    };
    auto data = api_post_nonce("/api/client/license", json::serialize(payload));

    user_.key       = json::get_string(data, "key");
    user_.username  = json::get_string(data, "username");
    user_.level     = json::get_int(data, "level");
    user_.expires_at = json::get_string(data, "expiresAt");

    LicenseResult result;
    result.user = user_;
    result.returning = json::get_bool(data, "returning");
    return result;
}

void Client::activate(const std::string& license_key) {
    require_init();
    fetch_nonce();
    std::map<std::string, std::string> payload = {
        {"sessionToken", session_token_},
        {"licenseKey", license_key},
    };
    api_post_nonce("/api/client/activate", json::serialize(payload));
}

bool Client::validate_token(const std::string& token) {
    require_init();
    std::map<std::string, std::string> payload = {
        {"sessionToken", session_token_},
        {"token", token},
    };
    auto data = api_post("/api/client/token", json::serialize(payload));
    return json::get_bool(data, "valid");
}

// ── Variables ───────────────────────────────────────────────────────

Variable Client::get_variable(const std::string& key) {
    require_init();
    auto data = api_post("/api/client/variable", json::serialize({
        {"sessionToken", session_token_}, {"key", key},
    }));
    return { json::get_string(data, "key"), json::get_string(data, "value"), json::get_string(data, "type") };
}

std::vector<Variable> Client::get_all_variables() {
    require_init();
    auto data = api_post("/api/client/variables", json::serialize({{"sessionToken", session_token_}}));
    std::vector<Variable> vars;
    auto items = json::split_array(data);
    for (auto& item : items) {
        vars.push_back({ json::get_string(item, "key"), json::get_string(item, "value"), json::get_string(item, "type") });
    }
    return vars;
}

UserVariable Client::get_user_variable(const std::string& key) {
    require_init();
    auto data = api_post("/api/client/user-variable", json::serialize({
        {"sessionToken", session_token_}, {"key", key},
    }));
    return { json::get_string(data, "key"), json::get_string(data, "value") };
}

std::vector<UserVariable> Client::get_all_user_variables() {
    require_init();
    auto data = api_post("/api/client/user-variables", json::serialize({{"sessionToken", session_token_}}));
    std::vector<UserVariable> vars;
    auto items = json::split_array(data);
    for (auto& item : items) {
        vars.push_back({ json::get_string(item, "key"), json::get_string(item, "value") });
    }
    return vars;
}

UserVariable Client::set_user_variable(const std::string& key, const std::string& value) {
    require_init();
    auto data = api_post("/api/client/set-user-variable", json::serialize({
        {"sessionToken", session_token_}, {"key", key}, {"value", value},
    }));
    return { json::get_string(data, "key"), json::get_string(data, "value") };
}

void Client::delete_user_variable(const std::string& key) {
    require_init();
    api_post("/api/client/delete-user-variable", json::serialize({
        {"sessionToken", session_token_}, {"key", key},
    }));
}

// ── Files ───────────────────────────────────────────────────────────

std::string Client::download_file(const std::string& name) {
    require_init();
    auto resp = http::post(base_url_ + "/api/client/file", json::serialize({
        {"sessionToken", session_token_}, {"name", name},
    }));

    // Decrypt if server sent encrypted response
    auto enc_it = resp.response_headers.find("x-file-encrypted");
    auto nonce_it = resp.response_headers.find("x-file-nonce");
    if (enc_it != resp.response_headers.end() && enc_it->second == "1" &&
        nonce_it != resp.response_headers.end() && !nonce_it->second.empty()) {
        return file_crypto::decrypt_file_bytes(resp.body, secret_, session_token_, nonce_it->second);
    }

    return resp.body;
}

UpdateCheck Client::check_update(const std::string& current_version, const std::string& file_name) {
    require_init();
    auto data = api_post("/api/client/check-update", json::serialize({
        {"sessionToken", session_token_},
        {"currentVersion", current_version},
        {"fileName", file_name},
    }));
    UpdateCheck result;
    result.update_available = json::get_bool(data, "updateAvailable");
    result.latest_version   = json::get_string(data, "latestVersion");
    result.current_version  = json::get_string(data, "currentVersion");
    return result;
}

// ── Session ─────────────────────────────────────────────────────────

std::string Client::heartbeat() {
    require_init();
    fetch_nonce();
    auto data = api_post_nonce("/api/client/heartbeat", json::serialize({{"sessionToken", session_token_}}));
    return json::get_string(data, "expiresAt");
}

bool Client::check_session() {
    require_init();
    auto data = api_post("/api/client/check", json::serialize({{"sessionToken", session_token_}}));
    return json::get_bool(data, "valid");
}

void Client::end_session() {
    require_init();
    api_post("/api/client/end", json::serialize({{"sessionToken", session_token_}}));
    session_token_.clear();
    user_ = {};
}

// ── User ────────────────────────────────────────────────────────────

UserData Client::get_user() {
    require_init();
    auto data = api_post("/api/client/user", json::serialize({{"sessionToken", session_token_}}));
    return {
        json::get_string(data, "key"),
        json::get_string(data, "username"),
        json::get_string(data, "email"),
        json::get_int(data, "level"),
        json::get_string(data, "expiresAt"),
    };
}

void Client::change_password(const std::string& current_pw, const std::string& new_pw) {
    require_init();
    api_post("/api/client/change-password", json::serialize({
        {"sessionToken", session_token_},
        {"currentPassword", current_pw},
        {"newPassword", new_pw},
    }));
}

void Client::request_reset() {
    require_init();
    api_post("/api/client/request-reset", json::serialize({{"sessionToken", session_token_}}));
}

// ── Logging ─────────────────────────────────────────────────────────

void Client::log(const std::string& message, const std::string& level) {
    require_init();
    api_post("/api/client/log", json::serialize({
        {"sessionToken", session_token_},
        {"message", message},
        {"level", level},
    }));
}

// ── WebSocket Stubs ─────────────────────────────────────────────────

void Client::on_ws_event(const std::string& event_type, WsCallback cb) {
    std::lock_guard<std::mutex> lock(ws_mutex_);
    ws_handlers_[event_type].push_back(std::move(cb));
}

void Client::ws_send(const std::string&) { /* Platform-specific WS impl */ }
void Client::ws_ping() { ws_send(R"({"type":"ping"})"); }
void Client::ws_set_status(const std::string& status) { ws_send(R"({"type":"set_status","status":")" + status + "\"}"); }
void Client::ws_send_chat(const std::string& message) { ws_send(R"({"type":"chat","message":")" + message + "\"}"); }
void Client::ws_set_typing(bool typing) { ws_send(std::string(R"({"type":"typing","typing":)") + (typing ? "true" : "false") + "}"); }

// ── Multi-Layer File Decryption ──────────────────────────────────────

namespace file_crypto {

static std::string hex_to_bytes(const std::string& hex) {
    std::string out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned int byte;
        std::sscanf(hex.c_str() + i, "%02x", &byte);
        out.push_back(static_cast<char>(byte));
    }
    return out;
}

static std::string bytes_to_hex(const std::string& bytes) {
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char b : bytes) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", b);
        out.append(buf, 2);
    }
    return out;
}

// LCG matching Go server's seededRNG
class SeededRNG {
    uint64_t state_;
public:
    explicit SeededRNG(const std::string& key) {
        state_ = 0;
        if (key.size() >= 8) {
            std::memcpy(&state_, key.data(), 8); // little-endian assumed
        }
        for (size_t i = 8; i < key.size(); i++) {
            state_ ^= static_cast<uint64_t>(static_cast<unsigned char>(key[i])) << ((i % 8) * 8);
            state_ = state_ * 6364136223846793005ULL + 1442695040888963407ULL;
        }
        if (state_ == 0) state_ = 0xdeadbeefcafe1234ULL;
    }

    uint64_t next() {
        state_ = state_ * 6364136223846793005ULL + 1442695040888963407ULL;
        return state_;
    }
};

static std::string derive_subkey(const std::string& master, uint8_t layer) {
    std::string input = master + std::string(1, static_cast<char>(layer));
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
    return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

static void derive_keys(const std::string& app_secret, const std::string& session_token,
                         const std::string& nonce, std::string& aes_key,
                         std::string& shuffle_key, std::string& xor_key) {
    // master = HMAC-SHA256(sessionToken + "|" + hex(nonce), appSecret)
    std::string data = session_token + "|" + bytes_to_hex(nonce);
    unsigned char master[SHA256_DIGEST_LENGTH];
    unsigned int md_len;
    HMAC(EVP_sha256(),
         app_secret.data(), static_cast<int>(app_secret.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(),
         master, &md_len);
    std::string master_key(reinterpret_cast<char*>(master), SHA256_DIGEST_LENGTH);

    aes_key = derive_subkey(master_key, 0x01);
    shuffle_key = derive_subkey(master_key, 0x02);
    xor_key = derive_subkey(master_key, 0x03);
}

std::string decrypt_file_bytes(const std::string& data, const std::string& app_secret,
                                const std::string& session_token, const std::string& nonce_hex) {
    std::string nonce = hex_to_bytes(nonce_hex);
    std::string aes_key, shuffle_key, xor_key;
    derive_keys(app_secret, session_token, nonce, aes_key, shuffle_key, xor_key);

    // Work with a mutable copy
    std::string buf = data;

    // Layer 4 (reverse): Rolling XOR
    for (size_t i = 0; i < buf.size(); i++)
        buf[i] ^= xor_key[i % xor_key.size()];

    // Layer 3 (reverse): Fisher-Yates unshuffle
    size_t n = buf.size();
    if (n > 1) {
        SeededRNG rng(shuffle_key);
        std::vector<size_t> swaps;
        swaps.reserve(n - 1);
        for (size_t i = n - 1; i > 0; i--)
            swaps.push_back(static_cast<size_t>(rng.next() % (i + 1)));
        for (int k = static_cast<int>(swaps.size()) - 1; k >= 0; k--) {
            size_t i = n - 1 - static_cast<size_t>(k);
            size_t j = swaps[k];
            std::swap(buf[i], buf[j]);
        }
    }

    // Layer 2 (reverse): AES-256-GCM (first 12 bytes = nonce, last 16 = tag)
    const int gcm_nonce_size = 12;
    const int tag_size = 16;
    if (static_cast<int>(buf.size()) < gcm_nonce_size + tag_size)
        throw Exception("DECRYPT_ERROR", "Encrypted data too short");

    std::string gcm_nonce = buf.substr(0, gcm_nonce_size);
    int ciphertext_len = static_cast<int>(buf.size()) - gcm_nonce_size - tag_size;
    std::string ciphertext = buf.substr(gcm_nonce_size, ciphertext_len);
    std::string tag = buf.substr(buf.size() - tag_size, tag_size);

    std::string plaintext(ciphertext_len + 16, '\0');
    int out_len = 0, final_len = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, gcm_nonce_size, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                       reinterpret_cast<const unsigned char*>(aes_key.data()),
                       reinterpret_cast<const unsigned char*>(gcm_nonce.data()));
    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &out_len,
                      reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_size,
                        const_cast<char*>(tag.data()));
    int ret = EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[out_len]), &final_len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0)
        throw Exception("DECRYPT_ERROR", "AES-GCM authentication failed");

    plaintext.resize(out_len + final_len);

    // Layer 1 (reverse): zlib decompress
    // Use zlib inflate
    z_stream strm = {};
    inflateInit(&strm);
    strm.next_in = reinterpret_cast<Bytef*>(&plaintext[0]);
    strm.avail_in = static_cast<uInt>(plaintext.size());

    std::string decompressed;
    char out_buf[8192];
    do {
        strm.next_out = reinterpret_cast<Bytef*>(out_buf);
        strm.avail_out = sizeof(out_buf);
        int zret = inflate(&strm, Z_NO_FLUSH);
        if (zret == Z_STREAM_ERROR || zret == Z_DATA_ERROR || zret == Z_MEM_ERROR) {
            inflateEnd(&strm);
            throw Exception("DECOMPRESS_ERROR", "zlib decompression failed");
        }
        decompressed.append(out_buf, sizeof(out_buf) - strm.avail_out);
    } while (strm.avail_out == 0);
    inflateEnd(&strm);

    return decompressed;
}

} // namespace file_crypto

} // namespace swiftauth
