--- SwiftAuth SDK for Lua
--- Requires: lua-cjson, lua-http or luasocket, luaossl or luacrypto
---
--- Usage:
---   local SwiftAuth = require("swiftauth")
---   local client = SwiftAuth.new("https://api.swiftauth.net", "YOUR_SECRET", "1.0.0")

local json = require("cjson")
local http_request = require("socket.http")
local ltn12 = require("ltn12")
local socket = require("socket")

local SwiftAuth = {}
SwiftAuth.__index = SwiftAuth

--- Create a new SwiftAuth client.
--- @param base_url string The API base URL
--- @param app_secret string Your app secret key
--- @param app_version string Your app version (default "1.0.0")
--- @param hwid string|nil Optional hardware ID
--- @return table SwiftAuth client instance
function SwiftAuth.new(base_url, app_secret, app_version, hwid)
    local self = setmetatable({}, SwiftAuth)
    self._base_url = base_url:gsub("/+$", "")
    self._secret = app_secret
    self._version = app_version or "1.0.0"
    self._hwid = hwid or (socket.dns.gethostname() .. "-" .. (os.getenv("USER") or os.getenv("USERNAME") or "unknown"))
    self._session_token = nil
    self._nonce = nil
    self.app = nil
    self.user = nil
    return self
end

--- Check if the client is initialized.
--- @return boolean
function SwiftAuth:is_initialized()
    return self._session_token ~= nil
end

--- Get the current session token.
--- @return string|nil
function SwiftAuth:session_token()
    return self._session_token
end

-- ── Initialization ──────────────────────────────────────────────

--- Initialize a session with the SwiftAuth server.
--- @return table Response data
function SwiftAuth:init()
    local data = self:_post("/api/client/init", {
        secret = self._secret,
        version = self._version,
        hwid = self._hwid,
    })
    self._session_token = data.sessionToken
    self.app = {
        name = data.appName or "",
        version = data.appVersion or "",
        anti_debug = data.antiDebug or false,
        anti_vm = data.antiVM or false,
        lock_hwid = data.lockHwid or false,
        lock_ip = data.lockIp or false,
        lock_pc_name = data.lockPcName or false,
    }
    return data
end

function SwiftAuth:_fetch_nonce()
    local data = self:_post("/api/client/nonce", { sessionToken = self._session_token })
    self._nonce = data.nonce
    return self._nonce
end

-- ── Authentication ──────────────────────────────────────────────

--- Login with username and password.
--- @param username string
--- @param password string
--- @param license_key string|nil Optional license key
--- @param pc_name string|nil Optional PC name
--- @return table Response data
function SwiftAuth:login(username, password, license_key, pc_name)
    self:_require_init()
    self:_fetch_nonce()
    local data = self:_post_with_nonce("/api/client/login", {
        sessionToken = self._session_token,
        username = username,
        password = password,
        licenseKey = license_key or "",
        hwid = self._hwid,
        pcName = pc_name or "",
    })
    self.user = self:_parse_user(data)
    return data
end

--- Register a new account.
--- @param username string
--- @param password string
--- @param email string|nil Optional email
--- @param display_name string|nil Optional display name
--- @param license_key string|nil Optional license key
--- @param pc_name string|nil Optional PC name
--- @return table Response data
function SwiftAuth:register(username, password, email, display_name, license_key, pc_name)
    self:_require_init()
    self:_fetch_nonce()
    local data = self:_post_with_nonce("/api/client/register", {
        sessionToken = self._session_token,
        username = username,
        password = password,
        email = email or "",
        displayName = display_name or "",
        licenseKey = license_key or "",
        hwid = self._hwid,
        pcName = pc_name or "",
    })
    self.user = self:_parse_user(data)
    return data
end

--- Login with a license key only.
--- @param license_key string
--- @param pc_name string|nil Optional PC name
--- @return table Response data
function SwiftAuth:license_login(license_key, pc_name)
    self:_require_init()
    self:_fetch_nonce()
    local data = self:_post_with_nonce("/api/client/license", {
        sessionToken = self._session_token,
        licenseKey = license_key,
        hwid = self._hwid,
        pcName = pc_name or "",
    })
    self.user = self:_parse_user(data)
    return data
end

-- ── Token Validation ────────────────────────────────────────────

--- Validate a pre-auth access token.
--- @param token string
--- @return table Response data
function SwiftAuth:validate_token(token)
    self:_require_init()
    return self:_post("/api/client/token", { sessionToken = self._session_token, token = token })
end

-- ── License Activation ──────────────────────────────────────────

--- Activate a license on the current user.
--- @param license_key string
--- @return table Response data
function SwiftAuth:activate(license_key)
    self:_require_init()
    self:_fetch_nonce()
    return self:_post_with_nonce("/api/client/activate", {
        sessionToken = self._session_token,
        licenseKey = license_key,
    })
end

-- ── Variables ───────────────────────────────────────────────────

--- Get a single app variable.
--- @param key string
--- @return table Variable data {key, value, type}
function SwiftAuth:get_variable(key)
    self:_require_init()
    return self:_post("/api/client/variable", { sessionToken = self._session_token, key = key })
end

--- Get all app variables.
--- @return table List of variables
function SwiftAuth:get_all_variables()
    self:_require_init()
    return self:_post("/api/client/variables", { sessionToken = self._session_token })
end

-- ── User Variables ──────────────────────────────────────────────

--- Get a user-scoped variable.
--- @param key string
--- @return table Variable data {key, value}
function SwiftAuth:get_user_variable(key)
    self:_require_init()
    return self:_post("/api/client/user-variable", { sessionToken = self._session_token, key = key })
end

--- Get all user-scoped variables.
--- @return table List of user variables
function SwiftAuth:get_all_user_variables()
    self:_require_init()
    return self:_post("/api/client/user-variables", { sessionToken = self._session_token })
end

--- Set or update a user-scoped variable.
--- @param key string
--- @param value string
--- @return table Variable data {key, value}
function SwiftAuth:set_user_variable(key, value)
    self:_require_init()
    return self:_post("/api/client/set-user-variable", {
        sessionToken = self._session_token,
        key = key,
        value = value,
    })
end

--- Delete a user-scoped variable.
--- @param key string
function SwiftAuth:delete_user_variable(key)
    self:_require_init()
    self:_post("/api/client/delete-user-variable", { sessionToken = self._session_token, key = key })
end

-- ── Session Management ──────────────────────────────────────────

--- Send a heartbeat to keep the session alive.
--- @return table Response data
function SwiftAuth:heartbeat()
    self:_require_init()
    self:_fetch_nonce()
    return self:_post_with_nonce("/api/client/heartbeat", { sessionToken = self._session_token })
end

--- Check if the session is still valid.
--- @return table Response data
function SwiftAuth:check_session()
    self:_require_init()
    return self:_post("/api/client/check", { sessionToken = self._session_token })
end

--- End and invalidate the current session.
function SwiftAuth:end_session()
    self:_require_init()
    self:_post("/api/client/end", { sessionToken = self._session_token })
    self._session_token = nil
    self.user = nil
end

-- ── User Info ───────────────────────────────────────────────────

--- Get current user profile info.
--- @return table User data
function SwiftAuth:get_user()
    self:_require_init()
    return self:_post("/api/client/user", { sessionToken = self._session_token })
end

--- Change the current user's password.
--- @param current_password string
--- @param new_password string
function SwiftAuth:change_password(current_password, new_password)
    self:_require_init()
    self:_post("/api/client/change-password", {
        sessionToken = self._session_token,
        currentPassword = current_password,
        newPassword = new_password,
    })
end

--- Request a HWID/IP reset.
function SwiftAuth:request_reset()
    self:_require_init()
    self:_post("/api/client/request-reset", { sessionToken = self._session_token })
end

-- ── Client Log ──────────────────────────────────────────────────

--- Send a client-side log entry.
--- @param message string
--- @param level string|nil Log level (default "INFO")
function SwiftAuth:log(message, level)
    self:_require_init()
    self:_post("/api/client/log", {
        sessionToken = self._session_token,
        message = message,
        level = level or "INFO",
    })
end

-- ── Files ─────────────────────────────────────────────────────────

--- Download a file by name (non-encrypted files only).
--- Note: Encrypted file decryption requires AES-256-GCM which is not
--- available in standard Lua. Use a C/C++ binding if encrypted files are needed.
--- @param name string
--- @return string Raw file bytes
function SwiftAuth:download_file(name)
    self:_require_init()
    local body = json.encode({ sessionToken = self._session_token, name = name })
    local response_body = {}
    local response_headers = {}

    local url = self._base_url .. "/api/client/file"
    local _, status, resp_hdrs = http_request.request({
        url = url,
        method = "POST",
        headers = {
            ["Content-Type"] = "application/json",
            ["Content-Length"] = tostring(#body),
        },
        source = ltn12.source.string(body),
        sink = ltn12.sink.table(response_body),
    })

    local data = table.concat(response_body)

    -- Check for encryption headers
    if resp_hdrs then
        local encrypted = resp_hdrs["x-file-encrypted"]
        local file_nonce = resp_hdrs["x-file-nonce"]
        if encrypted == "1" and file_nonce and file_nonce ~= "" then
            error("[DECRYPT_UNSUPPORTED] Encrypted file decryption is not supported in the Lua SDK. Use C/C++, Python, or another SDK with AES-256-GCM support.")
        end
    end

    return data
end

-- ── Check Update ────────────────────────────────────────────────

--- Check for app version updates.
--- @param current_version string
--- @param file_name string|nil Optional file name
--- @return table Response data
function SwiftAuth:check_update(current_version, file_name)
    self:_require_init()
    return self:_post("/api/client/check-update", {
        sessionToken = self._session_token,
        currentVersion = current_version,
        fileName = file_name or "",
    })
end

-- ── Internal ────────────────────────────────────────────────────

function SwiftAuth:_require_init()
    if not self._session_token then
        error("[NOT_INITIALIZED] Call init() before using other methods.")
    end
end

function SwiftAuth:_post(path, payload)
    return self:_request(path, payload, {})
end

function SwiftAuth:_post_with_nonce(path, payload)
    return self:_request(path, payload, { ["X-Nonce"] = self._nonce })
end

function SwiftAuth:_request(path, payload, extra_headers)
    local body = json.encode(payload)
    local response_body = {}
    local headers = {
        ["Content-Type"] = "application/json",
        ["Accept"] = "application/json",
        ["Content-Length"] = tostring(#body),
    }
    for k, v in pairs(extra_headers) do
        headers[k] = v
    end

    local url = self._base_url .. path
    local _, status = http_request.request({
        url = url,
        method = "POST",
        headers = headers,
        source = ltn12.source.string(body),
        sink = ltn12.sink.table(response_body),
    })

    local response_str = table.concat(response_body)
    local ok, result = pcall(json.decode, response_str)
    if not ok then
        error("[PARSE_ERROR] Invalid server response")
    end

    if not result.success then
        local err = result.error or {}
        error("[" .. (err.code or "UNKNOWN") .. "] " .. (err.message or "Request failed"))
    end

    return result.data or result.message or {}
end

function SwiftAuth:_parse_user(data)
    return {
        key = data.key or "",
        username = data.username or "",
        email = data.email or "",
        level = data.level or 0,
        expires_at = data.expiresAt,
        metadata = data.metadata,
    }
end

return SwiftAuth
