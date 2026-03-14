use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use flate2::read::ZlibDecoder;
use hmac::{Hmac, Mac};
use reqwest::blocking::Client as HttpClient;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub struct SwiftAuthError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for SwiftAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for SwiftAuthError {}

pub type Result<T> = std::result::Result<T, SwiftAuthError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub name: String,
    pub version: String,
    pub anti_debug: bool,
    pub anti_vm: bool,
    pub lock_hwid: bool,
    pub lock_ip: bool,
    pub lock_pc_name: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserData {
    pub key: String,
    pub username: String,
    pub email: String,
    pub level: i64,
    pub expires_at: Option<String>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct Variable {
    pub key: String,
    pub value: String,
    pub var_type: String,
}

#[derive(Debug, Clone)]
pub struct UserVariable {
    pub key: String,
    pub value: String,
}

pub struct SwiftAuthClient {
    base_url: String,
    secret: String,
    version: String,
    hwid: String,
    session_token: Option<String>,
    nonce: Option<String>,
    http: HttpClient,
    pub app: Option<AppInfo>,
    pub user: Option<UserData>,
}

impl SwiftAuthClient {
    pub fn new(base_url: &str, app_secret: &str, app_version: &str, hwid: Option<&str>) -> Self {
        let default_hwid = hwid.map(String::from).unwrap_or_else(|| {
            let host = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".into());
            let user = std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "unknown".into());
            format!("{}-{}", host, user)
        });

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            secret: app_secret.to_string(),
            version: app_version.to_string(),
            hwid: default_hwid,
            session_token: None,
            nonce: None,
            http: HttpClient::new(),
            app: None,
            user: None,
        }
    }

    pub fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref()
    }

    pub fn is_initialized(&self) -> bool {
        self.session_token.is_some()
    }

    // ── Initialization ──────────────────────────────────────────────

    pub fn init(&mut self) -> Result<Value> {
        let data = self.post("/api/client/init", json!({
            "secret": self.secret,
            "version": self.version,
            "hwid": self.hwid,
        }))?;

        self.session_token = Some(get_str(&data, "sessionToken").to_string());
        self.app = Some(AppInfo {
            name: get_str(&data, "appName").to_string(),
            version: get_str(&data, "appVersion").to_string(),
            anti_debug: get_bool(&data, "antiDebug"),
            anti_vm: get_bool(&data, "antiVM"),
            lock_hwid: get_bool(&data, "lockHwid"),
            lock_ip: get_bool(&data, "lockIp"),
            lock_pc_name: get_bool(&data, "lockPcName"),
        });
        Ok(data)
    }

    fn fetch_nonce(&mut self) -> Result<()> {
        let token = self.session_token.clone().unwrap_or_default();
        let data = self.post("/api/client/nonce", json!({ "sessionToken": token }))?;
        self.nonce = Some(get_str(&data, "nonce").to_string());
        Ok(())
    }

    // ── Authentication ──────────────────────────────────────────────

    pub fn login(&mut self, username: &str, password: &str, license_key: &str, pc_name: &str) -> Result<Value> {
        self.require_init()?;
        self.fetch_nonce()?;
        let token = self.session_token.clone().unwrap();
        let data = self.post_with_nonce("/api/client/login", json!({
            "sessionToken": token,
            "username": username,
            "password": password,
            "licenseKey": license_key,
            "hwid": self.hwid,
            "pcName": pc_name,
        }))?;
        self.user = Some(parse_user(&data));
        Ok(data)
    }

    pub fn register(&mut self, username: &str, password: &str, email: &str, display_name: &str, license_key: &str, pc_name: &str) -> Result<Value> {
        self.require_init()?;
        self.fetch_nonce()?;
        let token = self.session_token.clone().unwrap();
        let data = self.post_with_nonce("/api/client/register", json!({
            "sessionToken": token,
            "username": username,
            "password": password,
            "email": email,
            "displayName": display_name,
            "licenseKey": license_key,
            "hwid": self.hwid,
            "pcName": pc_name,
        }))?;
        self.user = Some(parse_user(&data));
        Ok(data)
    }

    pub fn license_login(&mut self, license_key: &str, pc_name: &str) -> Result<Value> {
        self.require_init()?;
        self.fetch_nonce()?;
        let token = self.session_token.clone().unwrap();
        let data = self.post_with_nonce("/api/client/license", json!({
            "sessionToken": token,
            "licenseKey": license_key,
            "hwid": self.hwid,
            "pcName": pc_name,
        }))?;
        self.user = Some(parse_user(&data));
        Ok(data)
    }

    // ── Token Validation ────────────────────────────────────────────

    pub fn validate_token(&self, token: &str) -> Result<Value> {
        self.require_init()?;
        let st = self.session_token.as_ref().unwrap();
        self.post("/api/client/token", json!({ "sessionToken": st, "token": token }))
    }

    // ── License Activation ──────────────────────────────────────────

    pub fn activate(&mut self, license_key: &str) -> Result<Value> {
        self.require_init()?;
        self.fetch_nonce()?;
        let token = self.session_token.clone().unwrap();
        self.post_with_nonce("/api/client/activate", json!({ "sessionToken": token, "licenseKey": license_key }))
    }

    // ── Variables ───────────────────────────────────────────────────

    pub fn get_variable(&self, key: &str) -> Result<Variable> {
        self.require_init()?;
        let st = self.session_token.as_ref().unwrap();
        let data = self.post("/api/client/variable", json!({ "sessionToken": st, "key": key }))?;
        Ok(Variable {
            key: get_str(&data, "key").to_string(),
            value: get_str(&data, "value").to_string(),
            var_type: get_str(&data, "type").to_string(),
        })
    }

    pub fn get_all_variables(&self) -> Result<Vec<Variable>> {
        self.require_init()?;
        let st = self.session_token.as_ref().unwrap();
        let data = self.post("/api/client/variables", json!({ "sessionToken": st }))?;
        let mut vars = Vec::new();
        if let Value::Array(arr) = data {
            for item in arr {
                vars.push(Variable {
                    key: get_str(&item, "key").to_string(),
                    value: get_str(&item, "value").to_string(),
                    var_type: get_str(&item, "type").to_string(),
                });
            }
        }
        Ok(vars)
    }

    // ── License Variables ────────────────────────────────────────────

    pub fn get_license_variable(&self, key: &str) -> Result<Variable> {
        self.require_init()?;
        let st = self.session_token.as_ref().unwrap();
        let data = self.post("/api/client/license-variable", json!({ "sessionToken": st, "key": key }))?;
        Ok(Variable {
            key: get_str(&data, "key").to_string(),
            value: get_str(&data, "value").to_string(),
            var_type: get_str(&data, "type").to_string(),
        })
    }

    pub fn get_all_license_variables(&self) -> Result<Vec<Variable>> {
        self.require_init()?;
        let st = self.session_token.as_ref().unwrap();
        let data = self.post("/api/client/license-variables", json!({ "sessionToken": st }))?;
        let mut vars = Vec::new();
        if let Value::Array(arr) = data {
            for item in arr {
                vars.push(Variable {
                    key: get_str(&item, "key").to_string(),
                    value: get_str(&item, "value").to_string(),
                    var_type: get_str(&item, "type").to_string(),
                });
            }
        }
        Ok(vars)
    }

    // ── User Variables ──────────────────────────────────────────────

    pub fn get_user_variable(&self, key: &str) -> Result<UserVariable> {
        self.require_init()?;
        let st = self.session_token.as_ref().unwrap();
        let data = self.post("/api/client/user-variable", json!({ "sessionToken": st, "key": key }))?;
        Ok(UserVariable {
            key: get_str(&data, "key").to_string(),
            value: get_str(&data, "value").to_string(),
        })
    }

    pub fn get_all_user_variables(&self) -> Result<Vec<UserVariable>> {
        self.require_init()?;
        let st = self.session_token.as_ref().unwrap();
        let data = self.post("/api/client/user-variables", json!({ "sessionToken": st }))?;
        let mut vars = Vec::new();
        if let Value::Array(arr) = data {
            for item in arr {
                vars.push(UserVariable {
                    key: get_str(&item, "key").to_string(),
                    value: get_str(&item, "value").to_string(),
                });
            }
        }
        Ok(vars)
    }

    pub fn set_user_variable(&self, key: &str, value: &str) -> Result<UserVariable> {
        self.require_init()?;
        let st = self.session_token.as_ref().unwrap();
        let data = self.post("/api/client/set-user-variable", json!({ "sessionToken": st, "key": key, "value": value }))?;
        Ok(UserVariable {
            key: get_str(&data, "key").to_string(),
            value: get_str(&data, "value").to_string(),
        })
    }

    pub fn delete_user_variable(&self, key: &str) -> Result<()> {
        self.require_init()?;
        let st = self.session_token.as_ref().unwrap();
        self.post("/api/client/delete-user-variable", json!({ "sessionToken": st, "key": key }))?;
        Ok(())
    }

    // ── Files ───────────────────────────────────────────────────────

    pub fn download_file(&self, name: &str) -> Result<Vec<u8>> {
        self.require_init()?;
        let st = self.session_token.as_ref().unwrap();
        let resp = self.http.post(&format!("{}/api/client/file", self.base_url))
            .header("Content-Type", "application/json")
            .json(&json!({ "sessionToken": st, "name": name }))
            .send()
            .map_err(|e| SwiftAuthError { code: "NETWORK_ERROR".into(), message: e.to_string() })?;

        let encrypted = resp.headers().get("x-file-encrypted")
            .and_then(|v| v.to_str().ok()) == Some("1");
        let nonce_hex = resp.headers().get("x-file-nonce")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let data = resp.bytes()
            .map_err(|e| SwiftAuthError { code: "NETWORK_ERROR".into(), message: e.to_string() })?
            .to_vec();

        if encrypted {
            if let Some(nonce) = nonce_hex {
                return decrypt_file_bytes(&data, &self.secret, st, &nonce);
            }
        }
        Ok(data)
    }

    pub fn check_update(&self, current_version: &str, file_name: &str) -> Result<Value> {
        self.require_init()?;
        let st = self.session_token.as_ref().unwrap();
        self.post("/api/client/check-update", json!({
            "sessionToken": st,
            "currentVersion": current_version,
            "fileName": file_name,
        }))
    }

    // ── Session Management ──────────────────────────────────────────

    pub fn heartbeat(&mut self) -> Result<Value> {
        self.require_init()?;
        self.fetch_nonce()?;
        let token = self.session_token.clone().unwrap();
        self.post_with_nonce("/api/client/heartbeat", json!({ "sessionToken": token }))
    }

    pub fn check_session(&self) -> Result<Value> {
        self.require_init()?;
        let st = self.session_token.as_ref().unwrap();
        self.post("/api/client/check", json!({ "sessionToken": st }))
    }

    pub fn end_session(&mut self) -> Result<()> {
        self.require_init()?;
        let st = self.session_token.clone().unwrap();
        self.post("/api/client/end", json!({ "sessionToken": st }))?;
        self.session_token = None;
        self.user = None;
        Ok(())
    }

    // ── User Info ───────────────────────────────────────────────────

    pub fn get_user(&self) -> Result<Value> {
        self.require_init()?;
        let st = self.session_token.as_ref().unwrap();
        self.post("/api/client/user", json!({ "sessionToken": st }))
    }

    pub fn change_password(&self, current_password: &str, new_password: &str) -> Result<()> {
        self.require_init()?;
        let st = self.session_token.as_ref().unwrap();
        self.post("/api/client/change-password", json!({
            "sessionToken": st,
            "currentPassword": current_password,
            "newPassword": new_password,
        }))?;
        Ok(())
    }

    pub fn request_reset(&self) -> Result<()> {
        self.require_init()?;
        let st = self.session_token.as_ref().unwrap();
        self.post("/api/client/request-reset", json!({ "sessionToken": st }))?;
        Ok(())
    }

    // ── Client Log ──────────────────────────────────────────────────

    pub fn log(&self, message: &str, level: &str) -> Result<()> {
        self.require_init()?;
        let st = self.session_token.as_ref().unwrap();
        self.post("/api/client/log", json!({
            "sessionToken": st,
            "message": message,
            "level": level,
        }))?;
        Ok(())
    }

    // ── Internal ────────────────────────────────────────────────────

    fn require_init(&self) -> Result<()> {
        if self.session_token.is_none() {
            return Err(SwiftAuthError {
                code: "NOT_INITIALIZED".into(),
                message: "Call init() before using other methods.".into(),
            });
        }
        Ok(())
    }

    fn post(&self, path: &str, payload: Value) -> Result<Value> {
        self.request(path, payload, HashMap::new())
    }

    fn post_with_nonce(&self, path: &str, payload: Value) -> Result<Value> {
        let mut headers = HashMap::new();
        if let Some(ref n) = self.nonce {
            headers.insert("X-Nonce".to_string(), n.clone());
        }
        self.request(path, payload, headers)
    }

    fn request(&self, path: &str, payload: Value, extra_headers: HashMap<String, String>) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut builder = self.http.post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json");

        for (k, v) in &extra_headers {
            builder = builder.header(k.as_str(), v.as_str());
        }

        let resp = builder.json(&payload).send()
            .map_err(|e| SwiftAuthError { code: "NETWORK_ERROR".into(), message: e.to_string() })?;

        let body: Value = resp.json()
            .map_err(|_| SwiftAuthError { code: "PARSE_ERROR".into(), message: "Invalid server response".into() })?;

        let success = body.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
        if !success {
            let err = body.get("error").cloned().unwrap_or(Value::Object(Map::new()));
            return Err(SwiftAuthError {
                code: get_str(&err, "code").to_string(),
                message: get_str(&err, "message").to_string(),
            });
        }

        if let Some(data) = body.get("data") {
            return Ok(data.clone());
        }
        if let Some(msg) = body.get("message") {
            return Ok(json!({ "message": msg }));
        }
        Ok(Value::Object(Map::new()))
    }
}

fn get_str<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

fn get_bool(v: &Value, key: &str) -> bool {
    v.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn parse_user(data: &Value) -> UserData {
    UserData {
        key: get_str(data, "key").to_string(),
        username: get_str(data, "username").to_string(),
        email: get_str(data, "email").to_string(),
        level: data.get("level").and_then(|v| v.as_i64()).unwrap_or(0),
        expires_at: data.get("expiresAt").and_then(|v| v.as_str()).map(String::from),
        metadata: data.get("metadata").cloned(),
    }
}

// ── Multi-Layer File Decryption ─────────────────────────────────────

struct SeededRNG {
    state: u64,
}

impl SeededRNG {
    fn new(key: &[u8]) -> Self {
        let mut state: u64 = 0;
        if key.len() >= 8 {
            state = u64::from_le_bytes(key[..8].try_into().unwrap());
        }
        for i in 8..key.len() {
            state ^= (key[i] as u64) << ((i % 8) * 8);
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        }
        if state == 0 {
            state = 0xDEADBEEFCAFE1234;
        }
        Self { state }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.state
    }
}

fn derive_keys(app_secret: &str, session_token: &str, nonce: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut mac = HmacSha256::new_from_slice(app_secret.as_bytes()).unwrap();
    mac.update(format!("{}|{}", session_token, hex::encode(nonce)).as_bytes());
    let master = mac.finalize().into_bytes();

    let sub = |layer: u8| -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&master);
        hasher.update([layer]);
        hasher.finalize().into()
    };

    (sub(0x01), sub(0x02), sub(0x03))
}

fn decrypt_file_bytes(data: &[u8], app_secret: &str, session_token: &str, nonce_hex: &str) -> Result<Vec<u8>> {
    let nonce = hex::decode(nonce_hex)
        .map_err(|e| SwiftAuthError { code: "DECRYPT_ERROR".into(), message: e.to_string() })?;
    let (aes_key, shuffle_key, xor_key) = derive_keys(app_secret, session_token, &nonce);

    // Layer 4: Rolling XOR
    let mut buf: Vec<u8> = data.to_vec();
    for i in 0..buf.len() {
        buf[i] ^= xor_key[i % xor_key.len()];
    }

    // Layer 3: Fisher-Yates unshuffle
    let n = buf.len();
    let mut rng = SeededRNG::new(&shuffle_key);
    let mut swaps = Vec::with_capacity(n);
    for i in (1..n).rev() {
        swaps.push((rng.next() % (i as u64 + 1)) as usize);
    }
    for k in (0..swaps.len()).rev() {
        let i = n - 1 - k;
        let j = swaps[k];
        buf.swap(i, j);
    }

    // Layer 2: AES-256-GCM
    let gcm_nonce = Nonce::from_slice(&buf[..12]);
    let ciphertext_and_tag = &buf[12..];
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| SwiftAuthError { code: "DECRYPT_ERROR".into(), message: e.to_string() })?;
    let plaintext = cipher.decrypt(gcm_nonce, ciphertext_and_tag)
        .map_err(|e| SwiftAuthError { code: "DECRYPT_ERROR".into(), message: e.to_string() })?;

    // Layer 1: zlib decompress
    let mut decoder = ZlibDecoder::new(&plaintext[..]);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)
        .map_err(|e| SwiftAuthError { code: "DECRYPT_ERROR".into(), message: e.to_string() })?;
    Ok(output)
}
