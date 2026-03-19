const https = require("https");
const http = require("http");
const crypto = require("crypto");
const zlib = require("zlib");
const { URL } = require("url");
const os = require("os");
const WebSocket = require("ws");
const EventEmitter = require("events");

class SwiftAuthError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "SwiftAuthError";
        this.code = code;
    }
}

class SwiftAuthClient extends EventEmitter {
    #baseUrl;
    #secret;
    #version;
    #hwid;
    #sessionToken;
    #nonce;
    #ws;
    #heartbeatTimer;

    app = null;
    user = null;

    constructor({ baseUrl, appSecret, appVersion = "1.0.0", hwid = null }) {
        super();
        if (!baseUrl) throw new Error("baseUrl is required");
        if (!appSecret) throw new Error("appSecret is required");

        this.#baseUrl = baseUrl.replace(/\/+$/, "");
        this.#secret = appSecret;
        this.#version = appVersion;
        this.#hwid = hwid || `${os.hostname()}-${os.userInfo().username}`;
    }

    get sessionToken() { return this.#sessionToken; }
    get isInitialized() { return !!this.#sessionToken; }
    get isWsConnected() { return this.#ws?.readyState === WebSocket.OPEN; }

    // ── Initialization ──────────────────────────────────────────────

    async init() {
        const data = await this.#post("/api/client/init", {
            secret: this.#secret,
            version: this.#version,
            hwid: this.#hwid,
        });

        this.#sessionToken = data.sessionToken;
        this.app = {
            name: data.appName,
            version: data.appVersion,
            antiDebug: data.antiDebug,
            antiVM: data.antiVM,
            lockHwid: data.lockHwid,
            lockIp: data.lockIp,
            lockPcName: data.lockPcName,
        };

        return data;
    }

    // ── Nonce ───────────────────────────────────────────────────────

    async #fetchNonce() {
        const data = await this.#post("/api/client/nonce", { sessionToken: this.#sessionToken });
        this.#nonce = data.nonce;
        return this.#nonce;
    }

    // ── Authentication ──────────────────────────────────────────────

    async login(username, password, { licenseKey = "", pcName = "" } = {}) {
        this.#requireInit();
        await this.#fetchNonce();
        const data = await this.#postWithNonce("/api/client/login", {
            sessionToken: this.#sessionToken,
            username, password, licenseKey,
            hwid: this.#hwid,
            pcName,
        });
        this.user = {
            key: data.key,
            username: data.username,
            email: data.email,
            level: data.level,
            expiresAt: data.expiresAt,
            metadata: data.metadata,
        };
        return data;
    }

    async register(username, password, { email = "", displayName = "", licenseKey = "", pcName = "" } = {}) {
        this.#requireInit();
        await this.#fetchNonce();
        const data = await this.#postWithNonce("/api/client/register", {
            sessionToken: this.#sessionToken,
            username, password, email, displayName, licenseKey,
            hwid: this.#hwid,
            pcName,
        });
        this.user = {
            key: data.key,
            username: data.username,
            email: data.email,
            level: data.level,
            expiresAt: data.expiresAt,
        };
        return data;
    }

    async licenseLogin(licenseKey, { pcName = "" } = {}) {
        this.#requireInit();
        await this.#fetchNonce();
        const data = await this.#postWithNonce("/api/client/license", {
            sessionToken: this.#sessionToken,
            licenseKey,
            hwid: this.#hwid,
            pcName,
        });
        this.user = {
            key: data.key,
            username: data.username,
            level: data.level,
            expiresAt: data.expiresAt,
        };
        return data;
    }

    // ── Token Validation ────────────────────────────────────────────

    async validateToken(token) {
        this.#requireInit();
        return this.#post("/api/client/token", { sessionToken: this.#sessionToken, token });
    }

    // ── License Activation ──────────────────────────────────────────

    async activate(licenseKey) {
        this.#requireInit();
        await this.#fetchNonce();
        return this.#postWithNonce("/api/client/activate", {
            sessionToken: this.#sessionToken,
            licenseKey,
        });
    }

    // ── License Check ──────────────────────────────────────────────

    async checkLicense(licenseKey) {
        this.#requireInit();
        return this.#post("/api/client/check-license", {
            sessionToken: this.#sessionToken,
            licenseKey,
        });
    }

    // ── Variables ───────────────────────────────────────────────────

    async getVariable(key) {
        this.#requireInit();
        return this.#post("/api/client/variable", { sessionToken: this.#sessionToken, key });
    }

    async getAllVariables() {
        this.#requireInit();
        return this.#post("/api/client/variables", { sessionToken: this.#sessionToken });
    }

    // ── License Variables ───────────────────────────────────────────

    async getLicenseVariable(key) {
        this.#requireInit();
        return this.#post("/api/client/license-variable", { sessionToken: this.#sessionToken, key });
    }

    async getAllLicenseVariables() {
        this.#requireInit();
        return this.#post("/api/client/license-variables", { sessionToken: this.#sessionToken });
    }

    // ── User Variables ──────────────────────────────────────────────

    async getUserVariable(key) {
        this.#requireInit();
        return this.#post("/api/client/user-variable", { sessionToken: this.#sessionToken, key });
    }

    async getAllUserVariables() {
        this.#requireInit();
        return this.#post("/api/client/user-variables", { sessionToken: this.#sessionToken });
    }

    async setUserVariable(key, value) {
        this.#requireInit();
        return this.#post("/api/client/set-user-variable", { sessionToken: this.#sessionToken, key, value });
    }

    async deleteUserVariable(key) {
        this.#requireInit();
        return this.#post("/api/client/delete-user-variable", { sessionToken: this.#sessionToken, key });
    }

    // ── Files ───────────────────────────────────────────────────────

    async downloadFile(name) {
        this.#requireInit();
        const { buffer, headers } = await this.#postRawWithHeaders("/api/client/file", { sessionToken: this.#sessionToken, name });

        if (headers["x-file-encrypted"] === "1" && headers["x-file-nonce"]) {
            return _decryptFileBytes(buffer, this.#secret, this.#sessionToken, headers["x-file-nonce"]);
        }

        return buffer;
    }

    async checkUpdate(currentVersion, fileName = "") {
        this.#requireInit();
        return this.#post("/api/client/check-update", {
            sessionToken: this.#sessionToken,
            currentVersion,
            fileName,
        });
    }

    // ── Session Management ──────────────────────────────────────────

    async heartbeat() {
        this.#requireInit();
        await this.#fetchNonce();
        return this.#postWithNonce("/api/client/heartbeat", { sessionToken: this.#sessionToken });
    }

    async checkSession() {
        this.#requireInit();
        return this.#post("/api/client/check", { sessionToken: this.#sessionToken });
    }

    async endSession() {
        this.#requireInit();
        await this.#post("/api/client/end", { sessionToken: this.#sessionToken });
        this.#sessionToken = null;
        this.user = null;
    }

    // ── User Info ───────────────────────────────────────────────────

    async getUser() {
        this.#requireInit();
        const data = await this.#post("/api/client/user", { sessionToken: this.#sessionToken });
        this.user = {
            key: data.key,
            username: data.username,
            email: data.email,
            level: data.level,
            expiresAt: data.expiresAt,
            metadata: data.metadata,
            avatarUrl: data.avatarUrl,
            discordId: data.discordId,
        };
        return data;
    }

    async changePassword(currentPassword, newPassword) {
        this.#requireInit();
        return this.#post("/api/client/change-password", {
            sessionToken: this.#sessionToken,
            currentPassword,
            newPassword,
        });
    }

    async requestReset() {
        this.#requireInit();
        return this.#post("/api/client/request-reset", { sessionToken: this.#sessionToken });
    }

    // ── Client Log ──────────────────────────────────────────────────

    async log(message, level = "INFO") {
        this.#requireInit();
        return this.#post("/api/client/log", { sessionToken: this.#sessionToken, message, level });
    }

    // ── WebSocket ───────────────────────────────────────────────────

    connectWs() {
        this.#requireInit();
        const wsUrl = this.#baseUrl.replace("https://", "wss://").replace("http://", "ws://")
            + `/api/client/ws?token=${encodeURIComponent(this.#sessionToken)}`;

        this.#ws = new WebSocket(wsUrl);

        this.#ws.on("open", () => this.emit("ws:open"));

        this.#ws.on("message", (raw) => {
            try {
                const evt = JSON.parse(raw.toString());
                this.emit("ws:message", evt);
                if (evt.type) this.emit(`ws:${evt.type}`, evt.data || {});
            } catch { /* drop malformed */ }
        });

        this.#ws.on("close", (code, reason) => {
            clearInterval(this.#heartbeatTimer);
            this.emit("ws:close", code, reason?.toString());
        });

        this.#ws.on("error", (err) => this.emit("ws:error", err));
    }

    wsSend(data) {
        if (this.#ws?.readyState === WebSocket.OPEN) {
            this.#ws.send(JSON.stringify(data));
        }
    }

    wsPing() { this.wsSend({ type: "ping" }); }
    wsSetStatus(status) { this.wsSend({ type: "set_status", status }); }
    wsSendChat(message) { this.wsSend({ type: "chat", message }); }
    wsSetTyping(typing) { this.wsSend({ type: "typing", typing }); }
    wsSetMetadata(metadata) { this.wsSend({ type: "set_metadata", metadata }); }

    startWsHeartbeat(intervalMs = 25000) {
        this.#heartbeatTimer = setInterval(() => this.wsPing(), intervalMs);
    }

    disconnectWs() {
        clearInterval(this.#heartbeatTimer);
        if (this.#ws) {
            this.#ws.close();
            this.#ws = null;
        }
    }

    // ── Internal ────────────────────────────────────────────────────

    #requireInit() {
        if (!this.#sessionToken)
            throw new SwiftAuthError("NOT_INITIALIZED", "Call init() before using other methods.");
    }

    async #post(path, payload) {
        return this.#request(path, payload, {});
    }

    async #postWithNonce(path, payload) {
        return this.#request(path, payload, { "X-Nonce": this.#nonce });
    }

    async #postRaw(path, payload) {
        const { buffer } = await this.#postRawWithHeaders(path, payload);
        return buffer;
    }

    async #postRawWithHeaders(path, payload) {
        const url = new URL(this.#baseUrl + path);
        const body = JSON.stringify(payload);
        const mod = url.protocol === "https:" ? https : http;

        return new Promise((resolve, reject) => {
            const req = mod.request(url, {
                method: "POST",
                headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
            }, (res) => {
                const chunks = [];
                res.on("data", (c) => chunks.push(c));
                res.on("end", () => resolve({ buffer: Buffer.concat(chunks), headers: res.headers }));
            });
            req.on("error", reject);
            req.write(body);
            req.end();
        });
    }

    async #request(path, payload, extraHeaders) {
        const url = new URL(this.#baseUrl + path);
        const body = JSON.stringify(payload);
        const mod = url.protocol === "https:" ? https : http;

        return new Promise((resolve, reject) => {
            const req = mod.request(url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Content-Length": Buffer.byteLength(body),
                    ...extraHeaders,
                },
            }, (res) => {
                const chunks = [];
                res.on("data", (c) => chunks.push(c));
                res.on("end", () => {
                    try {
                        const json = JSON.parse(Buffer.concat(chunks).toString());
                        if (!json.success) {
                            const err = json.error || {};
                            reject(new SwiftAuthError(err.code || "UNKNOWN", err.message || "Request failed"));
                            return;
                        }
                        resolve(json.data !== undefined ? json.data : json.message);
                    } catch (e) {
                        const raw = Buffer.concat(chunks).toString();
                        const preview = raw.length > 200 ? raw.slice(0, 200) + "..." : raw;
                        reject(new SwiftAuthError("PARSE_ERROR", `Invalid JSON response from server. This usually means the request hit a non-API endpoint (e.g. Cloudflare, reverse proxy, or wrong base URL). Response preview: ${preview}`));
                    }
                });
            });

            req.on("error", reject);
            req.write(body);
            req.end();
        });
    }
}

// ── Multi-Layer File Decryption ──────────────────────────────────────

class _SeededRNG {
    constructor(key) {
        let state = 0n;
        if (key.length >= 8) state = key.readBigUInt64LE(0);
        for (let i = 8; i < key.length; i++) {
            state ^= BigInt(key[i]) << BigInt((i % 8) * 8);
            state = BigInt.asUintN(64, state * 6364136223846793005n + 1442695040888963407n);
        }
        if (state === 0n) state = 0xdeadbeefcafe1234n;
        this._state = state;
    }
    next() {
        this._state = BigInt.asUintN(64, this._state * 6364136223846793005n + 1442695040888963407n);
        return this._state;
    }
}

function _deriveKeys(appSecret, sessionToken, nonce) {
    const master = crypto.createHmac("sha256", appSecret)
        .update(sessionToken + "|" + nonce.toString("hex"))
        .digest();

    const sub = (layer) => crypto.createHash("sha256")
        .update(Buffer.concat([master, Buffer.from([layer])]))
        .digest();

    return { aesKey: sub(0x01), shuffleKey: sub(0x02), xorKey: sub(0x03) };
}

function _decryptFileBytes(data, appSecret, sessionToken, nonceHex) {
    const nonce = Buffer.from(nonceHex, "hex");
    const { aesKey, shuffleKey, xorKey } = _deriveKeys(appSecret, sessionToken, nonce);

    // Layer 4: Rolling XOR
    const buf = Buffer.from(data);
    for (let i = 0; i < buf.length; i++) buf[i] ^= xorKey[i % xorKey.length];

    // Layer 3: Fisher-Yates unshuffle
    const n = buf.length;
    const rng = new _SeededRNG(shuffleKey);
    const swaps = [];
    for (let i = n - 1; i > 0; i--) {
        const r = rng.next();
        swaps.push(Number(r % BigInt(i + 1)));
    }
    for (let k = swaps.length - 1; k >= 0; k--) {
        const i = n - 1 - k;
        const j = swaps[k];
        [buf[i], buf[j]] = [buf[j], buf[i]];
    }

    // Layer 2: AES-256-GCM decrypt (first 12 bytes = nonce, last 16 bytes = tag)
    const gcmNonce = buf.subarray(0, 12);
    const tagStart = buf.length - 16;
    const ciphertext = buf.subarray(12, tagStart);
    const tag = buf.subarray(tagStart);
    const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, gcmNonce);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    // Layer 1: zlib decompress
    return zlib.inflateSync(decrypted);
}

module.exports = { SwiftAuthClient, SwiftAuthError };
