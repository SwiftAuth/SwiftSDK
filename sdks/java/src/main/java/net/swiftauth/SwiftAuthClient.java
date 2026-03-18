package net.swiftauth;

import java.io.*;
import java.net.*;
import java.net.http.*;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.Inflater;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * SwiftAuth SDK for Java.
 * Full client for authentication, licensing, variables, files, and WebSocket.
 */
public class SwiftAuthClient {

    private final String baseUrl;
    private final String secret;
    private final String version;
    private final String hwid;
    private final HttpClient httpClient;

    private String sessionToken;
    private String nonce;

    private AppInfo app;
    private UserData user;

    private java.net.http.WebSocket ws;
    private final Map<String, List<WsCallback>> wsCallbacks = new ConcurrentHashMap<>();

    @FunctionalInterface
    public interface WsCallback {
        void handle(Map<String, Object> event);
    }

    public SwiftAuthClient(String baseUrl, String appSecret, String appVersion) {
        this(baseUrl, appSecret, appVersion, null);
    }

    public SwiftAuthClient(String baseUrl, String appSecret, String appVersion, String hwid) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.secret = appSecret;
        this.version = appVersion;
        this.hwid = (hwid != null && !hwid.isEmpty()) ? hwid : defaultHwid();
        this.httpClient = HttpClient.newHttpClient();
    }

    public AppInfo getApp() { return app; }
    public UserData getUser() { return user; }
    public String getSessionToken() { return sessionToken; }
    public boolean isInitialized() { return sessionToken != null; }

    // ── Initialization ──────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    public Map<String, Object> init() throws SwiftAuthException {
        Map<String, Object> data = post("/api/client/init", Map.of(
            "secret", secret,
            "version", version,
            "hwid", hwid
        ));
        sessionToken = getString(data, "sessionToken");
        app = new AppInfo(
            getString(data, "appName"),
            getString(data, "appVersion"),
            getBool(data, "antiDebug"),
            getBool(data, "antiVM"),
            getBool(data, "lockHwid"),
            getBool(data, "lockIp"),
            getBool(data, "lockPcName")
        );
        return data;
    }

    private void fetchNonce() throws SwiftAuthException {
        Map<String, Object> data = post("/api/client/nonce", Map.of("sessionToken", sessionToken));
        nonce = getString(data, "nonce");
    }

    // ── Authentication ──────────────────────────────────────────────

    public Map<String, Object> login(String username, String password) throws SwiftAuthException {
        return login(username, password, "", "");
    }

    public Map<String, Object> login(String username, String password, String licenseKey, String pcName) throws SwiftAuthException {
        requireInit();
        fetchNonce();
        Map<String, Object> payload = new HashMap<>();
        payload.put("sessionToken", sessionToken);
        payload.put("username", username);
        payload.put("password", password);
        payload.put("licenseKey", licenseKey);
        payload.put("hwid", hwid);
        payload.put("pcName", pcName);
        Map<String, Object> data = postWithNonce("/api/client/login", payload);
        user = parseUser(data);
        return data;
    }

    public Map<String, Object> register(String username, String password, String email, String displayName, String licenseKey, String pcName) throws SwiftAuthException {
        requireInit();
        fetchNonce();
        Map<String, Object> payload = new HashMap<>();
        payload.put("sessionToken", sessionToken);
        payload.put("username", username);
        payload.put("password", password);
        payload.put("email", email);
        payload.put("displayName", displayName);
        payload.put("licenseKey", licenseKey);
        payload.put("hwid", hwid);
        payload.put("pcName", pcName);
        Map<String, Object> data = postWithNonce("/api/client/register", payload);
        user = parseUser(data);
        return data;
    }

    public Map<String, Object> licenseLogin(String licenseKey) throws SwiftAuthException {
        return licenseLogin(licenseKey, "");
    }

    public Map<String, Object> licenseLogin(String licenseKey, String pcName) throws SwiftAuthException {
        requireInit();
        fetchNonce();
        Map<String, Object> payload = new HashMap<>();
        payload.put("sessionToken", sessionToken);
        payload.put("licenseKey", licenseKey);
        payload.put("hwid", hwid);
        payload.put("pcName", pcName);
        Map<String, Object> data = postWithNonce("/api/client/license", payload);
        user = parseUser(data);
        return data;
    }

    // ── Token Validation ────────────────────────────────────────────

    public Map<String, Object> validateToken(String token) throws SwiftAuthException {
        requireInit();
        return post("/api/client/token", Map.of("sessionToken", sessionToken, "token", token));
    }

    // ── License Activation ──────────────────────────────────────────

    public Map<String, Object> activate(String licenseKey) throws SwiftAuthException {
        requireInit();
        fetchNonce();
        return postWithNonce("/api/client/activate", Map.of("sessionToken", sessionToken, "licenseKey", licenseKey));
    }

    // ── Variables ───────────────────────────────────────────────────

    public Map<String, Object> getVariable(String key) throws SwiftAuthException {
        requireInit();
        return post("/api/client/variable", Map.of("sessionToken", sessionToken, "key", key));
    }

    public Map<String, Object> getAllVariables() throws SwiftAuthException {
        requireInit();
        return post("/api/client/variables", Map.of("sessionToken", sessionToken));
    }

    // ── License Variables ────────────────────────────────────────────

    public Map<String, Object> getLicenseVariable(String key) throws SwiftAuthException {
        requireInit();
        return post("/api/client/license-variable", Map.of("sessionToken", sessionToken, "key", key));
    }

    public Map<String, Object> getAllLicenseVariables() throws SwiftAuthException {
        requireInit();
        return post("/api/client/license-variables", Map.of("sessionToken", sessionToken));
    }

    // ── User Variables ──────────────────────────────────────────────

    public Map<String, Object> getUserVariable(String key) throws SwiftAuthException {
        requireInit();
        return post("/api/client/user-variable", Map.of("sessionToken", sessionToken, "key", key));
    }

    public Map<String, Object> getAllUserVariables() throws SwiftAuthException {
        requireInit();
        return post("/api/client/user-variables", Map.of("sessionToken", sessionToken));
    }

    public Map<String, Object> setUserVariable(String key, String value) throws SwiftAuthException {
        requireInit();
        return post("/api/client/set-user-variable", Map.of("sessionToken", sessionToken, "key", key, "value", value));
    }

    public Map<String, Object> deleteUserVariable(String key) throws SwiftAuthException {
        requireInit();
        return post("/api/client/delete-user-variable", Map.of("sessionToken", sessionToken, "key", key));
    }

    // ── Files ───────────────────────────────────────────────────────

    public byte[] downloadFile(String name) throws SwiftAuthException {
        requireInit();
        String json = toJson(Map.of("sessionToken", sessionToken, "name", name));
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/api/client/file"))
            .header("Content-Type", "application/json")
            .POST(BodyPublishers.ofString(json))
            .build();
        HttpResponse<byte[]> resp;
        try {
            resp = httpClient.send(req, BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new SwiftAuthException("NETWORK_ERROR", "Network request failed: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SwiftAuthException("TIMEOUT", "Request interrupted: " + e.getMessage());
        }
        byte[] data = resp.body();
        if ("1".equals(resp.headers().firstValue("x-file-encrypted").orElse(""))) {
            String nonceHex = resp.headers().firstValue("x-file-nonce").orElse("");
            if (!nonceHex.isEmpty()) {
                data = decryptFileBytes(data, secret, sessionToken, nonceHex);
            }
        }
        return data;
    }

    public Map<String, Object> checkUpdate(String currentVersion, String fileName) throws SwiftAuthException {
        requireInit();
        Map<String, Object> payload = new HashMap<>();
        payload.put("sessionToken", sessionToken);
        payload.put("currentVersion", currentVersion);
        payload.put("fileName", fileName);
        return post("/api/client/check-update", payload);
    }

    // ── Session Management ──────────────────────────────────────────

    public Map<String, Object> heartbeat() throws SwiftAuthException {
        requireInit();
        fetchNonce();
        return postWithNonce("/api/client/heartbeat", Map.of("sessionToken", sessionToken));
    }

    public Map<String, Object> checkSession() throws SwiftAuthException {
        requireInit();
        return post("/api/client/check", Map.of("sessionToken", sessionToken));
    }

    public void endSession() throws SwiftAuthException {
        requireInit();
        post("/api/client/end", Map.of("sessionToken", sessionToken));
        sessionToken = null;
        user = null;
    }

    // ── User Info ───────────────────────────────────────────────────

    public Map<String, Object> getUserInfo() throws SwiftAuthException {
        requireInit();
        return post("/api/client/user", Map.of("sessionToken", sessionToken));
    }

    public void changePassword(String currentPassword, String newPassword) throws SwiftAuthException {
        requireInit();
        post("/api/client/change-password", Map.of(
            "sessionToken", sessionToken,
            "currentPassword", currentPassword,
            "newPassword", newPassword
        ));
    }

    public void requestReset() throws SwiftAuthException {
        requireInit();
        post("/api/client/request-reset", Map.of("sessionToken", sessionToken));
    }

    // ── Client Log ──────────────────────────────────────────────────

    public void log(String message, String level) throws SwiftAuthException {
        requireInit();
        post("/api/client/log", Map.of("sessionToken", sessionToken, "message", message, "level", level));
    }

    // ── WebSocket ───────────────────────────────────────────────────

    public void on(String event, WsCallback callback) {
        wsCallbacks.computeIfAbsent(event, k -> new CopyOnWriteArrayList<>()).add(callback);
    }

    public void connectWs() throws SwiftAuthException {
        requireInit();
        String wsUrl = baseUrl.replace("https://", "wss://").replace("http://", "ws://")
            + "/api/client/ws?token=" + URLEncoder.encode(sessionToken, StandardCharsets.UTF_8);

        CompletableFuture<java.net.http.WebSocket> wsFuture = httpClient.newWebSocketBuilder()
            .buildAsync(URI.create(wsUrl), new java.net.http.WebSocket.Listener() {
                private StringBuilder buffer = new StringBuilder();

                @Override
                public CompletionStage<?> onText(java.net.http.WebSocket webSocket, CharSequence data, boolean last) {
                    buffer.append(data);
                    if (last) {
                        String msg = buffer.toString();
                        buffer = new StringBuilder();
                        try {
                            @SuppressWarnings("unchecked")
                            Map<String, Object> evt = (Map<String, Object>) parseJson(msg);
                            String type = (String) evt.getOrDefault("type", "");
                            fire(type, evt);
                            fire("*", evt);
                        } catch (Exception ignored) {}
                    }
                    webSocket.request(1);
                    return null;
                }

                @Override
                public CompletionStage<?> onClose(java.net.http.WebSocket webSocket, int statusCode, String reason) {
                    fire("close", Map.of("code", statusCode, "reason", reason != null ? reason : ""));
                    return null;
                }

                @Override
                public void onError(java.net.http.WebSocket webSocket, Throwable error) {
                    fire("error", Map.of("error", error.getMessage()));
                }
            });
        try {
            ws = wsFuture.get(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new SwiftAuthException("WS_ERROR", "Failed to connect WebSocket: " + e.getMessage());
        }
    }

    public void wsSend(Map<String, Object> data) {
        if (ws != null) {
            ws.sendText(toJson(data), true);
        }
    }

    public void wsPing() { wsSend(Map.of("type", "ping")); }
    public void wsSetStatus(String status) { wsSend(Map.of("type", "set_status", "status", status)); }
    public void wsSendChat(String message) { wsSend(Map.of("type", "chat", "message", message)); }
    public void wsSetTyping(boolean typing) { wsSend(Map.of("type", "typing", "typing", typing)); }
    public void wsSetMetadata(Map<String, Object> metadata) { wsSend(Map.of("type", "set_metadata", "metadata", metadata)); }

    public void disconnectWs() {
        if (ws != null) {
            ws.sendClose(java.net.http.WebSocket.NORMAL_CLOSURE, "bye");
            ws = null;
        }
    }

    // ── Internal ────────────────────────────────────────────────────

    private void requireInit() throws SwiftAuthException {
        if (sessionToken == null) {
            throw new SwiftAuthException("NOT_INITIALIZED", "Call init() before using other methods.");
        }
    }

    private Map<String, Object> post(String path, Map<String, Object> payload) throws SwiftAuthException {
        return request(path, payload, Map.of());
    }

    private Map<String, Object> postWithNonce(String path, Map<String, Object> payload) throws SwiftAuthException {
        return request(path, payload, Map.of("X-Nonce", nonce));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> request(String path, Map<String, Object> payload, Map<String, String> extraHeaders) throws SwiftAuthException {
        String json = toJson(payload);
        HttpRequest.Builder builder = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .POST(BodyPublishers.ofString(json));
        extraHeaders.forEach(builder::header);

        HttpResponse<String> resp;
        try {
            resp = httpClient.send(builder.build(), BodyHandlers.ofString());
        } catch (IOException e) {
            throw new SwiftAuthException("NETWORK_ERROR", "Network request failed: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SwiftAuthException("TIMEOUT", "Request interrupted: " + e.getMessage());
        }
        Map<String, Object> body;
        try {
            body = (Map<String, Object>) parseJson(resp.body());
        } catch (Exception e) {
            throw new SwiftAuthException("PARSE_ERROR", "Invalid server response");
        }

        Boolean success = (Boolean) body.get("success");
        if (success == null || !success) {
            Map<String, Object> err = (Map<String, Object>) body.getOrDefault("error", Map.of());
            throw new SwiftAuthException(
                (String) err.getOrDefault("code", "UNKNOWN"),
                (String) err.getOrDefault("message", "Request failed")
            );
        }

        Object data = body.get("data");
        if (data instanceof Map) return (Map<String, Object>) data;
        if (data != null) return Map.of("_list", data);
        Object msg = body.get("message");
        if (msg != null) return Map.of("message", msg);
        return Map.of();
    }

    private void fire(String type, Map<String, Object> evt) {
        List<WsCallback> cbs = wsCallbacks.get(type);
        if (cbs != null) {
            for (WsCallback cb : cbs) {
                try { cb.handle(evt); } catch (Exception ignored) {}
            }
        }
    }

    private static String getString(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v != null ? v.toString() : "";
    }

    private static boolean getBool(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v instanceof Boolean && (Boolean) v;
    }

    private static int getInt(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v instanceof Number) return ((Number) v).intValue();
        return 0;
    }

    private static UserData parseUser(Map<String, Object> data) {
        return new UserData(
            getString(data, "key"),
            getString(data, "username"),
            getString(data, "email"),
            getInt(data, "level"),
            getString(data, "expiresAt"),
            data.get("metadata")
        );
    }

    private static String defaultHwid() {
        try {
            String hostname = InetAddress.getLocalHost().getHostName();
            String username = System.getProperty("user.name", "unknown");
            return hostname + "-" + username;
        } catch (Exception e) {
            return "java-" + System.getProperty("user.name", "unknown");
        }
    }

    // ── JSON (minimal, no external deps) ────────────────────────────

    @SuppressWarnings("unchecked")
    private static String toJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : map.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(escapeJson(e.getKey())).append("\":");
            sb.append(valueToJson(e.getValue()));
        }
        sb.append("}");
        return sb.toString();
    }

    private static String valueToJson(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return "\"" + escapeJson((String) v) + "\"";
        if (v instanceof Boolean || v instanceof Number) return v.toString();
        if (v instanceof Map) return toJson((Map<String, Object>) v);
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object item : (List<?>) v) {
                if (!first) sb.append(",");
                first = false;
                sb.append(valueToJson(item));
            }
            sb.append("]");
            return sb.toString();
        }
        return "\"" + escapeJson(v.toString()) + "\"";
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    @SuppressWarnings("unchecked")
    private static Object parseJson(String json) {
        return new JsonParser(json.trim()).parseValue();
    }

    // Minimal JSON parser
    private static class JsonParser {
        private final String s;
        private int pos;

        JsonParser(String s) { this.s = s; this.pos = 0; }

        Object parseValue() {
            skipWhitespace();
            if (pos >= s.length()) return null;
            char c = s.charAt(pos);
            if (c == '{') return parseObject();
            if (c == '[') return parseArray();
            if (c == '"') return parseString();
            if (c == 't' || c == 'f') return parseBoolean();
            if (c == 'n') return parseNull();
            return parseNumber();
        }

        Map<String, Object> parseObject() {
            Map<String, Object> map = new LinkedHashMap<>();
            pos++; // skip {
            skipWhitespace();
            if (pos < s.length() && s.charAt(pos) == '}') { pos++; return map; }
            while (pos < s.length()) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                pos++; // skip :
                Object value = parseValue();
                map.put(key, value);
                skipWhitespace();
                if (pos < s.length() && s.charAt(pos) == ',') { pos++; continue; }
                break;
            }
            if (pos < s.length()) pos++; // skip }
            return map;
        }

        List<Object> parseArray() {
            List<Object> list = new ArrayList<>();
            pos++; // skip [
            skipWhitespace();
            if (pos < s.length() && s.charAt(pos) == ']') { pos++; return list; }
            while (pos < s.length()) {
                list.add(parseValue());
                skipWhitespace();
                if (pos < s.length() && s.charAt(pos) == ',') { pos++; continue; }
                break;
            }
            if (pos < s.length()) pos++; // skip ]
            return list;
        }

        String parseString() {
            pos++; // skip opening "
            StringBuilder sb = new StringBuilder();
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == '\\') {
                    pos++;
                    if (pos < s.length()) {
                        char esc = s.charAt(pos);
                        switch (esc) {
                            case '"': case '\\': case '/': sb.append(esc); break;
                            case 'n': sb.append('\n'); break;
                            case 'r': sb.append('\r'); break;
                            case 't': sb.append('\t'); break;
                            case 'u':
                                sb.append((char) Integer.parseInt(s.substring(pos + 1, pos + 5), 16));
                                pos += 4;
                                break;
                            default: sb.append(esc);
                        }
                    }
                } else if (c == '"') {
                    pos++;
                    return sb.toString();
                } else {
                    sb.append(c);
                }
                pos++;
            }
            return sb.toString();
        }

        Object parseNumber() {
            int start = pos;
            if (pos < s.length() && s.charAt(pos) == '-') pos++;
            while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++;
            boolean isFloat = false;
            if (pos < s.length() && s.charAt(pos) == '.') { isFloat = true; pos++; while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++; }
            if (pos < s.length() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) { isFloat = true; pos++; if (pos < s.length() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) pos++; while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++; }
            String num = s.substring(start, pos);
            if (isFloat) return Double.parseDouble(num);
            long l = Long.parseLong(num);
            if (l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE) return (int) l;
            return l;
        }

        Boolean parseBoolean() {
            if (s.startsWith("true", pos)) { pos += 4; return true; }
            pos += 5; return false;
        }

        Object parseNull() { pos += 4; return null; }

        void skipWhitespace() {
            while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++;
        }
    }

    // ── Multi-Layer File Decryption ─────────────────────────────────

    private static byte[] decryptFileBytes(byte[] data, String appSecret, String sessionToken, String nonceHex) throws SwiftAuthException {
        try {
            byte[] fileNonce = hexToBytes(nonceHex);
            byte[][] keys = deriveKeys(appSecret, sessionToken, fileNonce);
            byte[] aesKey = keys[0], shuffleKey = keys[1], xorKey = keys[2];

            // Layer 4: Rolling XOR
            byte[] buf = data.clone();
            for (int i = 0; i < buf.length; i++) {
                buf[i] ^= xorKey[i % xorKey.length];
            }

            // Layer 3: Fisher-Yates unshuffle
            int n = buf.length;
            SeededRNG rng = new SeededRNG(shuffleKey);
            int[] swaps = new int[n - 1];
            for (int idx = 0, i = n - 1; i > 0; i--, idx++) {
                swaps[idx] = (int) (Long.remainderUnsigned(rng.next(), i + 1));
            }
            for (int k = swaps.length - 1; k >= 0; k--) {
                int i = n - 1 - k;
                int j = swaps[k];
                byte tmp = buf[i]; buf[i] = buf[j]; buf[j] = tmp;
            }

            // Layer 2: AES-256-GCM
            byte[] gcmNonce = Arrays.copyOfRange(buf, 0, 12);
            byte[] ciphertextAndTag = Arrays.copyOfRange(buf, 12, buf.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, gcmNonce));
            byte[] plaintext = cipher.doFinal(ciphertextAndTag);

            // Layer 1: zlib decompress
            Inflater inflater = new Inflater();
            inflater.setInput(plaintext);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] tmp = new byte[4096];
            while (!inflater.finished()) {
                int count = inflater.inflate(tmp);
                out.write(tmp, 0, count);
            }
            inflater.end();
            return out.toByteArray();
        } catch (SwiftAuthException e) {
            throw e;
        } catch (Exception e) {
            throw new SwiftAuthException("DECRYPT_ERROR", "Failed to decrypt file: " + e.getMessage());
        }
    }

    private static byte[][] deriveKeys(String appSecret, String sessionToken, byte[] nonce) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(appSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] master = mac.doFinal((sessionToken + "|" + bytesToHex(nonce)).getBytes(StandardCharsets.UTF_8));

        byte[][] keys = new byte[3][];
        for (int i = 0; i < 3; i++) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(master);
            md.update((byte) (i + 1));
            keys[i] = md.digest();
        }
        return keys;
    }

    private static class SeededRNG {
        private long state;

        SeededRNG(byte[] key) {
            state = 0;
            if (key.length >= 8) {
                ByteBuffer bb = ByteBuffer.wrap(key, 0, 8).order(ByteOrder.LITTLE_ENDIAN);
                state = bb.getLong();
            }
            for (int i = 8; i < key.length; i++) {
                state ^= (long) (key[i] & 0xFF) << ((i % 8) * 8);
                state = state * 6364136223846793005L + 1442695040888963407L;
            }
            if (state == 0) state = 0xDEADBEEFCAFE1234L;
        }

        long next() {
            state = state * 6364136223846793005L + 1442695040888963407L;
            return state;
        }
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // ── Data Classes ────────────────────────────────────────────────

    public record AppInfo(String name, String version, boolean antiDebug, boolean antiVM, boolean lockHwid, boolean lockIp, boolean lockPcName) {}
    public record UserData(String key, String username, String email, int level, String expiresAt, Object metadata) {}
}
