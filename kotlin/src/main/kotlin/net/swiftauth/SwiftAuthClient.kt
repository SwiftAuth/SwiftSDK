package net.swiftauth

import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.zip.Inflater
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class SwiftAuthException(val code: String, message: String) : Exception("[$code] $message")

data class AppInfo(
    val name: String,
    val version: String,
    val antiDebug: Boolean,
    val antiVM: Boolean,
    val lockHwid: Boolean,
    val lockIp: Boolean,
    val lockPcName: Boolean,
)

data class UserData(
    val key: String,
    val username: String,
    val email: String,
    val level: Int,
    val expiresAt: String?,
    val metadata: Any?,
    val avatarUrl: String? = null,
    val discordId: String? = null,
)

data class Variable(val key: String, val value: String, val type: String)
data class UserVariable(val key: String, val value: String)

class SwiftAuthClient(
    baseUrl: String,
    private val secret: String,
    private val version: String,
    hwid: String? = null,
) {
    private val baseUrl = baseUrl.trimEnd('/')
    private val hwid = hwid ?: defaultHwid()
    private val httpClient = HttpClient.newHttpClient()

    private var sessionToken: String? = null
    private var nonce: String? = null

    var app: AppInfo? = null
        private set
    var user: UserData? = null
        private set

    private val wsCallbacks = ConcurrentHashMap<String, CopyOnWriteArrayList<(Map<String, Any?>) -> Unit>>()
    private var ws: java.net.http.WebSocket? = null

    fun getSessionToken(): String? = sessionToken
    fun isInitialized(): Boolean = sessionToken != null

    // ── Initialization ──────────────────────────────────────────────

    fun init(): Map<String, Any?> {
        val data = post("/api/client/init", mapOf(
            "secret" to secret,
            "version" to version,
            "hwid" to hwid,
        ))
        sessionToken = data.str("sessionToken")
        app = AppInfo(
            name = data.str("appName"),
            version = data.str("appVersion"),
            antiDebug = data.bool("antiDebug"),
            antiVM = data.bool("antiVM"),
            lockHwid = data.bool("lockHwid"),
            lockIp = data.bool("lockIp"),
            lockPcName = data.bool("lockPcName"),
        )
        return data
    }

    private fun fetchNonce() {
        val data = post("/api/client/nonce", mapOf("sessionToken" to sessionToken))
        nonce = data.str("nonce")
    }

    // ── Authentication ──────────────────────────────────────────────

    fun login(username: String, password: String, licenseKey: String = "", pcName: String = ""): Map<String, Any?> {
        requireInit()
        fetchNonce()
        val data = postWithNonce("/api/client/login", mapOf(
            "sessionToken" to sessionToken,
            "username" to username,
            "password" to password,
            "licenseKey" to licenseKey,
            "hwid" to hwid,
            "pcName" to pcName,
        ))
        user = parseUser(data)
        return data
    }

    fun register(username: String, password: String, email: String = "", displayName: String = "", licenseKey: String = "", pcName: String = ""): Map<String, Any?> {
        requireInit()
        fetchNonce()
        val data = postWithNonce("/api/client/register", mapOf(
            "sessionToken" to sessionToken,
            "username" to username,
            "password" to password,
            "email" to email,
            "displayName" to displayName,
            "licenseKey" to licenseKey,
            "hwid" to hwid,
            "pcName" to pcName,
        ))
        user = parseUser(data)
        return data
    }

    fun licenseLogin(licenseKey: String, pcName: String = ""): Map<String, Any?> {
        requireInit()
        fetchNonce()
        val data = postWithNonce("/api/client/license", mapOf(
            "sessionToken" to sessionToken,
            "licenseKey" to licenseKey,
            "hwid" to hwid,
            "pcName" to pcName,
        ))
        user = parseUser(data)
        return data
    }

    // ── Token Validation ────────────────────────────────────────────

    fun validateToken(token: String): Map<String, Any?> {
        requireInit()
        return post("/api/client/token", mapOf("sessionToken" to sessionToken, "token" to token))
    }

    // ── License Activation ──────────────────────────────────────────

    fun activate(licenseKey: String): Map<String, Any?> {
        requireInit()
        fetchNonce()
        return postWithNonce("/api/client/activate", mapOf("sessionToken" to sessionToken, "licenseKey" to licenseKey))
    }

    // ── Variables ───────────────────────────────────────────────────

    fun getVariable(key: String): Variable {
        requireInit()
        val data = post("/api/client/variable", mapOf("sessionToken" to sessionToken, "key" to key))
        return Variable(key = data.str("key"), value = data.str("value"), type = data.str("type").ifEmpty { "STRING" })
    }

    @Suppress("UNCHECKED_CAST")
    fun getAllVariables(): List<Variable> {
        requireInit()
        val data = post("/api/client/variables", mapOf("sessionToken" to sessionToken))
        val list = data["_list"] as? List<Map<String, Any?>> ?: return emptyList()
        return list.map { Variable(key = it.str("key"), value = it.str("value"), type = (it.str("type")).ifEmpty { "STRING" }) }
    }

    // ── License Variables ────────────────────────────────────────────

    fun getLicenseVariable(key: String): Variable {
        requireInit()
        val data = post("/api/client/license-variable", mapOf("sessionToken" to sessionToken, "key" to key))
        return Variable(key = data.str("key"), value = data.str("value"), type = data.str("type").ifEmpty { "STRING" })
    }

    @Suppress("UNCHECKED_CAST")
    fun getAllLicenseVariables(): List<Variable> {
        requireInit()
        val data = post("/api/client/license-variables", mapOf("sessionToken" to sessionToken))
        val list = data["_list"] as? List<Map<String, Any?>> ?: return emptyList()
        return list.map { Variable(key = it.str("key"), value = it.str("value"), type = (it.str("type")).ifEmpty { "STRING" }) }
    }

    // ── User Variables ──────────────────────────────────────────────

    fun getUserVariable(key: String): UserVariable {
        requireInit()
        val data = post("/api/client/user-variable", mapOf("sessionToken" to sessionToken, "key" to key))
        return UserVariable(key = data.str("key"), value = data.str("value"))
    }

    @Suppress("UNCHECKED_CAST")
    fun getAllUserVariables(): List<UserVariable> {
        requireInit()
        val data = post("/api/client/user-variables", mapOf("sessionToken" to sessionToken))
        val list = data["_list"] as? List<Map<String, Any?>> ?: return emptyList()
        return list.map { UserVariable(key = it.str("key"), value = it.str("value")) }
    }

    fun setUserVariable(key: String, value: String): UserVariable {
        requireInit()
        val data = post("/api/client/set-user-variable", mapOf("sessionToken" to sessionToken, "key" to key, "value" to value))
        return UserVariable(key = data.str("key"), value = data.str("value"))
    }

    fun deleteUserVariable(key: String) {
        requireInit()
        post("/api/client/delete-user-variable", mapOf("sessionToken" to sessionToken, "key" to key))
    }

    // ── Files ───────────────────────────────────────────────────────

    fun downloadFile(name: String): ByteArray {
        requireInit()
        val json = toJson(mapOf("sessionToken" to sessionToken, "name" to name))
        val req = HttpRequest.newBuilder()
            .uri(URI.create("$baseUrl/api/client/file"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .build()
        val resp = httpClient.send(req, HttpResponse.BodyHandlers.ofByteArray())
        var data = resp.body()

        if (resp.headers().firstValue("x-file-encrypted").orElse("") == "1") {
            val nonceHex = resp.headers().firstValue("x-file-nonce").orElse("")
            if (nonceHex.isNotEmpty()) {
                data = decryptFileBytes(data, secret, sessionToken!!, nonceHex)
            }
        }
        return data
    }

    fun checkUpdate(currentVersion: String, fileName: String = ""): Map<String, Any?> {
        requireInit()
        return post("/api/client/check-update", mapOf(
            "sessionToken" to sessionToken,
            "currentVersion" to currentVersion,
            "fileName" to fileName,
        ))
    }

    // ── Session Management ──────────────────────────────────────────

    fun heartbeat(): Map<String, Any?> {
        requireInit()
        fetchNonce()
        return postWithNonce("/api/client/heartbeat", mapOf("sessionToken" to sessionToken))
    }

    fun checkSession(): Map<String, Any?> {
        requireInit()
        return post("/api/client/check", mapOf("sessionToken" to sessionToken))
    }

    fun endSession() {
        requireInit()
        post("/api/client/end", mapOf("sessionToken" to sessionToken))
        sessionToken = null
        user = null
    }

    // ── User Info ───────────────────────────────────────────────────

    fun getUser(): Map<String, Any?> {
        requireInit()
        val data = post("/api/client/user", mapOf("sessionToken" to sessionToken))
        user = parseUser(data)
        return data
    }

    fun changePassword(currentPassword: String, newPassword: String) {
        requireInit()
        post("/api/client/change-password", mapOf(
            "sessionToken" to sessionToken,
            "currentPassword" to currentPassword,
            "newPassword" to newPassword,
        ))
    }

    fun requestReset() {
        requireInit()
        post("/api/client/request-reset", mapOf("sessionToken" to sessionToken))
    }

    // ── Client Log ──────────────────────────────────────────────────

    fun log(message: String, level: String = "INFO") {
        requireInit()
        post("/api/client/log", mapOf("sessionToken" to sessionToken, "message" to message, "level" to level))
    }

    // ── WebSocket ───────────────────────────────────────────────────

    fun on(event: String, callback: (Map<String, Any?>) -> Unit) {
        wsCallbacks.computeIfAbsent(event) { CopyOnWriteArrayList() }.add(callback)
    }

    @Suppress("UNCHECKED_CAST")
    fun connectWs() {
        requireInit()
        val wsUrl = baseUrl.replace("https://", "wss://").replace("http://", "ws://") +
            "/api/client/ws?token=" + URLEncoder.encode(sessionToken, StandardCharsets.UTF_8)

        val future = httpClient.newWebSocketBuilder()
            .buildAsync(URI.create(wsUrl), object : java.net.http.WebSocket.Listener {
                private val buffer = StringBuilder()

                override fun onText(webSocket: java.net.http.WebSocket, data: CharSequence, last: Boolean): java.util.concurrent.CompletionStage<*>? {
                    buffer.append(data)
                    if (last) {
                        val msg = buffer.toString()
                        buffer.clear()
                        try {
                            val evt = parseJson(msg) as Map<String, Any?>
                            val type = evt["type"] as? String ?: ""
                            fire(type, evt)
                            fire("*", evt)
                        } catch (_: Exception) {}
                    }
                    webSocket.request(1)
                    return null
                }

                override fun onClose(webSocket: java.net.http.WebSocket, statusCode: Int, reason: String?): java.util.concurrent.CompletionStage<*>? {
                    fire("close", mapOf("code" to statusCode, "reason" to (reason ?: "")))
                    return null
                }

                override fun onError(webSocket: java.net.http.WebSocket, error: Throwable) {
                    fire("error", mapOf("error" to error.message))
                }
            })

        ws = future.get(10, TimeUnit.SECONDS)
    }

    fun wsSend(data: Map<String, Any?>) {
        ws?.sendText(toJson(data), true)
    }

    fun wsPing() = wsSend(mapOf("type" to "ping"))
    fun wsSetStatus(status: String) = wsSend(mapOf("type" to "set_status", "status" to status))
    fun wsSendChat(message: String) = wsSend(mapOf("type" to "chat", "message" to message))
    fun wsSetTyping(typing: Boolean) = wsSend(mapOf("type" to "typing", "typing" to typing))
    fun wsSetMetadata(metadata: Map<String, Any>) = wsSend(mapOf("type" to "set_metadata", "metadata" to metadata))

    fun disconnectWs() {
        ws?.sendClose(java.net.http.WebSocket.NORMAL_CLOSURE, "bye")
        ws = null
    }

    // ── Internal ────────────────────────────────────────────────────

    private fun requireInit() {
        if (sessionToken == null) throw SwiftAuthException("NOT_INITIALIZED", "Call init() before using other methods.")
    }

    private fun post(path: String, payload: Map<String, Any?>): Map<String, Any?> = request(path, payload, emptyMap())

    private fun postWithNonce(path: String, payload: Map<String, Any?>): Map<String, Any?> =
        request(path, payload, mapOf("X-Nonce" to (nonce ?: "")))

    @Suppress("UNCHECKED_CAST")
    private fun request(path: String, payload: Map<String, Any?>, extraHeaders: Map<String, String>): Map<String, Any?> {
        val json = toJson(payload)
        val builder = HttpRequest.newBuilder()
            .uri(URI.create("$baseUrl$path"))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json))
        extraHeaders.forEach { (k, v) -> builder.header(k, v) }

        val resp = try {
            httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString())
        } catch (e: java.io.IOException) {
            throw SwiftAuthException("NETWORK_ERROR", "Network request failed: ${e.message}")
        } catch (e: InterruptedException) {
            throw SwiftAuthException("TIMEOUT", "Request interrupted: ${e.message}")
        }
        val body = try {
            parseJson(resp.body()) as? Map<String, Any?>
        } catch (e: Exception) {
            null
        } ?: throw SwiftAuthException("PARSE_ERROR", "Invalid server response")

        val success = body["success"] as? Boolean ?: false
        if (!success) {
            val err = body["error"] as? Map<String, Any?> ?: emptyMap()
            throw SwiftAuthException(
                err["code"] as? String ?: "UNKNOWN",
                err["message"] as? String ?: "Request failed",
            )
        }

        return when (val data = body["data"]) {
            is Map<*, *> -> data as Map<String, Any?>
            is List<*> -> mapOf("_list" to data)
            null -> body["message"]?.let { mapOf("message" to it) } ?: emptyMap()
            else -> mapOf("_list" to data)
        }
    }

    private fun fire(type: String, evt: Map<String, Any?>) {
        wsCallbacks[type]?.forEach { cb -> try { cb(evt) } catch (_: Exception) {} }
    }

    private fun parseUser(data: Map<String, Any?>) = UserData(
        key = data.str("key"),
        username = data.str("username"),
        email = data.str("email"),
        level = (data["level"] as? Number)?.toInt() ?: 0,
        expiresAt = data["expiresAt"] as? String,
        metadata = data["metadata"],
        avatarUrl = data["avatarUrl"] as? String,
        discordId = data["discordId"] as? String,
    )

    companion object {
        private fun defaultHwid(): String {
            val hostname = try { InetAddress.getLocalHost().hostName } catch (_: Exception) { "unknown" }
            val username = System.getProperty("user.name", "unknown")
            return "$hostname-$username"
        }

        private fun Map<String, Any?>.str(key: String): String = (this[key] as? String) ?: ""
        private fun Map<String, Any?>.bool(key: String): Boolean = (this[key] as? Boolean) ?: false

        // ── Minimal JSON ────────────────────────────────────────────

        fun toJson(obj: Any?): String = when (obj) {
            null -> "null"
            is String -> "\"${obj.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r")}\""
            is Number, is Boolean -> obj.toString()
            is Map<*, *> -> obj.entries.joinToString(",", "{", "}") { (k, v) -> "\"$k\":${toJson(v)}" }
            is List<*> -> obj.joinToString(",", "[", "]") { toJson(it) }
            else -> "\"$obj\""
        }

        @Suppress("UNCHECKED_CAST")
        fun parseJson(json: String): Any? {
            val parser = JsonParser(json.trim())
            return parser.parseValue()
        }

        private class JsonParser(private val s: String) {
            private var pos = 0

            fun parseValue(): Any? {
                skipWs()
                if (pos >= s.length) return null
                return when (s[pos]) {
                    '{' -> parseObject()
                    '[' -> parseArray()
                    '"' -> parseString()
                    't', 'f' -> parseBool()
                    'n' -> parseNull()
                    else -> parseNumber()
                }
            }

            private fun parseObject(): Map<String, Any?> {
                pos++ // {
                skipWs()
                val map = LinkedHashMap<String, Any?>()
                if (pos < s.length && s[pos] == '}') { pos++; return map }
                while (pos < s.length) {
                    skipWs()
                    val key = parseString()
                    skipWs(); pos++ // :
                    map[key] = parseValue()
                    skipWs()
                    if (pos < s.length && s[pos] == ',') { pos++; continue }
                    break
                }
                if (pos < s.length) pos++ // }
                return map
            }

            private fun parseArray(): List<Any?> {
                pos++ // [
                skipWs()
                val list = mutableListOf<Any?>()
                if (pos < s.length && s[pos] == ']') { pos++; return list }
                while (pos < s.length) {
                    list.add(parseValue())
                    skipWs()
                    if (pos < s.length && s[pos] == ',') { pos++; continue }
                    break
                }
                if (pos < s.length) pos++ // ]
                return list
            }

            private fun parseString(): String {
                pos++ // "
                val sb = StringBuilder()
                while (pos < s.length) {
                    val c = s[pos]
                    if (c == '\\') {
                        pos++
                        if (pos < s.length) {
                            when (s[pos]) {
                                '"', '\\', '/' -> sb.append(s[pos])
                                'n' -> sb.append('\n')
                                'r' -> sb.append('\r')
                                't' -> sb.append('\t')
                                'u' -> { sb.append(s.substring(pos + 1, pos + 5).toInt(16).toChar()); pos += 4 }
                                else -> sb.append(s[pos])
                            }
                        }
                    } else if (c == '"') { pos++; return sb.toString() }
                    else sb.append(c)
                    pos++
                }
                return sb.toString()
            }

            private fun parseNumber(): Number {
                val start = pos
                if (pos < s.length && s[pos] == '-') pos++
                while (pos < s.length && s[pos].isDigit()) pos++
                var isFloat = false
                if (pos < s.length && s[pos] == '.') { isFloat = true; pos++; while (pos < s.length && s[pos].isDigit()) pos++ }
                if (pos < s.length && (s[pos] == 'e' || s[pos] == 'E')) { isFloat = true; pos++; if (pos < s.length && (s[pos] == '+' || s[pos] == '-')) pos++; while (pos < s.length && s[pos].isDigit()) pos++ }
                val num = s.substring(start, pos)
                return if (isFloat) num.toDouble() else num.toLong().let { if (it in Int.MIN_VALUE..Int.MAX_VALUE) it.toInt() else it }
            }

            private fun parseBool(): Boolean {
                if (s.startsWith("true", pos)) { pos += 4; return true }
                pos += 5; return false
            }

            private fun parseNull(): Nothing? { pos += 4; return null }
            private fun skipWs() { while (pos < s.length && s[pos].isWhitespace()) pos++ }
        }

        // ── Multi-Layer File Decryption ─────────────────────────────

        private fun decryptFileBytes(data: ByteArray, appSecret: String, sessionToken: String, nonceHex: String): ByteArray {
            val nonce = hexToBytes(nonceHex)
            val (aesKey, shuffleKey, xorKey) = deriveKeys(appSecret, sessionToken, nonce)

            // Layer 4: Rolling XOR
            val buf = data.copyOf()
            for (i in buf.indices) buf[i] = (buf[i].toInt() xor xorKey[i % xorKey.size].toInt()).toByte()

            // Layer 3: Fisher-Yates unshuffle
            val n = buf.size
            val rng = SeededRNG(shuffleKey)
            val swaps = IntArray(n - 1)
            var idx = 0
            for (i in n - 1 downTo 1) {
                swaps[idx++] = (java.lang.Long.remainderUnsigned(rng.next(), (i + 1).toLong())).toInt()
            }
            for (k in swaps.indices.reversed()) {
                val i = n - 1 - k
                val j = swaps[k]
                val tmp = buf[i]; buf[i] = buf[j]; buf[j] = tmp
            }

            // Layer 2: AES-256-GCM
            val gcmNonce = buf.sliceArray(0 until 12)
            val ciphertextAndTag = buf.sliceArray(12 until buf.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(aesKey, "AES"), GCMParameterSpec(128, gcmNonce))
            val plaintext = cipher.doFinal(ciphertextAndTag)

            // Layer 1: zlib decompress
            val inflater = Inflater()
            inflater.setInput(plaintext)
            val out = ByteArrayOutputStream()
            val tmp = ByteArray(4096)
            while (!inflater.finished()) {
                val count = inflater.inflate(tmp)
                out.write(tmp, 0, count)
            }
            inflater.end()
            return out.toByteArray()
        }

        private fun deriveKeys(appSecret: String, sessionToken: String, nonce: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(appSecret.toByteArray(), "HmacSHA256"))
            val master = mac.doFinal("$sessionToken|${bytesToHex(nonce)}".toByteArray())

            fun sub(layer: Int): ByteArray {
                val md = MessageDigest.getInstance("SHA-256")
                md.update(master)
                md.update(layer.toByte())
                return md.digest()
            }

            return Triple(sub(0x01), sub(0x02), sub(0x03))
        }

        private class SeededRNG(key: ByteArray) {
            private var state: Long

            init {
                var s: Long = 0
                if (key.size >= 8) {
                    s = ByteBuffer.wrap(key, 0, 8).order(ByteOrder.LITTLE_ENDIAN).long
                }
                for (i in 8 until key.size) {
                    s = s xor ((key[i].toLong() and 0xFF) shl ((i % 8) * 8))
                    s = s * 6364136223846793005L + 1442695040888963407L
                }
                if (s == 0L) s = 0xDEADBEEFCAFE1234u.toLong()
                state = s
            }

            fun next(): Long {
                state = state * 6364136223846793005L + 1442695040888963407L
                return state
            }
        }

        private fun hexToBytes(hex: String): ByteArray {
            val len = hex.length
            val data = ByteArray(len / 2)
            for (i in 0 until len step 2) {
                data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
            }
            return data
        }

        private fun bytesToHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
    }
}
