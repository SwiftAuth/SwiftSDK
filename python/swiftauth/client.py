import hashlib
import hmac as _hmac
import json
import platform
import struct
import threading
import zlib
from typing import Callable, Optional

import requests
import websocket

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from swiftauth.models import (
    AppInfo,
    UpdateCheckResult,
    UserData,
    UserVariableData,
    VariableData,
)


class SwiftAuthError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


class SwiftAuthClient:
    def __init__(
        self,
        base_url: str,
        app_secret: str,
        app_version: str = "1.0.0",
        hwid: str = "",
    ):
        self._base_url = base_url.rstrip("/")
        self._secret = app_secret
        self._version = app_version
        self._hwid = hwid or self._default_hwid()
        self._session_token: Optional[str] = None
        self._nonce: Optional[str] = None
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})

        self.app: Optional[AppInfo] = None
        self.user: Optional[UserData] = None

        self._ws: Optional[websocket.WebSocketApp] = None
        self._ws_thread: Optional[threading.Thread] = None
        self._ws_callbacks: dict[str, list[Callable]] = {}

    @property
    def session_token(self) -> Optional[str]:
        return self._session_token

    @property
    def is_initialized(self) -> bool:
        return self._session_token is not None

    # ── Initialization ──────────────────────────────────────────────

    def init(self) -> dict:
        data = self._post("/api/client/init", {
            "secret": self._secret,
            "version": self._version,
            "hwid": self._hwid,
        })
        self._session_token = data["sessionToken"]
        self.app = AppInfo(
            name=data.get("appName", ""),
            version=data.get("appVersion", ""),
            anti_debug=data.get("antiDebug", False),
            anti_vm=data.get("antiVM", False),
            lock_hwid=data.get("lockHwid", False),
            lock_ip=data.get("lockIp", False),
            lock_pc_name=data.get("lockPcName", False),
        )
        return data

    # ── Nonce ───────────────────────────────────────────────────────

    def _fetch_nonce(self) -> str:
        data = self._post("/api/client/nonce", {"sessionToken": self._session_token})
        self._nonce = data["nonce"]
        return self._nonce

    # ── Authentication ──────────────────────────────────────────────

    def login(
        self,
        username: str,
        password: str,
        license_key: str = "",
        pc_name: str = "",
    ) -> dict:
        self._require_init()
        self._fetch_nonce()
        data = self._post_with_nonce("/api/client/login", {
            "sessionToken": self._session_token,
            "username": username,
            "password": password,
            "licenseKey": license_key,
            "hwid": self._hwid,
            "pcName": pc_name,
        })
        self.user = UserData(
            key=data.get("key", ""),
            username=data.get("username", ""),
            email=data.get("email", ""),
            level=data.get("level", 0),
            expires_at=data.get("expiresAt"),
            metadata=data.get("metadata"),
        )
        return data

    def register(
        self,
        username: str,
        password: str,
        email: str = "",
        display_name: str = "",
        license_key: str = "",
        pc_name: str = "",
    ) -> dict:
        self._require_init()
        self._fetch_nonce()
        data = self._post_with_nonce("/api/client/register", {
            "sessionToken": self._session_token,
            "username": username,
            "password": password,
            "email": email,
            "displayName": display_name,
            "licenseKey": license_key,
            "hwid": self._hwid,
            "pcName": pc_name,
        })
        self.user = UserData(
            key=data.get("key", ""),
            username=data.get("username", ""),
            email=data.get("email", ""),
            level=data.get("level", 0),
            expires_at=data.get("expiresAt"),
        )
        return data

    def license_login(self, license_key: str, pc_name: str = "") -> dict:
        self._require_init()
        self._fetch_nonce()
        data = self._post_with_nonce("/api/client/license", {
            "sessionToken": self._session_token,
            "licenseKey": license_key,
            "hwid": self._hwid,
            "pcName": pc_name,
        })
        self.user = UserData(
            key=data.get("key", ""),
            username=data.get("username", ""),
            level=data.get("level", 0),
            expires_at=data.get("expiresAt"),
        )
        return data

    # ── Token Validation ────────────────────────────────────────────

    def validate_token(self, token: str) -> dict:
        self._require_init()
        return self._post("/api/client/token", {
            "sessionToken": self._session_token,
            "token": token,
        })

    # ── License Activation ──────────────────────────────────────────

    def activate(self, license_key: str) -> dict:
        self._require_init()
        self._fetch_nonce()
        return self._post_with_nonce("/api/client/activate", {
            "sessionToken": self._session_token,
            "licenseKey": license_key,
        })

    # ── License Check ────────────────────────────────────────────────

    def check_license(self, license_key: str) -> dict:
        """Check if a license key is valid/banned/expired without activating it."""
        self._require_init()
        return self._post("/api/client/check-license", {
            "sessionToken": self._session_token,
            "licenseKey": license_key,
        })

    # ── Variables ───────────────────────────────────────────────────

    def get_variable(self, key: str) -> VariableData:
        self._require_init()
        data = self._post("/api/client/variable", {
            "sessionToken": self._session_token,
            "key": key,
        })
        return VariableData(key=data["key"], value=data["value"], type=data.get("type", "STRING"))

    def get_all_variables(self) -> list[VariableData]:
        self._require_init()
        data = self._post("/api/client/variables", {"sessionToken": self._session_token})
        if isinstance(data, list):
            return [VariableData(key=v["key"], value=v["value"], type=v.get("type", "STRING")) for v in data]
        return []

    # ── License Variables ────────────────────────────────────────────

    def get_license_variable(self, key: str) -> VariableData:
        self._require_init()
        data = self._post("/api/client/license-variable", {
            "sessionToken": self._session_token,
            "key": key,
        })
        return VariableData(key=data["key"], value=data["value"], type=data.get("type", "STRING"))

    def get_all_license_variables(self) -> list[VariableData]:
        self._require_init()
        data = self._post("/api/client/license-variables", {"sessionToken": self._session_token})
        if isinstance(data, list):
            return [VariableData(key=v["key"], value=v["value"], type=v.get("type", "STRING")) for v in data]
        return []

    # ── User Variables ──────────────────────────────────────────────

    def get_user_variable(self, key: str) -> UserVariableData:
        self._require_init()
        data = self._post("/api/client/user-variable", {
            "sessionToken": self._session_token,
            "key": key,
        })
        return UserVariableData(key=data["key"], value=data["value"])

    def get_all_user_variables(self) -> list[UserVariableData]:
        self._require_init()
        data = self._post("/api/client/user-variables", {"sessionToken": self._session_token})
        if isinstance(data, list):
            return [UserVariableData(key=v["key"], value=v["value"]) for v in data]
        return []

    def set_user_variable(self, key: str, value: str) -> UserVariableData:
        self._require_init()
        data = self._post("/api/client/set-user-variable", {
            "sessionToken": self._session_token,
            "key": key,
            "value": value,
        })
        return UserVariableData(key=data["key"], value=data["value"])

    def delete_user_variable(self, key: str) -> None:
        self._require_init()
        self._post("/api/client/delete-user-variable", {
            "sessionToken": self._session_token,
            "key": key,
        })

    # ── Files ───────────────────────────────────────────────────────

    def download_file(self, name: str) -> bytes:
        self._require_init()
        try:
            resp = self._session.post(
                f"{self._base_url}/api/client/file",
                json={"sessionToken": self._session_token, "name": name},
            )
        except requests.RequestException as e:
            raise SwiftAuthError("NETWORK_ERROR", f"Network request failed: {e}")
        encrypted_bytes = resp.content

        # Decrypt if server sent encrypted response
        if resp.headers.get("X-File-Encrypted") == "1":
            nonce_hex = resp.headers.get("X-File-Nonce", "")
            if nonce_hex:
                encrypted_bytes = _decrypt_file_bytes(
                    encrypted_bytes, self._secret, self._session_token, nonce_hex
                )

        return encrypted_bytes

    def check_update(self, current_version: str, file_name: str = "") -> UpdateCheckResult:
        self._require_init()
        data = self._post("/api/client/check-update", {
            "sessionToken": self._session_token,
            "currentVersion": current_version,
            "fileName": file_name,
        })
        return UpdateCheckResult(
            update_available=data.get("updateAvailable", False),
            latest_version=data.get("latestVersion", ""),
            current_version=data.get("currentVersion", ""),
            file=data.get("file"),
        )

    # ── Session Management ──────────────────────────────────────────

    def heartbeat(self) -> dict:
        self._require_init()
        self._fetch_nonce()
        return self._post_with_nonce("/api/client/heartbeat", {
            "sessionToken": self._session_token,
        })

    def check_session(self) -> dict:
        self._require_init()
        return self._post("/api/client/check", {"sessionToken": self._session_token})

    def end_session(self) -> None:
        self._require_init()
        self._post("/api/client/end", {"sessionToken": self._session_token})
        self._session_token = None
        self.user = None

    # ── User Info ───────────────────────────────────────────────────

    def get_user(self) -> dict:
        self._require_init()
        data = self._post("/api/client/user", {"sessionToken": self._session_token})
        self.user = UserData(
            key=data.get("key", ""),
            username=data.get("username", ""),
            email=data.get("email", ""),
            level=data.get("level", 0),
            expires_at=data.get("expiresAt"),
            metadata=data.get("metadata"),
            avatar_url=data.get("avatarUrl"),
            discord_id=data.get("discordId"),
        )
        return data

    def change_password(self, current_password: str, new_password: str) -> None:
        self._require_init()
        self._post("/api/client/change-password", {
            "sessionToken": self._session_token,
            "currentPassword": current_password,
            "newPassword": new_password,
        })

    def request_reset(self) -> None:
        self._require_init()
        self._post("/api/client/request-reset", {"sessionToken": self._session_token})

    # ── Client Log ──────────────────────────────────────────────────

    def log(self, message: str, level: str = "INFO") -> None:
        self._require_init()
        self._post("/api/client/log", {
            "sessionToken": self._session_token,
            "message": message,
            "level": level,
        })

    # ── WebSocket ───────────────────────────────────────────────────

    def on(self, event: str, callback: Callable) -> None:
        self._ws_callbacks.setdefault(event, []).append(callback)

    def connect_ws(self) -> None:
        self._require_init()
        ws_url = self._base_url.replace("https://", "wss://").replace("http://", "ws://")
        ws_url += f"/api/client/ws?token={self._session_token}"

        def on_message(ws, msg):
            try:
                evt = json.loads(msg)
                event_type = evt.get("type", "")
                for cb in self._ws_callbacks.get(event_type, []):
                    cb(evt)
                for cb in self._ws_callbacks.get("*", []):
                    cb(evt)
            except json.JSONDecodeError:
                pass

        def on_error(ws, error):
            for cb in self._ws_callbacks.get("error", []):
                cb(str(error))

        def on_close(ws, code, reason):
            for cb in self._ws_callbacks.get("close", []):
                cb(code, reason)

        self._ws = websocket.WebSocketApp(
            ws_url,
            on_message=on_message,
            on_error=on_error,
            on_close=on_close,
        )
        self._ws_thread = threading.Thread(target=self._ws.run_forever, daemon=True)
        self._ws_thread.start()

    def ws_send(self, data: dict) -> None:
        if self._ws:
            self._ws.send(json.dumps(data))

    def ws_ping(self) -> None:
        self.ws_send({"type": "ping"})

    def ws_set_status(self, status: str) -> None:
        self.ws_send({"type": "set_status", "status": status})

    def ws_send_chat(self, message: str) -> None:
        self.ws_send({"type": "chat", "message": message})

    def ws_set_typing(self, typing: bool) -> None:
        self.ws_send({"type": "typing", "typing": typing})

    def ws_set_metadata(self, metadata: dict) -> None:
        self.ws_send({"type": "set_metadata", "metadata": metadata})

    def disconnect_ws(self) -> None:
        if self._ws:
            self._ws.close()
            self._ws = None

    # ── Internal ────────────────────────────────────────────────────

    def _require_init(self) -> None:
        if not self._session_token:
            raise SwiftAuthError("NOT_INITIALIZED", "Call init() before using other methods.")

    def _post(self, path: str, payload: dict) -> dict:
        try:
            resp = self._session.post(f"{self._base_url}{path}", json=payload)
        except requests.RequestException as e:
            raise SwiftAuthError("NETWORK_ERROR", f"Network request failed: {e}")
        return self._handle_response(resp)

    def _post_with_nonce(self, path: str, payload: dict) -> dict:
        try:
            resp = self._session.post(
                f"{self._base_url}{path}",
                json=payload,
                headers={"X-Nonce": self._nonce},
            )
        except requests.RequestException as e:
            raise SwiftAuthError("NETWORK_ERROR", f"Network request failed: {e}")
        return self._handle_response(resp)

    @staticmethod
    def _handle_response(resp: requests.Response) -> dict:
        try:
            body = resp.json()
        except ValueError:
            preview = resp.text[:200] + "..." if len(resp.text) > 200 else resp.text
            raise SwiftAuthError(
                "PARSE_ERROR",
                f"Invalid JSON response from server. This usually means the request hit a non-API endpoint "
                f"(e.g. Cloudflare, reverse proxy, or wrong base URL). Response preview: {preview}",
            )

        if not body.get("success", False):
            error = body.get("error", {})
            raise SwiftAuthError(
                error.get("code", "UNKNOWN"),
                error.get("message", "Request failed"),
            )
        return body.get("data", body.get("message", {}))

    @staticmethod
    def _default_hwid() -> str:
        return f"{platform.node()}-{platform.system()}"


# ── Multi-Layer File Decryption ──────────────────────────────────────

class _SeededRNG:
    """LCG matching the Go server's seededRNG."""

    def __init__(self, key: bytes):
        state = 0
        if len(key) >= 8:
            state = struct.unpack_from("<Q", key)[0]
        for i in range(8, len(key)):
            state ^= key[i] << ((i % 8) * 8)
            state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        if state == 0:
            state = 0xDEADBEEFCAFE1234
        self._state = state

    def next(self) -> int:
        self._state = (self._state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        return self._state


def _derive_keys(app_secret: str, session_token: str, nonce: bytes):
    """Derive AES, shuffle, and XOR keys from shared secrets."""
    master = _hmac.new(
        app_secret.encode(), (session_token + "|" + nonce.hex()).encode(), hashlib.sha256
    ).digest()

    def sub(layer: int) -> bytes:
        return hashlib.sha256(master + bytes([layer])).digest()

    return sub(0x01), sub(0x02), sub(0x03)


def _decrypt_file_bytes(data: bytes, app_secret: str, session_token: str, nonce_hex: str) -> bytes:
    nonce = bytes.fromhex(nonce_hex)
    aes_key, shuffle_key, xor_key = _derive_keys(app_secret, session_token, nonce)

    # Layer 4 (reverse): Rolling XOR
    buf = bytearray(data)
    kl = len(xor_key)
    for i in range(len(buf)):
        buf[i] ^= xor_key[i % kl]

    # Layer 3 (reverse): Fisher-Yates unshuffle
    n = len(buf)
    rng = _SeededRNG(shuffle_key)
    swaps = []
    for i in range(n - 1, 0, -1):
        swaps.append(int(rng.next() % (i + 1)))
    for k in range(len(swaps) - 1, -1, -1):
        i = n - 1 - k
        j = swaps[k]
        buf[i], buf[j] = buf[j], buf[i]

    # Layer 2 (reverse): AES-256-GCM
    gcm_nonce = bytes(buf[:12])
    ciphertext_and_tag = bytes(buf[12:])
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(gcm_nonce, ciphertext_and_tag, None)

    # Layer 1 (reverse): zlib decompress
    return zlib.decompress(plaintext)
