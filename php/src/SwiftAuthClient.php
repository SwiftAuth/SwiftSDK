<?php
declare(strict_types=1);

namespace SwiftAuth;

/**
 * SwiftAuth SDK for PHP.
 * Full client for authentication, licensing, variables, files, and WebSocket.
 */
class SwiftAuthClient
{
    private string $baseUrl;
    private string $secret;
    private string $version;
    private string $hwid;
    private ?string $sessionToken = null;
    private ?string $nonce = null;

    public ?array $app = null;
    public ?array $user = null;

    public function __construct(
        string $baseUrl,
        string $appSecret,
        string $appVersion = '1.0.0',
        string $hwid = ''
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->secret = $appSecret;
        $this->version = $appVersion;
        $this->hwid = $hwid ?: (gethostname() . '-' . (getenv('USER') ?: getenv('USERNAME') ?: 'unknown'));
    }

    public function getSessionToken(): ?string
    {
        return $this->sessionToken;
    }

    public function isInitialized(): bool
    {
        return $this->sessionToken !== null;
    }

    // ── Initialization ──────────────────────────────────────────────

    public function init(): array
    {
        $data = $this->post('/api/client/init', [
            'secret' => $this->secret,
            'version' => $this->version,
            'hwid' => $this->hwid,
        ]);
        $this->sessionToken = $data['sessionToken'] ?? '';
        $this->app = [
            'name' => $data['appName'] ?? '',
            'version' => $data['appVersion'] ?? '',
            'antiDebug' => $data['antiDebug'] ?? false,
            'antiVM' => $data['antiVM'] ?? false,
            'lockHwid' => $data['lockHwid'] ?? false,
            'lockIp' => $data['lockIp'] ?? false,
            'lockPcName' => $data['lockPcName'] ?? false,
        ];
        return $data;
    }

    private function fetchNonce(): void
    {
        $data = $this->post('/api/client/nonce', ['sessionToken' => $this->sessionToken]);
        $this->nonce = $data['nonce'] ?? '';
    }

    // ── Authentication ──────────────────────────────────────────────

    public function login(string $username, string $password, string $licenseKey = '', string $pcName = ''): array
    {
        $this->requireInit();
        $this->fetchNonce();
        $data = $this->postWithNonce('/api/client/login', [
            'sessionToken' => $this->sessionToken,
            'username' => $username,
            'password' => $password,
            'licenseKey' => $licenseKey,
            'hwid' => $this->hwid,
            'pcName' => $pcName,
        ]);
        $this->user = $this->parseUser($data);
        return $data;
    }

    public function register(
        string $username,
        string $password,
        string $email = '',
        string $displayName = '',
        string $licenseKey = '',
        string $pcName = ''
    ): array {
        $this->requireInit();
        $this->fetchNonce();
        $data = $this->postWithNonce('/api/client/register', [
            'sessionToken' => $this->sessionToken,
            'username' => $username,
            'password' => $password,
            'email' => $email,
            'displayName' => $displayName,
            'licenseKey' => $licenseKey,
            'hwid' => $this->hwid,
            'pcName' => $pcName,
        ]);
        $this->user = $this->parseUser($data);
        return $data;
    }

    public function licenseLogin(string $licenseKey, string $pcName = ''): array
    {
        $this->requireInit();
        $this->fetchNonce();
        $data = $this->postWithNonce('/api/client/license', [
            'sessionToken' => $this->sessionToken,
            'licenseKey' => $licenseKey,
            'hwid' => $this->hwid,
            'pcName' => $pcName,
        ]);
        $this->user = $this->parseUser($data);
        return $data;
    }

    // ── Token Validation ────────────────────────────────────────────

    public function validateToken(string $token): array
    {
        $this->requireInit();
        return $this->post('/api/client/token', ['sessionToken' => $this->sessionToken, 'token' => $token]);
    }

    // ── License Activation ──────────────────────────────────────────

    public function activate(string $licenseKey): array
    {
        $this->requireInit();
        $this->fetchNonce();
        return $this->postWithNonce('/api/client/activate', [
            'sessionToken' => $this->sessionToken,
            'licenseKey' => $licenseKey,
        ]);
    }

    // ── Variables ───────────────────────────────────────────────────

    public function getVariable(string $key): array
    {
        $this->requireInit();
        return $this->post('/api/client/variable', ['sessionToken' => $this->sessionToken, 'key' => $key]);
    }

    public function getAllVariables(): array
    {
        $this->requireInit();
        return $this->post('/api/client/variables', ['sessionToken' => $this->sessionToken]);
    }

    // ── License Variables ───────────────────────────────────────────

    public function getLicenseVariable(string $key): array
    {
        $this->requireInit();
        return $this->post('/api/client/license-variable', ['sessionToken' => $this->sessionToken, 'key' => $key]);
    }

    public function getAllLicenseVariables(): array
    {
        $this->requireInit();
        return $this->post('/api/client/license-variables', ['sessionToken' => $this->sessionToken]);
    }

    // ── User Variables ──────────────────────────────────────────────

    public function getUserVariable(string $key): array
    {
        $this->requireInit();
        return $this->post('/api/client/user-variable', ['sessionToken' => $this->sessionToken, 'key' => $key]);
    }

    public function getAllUserVariables(): array
    {
        $this->requireInit();
        return $this->post('/api/client/user-variables', ['sessionToken' => $this->sessionToken]);
    }

    public function setUserVariable(string $key, string $value): array
    {
        $this->requireInit();
        return $this->post('/api/client/set-user-variable', [
            'sessionToken' => $this->sessionToken,
            'key' => $key,
            'value' => $value,
        ]);
    }

    public function deleteUserVariable(string $key): array
    {
        $this->requireInit();
        return $this->post('/api/client/delete-user-variable', ['sessionToken' => $this->sessionToken, 'key' => $key]);
    }

    // ── Files ───────────────────────────────────────────────────────

    public function downloadFile(string $name): string
    {
        $this->requireInit();
        $payload = json_encode(['sessionToken' => $this->sessionToken, 'name' => $name]);
        $ctx = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\n",
                'content' => $payload,
            ],
        ]);
        $response = file_get_contents($this->baseUrl . '/api/client/file', false, $ctx);

        // Parse response headers
        $encrypted = false;
        $fileNonce = '';
        foreach ($http_response_header ?? [] as $header) {
            if (stripos($header, 'x-file-encrypted: 1') !== false) {
                $encrypted = true;
            }
            if (preg_match('/x-file-nonce:\s*(\S+)/i', $header, $m)) {
                $fileNonce = $m[1];
            }
        }

        if ($encrypted && $fileNonce) {
            return $this->decryptFileBytes($response, $this->secret, $this->sessionToken, $fileNonce);
        }

        return $response;
    }

    public function checkUpdate(string $currentVersion, string $fileName = ''): array
    {
        $this->requireInit();
        return $this->post('/api/client/check-update', [
            'sessionToken' => $this->sessionToken,
            'currentVersion' => $currentVersion,
            'fileName' => $fileName,
        ]);
    }

    // ── Session Management ──────────────────────────────────────────

    public function heartbeat(): array
    {
        $this->requireInit();
        $this->fetchNonce();
        return $this->postWithNonce('/api/client/heartbeat', ['sessionToken' => $this->sessionToken]);
    }

    public function checkSession(): array
    {
        $this->requireInit();
        return $this->post('/api/client/check', ['sessionToken' => $this->sessionToken]);
    }

    public function endSession(): void
    {
        $this->requireInit();
        $this->post('/api/client/end', ['sessionToken' => $this->sessionToken]);
        $this->sessionToken = null;
        $this->user = null;
    }

    // ── User Info ───────────────────────────────────────────────────

    public function getUser(): array
    {
        $this->requireInit();
        return $this->post('/api/client/user', ['sessionToken' => $this->sessionToken]);
    }

    public function changePassword(string $currentPassword, string $newPassword): void
    {
        $this->requireInit();
        $this->post('/api/client/change-password', [
            'sessionToken' => $this->sessionToken,
            'currentPassword' => $currentPassword,
            'newPassword' => $newPassword,
        ]);
    }

    public function requestReset(): void
    {
        $this->requireInit();
        $this->post('/api/client/request-reset', ['sessionToken' => $this->sessionToken]);
    }

    // ── Client Log ──────────────────────────────────────────────────

    public function log(string $message, string $level = 'INFO'): void
    {
        $this->requireInit();
        $this->post('/api/client/log', [
            'sessionToken' => $this->sessionToken,
            'message' => $message,
            'level' => $level,
        ]);
    }

    // ── Internal ────────────────────────────────────────────────────

    private function requireInit(): void
    {
        if ($this->sessionToken === null) {
            throw new SwiftAuthException('NOT_INITIALIZED', 'Call init() before using other methods.');
        }
    }

    private function post(string $path, array $payload): mixed
    {
        return $this->request($path, $payload, []);
    }

    private function postWithNonce(string $path, array $payload): mixed
    {
        return $this->request($path, $payload, ['X-Nonce' => $this->nonce]);
    }

    private function request(string $path, array $payload, array $extraHeaders): mixed
    {
        $json = json_encode($payload);
        $headerStr = "Content-Type: application/json\r\nAccept: application/json\r\n";
        foreach ($extraHeaders as $k => $v) {
            $headerStr .= "$k: $v\r\n";
        }

        $ctx = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => $headerStr,
                'content' => $json,
                'ignore_errors' => true,
            ],
        ]);

        $response = file_get_contents($this->baseUrl . $path, false, $ctx);
        if ($response === false) {
            throw new SwiftAuthException('NETWORK_ERROR', 'Failed to connect to server');
        }

        $body = json_decode($response, true);
        if ($body === null) {
            throw new SwiftAuthException('PARSE_ERROR', 'Invalid server response');
        }

        if (empty($body['success'])) {
            $error = $body['error'] ?? [];
            throw new SwiftAuthException(
                $error['code'] ?? 'UNKNOWN',
                $error['message'] ?? 'Request failed',
            );
        }

        return $body['data'] ?? $body['message'] ?? [];
    }

    private function parseUser(array $data): array
    {
        return [
            'key' => $data['key'] ?? '',
            'username' => $data['username'] ?? '',
            'email' => $data['email'] ?? '',
            'level' => $data['level'] ?? 0,
            'expiresAt' => $data['expiresAt'] ?? null,
            'metadata' => $data['metadata'] ?? null,
        ];
    }

    // ── Multi-Layer File Decryption ─────────────────────────────────

    private function decryptFileBytes(string $data, string $appSecret, string $sessionToken, string $nonceHex): string
    {
        $nonce = hex2bin($nonceHex);
        [$aesKey, $shuffleKey, $xorKey] = $this->deriveKeys($appSecret, $sessionToken, $nonce);

        // Layer 4: Rolling XOR
        $buf = array_values(unpack('C*', $data));
        $xorBytes = array_values(unpack('C*', $xorKey));
        $xorLen = count($xorBytes);
        for ($i = 0; $i < count($buf); $i++) {
            $buf[$i] ^= $xorBytes[$i % $xorLen];
        }

        // Layer 3: Fisher-Yates unshuffle
        $n = count($buf);
        $rng = new SeededRNG($shuffleKey);
        $swaps = [];
        for ($i = $n - 1; $i > 0; $i--) {
            $swaps[] = $rng->nextMod($i + 1);
        }
        for ($k = count($swaps) - 1; $k >= 0; $k--) {
            $i = $n - 1 - $k;
            $j = $swaps[$k];
            [$buf[$i], $buf[$j]] = [$buf[$j], $buf[$i]];
        }

        // Layer 2: AES-256-GCM
        $packed = pack('C*', ...$buf);
        $gcmNonce = substr($packed, 0, 12);
        $ciphertextAndTag = substr($packed, 12);
        $tag = substr($ciphertextAndTag, -16);
        $ciphertext = substr($ciphertextAndTag, 0, -16);

        $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $aesKey, OPENSSL_RAW_DATA, $gcmNonce, $tag);
        if ($plaintext === false) {
            throw new SwiftAuthException('DECRYPT_ERROR', 'AES-GCM decryption failed');
        }

        // Layer 1: zlib decompress
        return gzuncompress($plaintext);
    }

    private function deriveKeys(string $appSecret, string $sessionToken, string $nonce): array
    {
        $master = hash_hmac('sha256', $sessionToken . '|' . bin2hex($nonce), $appSecret, true);

        $keys = [];
        foreach ([0x01, 0x02, 0x03] as $layer) {
            $keys[] = hash('sha256', $master . chr($layer), true);
        }
        return $keys;
    }
}

class SwiftAuthException extends \Exception
{
    private string $errorCode;

    public function __construct(string $code, string $message)
    {
        $this->errorCode = $code;
        parent::__construct("[{$code}] {$message}", 0);
    }

    public function getErrorCode(): string
    {
        return $this->errorCode;
    }
}

class SeededRNG
{
    private array $state; // [low32, high32] to simulate uint64

    public function __construct(string $key)
    {
        // Use GMP for 64-bit unsigned arithmetic
        $state = gmp_init(0);
        if (strlen($key) >= 8) {
            $bytes = unpack('V2', substr($key, 0, 8));
            $state = gmp_or(gmp_init($bytes[1] & 0xFFFFFFFF), gmp_mul(gmp_init($bytes[2] & 0xFFFFFFFF), gmp_pow(2, 32)));
        }
        for ($i = 8; $i < strlen($key); $i++) {
            $byte = gmp_init(ord($key[$i]));
            $shift = ($i % 8) * 8;
            $state = gmp_xor($state, gmp_mul($byte, gmp_pow(2, $shift)));
            $state = gmp_and(
                gmp_add(gmp_mul($state, gmp_init('6364136223846793005')), gmp_init('1442695040888963407')),
                gmp_sub(gmp_pow(2, 64), 1)
            );
        }
        if (gmp_cmp($state, 0) === 0) {
            $state = gmp_init('0xDEADBEEFCAFE1234');
        }
        $this->state = [$state];
    }

    public function next(): string
    {
        $mask = gmp_sub(gmp_pow(2, 64), 1);
        $this->state[0] = gmp_and(
            gmp_add(gmp_mul($this->state[0], gmp_init('6364136223846793005')), gmp_init('1442695040888963407')),
            $mask
        );
        return gmp_strval($this->state[0]);
    }

    public function nextMod(int $mod): int
    {
        $val = $this->next();
        return (int) gmp_strval(gmp_mod(gmp_init($val), gmp_init($mod)));
    }
}
