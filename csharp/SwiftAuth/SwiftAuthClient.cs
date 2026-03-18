using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace SwiftAuth
{
    public sealed class SwiftAuthClient : IDisposable
    {
        private readonly HttpClient _http;
        private readonly string _baseUrl;
        private readonly string _appSecret;
        private readonly string _appVersion;
        private readonly string _hwid;

        private string _sessionToken;
        private string _nonce;
        private ClientWebSocket _ws;
        private CancellationTokenSource _wsCts;
        private Task _wsReadTask;

        private bool _disposed;

        public string SessionToken => _sessionToken;
        public bool IsInitialized => !string.IsNullOrEmpty(_sessionToken);
        public bool IsWebSocketConnected => _ws?.State == WebSocketState.Open;

        public UserData CurrentUser { get; private set; }
        public AppInfo App { get; private set; }

        public event Action<WsEvent> OnMessage;
        public event Action<WsEvent> OnForceLogout;
        public event Action<WsEvent> OnCommand;
        public event Action<WsEvent> OnChat;
        public event Action<WsEvent> OnCustom;
        public event Action<string> OnError;
        public event Action OnDisconnected;

        public SwiftAuthClient(string baseUrl, string appSecret, string appVersion, string hwid = null)
        {
            _baseUrl = baseUrl.TrimEnd('/');
            _appSecret = appSecret ?? throw new ArgumentNullException(nameof(appSecret));
            _appVersion = appVersion ?? "1.0.0";
            _hwid = hwid ?? GetDefaultHWID();

            _http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }

        // ── Initialization ──────────────────────────────────────────────

        public async Task<InitResponse> InitAsync()
        {
            var payload = new { secret = _appSecret, version = _appVersion, hwid = _hwid };
            var result = await PostAsync<InitResponse>("/api/client/init", payload);

            _sessionToken = result.SessionToken;
            App = new AppInfo
            {
                Name = result.AppName,
                Version = result.AppVersion,
                AntiDebug = result.AntiDebug,
                AntiVM = result.AntiVM,
                LockHwid = result.LockHwid,
                LockIp = result.LockIp,
                LockPcName = result.LockPcName,
            };

            return result;
        }

        // ── Nonce ───────────────────────────────────────────────────────

        private async Task<string> FetchNonceAsync()
        {
            var payload = new { sessionToken = _sessionToken };
            var result = await PostAsync<NonceResponse>("/api/client/nonce", payload);
            _nonce = result.Nonce;
            return _nonce;
        }

        // ── Authentication ──────────────────────────────────────────────

        public async Task<LoginResponse> LoginAsync(string username, string password, string licenseKey = null, string pcName = null)
        {
            EnsureInitialized();
            await FetchNonceAsync();

            var payload = new
            {
                sessionToken = _sessionToken,
                username,
                password,
                licenseKey = licenseKey ?? "",
                hwid = _hwid,
                pcName = pcName ?? "",
            };

            var result = await PostWithNonceAsync<LoginResponse>("/api/client/login", payload);
            CurrentUser = new UserData
            {
                Key = result.Key,
                Username = result.Username,
                Email = result.Email,
                Level = result.Level,
                ExpiresAt = result.ExpiresAt,
            };
            return result;
        }

        public async Task<RegisterResponse> RegisterAsync(string username, string password, string email = null, string displayName = null, string licenseKey = null, string pcName = null)
        {
            EnsureInitialized();
            await FetchNonceAsync();

            var payload = new
            {
                sessionToken = _sessionToken,
                username,
                password,
                email = email ?? "",
                displayName = displayName ?? "",
                licenseKey = licenseKey ?? "",
                hwid = _hwid,
                pcName = pcName ?? "",
            };

            var result = await PostWithNonceAsync<RegisterResponse>("/api/client/register", payload);
            CurrentUser = new UserData
            {
                Key = result.Key,
                Username = result.Username,
                Email = result.Email,
                Level = result.Level,
                ExpiresAt = result.ExpiresAt,
            };
            return result;
        }

        public async Task<LicenseResponse> LicenseAsync(string licenseKey, string pcName = null)
        {
            EnsureInitialized();
            await FetchNonceAsync();

            var payload = new
            {
                sessionToken = _sessionToken,
                licenseKey,
                hwid = _hwid,
                pcName = pcName ?? "",
            };

            var result = await PostWithNonceAsync<LicenseResponse>("/api/client/license", payload);
            CurrentUser = new UserData
            {
                Key = result.Key,
                Username = result.Username,
                Level = result.Level,
                ExpiresAt = result.ExpiresAt,
            };
            return result;
        }

        // ── License Check ───────────────────────────────────────────────

        public async Task<LicenseCheckResponse> CheckLicenseAsync(string licenseKey)
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken, licenseKey };
            return await PostAsync<LicenseCheckResponse>("/api/client/check-license", payload);
        }

        // ── Token Validation ────────────────────────────────────────────

        public async Task<TokenResponse> ValidateTokenAsync(string token)
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken, token };
            return await PostAsync<TokenResponse>("/api/client/token", payload);
        }

        // ── License Activation ──────────────────────────────────────────

        public async Task<ActivateResponse> ActivateAsync(string licenseKey)
        {
            EnsureInitialized();
            await FetchNonceAsync();
            var payload = new { sessionToken = _sessionToken, licenseKey };
            return await PostWithNonceAsync<ActivateResponse>("/api/client/activate", payload);
        }

        // ── Variables ───────────────────────────────────────────────────

        public async Task<VariableData> GetVariableAsync(string key)
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken, key };
            return await PostAsync<VariableData>("/api/client/variable", payload);
        }

        public async Task<List<VariableData>> GetAllVariablesAsync()
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken };
            return await PostListAsync<VariableData>("/api/client/variables", payload);
        }

        // ── License Variables ────────────────────────────────────────────

        public async Task<VariableData> GetLicenseVariableAsync(string key)
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken, key };
            return await PostAsync<VariableData>("/api/client/license-variable", payload);
        }

        public async Task<List<VariableData>> GetAllLicenseVariablesAsync()
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken };
            return await PostListAsync<VariableData>("/api/client/license-variables", payload);
        }

        // ── User Variables ──────────────────────────────────────────────

        public async Task<UserVariableData> GetUserVariableAsync(string key)
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken, key };
            return await PostAsync<UserVariableData>("/api/client/user-variable", payload);
        }

        public async Task<List<UserVariableData>> GetAllUserVariablesAsync()
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken };
            return await PostListAsync<UserVariableData>("/api/client/user-variables", payload);
        }

        public async Task<UserVariableData> SetUserVariableAsync(string key, string value)
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken, key, value };
            return await PostAsync<UserVariableData>("/api/client/set-user-variable", payload);
        }

        public async Task DeleteUserVariableAsync(string key)
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken, key };
            await PostRawAsync("/api/client/delete-user-variable", payload);
        }

        // ── Files ───────────────────────────────────────────────────────

        public async Task<byte[]> DownloadFileAsync(string name)
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken, name };
            var json = JsonSerializer.Serialize(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _http.PostAsync($"{_baseUrl}/api/client/file", content);
            var encryptedBytes = await response.Content.ReadAsByteArrayAsync();

            // Check if response is encrypted
            if (response.Headers.TryGetValues("X-File-Encrypted", out var encValues) &&
                encValues.FirstOrDefault() == "1" &&
                response.Headers.TryGetValues("X-File-Nonce", out var nonceValues))
            {
                var nonceHex = nonceValues.FirstOrDefault();
                if (!string.IsNullOrEmpty(nonceHex))
                    return FileDecryptor.Decrypt(encryptedBytes, _appSecret, _sessionToken, nonceHex);
            }

            return encryptedBytes;
        }

        public async Task<UpdateCheckResult> CheckUpdateAsync(string currentVersion, string fileName = null)
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken, currentVersion, fileName = fileName ?? "" };
            return await PostAsync<UpdateCheckResult>("/api/client/check-update", payload);
        }

        // ── Session Management ──────────────────────────────────────────

        public async Task<HeartbeatResponse> HeartbeatAsync()
        {
            EnsureInitialized();
            await FetchNonceAsync();
            var payload = new { sessionToken = _sessionToken };
            return await PostWithNonceAsync<HeartbeatResponse>("/api/client/heartbeat", payload);
        }

        public async Task<SessionCheckResponse> CheckSessionAsync()
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken };
            return await PostAsync<SessionCheckResponse>("/api/client/check", payload);
        }

        public async Task EndSessionAsync()
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken };
            await PostRawAsync("/api/client/end", payload);
            _sessionToken = null;
            CurrentUser = null;
        }

        // ── User Info ───────────────────────────────────────────────────

        public async Task<UserInfoResponse> GetUserAsync()
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken };
            return await PostAsync<UserInfoResponse>("/api/client/user", payload);
        }

        public async Task ChangePasswordAsync(string currentPassword, string newPassword)
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken, currentPassword, newPassword };
            await PostRawAsync("/api/client/change-password", payload);
        }

        public async Task RequestResetAsync()
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken };
            await PostRawAsync("/api/client/request-reset", payload);
        }

        // ── Client Log ─────────────────────────────────────────────────

        public async Task LogAsync(string message, string level = "INFO")
        {
            EnsureInitialized();
            var payload = new { sessionToken = _sessionToken, message, level };
            await PostRawAsync("/api/client/log", payload);
        }

        // ── WebSocket ───────────────────────────────────────────────────

        public async Task ConnectWebSocketAsync()
        {
            EnsureInitialized();
            if (_ws?.State == WebSocketState.Open) return;

            var wsUrl = _baseUrl.Replace("https://", "wss://").Replace("http://", "ws://");
            wsUrl += $"/api/client/ws?token={Uri.EscapeDataString(_sessionToken)}";

            _ws = new ClientWebSocket();
            _wsCts = new CancellationTokenSource();

            await _ws.ConnectAsync(new Uri(wsUrl), _wsCts.Token);
            _wsReadTask = Task.Run(() => WsReadLoop(_wsCts.Token));
        }

        public async Task SendWsMessageAsync(object message)
        {
            if (_ws?.State != WebSocketState.Open) return;

            var json = JsonSerializer.Serialize(message, _jsonOpts);
            var bytes = Encoding.UTF8.GetBytes(json);
            await _ws.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, _wsCts.Token);
        }

        public async Task SendPingAsync() => await SendWsMessageAsync(new { type = "ping" });

        public async Task SetStatusAsync(string status) => await SendWsMessageAsync(new { type = "set_status", status });

        public async Task SendChatAsync(string message) => await SendWsMessageAsync(new { type = "chat", message });

        public async Task SetTypingAsync(bool typing) => await SendWsMessageAsync(new { type = "typing", typing });

        public async Task SetMetadataAsync(Dictionary<string, object> metadata) => await SendWsMessageAsync(new { type = "set_metadata", metadata });

        public async Task DisconnectWebSocketAsync()
        {
            if (_ws?.State == WebSocketState.Open)
            {
                _wsCts?.Cancel();
                try { await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Client disconnect", CancellationToken.None); }
                catch { /* swallow close errors */ }
            }
            _ws?.Dispose();
            _ws = null;
        }

        // ── Internal ────────────────────────────────────────────────────

        private static readonly JsonSerializerOptions _jsonOpts = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        private void EnsureInitialized()
        {
            if (string.IsNullOrEmpty(_sessionToken))
                throw new SwiftAuthException("NOT_INITIALIZED", "Call InitAsync() before using other methods.");
        }

        private async Task<T> PostAsync<T>(string path, object payload)
        {
            string body;
            try
            {
                var json = JsonSerializer.Serialize(payload, _jsonOpts);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await _http.PostAsync($"{_baseUrl}{path}", content);
                body = await response.Content.ReadAsStringAsync();
            }
            catch (HttpRequestException ex)
            {
                throw new SwiftAuthException("NETWORK_ERROR", $"Network request failed: {ex.Message}");
            }
            catch (TaskCanceledException ex)
            {
                throw new SwiftAuthException("TIMEOUT", $"Request timed out: {ex.Message}");
            }
            return ParseResponse<T>(body);
        }

        private async Task<T> PostWithNonceAsync<T>(string path, object payload)
        {
            string body;
            try
            {
                var json = JsonSerializer.Serialize(payload, _jsonOpts);
                var request = new HttpRequestMessage(HttpMethod.Post, $"{_baseUrl}{path}")
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json"),
                };
                request.Headers.Add("X-Nonce", _nonce);
                var response = await _http.SendAsync(request);
                body = await response.Content.ReadAsStringAsync();
            }
            catch (HttpRequestException ex)
            {
                throw new SwiftAuthException("NETWORK_ERROR", $"Network request failed: {ex.Message}");
            }
            catch (TaskCanceledException ex)
            {
                throw new SwiftAuthException("TIMEOUT", $"Request timed out: {ex.Message}");
            }
            return ParseResponse<T>(body);
        }

        private async Task<List<T>> PostListAsync<T>(string path, object payload)
        {
            string body;
            try
            {
                var json = JsonSerializer.Serialize(payload, _jsonOpts);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await _http.PostAsync($"{_baseUrl}{path}", content);
                body = await response.Content.ReadAsStringAsync();
            }
            catch (HttpRequestException ex)
            {
                throw new SwiftAuthException("NETWORK_ERROR", $"Network request failed: {ex.Message}");
            }
            catch (TaskCanceledException ex)
            {
                throw new SwiftAuthException("TIMEOUT", $"Request timed out: {ex.Message}");
            }
            return ParseListResponse<T>(body);
        }

        private async Task PostRawAsync(string path, object payload)
        {
            string body;
            try
            {
                var json = JsonSerializer.Serialize(payload, _jsonOpts);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await _http.PostAsync($"{_baseUrl}{path}", content);
                body = await response.Content.ReadAsStringAsync();
            }
            catch (HttpRequestException ex)
            {
                throw new SwiftAuthException("NETWORK_ERROR", $"Network request failed: {ex.Message}");
            }
            catch (TaskCanceledException ex)
            {
                throw new SwiftAuthException("TIMEOUT", $"Request timed out: {ex.Message}");
            }
            EnsureSuccess(body);
        }

        private static T ParseResponse<T>(string body)
        {
            JsonDocument doc;
            try { doc = JsonDocument.Parse(body); }
            catch (JsonException)
            {
                var preview = body?.Length > 200 ? body.Substring(0, 200) + "..." : body ?? "(empty)";
                throw new SwiftAuthException("PARSE_ERROR", $"Invalid JSON response from server. This usually means the request hit a non-API endpoint (e.g. Cloudflare, reverse proxy, or wrong base URL). Response preview: {preview}");
            }
            using var _ = doc;
            var root = doc.RootElement;

            if (!root.TryGetProperty("success", out var successProp) || !successProp.GetBoolean())
            {
                var code = "UNKNOWN";
                var msg = "Request failed";
                if (root.TryGetProperty("error", out var errorProp))
                {
                    if (errorProp.TryGetProperty("code", out var codeProp)) code = codeProp.GetString();
                    if (errorProp.TryGetProperty("message", out var msgProp)) msg = msgProp.GetString();
                }
                throw new SwiftAuthException(code, msg);
            }

            if (root.TryGetProperty("data", out var dataProp))
                return JsonSerializer.Deserialize<T>(dataProp.GetRawText(), _jsonOpts);

            return default;
        }

        private static List<T> ParseListResponse<T>(string body)
        {
            JsonDocument doc;
            try { doc = JsonDocument.Parse(body); }
            catch (JsonException)
            {
                var preview = body?.Length > 200 ? body.Substring(0, 200) + "..." : body ?? "(empty)";
                throw new SwiftAuthException("PARSE_ERROR", $"Invalid JSON response from server. This usually means the request hit a non-API endpoint (e.g. Cloudflare, reverse proxy, or wrong base URL). Response preview: {preview}");
            }
            using var _ = doc;
            var root = doc.RootElement;

            if (!root.TryGetProperty("success", out var successProp) || !successProp.GetBoolean())
            {
                var code = "UNKNOWN";
                var msg = "Request failed";
                if (root.TryGetProperty("error", out var errorProp))
                {
                    if (errorProp.TryGetProperty("code", out var codeProp)) code = codeProp.GetString();
                    if (errorProp.TryGetProperty("message", out var msgProp)) msg = msgProp.GetString();
                }
                throw new SwiftAuthException(code, msg);
            }

            if (root.TryGetProperty("data", out var dataProp))
                return JsonSerializer.Deserialize<List<T>>(dataProp.GetRawText(), _jsonOpts);

            return new List<T>();
        }

        private static void EnsureSuccess(string body)
        {
            JsonDocument doc;
            try { doc = JsonDocument.Parse(body); }
            catch (JsonException)
            {
                var preview = body?.Length > 200 ? body.Substring(0, 200) + "..." : body ?? "(empty)";
                throw new SwiftAuthException("PARSE_ERROR", $"Invalid JSON response from server. This usually means the request hit a non-API endpoint (e.g. Cloudflare, reverse proxy, or wrong base URL). Response preview: {preview}");
            }
            using var _ = doc;
            var root = doc.RootElement;

            if (!root.TryGetProperty("success", out var successProp) || !successProp.GetBoolean())
            {
                var code = "UNKNOWN";
                var msg = "Request failed";
                if (root.TryGetProperty("error", out var errorProp))
                {
                    if (errorProp.TryGetProperty("code", out var codeProp)) code = codeProp.GetString();
                    if (errorProp.TryGetProperty("message", out var msgProp)) msg = msgProp.GetString();
                }
                throw new SwiftAuthException(code, msg);
            }
        }

        private async Task WsReadLoop(CancellationToken ct)
        {
            var buffer = new byte[8192];
            var messageBuffer = new List<byte>();

            try
            {
                while (_ws?.State == WebSocketState.Open && !ct.IsCancellationRequested)
                {
                    var result = await _ws.ReceiveAsync(new ArraySegment<byte>(buffer), ct);

                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        OnDisconnected?.Invoke();
                        break;
                    }

                    messageBuffer.AddRange(new ArraySegment<byte>(buffer, 0, result.Count));

                    if (result.EndOfMessage)
                    {
                        var json = Encoding.UTF8.GetString(messageBuffer.ToArray());
                        messageBuffer.Clear();
                        DispatchWsEvent(json);
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                OnError?.Invoke(ex.Message);
            }
            finally
            {
                OnDisconnected?.Invoke();
            }
        }

        private void DispatchWsEvent(string json)
        {
            try
            {
                var evt = JsonSerializer.Deserialize<WsEvent>(json, _jsonOpts);
                if (evt == null) return;

                OnMessage?.Invoke(evt);

                switch (evt.Type)
                {
                    case "force_logout": OnForceLogout?.Invoke(evt); break;
                    case "command": OnCommand?.Invoke(evt); break;
                    case "chat": OnChat?.Invoke(evt); break;
                    case "custom": OnCustom?.Invoke(evt); break;
                }
            }
            catch { /* malformed messages are silently dropped */ }
        }

        private static string GetDefaultHWID()
        {
            return Environment.MachineName + "-" + Environment.UserName;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _wsCts?.Cancel();
            _ws?.Dispose();
            _http?.Dispose();
        }
    }

    // ── Exceptions ──────────────────────────────────────────────────────

    public class SwiftAuthException : Exception
    {
        public string Code { get; }
        public SwiftAuthException(string code, string message) : base(message) { Code = code; }
    }

    // ── Models ──────────────────────────────────────────────────────────

    public class WsEvent
    {
        [JsonPropertyName("type")]  public string Type { get; set; }
        [JsonPropertyName("data")]  public JsonElement? Data { get; set; }
    }

    public class AppInfo
    {
        public string Name { get; set; }
        public string Version { get; set; }
        public bool AntiDebug { get; set; }
        public bool AntiVM { get; set; }
        public bool LockHwid { get; set; }
        public bool LockIp { get; set; }
        public bool LockPcName { get; set; }
    }

    public class UserData
    {
        public string Key { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public int Level { get; set; }
        public string ExpiresAt { get; set; }
    }

    public class InitResponse
    {
        [JsonPropertyName("sessionToken")] public string SessionToken { get; set; }
        [JsonPropertyName("appName")]      public string AppName { get; set; }
        [JsonPropertyName("appVersion")]   public string AppVersion { get; set; }
        [JsonPropertyName("antiDebug")]    public bool AntiDebug { get; set; }
        [JsonPropertyName("antiVM")]       public bool AntiVM { get; set; }
        [JsonPropertyName("lockHwid")]     public bool LockHwid { get; set; }
        [JsonPropertyName("lockIp")]       public bool LockIp { get; set; }
        [JsonPropertyName("lockPcName")]   public bool LockPcName { get; set; }
        [JsonPropertyName("expiresAt")]    public string ExpiresAt { get; set; }
        [JsonPropertyName("resumed")]      public bool Resumed { get; set; }
    }

    public class NonceResponse
    {
        [JsonPropertyName("nonce")] public string Nonce { get; set; }
    }

    public class LoginResponse
    {
        [JsonPropertyName("key")]              public string Key { get; set; }
        [JsonPropertyName("username")]         public string Username { get; set; }
        [JsonPropertyName("email")]            public string Email { get; set; }
        [JsonPropertyName("level")]            public int Level { get; set; }
        [JsonPropertyName("expiresAt")]        public string ExpiresAt { get; set; }
        [JsonPropertyName("metadata")]         public JsonElement? Metadata { get; set; }
        [JsonPropertyName("licenseActivated")] public bool LicenseActivated { get; set; }
        [JsonPropertyName("warnings")]         public List<string> Warnings { get; set; }
    }

    public class RegisterResponse
    {
        [JsonPropertyName("key")]       public string Key { get; set; }
        [JsonPropertyName("username")]  public string Username { get; set; }
        [JsonPropertyName("email")]     public string Email { get; set; }
        [JsonPropertyName("level")]     public int Level { get; set; }
        [JsonPropertyName("expiresAt")] public string ExpiresAt { get; set; }
        [JsonPropertyName("warnings")]  public List<string> Warnings { get; set; }
    }

    public class LicenseResponse
    {
        [JsonPropertyName("key")]       public string Key { get; set; }
        [JsonPropertyName("username")]  public string Username { get; set; }
        [JsonPropertyName("level")]     public int Level { get; set; }
        [JsonPropertyName("expiresAt")] public string ExpiresAt { get; set; }
        [JsonPropertyName("returning")] public bool Returning { get; set; }
        [JsonPropertyName("warnings")]  public List<string> Warnings { get; set; }
    }

    public class TokenResponse
    {
        [JsonPropertyName("valid")] public bool Valid { get; set; }
        [JsonPropertyName("level")] public int Level { get; set; }
    }

    public class ActivateResponse
    {
        [JsonPropertyName("expiresAt")] public string ExpiresAt { get; set; }
        [JsonPropertyName("level")]     public int Level { get; set; }
    }

    public class VariableData
    {
        [JsonPropertyName("key")]   public string Key { get; set; }
        [JsonPropertyName("value")] public string Value { get; set; }
        [JsonPropertyName("type")]  public string Type { get; set; }
    }

    public class UserVariableData
    {
        [JsonPropertyName("key")]   public string Key { get; set; }
        [JsonPropertyName("value")] public string Value { get; set; }
    }

    public class UpdateCheckResult
    {
        [JsonPropertyName("updateAvailable")] public bool UpdateAvailable { get; set; }
        [JsonPropertyName("latestVersion")]   public string LatestVersion { get; set; }
        [JsonPropertyName("currentVersion")]  public string CurrentVersion { get; set; }
        [JsonPropertyName("file")]            public FileInfo File { get; set; }
    }

    public class FileInfo
    {
        [JsonPropertyName("name")]    public string Name { get; set; }
        [JsonPropertyName("version")] public string Version { get; set; }
        [JsonPropertyName("size")]    public long Size { get; set; }
        [JsonPropertyName("hash")]    public string Hash { get; set; }
    }

    public class HeartbeatResponse
    {
        [JsonPropertyName("expiresAt")] public string ExpiresAt { get; set; }
    }

    public class SessionCheckResponse
    {
        [JsonPropertyName("valid")]     public bool Valid { get; set; }
        [JsonPropertyName("expiresAt")] public string ExpiresAt { get; set; }
        [JsonPropertyName("username")]  public string Username { get; set; }
    }

    public class LicenseCheckResponse
    {
        [JsonPropertyName("valid")]   public bool Valid { get; set; }
        [JsonPropertyName("exists")]  public bool Exists { get; set; }
        [JsonPropertyName("banned")]  public bool Banned { get; set; }
        [JsonPropertyName("enabled")] public bool Enabled { get; set; }
        [JsonPropertyName("issues")]  public List<string> Issues { get; set; }
        [JsonPropertyName("reason")]  public string Reason { get; set; }
        [JsonPropertyName("license")] public LicenseCheckInfo License { get; set; }
    }

    public class LicenseCheckInfo
    {
        [JsonPropertyName("level")]     public int Level { get; set; }
        [JsonPropertyName("duration")]  public int? Duration { get; set; }
        [JsonPropertyName("expiresAt")] public string ExpiresAt { get; set; }
        [JsonPropertyName("usedCount")] public int UsedCount { get; set; }
        [JsonPropertyName("maxUses")]   public int MaxUses { get; set; }
        [JsonPropertyName("usedBy")]    public string UsedBy { get; set; }
    }

    public class UserInfoResponse
    {
        [JsonPropertyName("key")]         public string Key { get; set; }
        [JsonPropertyName("username")]    public string Username { get; set; }
        [JsonPropertyName("email")]       public string Email { get; set; }
        [JsonPropertyName("level")]       public int Level { get; set; }
        [JsonPropertyName("expiresAt")]   public string ExpiresAt { get; set; }
        [JsonPropertyName("metadata")]    public JsonElement? Metadata { get; set; }
        [JsonPropertyName("createdAt")]   public string CreatedAt { get; set; }
        [JsonPropertyName("lastLoginAt")] public string LastLoginAt { get; set; }
    }

    // ── Multi-Layer File Decryption ─────────────────────────────────────
    //
    // Reverses 4 encryption layers applied by server:
    //   Layer 4 (undo first): Rolling XOR with xorKey
    //   Layer 3: Inverse Fisher-Yates unshuffle with shuffleKey
    //   Layer 2: AES-256-GCM decrypt with aesKey
    //   Layer 1: zlib decompress

    internal static class FileDecryptor
    {
        public static byte[] Decrypt(byte[] data, string appSecret, string sessionToken, string nonceHex)
        {
            byte[] nonce = HexToBytes(nonceHex);
            DeriveKeys(appSecret, sessionToken, nonce, out byte[] aesKey, out byte[] shuffleKey, out byte[] xorKey);

            // Layer 4 (reverse): Rolling XOR
            RollingXOR(data, xorKey);

            // Layer 3 (reverse): Fisher-Yates unshuffle
            data = FisherYatesUnshuffle(data, shuffleKey);

            // Layer 2 (reverse): AES-256-GCM decrypt (first 12 bytes are GCM nonce)
            data = AesGcmDecrypt(data, aesKey);

            // Layer 1 (reverse): zlib decompress
            data = ZlibDecompress(data);

            return data;
        }

        private static void DeriveKeys(string appSecret, string sessionToken, byte[] nonce, out byte[] aesKey, out byte[] shuffleKey, out byte[] xorKey)
        {
            // Master key = HMAC-SHA256(sessionToken + "|" + hex(nonce), appSecret)
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(appSecret));
            byte[] masterKey = hmac.ComputeHash(Encoding.UTF8.GetBytes(sessionToken + "|" + BytesToHex(nonce)));

            aesKey = DeriveSubKey(masterKey, 0x01);
            shuffleKey = DeriveSubKey(masterKey, 0x02);
            xorKey = DeriveSubKey(masterKey, 0x03);
        }

        private static byte[] DeriveSubKey(byte[] masterKey, byte layer)
        {
            using var sha = SHA256.Create();
            byte[] input = new byte[masterKey.Length + 1];
            Buffer.BlockCopy(masterKey, 0, input, 0, masterKey.Length);
            input[masterKey.Length] = layer;
            return sha.ComputeHash(input);
        }

        private static void RollingXOR(byte[] data, byte[] key)
        {
            for (int i = 0; i < data.Length; i++)
                data[i] ^= key[i % key.Length];
        }

        private static byte[] FisherYatesUnshuffle(byte[] data, byte[] key)
        {
            int n = data.Length;
            if (n <= 1) return data;

            byte[] result = new byte[n];
            Buffer.BlockCopy(data, 0, result, 0, n);

            var rng = new SeededRNG(key);

            // Generate all swap indices
            int[] swaps = new int[n - 1];
            for (int i = n - 1; i > 0; i--)
                swaps[n - 1 - i] = (int)(rng.Next() % (ulong)(i + 1));

            // Apply in reverse order
            for (int k = swaps.Length - 1; k >= 0; k--)
            {
                int i = n - 1 - k;
                int j = swaps[k];
                (result[i], result[j]) = (result[j], result[i]);
            }

            return result;
        }

        private static byte[] AesGcmDecrypt(byte[] data, byte[] key)
        {
            // First 12 bytes are the GCM nonce, rest is ciphertext + tag
            const int nonceSize = 12;
            const int tagSize = 16;

            if (data.Length < nonceSize + tagSize)
                throw new SwiftAuthException("DECRYPT_ERROR", "Encrypted data too short");

            byte[] gcmNonce = new byte[nonceSize];
            Buffer.BlockCopy(data, 0, gcmNonce, 0, nonceSize);

            int ciphertextLen = data.Length - nonceSize - tagSize;
            byte[] ciphertext = new byte[ciphertextLen];
            Buffer.BlockCopy(data, nonceSize, ciphertext, 0, ciphertextLen);

            byte[] tag = new byte[tagSize];
            Buffer.BlockCopy(data, data.Length - tagSize, tag, 0, tagSize);

            byte[] plaintext = new byte[ciphertextLen];
            using var aesGcm = new AesGcm(key, tagSize);
            aesGcm.Decrypt(gcmNonce, ciphertext, tag, plaintext);

            return plaintext;
        }

        private static byte[] ZlibDecompress(byte[] data)
        {
            using var input = new MemoryStream(data);
            using var zlib = new ZLibStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            zlib.CopyTo(output);
            return output.ToArray();
        }

        private static byte[] HexToBytes(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }

        private static string BytesToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        // Simple LCG matching Go server's seededRNG
        private class SeededRNG
        {
            private ulong _state;

            public SeededRNG(byte[] key)
            {
                if (key.Length >= 8)
                    _state = BitConverter.ToUInt64(key, 0);

                for (int i = 8; i < key.Length; i++)
                {
                    _state ^= (ulong)key[i] << ((i % 8) * 8);
                    _state = unchecked(_state * 6364136223846793005UL + 1442695040888963407UL);
                }

                if (_state == 0)
                    _state = 0xdeadbeefcafe1234UL;
            }

            public ulong Next()
            {
                _state = unchecked(_state * 6364136223846793005UL + 1442695040888963407UL);
                return _state;
            }
        }
    }
}
