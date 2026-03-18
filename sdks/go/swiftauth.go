// Package swiftauth provides a Go client for the SwiftAuth authentication API.
package swiftauth

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

// SwiftAuthError represents an API error.
type SwiftAuthError struct {
	Code    string
	Message string
}

func (e *SwiftAuthError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// AppInfo holds application metadata returned from init.
type AppInfo struct {
	Name       string `json:"appName"`
	Version    string `json:"appVersion"`
	AntiDebug  bool   `json:"antiDebug"`
	AntiVM     bool   `json:"antiVM"`
	LockHwid   bool   `json:"lockHwid"`
	LockIp     bool   `json:"lockIp"`
	LockPcName bool   `json:"lockPcName"`
}

// UserData holds authenticated user info.
type UserData struct {
	Key       string `json:"key"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Level     int    `json:"level"`
	ExpiresAt string `json:"expiresAt"`
	Metadata  any    `json:"metadata"`
}

// Variable represents an app variable.
type Variable struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

// UserVariable represents a user-scoped variable.
type UserVariable struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Client is the main SwiftAuth SDK client.
type Client struct {
	baseURL      string
	secret       string
	version      string
	hwid         string
	sessionToken string
	nonce        string
	httpClient   *http.Client

	App  *AppInfo
	User *UserData

	ws          *websocket.Conn
	wsMu        sync.Mutex
	wsCallbacks map[string][]func(map[string]any)
	wsDone      chan struct{}
}

// NewClient creates a new SwiftAuth client.
func NewClient(baseURL, appSecret, appVersion, hwid string) *Client {
	if hwid == "" {
		hostname, _ := os.Hostname()
		u, _ := user.Current()
		uname := "unknown"
		if u != nil {
			uname = u.Username
		}
		hwid = hostname + "-" + uname
	}
	return &Client{
		baseURL:     strings.TrimRight(baseURL, "/"),
		secret:      appSecret,
		version:     appVersion,
		hwid:        hwid,
		httpClient:  &http.Client{},
		wsCallbacks: make(map[string][]func(map[string]any)),
	}
}

// Init initializes a session with the SwiftAuth server.
func (c *Client) Init() (map[string]any, error) {
	data, err := c.post("/api/client/init", map[string]any{
		"secret":  c.secret,
		"version": c.version,
		"hwid":    c.hwid,
	})
	if err != nil {
		return nil, err
	}
	c.sessionToken = str(data, "sessionToken")
	c.App = &AppInfo{
		Name:       str(data, "appName"),
		Version:    str(data, "appVersion"),
		AntiDebug:  boolVal(data, "antiDebug"),
		AntiVM:     boolVal(data, "antiVM"),
		LockHwid:   boolVal(data, "lockHwid"),
		LockIp:     boolVal(data, "lockIp"),
		LockPcName: boolVal(data, "lockPcName"),
	}
	return data, nil
}

func (c *Client) fetchNonce() error {
	data, err := c.post("/api/client/nonce", map[string]any{
		"sessionToken": c.sessionToken,
	})
	if err != nil {
		return err
	}
	c.nonce = str(data, "nonce")
	return nil
}

// Login authenticates with username and password.
func (c *Client) Login(username, password, licenseKey, pcName string) (map[string]any, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	if err := c.fetchNonce(); err != nil {
		return nil, err
	}
	data, err := c.postWithNonce("/api/client/login", map[string]any{
		"sessionToken": c.sessionToken,
		"username":     username,
		"password":     password,
		"licenseKey":   licenseKey,
		"hwid":         c.hwid,
		"pcName":       pcName,
	})
	if err != nil {
		return nil, err
	}
	c.User = parseUser(data)
	return data, nil
}

// Register creates a new user account.
func (c *Client) Register(username, password, email, displayName, licenseKey, pcName string) (map[string]any, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	if err := c.fetchNonce(); err != nil {
		return nil, err
	}
	data, err := c.postWithNonce("/api/client/register", map[string]any{
		"sessionToken": c.sessionToken,
		"username":     username,
		"password":     password,
		"email":        email,
		"displayName":  displayName,
		"licenseKey":   licenseKey,
		"hwid":         c.hwid,
		"pcName":       pcName,
	})
	if err != nil {
		return nil, err
	}
	c.User = parseUser(data)
	return data, nil
}

// LicenseLogin authenticates with a license key only.
func (c *Client) LicenseLogin(licenseKey, pcName string) (map[string]any, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	if err := c.fetchNonce(); err != nil {
		return nil, err
	}
	data, err := c.postWithNonce("/api/client/license", map[string]any{
		"sessionToken": c.sessionToken,
		"licenseKey":   licenseKey,
		"hwid":         c.hwid,
		"pcName":       pcName,
	})
	if err != nil {
		return nil, err
	}
	c.User = parseUser(data)
	return data, nil
}

// ValidateToken validates a pre-auth access token.
func (c *Client) ValidateToken(token string) (map[string]any, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	return c.post("/api/client/token", map[string]any{
		"sessionToken": c.sessionToken,
		"token":        token,
	})
}

// Activate activates a license on the current user.
func (c *Client) Activate(licenseKey string) (map[string]any, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	if err := c.fetchNonce(); err != nil {
		return nil, err
	}
	return c.postWithNonce("/api/client/activate", map[string]any{
		"sessionToken": c.sessionToken,
		"licenseKey":   licenseKey,
	})
}

// GetVariable fetches a single app variable.
func (c *Client) GetVariable(key string) (*Variable, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	data, err := c.post("/api/client/variable", map[string]any{
		"sessionToken": c.sessionToken,
		"key":          key,
	})
	if err != nil {
		return nil, err
	}
	return &Variable{Key: str(data, "key"), Value: str(data, "value"), Type: str(data, "type")}, nil
}

// GetAllVariables fetches all app variables.
func (c *Client) GetAllVariables() ([]Variable, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	data, err := c.post("/api/client/variables", map[string]any{
		"sessionToken": c.sessionToken,
	})
	if err != nil {
		return nil, err
	}
	return parseVariables(data), nil
}

// GetLicenseVariable fetches a single license-scoped variable.
func (c *Client) GetLicenseVariable(key string) (*Variable, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	data, err := c.post("/api/client/license-variable", map[string]any{
		"sessionToken": c.sessionToken,
		"key":          key,
	})
	if err != nil {
		return nil, err
	}
	return &Variable{Key: str(data, "key"), Value: str(data, "value"), Type: str(data, "type")}, nil
}

// GetAllLicenseVariables fetches all license-scoped variables.
func (c *Client) GetAllLicenseVariables() ([]Variable, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	data, err := c.post("/api/client/license-variables", map[string]any{
		"sessionToken": c.sessionToken,
	})
	if err != nil {
		return nil, err
	}
	return parseVariables(data), nil
}

// GetUserVariable fetches a user-scoped variable.
func (c *Client) GetUserVariable(key string) (*UserVariable, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	data, err := c.post("/api/client/user-variable", map[string]any{
		"sessionToken": c.sessionToken,
		"key":          key,
	})
	if err != nil {
		return nil, err
	}
	return &UserVariable{Key: str(data, "key"), Value: str(data, "value")}, nil
}

// GetAllUserVariables fetches all user-scoped variables.
func (c *Client) GetAllUserVariables() ([]UserVariable, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	data, err := c.post("/api/client/user-variables", map[string]any{
		"sessionToken": c.sessionToken,
	})
	if err != nil {
		return nil, err
	}
	return parseUserVariables(data), nil
}

// SetUserVariable sets or updates a user-scoped variable.
func (c *Client) SetUserVariable(key, value string) (*UserVariable, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	data, err := c.post("/api/client/set-user-variable", map[string]any{
		"sessionToken": c.sessionToken,
		"key":          key,
		"value":        value,
	})
	if err != nil {
		return nil, err
	}
	return &UserVariable{Key: str(data, "key"), Value: str(data, "value")}, nil
}

// DeleteUserVariable deletes a user-scoped variable.
func (c *Client) DeleteUserVariable(key string) error {
	if err := c.requireInit(); err != nil {
		return err
	}
	_, err := c.post("/api/client/delete-user-variable", map[string]any{
		"sessionToken": c.sessionToken,
		"key":          key,
	})
	return err
}

// DownloadFile downloads and decrypts a file by name.
func (c *Client) DownloadFile(name string) ([]byte, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]any{
		"sessionToken": c.sessionToken,
		"name":         name,
	})
	resp, err := c.httpClient.Post(c.baseURL+"/api/client/file", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.Header.Get("X-File-Encrypted") == "1" {
		nonceHex := resp.Header.Get("X-File-Nonce")
		if nonceHex != "" {
			return decryptFileBytes(raw, c.secret, c.sessionToken, nonceHex)
		}
	}
	return raw, nil
}

// CheckUpdate checks for app version updates.
func (c *Client) CheckUpdate(currentVersion, fileName string) (map[string]any, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	return c.post("/api/client/check-update", map[string]any{
		"sessionToken":   c.sessionToken,
		"currentVersion": currentVersion,
		"fileName":       fileName,
	})
}

// Heartbeat sends a keep-alive heartbeat.
func (c *Client) Heartbeat() (map[string]any, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	if err := c.fetchNonce(); err != nil {
		return nil, err
	}
	return c.postWithNonce("/api/client/heartbeat", map[string]any{
		"sessionToken": c.sessionToken,
	})
}

// CheckSession verifies the session is still valid.
func (c *Client) CheckSession() (map[string]any, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	return c.post("/api/client/check", map[string]any{
		"sessionToken": c.sessionToken,
	})
}

// EndSession ends and invalidates the current session.
func (c *Client) EndSession() error {
	if err := c.requireInit(); err != nil {
		return err
	}
	_, err := c.post("/api/client/end", map[string]any{
		"sessionToken": c.sessionToken,
	})
	c.sessionToken = ""
	c.User = nil
	return err
}

// GetUser gets current user profile info.
func (c *Client) GetUser() (map[string]any, error) {
	if err := c.requireInit(); err != nil {
		return nil, err
	}
	return c.post("/api/client/user", map[string]any{
		"sessionToken": c.sessionToken,
	})
}

// ChangePassword changes the current user's password.
func (c *Client) ChangePassword(currentPassword, newPassword string) error {
	if err := c.requireInit(); err != nil {
		return err
	}
	_, err := c.post("/api/client/change-password", map[string]any{
		"sessionToken":    c.sessionToken,
		"currentPassword": currentPassword,
		"newPassword":     newPassword,
	})
	return err
}

// RequestReset requests a HWID/IP reset.
func (c *Client) RequestReset() error {
	if err := c.requireInit(); err != nil {
		return err
	}
	_, err := c.post("/api/client/request-reset", map[string]any{
		"sessionToken": c.sessionToken,
	})
	return err
}

// Log sends a client-side log entry.
func (c *Client) Log(message, level string) error {
	if err := c.requireInit(); err != nil {
		return err
	}
	if level == "" {
		level = "INFO"
	}
	_, err := c.post("/api/client/log", map[string]any{
		"sessionToken": c.sessionToken,
		"message":      message,
		"level":        level,
	})
	return err
}

// SessionToken returns the current session token.
func (c *Client) SessionToken() string {
	return c.sessionToken
}

// IsInitialized returns true if the client has been initialized.
func (c *Client) IsInitialized() bool {
	return c.sessionToken != ""
}

// ── WebSocket ───────────────────────────────────────────────────────

// On registers a callback for a WebSocket event type.
func (c *Client) On(event string, cb func(map[string]any)) {
	c.wsCallbacks[event] = append(c.wsCallbacks[event], cb)
}

// ConnectWs opens a WebSocket connection.
func (c *Client) ConnectWs() error {
	if err := c.requireInit(); err != nil {
		return err
	}
	wsURL := strings.Replace(c.baseURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	wsURL += "/api/client/ws?token=" + url.QueryEscape(c.sessionToken)

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return err
	}
	c.ws = conn
	c.wsDone = make(chan struct{})

	go func() {
		defer close(c.wsDone)
		for {
			_, msg, err := c.ws.ReadMessage()
			if err != nil {
				for _, cb := range c.wsCallbacks["close"] {
					cb(map[string]any{"error": err.Error()})
				}
				return
			}
			var evt map[string]any
			if json.Unmarshal(msg, &evt) == nil {
				eventType, _ := evt["type"].(string)
				for _, cb := range c.wsCallbacks[eventType] {
					cb(evt)
				}
				for _, cb := range c.wsCallbacks["*"] {
					cb(evt)
				}
			}
		}
	}()
	return nil
}

// WsSend sends a JSON message over the WebSocket.
func (c *Client) WsSend(data map[string]any) error {
	c.wsMu.Lock()
	defer c.wsMu.Unlock()
	if c.ws == nil {
		return fmt.Errorf("websocket not connected")
	}
	return c.ws.WriteJSON(data)
}

// WsPing sends a ping message.
func (c *Client) WsPing() error {
	return c.WsSend(map[string]any{"type": "ping"})
}

// WsSetStatus sets the user's online status.
func (c *Client) WsSetStatus(status string) error {
	return c.WsSend(map[string]any{"type": "set_status", "status": status})
}

// WsSendChat sends a chat message.
func (c *Client) WsSendChat(message string) error {
	return c.WsSend(map[string]any{"type": "chat", "message": message})
}

// WsSetTyping sends a typing indicator.
func (c *Client) WsSetTyping(typing bool) error {
	return c.WsSend(map[string]any{"type": "typing", "typing": typing})
}

// WsSetMetadata sets session metadata.
func (c *Client) WsSetMetadata(metadata map[string]any) error {
	return c.WsSend(map[string]any{"type": "set_metadata", "metadata": metadata})
}

// DisconnectWs closes the WebSocket connection.
func (c *Client) DisconnectWs() {
	if c.ws != nil {
		c.ws.Close()
		c.ws = nil
	}
}

// ── Internal ────────────────────────────────────────────────────────

func (c *Client) requireInit() error {
	if c.sessionToken == "" {
		return &SwiftAuthError{Code: "NOT_INITIALIZED", Message: "Call Init() before using other methods."}
	}
	return nil
}

func (c *Client) post(path string, payload map[string]any) (map[string]any, error) {
	return c.request(path, payload, nil)
}

func (c *Client) postWithNonce(path string, payload map[string]any) (map[string]any, error) {
	return c.request(path, payload, map[string]string{"X-Nonce": c.nonce})
}

func (c *Client) request(path string, payload map[string]any, headers map[string]string) (map[string]any, error) {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, &SwiftAuthError{Code: "PARSE_ERROR", Message: "Invalid server response"}
	}

	success, _ := result["success"].(bool)
	if !success {
		errMap, _ := result["error"].(map[string]any)
		code := "UNKNOWN"
		msg := "Request failed"
		if errMap != nil {
			if c, ok := errMap["code"].(string); ok {
				code = c
			}
			if m, ok := errMap["message"].(string); ok {
				msg = m
			}
		}
		return nil, &SwiftAuthError{Code: code, Message: msg}
	}

	if data, ok := result["data"].(map[string]any); ok {
		return data, nil
	}
	if data, ok := result["data"]; ok {
		// data could be a slice for list endpoints
		return map[string]any{"_list": data}, nil
	}
	if msg, ok := result["message"]; ok {
		return map[string]any{"message": msg}, nil
	}
	return map[string]any{}, nil
}

// ── Helpers ─────────────────────────────────────────────────────────

func str(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func boolVal(m map[string]any, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func parseUser(data map[string]any) *UserData {
	u := &UserData{
		Key:       str(data, "key"),
		Username:  str(data, "username"),
		Email:     str(data, "email"),
		ExpiresAt: str(data, "expiresAt"),
		Metadata:  data["metadata"],
	}
	if v, ok := data["level"].(float64); ok {
		u.Level = int(v)
	}
	return u
}

func parseVariables(data map[string]any) []Variable {
	list, ok := data["_list"].([]any)
	if !ok {
		return nil
	}
	var vars []Variable
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			vars = append(vars, Variable{Key: str(m, "key"), Value: str(m, "value"), Type: str(m, "type")})
		}
	}
	return vars
}

func parseUserVariables(data map[string]any) []UserVariable {
	list, ok := data["_list"].([]any)
	if !ok {
		return nil
	}
	var vars []UserVariable
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			vars = append(vars, UserVariable{Key: str(m, "key"), Value: str(m, "value")})
		}
	}
	return vars
}

// ── Multi-Layer File Decryption ─────────────────────────────────────

type seededRNG struct {
	state uint64
}

func newSeededRNG(key []byte) *seededRNG {
	var state uint64
	if len(key) >= 8 {
		state = binary.LittleEndian.Uint64(key[:8])
	}
	for i := 8; i < len(key); i++ {
		state ^= uint64(key[i]) << ((uint(i) % 8) * 8)
		state = state*6364136223846793005 + 1442695040888963407
	}
	if state == 0 {
		state = 0xDEADBEEFCAFE1234
	}
	return &seededRNG{state: state}
}

func (r *seededRNG) next() uint64 {
	r.state = r.state*6364136223846793005 + 1442695040888963407
	return r.state
}

func deriveKeys(appSecret, sessionToken string, nonce []byte) (aesKey, shuffleKey, xorKey []byte) {
	mac := hmac.New(sha256.New, []byte(appSecret))
	mac.Write([]byte(sessionToken + "|" + hex.EncodeToString(nonce)))
	master := mac.Sum(nil)

	sub := func(layer byte) []byte {
		h := sha256.Sum256(append(master, layer))
		return h[:]
	}

	return sub(0x01), sub(0x02), sub(0x03)
}

func decryptFileBytes(data []byte, appSecret, sessionToken, nonceHex string) ([]byte, error) {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nil, err
	}
	aesKey, shuffleKey, xorKey := deriveKeys(appSecret, sessionToken, nonce)

	// Layer 4: Rolling XOR
	buf := make([]byte, len(data))
	copy(buf, data)
	for i := range buf {
		buf[i] ^= xorKey[i%len(xorKey)]
	}

	// Layer 3: Fisher-Yates unshuffle
	n := len(buf)
	rng := newSeededRNG(shuffleKey)
	swaps := make([]int, 0, n)
	for i := n - 1; i > 0; i-- {
		swaps = append(swaps, int(rng.next()%uint64(i+1)))
	}
	for k := len(swaps) - 1; k >= 0; k-- {
		i := n - 1 - k
		j := swaps[k]
		buf[i], buf[j] = buf[j], buf[i]
	}

	// Layer 2: AES-256-GCM decrypt
	gcmNonce := buf[:12]
	ciphertextAndTag := buf[12:]
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, gcmNonce, ciphertextAndTag, nil)
	if err != nil {
		return nil, err
	}

	// Layer 1: zlib decompress
	r, err := zlib.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
