require "json"
require "net/http"
require "uri"
require "openssl"
require "socket"
require "zlib"
require "digest"

module SwiftAuth
  class Error < StandardError
    attr_reader :code

    def initialize(code, message)
      @code = code
      super("[#{code}] #{message}")
    end
  end

  AppInfo = Struct.new(:name, :version, :anti_debug, :anti_vm, :lock_hwid, :lock_ip, :lock_pc_name, keyword_init: true)
  UserData = Struct.new(:key, :username, :email, :level, :expires_at, :metadata, keyword_init: true)
  Variable = Struct.new(:key, :value, :type, keyword_init: true)
  UserVariable = Struct.new(:key, :value, keyword_init: true)

  class Client
    attr_reader :app, :user, :session_token

    def initialize(base_url:, app_secret:, app_version: "1.0.0", hwid: nil)
      @base_url = base_url.chomp("/")
      @secret = app_secret
      @version = app_version
      @hwid = hwid || "#{Socket.gethostname}-#{ENV["USER"] || ENV["USERNAME"] || "unknown"}"
      @session_token = nil
      @nonce = nil
      @app = nil
      @user = nil
      @ws_callbacks = Hash.new { |h, k| h[k] = [] }
    end

    def initialized?
      !@session_token.nil?
    end

    # ── Initialization ──────────────────────────────────────────────

    def init
      data = post("/api/client/init", {
        secret: @secret,
        version: @version,
        hwid: @hwid,
      })
      @session_token = data["sessionToken"]
      @app = AppInfo.new(
        name: data["appName"] || "",
        version: data["appVersion"] || "",
        anti_debug: data["antiDebug"] || false,
        anti_vm: data["antiVM"] || false,
        lock_hwid: data["lockHwid"] || false,
        lock_ip: data["lockIp"] || false,
        lock_pc_name: data["lockPcName"] || false,
      )
      data
    end

    # ── Authentication ──────────────────────────────────────────────

    def login(username, password, license_key: "", pc_name: "")
      require_init!
      fetch_nonce
      data = post_with_nonce("/api/client/login", {
        sessionToken: @session_token,
        username: username,
        password: password,
        licenseKey: license_key,
        hwid: @hwid,
        pcName: pc_name,
      })
      @user = parse_user(data)
      data
    end

    def register(username, password, email: "", display_name: "", license_key: "", pc_name: "")
      require_init!
      fetch_nonce
      data = post_with_nonce("/api/client/register", {
        sessionToken: @session_token,
        username: username,
        password: password,
        email: email,
        displayName: display_name,
        licenseKey: license_key,
        hwid: @hwid,
        pcName: pc_name,
      })
      @user = parse_user(data)
      data
    end

    def license_login(license_key, pc_name: "")
      require_init!
      fetch_nonce
      data = post_with_nonce("/api/client/license", {
        sessionToken: @session_token,
        licenseKey: license_key,
        hwid: @hwid,
        pcName: pc_name,
      })
      @user = parse_user(data)
      data
    end

    # ── Token Validation ────────────────────────────────────────────

    def validate_token(token)
      require_init!
      post("/api/client/token", { sessionToken: @session_token, token: token })
    end

    # ── License Activation ──────────────────────────────────────────

    def activate(license_key)
      require_init!
      fetch_nonce
      post_with_nonce("/api/client/activate", { sessionToken: @session_token, licenseKey: license_key })
    end

    # ── Variables ───────────────────────────────────────────────────

    def get_variable(key)
      require_init!
      data = post("/api/client/variable", { sessionToken: @session_token, key: key })
      Variable.new(key: data["key"], value: data["value"], type: data["type"] || "STRING")
    end

    def get_all_variables
      require_init!
      data = post("/api/client/variables", { sessionToken: @session_token })
      return [] unless data.is_a?(Array)
      data.map { |v| Variable.new(key: v["key"], value: v["value"], type: v["type"] || "STRING") }
    end

    # ── User Variables ──────────────────────────────────────────────

    def get_user_variable(key)
      require_init!
      data = post("/api/client/user-variable", { sessionToken: @session_token, key: key })
      UserVariable.new(key: data["key"], value: data["value"])
    end

    def get_all_user_variables
      require_init!
      data = post("/api/client/user-variables", { sessionToken: @session_token })
      return [] unless data.is_a?(Array)
      data.map { |v| UserVariable.new(key: v["key"], value: v["value"]) }
    end

    def set_user_variable(key, value)
      require_init!
      data = post("/api/client/set-user-variable", { sessionToken: @session_token, key: key, value: value })
      UserVariable.new(key: data["key"], value: data["value"])
    end

    def delete_user_variable(key)
      require_init!
      post("/api/client/delete-user-variable", { sessionToken: @session_token, key: key })
    end

    # ── Files ───────────────────────────────────────────────────────

    def download_file(name)
      require_init!
      uri = URI("#{@base_url}/api/client/file")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      req = Net::HTTP::Post.new(uri.path, { "Content-Type" => "application/json" })
      req.body = JSON.generate({ sessionToken: @session_token, name: name })
      resp = http.request(req)
      data = resp.body.b

      if resp["x-file-encrypted"] == "1" && resp["x-file-nonce"]
        data = decrypt_file_bytes(data, @secret, @session_token, resp["x-file-nonce"])
      end

      data
    end

    def check_update(current_version, file_name: "")
      require_init!
      post("/api/client/check-update", {
        sessionToken: @session_token,
        currentVersion: current_version,
        fileName: file_name,
      })
    end

    # ── Session Management ──────────────────────────────────────────

    def heartbeat
      require_init!
      fetch_nonce
      post_with_nonce("/api/client/heartbeat", { sessionToken: @session_token })
    end

    def check_session
      require_init!
      post("/api/client/check", { sessionToken: @session_token })
    end

    def end_session
      require_init!
      post("/api/client/end", { sessionToken: @session_token })
      @session_token = nil
      @user = nil
    end

    # ── User Info ───────────────────────────────────────────────────

    def get_user
      require_init!
      post("/api/client/user", { sessionToken: @session_token })
    end

    def change_password(current_password, new_password)
      require_init!
      post("/api/client/change-password", {
        sessionToken: @session_token,
        currentPassword: current_password,
        newPassword: new_password,
      })
    end

    def request_reset
      require_init!
      post("/api/client/request-reset", { sessionToken: @session_token })
    end

    # ── Client Log ──────────────────────────────────────────────────

    def log(message, level: "INFO")
      require_init!
      post("/api/client/log", { sessionToken: @session_token, message: message, level: level })
    end

    private

    def require_init!
      raise Error.new("NOT_INITIALIZED", "Call init() before using other methods.") unless @session_token
    end

    def fetch_nonce
      data = post("/api/client/nonce", { sessionToken: @session_token })
      @nonce = data["nonce"]
    end

    def post(path, payload)
      request(path, payload, {})
    end

    def post_with_nonce(path, payload)
      request(path, payload, { "X-Nonce" => @nonce })
    end

    def request(path, payload, extra_headers)
      uri = URI("#{@base_url}#{path}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"

      req = Net::HTTP::Post.new(uri.path, {
        "Content-Type" => "application/json",
        "Accept" => "application/json",
      }.merge(extra_headers))
      req.body = JSON.generate(payload)

      resp = http.request(req)
      body = JSON.parse(resp.body)

      unless body["success"]
        err = body["error"] || {}
        raise Error.new(err["code"] || "UNKNOWN", err["message"] || "Request failed")
      end

      body["data"] || body["message"] || {}
    end

    def parse_user(data)
      UserData.new(
        key: data["key"] || "",
        username: data["username"] || "",
        email: data["email"] || "",
        level: data["level"] || 0,
        expires_at: data["expiresAt"],
        metadata: data["metadata"],
      )
    end

    # ── Multi-Layer File Decryption ─────────────────────────────────

    def decrypt_file_bytes(data, app_secret, session_token, nonce_hex)
      nonce = [nonce_hex].pack("H*")
      aes_key, shuffle_key, xor_key = derive_keys(app_secret, session_token, nonce)

      # Layer 4: Rolling XOR
      buf = data.bytes.to_a
      buf.each_index { |i| buf[i] ^= xor_key.bytes[i % xor_key.bytesize] }

      # Layer 3: Fisher-Yates unshuffle
      n = buf.length
      rng = SeededRNG.new(shuffle_key)
      swaps = []
      (n - 1).downto(1) { |i| swaps << (rng.next_val % (i + 1)) }
      (swaps.length - 1).downto(0) do |k|
        i = n - 1 - k
        j = swaps[k]
        buf[i], buf[j] = buf[j], buf[i]
      end

      # Layer 2: AES-256-GCM
      gcm_nonce = buf[0, 12].pack("C*")
      ciphertext_and_tag = buf[12..].pack("C*")
      tag = ciphertext_and_tag[-16..]
      ciphertext = ciphertext_and_tag[0...-16]
      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.decrypt
      cipher.key = aes_key
      cipher.iv = gcm_nonce
      cipher.auth_tag = tag
      plaintext = cipher.update(ciphertext) + cipher.final

      # Layer 1: zlib decompress
      Zlib::Inflate.inflate(plaintext)
    end

    def derive_keys(app_secret, session_token, nonce)
      master = OpenSSL::HMAC.digest("SHA256", app_secret, "#{session_token}|#{nonce.unpack1("H*")}")
      [0x01, 0x02, 0x03].map { |layer| Digest::SHA256.digest(master + [layer].pack("C")) }
    end

    class SeededRNG
      def initialize(key)
        @state = 0
        if key.bytesize >= 8
          @state = key[0, 8].unpack1("Q<")
        end
        (8...key.bytesize).each do |i|
          @state ^= (key.getbyte(i) & 0xFF) << ((i % 8) * 8)
          @state = (@state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        end
        @state = 0xDEADBEEFCAFE1234 if @state == 0
      end

      def next_val
        @state = (@state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        @state
      end
    end
  end
end
