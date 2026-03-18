#!/usr/bin/env ruby
# ╔═══════════════════════════════════════════════╗
# ║       SwiftAuth SDK — Ruby Example App        ║
# ╚═══════════════════════════════════════════════╝
#
# Replace the values below with your own app secret
# from the SwiftAuth dashboard.

require_relative "../lib/swiftauth"

BASE_URL    = "https://api.swiftauth.net"
APP_SECRET  = "YOUR_APP_SECRET_HERE"
APP_VERSION = "1.0.0"

# ── Colors ───────────────────────────────────────────────────────────

CYAN    = "\033[96m"
GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
MAGENTA = "\033[95m"
DIM     = "\033[90m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

def info(label, msg)    = puts "  #{DIM}[#{label}]#{RESET} #{msg}"
def success(msg)        = puts "  #{GREEN}✓ #{msg}#{RESET}"
def error(msg)          = puts "  #{RED}✗ #{msg}#{RESET}"
def detail(msg)         = puts "    #{CYAN}#{msg}#{RESET}"
def ws_msg(msg)         = puts "  #{MAGENTA}⚡ #{msg}#{RESET}"
def separator           = puts "  #{DIM}#{"─" * 49}#{RESET}"

def main
  puts "#{CYAN}"
  puts "  ╔═══════════════════════════════════════════════╗"
  puts "  ║       SwiftAuth SDK — Ruby Example App        ║"
  puts "  ╚═══════════════════════════════════════════════╝"
  puts "#{RESET}"

  client = SwiftAuth::Client.new(
    base_url: BASE_URL,
    app_secret: APP_SECRET,
    app_version: APP_VERSION,
  )

  begin
    # Step 1: Initialize
    info("Init", "Connecting to SwiftAuth...")
    data = client.init
    success("Connected to #{client.app.name} v#{client.app.version}")
    token = data["sessionToken"].to_s
    detail("Session Token: #{token[0, 20]}...")
    detail("HWID Lock: #{client.app.lock_hwid}  |  IP Lock: #{client.app.lock_ip}  |  Anti-Debug: #{client.app.anti_debug}")

    separator

    # Step 2: Choose Auth Method
    puts "  #{YELLOW}Select authentication method:#{RESET}"
    puts "    [1] Login with username/password"
    puts "    [2] Register a new account"
    puts "    [3] License key only"
    print "  #{BOLD}>#{RESET} "
    choice = gets&.strip

    case choice
    when "1"
      print "  Username: "
      username = gets&.strip
      print "  Password: "
      password = gets&.strip
      info("Login", "Authenticating as #{username}...")
      client.login(username, password)
    when "2"
      print "  Username: "
      username = gets&.strip
      print "  Password: "
      password = gets&.strip
      print "  Email (optional): "
      email = gets&.strip
      print "  License Key (optional): "
      license_key = gets&.strip
      info("Register", "Creating account #{username}...")
      client.register(username, password, email: email || "", license_key: license_key || "")
    when "3"
      print "  License Key: "
      key = gets&.strip
      info("License", "Validating license...")
      client.license_login(key)
    else
      error("Invalid choice.")
      return
    end

    separator

    # Step 3: Display User Info
    success("Authenticated as: #{client.user.key}")
    detail("Level: #{client.user.level}")
    detail("Expires: #{client.user.expires_at || "Never"}")

    separator

    # Step 4: Fetch Variables
    info("Variables", "Fetching app variables...")
    begin
      vars = client.get_all_variables
      if vars.empty?
        detail("No variables found.")
      else
        vars.each { |v| detail("  #{v.key} = #{v.value} (#{v.type})") }
      end
    rescue SwiftAuth::Error => e
      detail("Variables: #{e.message}")
    end

    separator

    # Step 5: User Variables
    info("User Vars", "Testing user variable storage...")
    begin
      result = client.set_user_variable("last_seen", Time.now.to_i.to_s)
      success("Set user variable: #{result.key} = #{result.value}")

      all_vars = client.get_all_user_variables
      all_vars.each { |v| detail("  #{v.key} = #{v.value}") }
    rescue SwiftAuth::Error => e
      detail("User Variables: #{e.message}")
    end

    separator

    # Step 6: Heartbeat
    info("Session", "Sending heartbeat...")
    hb = client.heartbeat
    success("Session alive until #{hb["expiresAt"] || "unknown"}")

    separator

    # Step 7: End Session
    info("Cleanup", "Ending session...")
    client.end_session
    success("Session ended. Goodbye.")

  rescue SwiftAuth::Error => e
    error(e.message)
    exit 1
  rescue Interrupt
    puts "\n  #{DIM}Interrupted.#{RESET}"
  rescue => e
    error("Unexpected error: #{e.message}")
    exit 1
  end
end

main
