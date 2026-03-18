#!/usr/bin/env swift
// ╔═══════════════════════════════════════════════╗
// ║       SwiftAuth SDK — Swift Example App       ║
// ╚═══════════════════════════════════════════════╝
//
// Replace the values below with your own app secret
// from the SwiftAuth dashboard.

import Foundation

// Add the SDK Sources directory to your project to use SwiftAuthClient

let baseURL    = "https://api.swiftauth.net"
let appSecret  = "YOUR_APP_SECRET_HERE"
let appVersion = "1.0.0"

let CYAN    = "\u{001B}[96m"
let GREEN   = "\u{001B}[92m"
let RED     = "\u{001B}[91m"
let YELLOW  = "\u{001B}[93m"
let MAGENTA = "\u{001B}[95m"
let DIM     = "\u{001B}[90m"
let BOLD    = "\u{001B}[1m"
let RESET   = "\u{001B}[0m"

func info(_ label: String, _ msg: String)  { print("  \(DIM)[\(label)]\(RESET) \(msg)") }
func success(_ msg: String)                { print("  \(GREEN)✓ \(msg)\(RESET)") }
func error(_ msg: String)                  { print("  \(RED)✗ \(msg)\(RESET)") }
func detail(_ msg: String)                 { print("    \(CYAN)\(msg)\(RESET)") }
func wsMsg(_ msg: String)                  { print("  \(MAGENTA)⚡ \(msg)\(RESET)") }
func separator()                           { print("  \(DIM)\(String(repeating: "─", count: 49))\(RESET)") }

func ask(_ prompt: String) -> String {
    print("  \(prompt)", terminator: "")
    return readLine()?.trimmingCharacters(in: .whitespaces) ?? ""
}

func main() {
    print("\(CYAN)")
    print("  ╔═══════════════════════════════════════════════╗")
    print("  ║       SwiftAuth SDK — Swift Example App       ║")
    print("  ╚═══════════════════════════════════════════════╝")
    print("\(RESET)")

    let client = SwiftAuthClient(baseURL: baseURL, appSecret: appSecret, appVersion: appVersion)

    do {
        // Step 1: Initialize
        info("Init", "Connecting to SwiftAuth...")
        let initData = try client.initialize()
        let app = client.app!
        success("Connected to \(app.name) v\(app.version)")
        let token = (initData["sessionToken"] as? String) ?? ""
        let displayToken = String(token.prefix(20))
        detail("Session Token: \(displayToken)...")
        detail("HWID Lock: \(app.lockHwid)  |  IP Lock: \(app.lockIp)  |  Anti-Debug: \(app.antiDebug)")

        separator()

        // Step 2: Choose Auth Method
        print("  \(YELLOW)Select authentication method:\(RESET)")
        print("    [1] Login with username/password")
        print("    [2] Register a new account")
        print("    [3] License key only")
        let choice = ask("\(BOLD)>\(RESET) ")

        switch choice {
        case "1":
            let username = ask("Username: ")
            let password = ask("Password: ")
            info("Login", "Authenticating as \(username)...")
            _ = try client.login(username: username, password: password)
        case "2":
            let username = ask("Username: ")
            let password = ask("Password: ")
            let email = ask("Email (optional): ")
            let licenseKey = ask("License Key (optional): ")
            info("Register", "Creating account \(username)...")
            _ = try client.register(username: username, password: password, email: email, licenseKey: licenseKey)
        case "3":
            let key = ask("License Key: ")
            info("License", "Validating license...")
            _ = try client.licenseLogin(licenseKey: key)
        default:
            error("Invalid choice.")
            return
        }

        separator()

        // Step 3: Display User Info
        let user = client.user!
        success("Authenticated as: \(user.key)")
        detail("Level: \(user.level)")
        detail("Expires: \(user.expiresAt ?? "Never")")

        separator()

        // Step 4: Fetch Variables
        info("Variables", "Fetching app variables...")
        do {
            let vars = try client.getAllVariables()
            if vars.isEmpty {
                detail("No variables found.")
            } else {
                for v in vars { detail("  \(v.key) = \(v.value) (\(v.type))") }
            }
        } catch {
            detail("Variables: \(error.localizedDescription)")
        }

        separator()

        // Step 5: User Variables
        info("User Vars", "Testing user variable storage...")
        do {
            let result = try client.setUserVariable(key: "last_seen", value: "\(Int(Date().timeIntervalSince1970))")
            success("Set user variable: \(result.key) = \(result.value)")
            let allVars = try client.getAllUserVariables()
            for v in allVars { detail("  \(v.key) = \(v.value)") }
        } catch {
            detail("User Variables: \(error.localizedDescription)")
        }

        separator()

        // Step 6: Heartbeat
        info("Session", "Sending heartbeat...")
        let hb = try client.heartbeat()
        success("Session alive until \(hb["expiresAt"] as? String ?? "unknown")")

        separator()

        // Step 7: End Session
        info("Cleanup", "Ending session...")
        try client.endSession()
        success("Session ended. Goodbye.")

    } catch let e as SwiftAuthError {
        error("[\(e.code)] \(e.message)")
        exit(1)
    } catch {
        error("Unexpected error: \(error.localizedDescription)")
        exit(1)
    }
}

main()
