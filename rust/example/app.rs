//! SwiftAuth SDK — Rust Example App
//!
//! Replace the values below with your own app secret
//! from the SwiftAuth dashboard.

use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use swiftauth::SwiftAuthClient;

const BASE_URL: &str = "https://api.swiftauth.net";
const APP_SECRET: &str = "YOUR_APP_SECRET_HERE";
const APP_VERSION: &str = "1.0.0";

const CYAN: &str = "\x1b[96m";
const GREEN: &str = "\x1b[92m";
const RED: &str = "\x1b[91m";
const YELLOW: &str = "\x1b[93m";
const DIM: &str = "\x1b[90m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

fn info(label: &str, msg: &str) { println!("  {DIM}[{label}]{RESET} {msg}"); }
fn success(msg: &str) { println!("  {GREEN}✓ {msg}{RESET}"); }
fn error(msg: &str) { println!("  {RED}✗ {msg}{RESET}"); }
fn detail(msg: &str) { println!("    {CYAN}{msg}{RESET}"); }
fn separator() { println!("  {DIM}─────────────────────────────────────────────────{RESET}"); }

fn ask(prompt: &str) -> String {
    print!("  {prompt}");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn main() {
    println!("{CYAN}");
    println!("  ╔═══════════════════════════════════════════════╗");
    println!("  ║       SwiftAuth SDK — Rust Example App        ║");
    println!("  ╚═══════════════════════════════════════════════╝");
    println!("{RESET}");

    let mut client = SwiftAuthClient::new(BASE_URL, APP_SECRET, APP_VERSION, None);

    // Step 1: Initialize
    info("Init", "Connecting to SwiftAuth...");
    let init_data = match client.init() {
        Ok(d) => d,
        Err(e) => { error(&e.to_string()); std::process::exit(1); }
    };
    let app = client.app.as_ref().unwrap();
    success(&format!("Connected to {} v{}", app.name, app.version));
    let token = init_data.get("sessionToken").and_then(|v| v.as_str()).unwrap_or("");
    let display_token = if token.len() > 20 { &token[..20] } else { token };
    detail(&format!("Session Token: {}...", display_token));
    detail(&format!("HWID Lock: {}  |  IP Lock: {}  |  Anti-Debug: {}", app.lock_hwid, app.lock_ip, app.anti_debug));

    separator();

    // Step 2: Choose Auth Method
    println!("  {YELLOW}Select authentication method:{RESET}");
    println!("    [1] Login with username/password");
    println!("    [2] Register a new account");
    println!("    [3] License key only");
    let choice = ask(&format!("{BOLD}>{RESET} "));

    let auth_result = match choice.as_str() {
        "1" => {
            let username = ask("Username: ");
            let password = ask("Password: ");
            info("Login", &format!("Authenticating as {}...", username));
            client.login(&username, &password, "", "")
        }
        "2" => {
            let username = ask("Username: ");
            let password = ask("Password: ");
            let email = ask("Email (optional): ");
            let license_key = ask("License Key (optional): ");
            info("Register", &format!("Creating account {}...", username));
            client.register(&username, &password, &email, "", &license_key, "")
        }
        "3" => {
            let key = ask("License Key: ");
            info("License", "Validating license...");
            client.license_login(&key, "")
        }
        _ => { error("Invalid choice."); std::process::exit(1); }
    };

    if let Err(e) = auth_result {
        error(&e.to_string());
        std::process::exit(1);
    }

    separator();

    // Step 3: Display User Info
    let user = client.user.as_ref().unwrap();
    success(&format!("Authenticated as: {}", user.key));
    detail(&format!("Level: {}", user.level));
    detail(&format!("Expires: {}", user.expires_at.as_deref().unwrap_or("Never")));

    separator();

    // Step 4: Fetch Variables
    info("Variables", "Fetching app variables...");
    match client.get_all_variables() {
        Ok(vars) if vars.is_empty() => detail("No variables found."),
        Ok(vars) => {
            for v in &vars {
                detail(&format!("  {} = {} ({})", v.key, v.value, v.var_type));
            }
        }
        Err(e) => detail(&format!("Variables: {}", e)),
    }

    separator();

    // Step 5: User Variables
    info("User Vars", "Testing user variable storage...");
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    match client.set_user_variable("last_seen", &now.to_string()) {
        Ok(uv) => {
            success(&format!("Set user variable: {} = {}", uv.key, uv.value));
            if let Ok(all) = client.get_all_user_variables() {
                for v in &all {
                    detail(&format!("  {} = {}", v.key, v.value));
                }
            }
        }
        Err(e) => detail(&format!("User Variables: {}", e)),
    }

    separator();

    // Step 6: Heartbeat
    info("Session", "Sending heartbeat...");
    match client.heartbeat() {
        Ok(hb) => {
            let exp = hb.get("expiresAt").and_then(|v| v.as_str()).unwrap_or("unknown");
            success(&format!("Session alive until {}", exp));
        }
        Err(e) => detail(&format!("Heartbeat: {}", e)),
    }

    separator();

    // Step 7: End Session
    info("Cleanup", "Ending session...");
    match client.end_session() {
        Ok(_) => success("Session ended. Goodbye."),
        Err(e) => error(&e.to_string()),
    }
}
