/*
 * ╔═══════════════════════════════════════════════╗
 * ║       SwiftAuth SDK — C++ Example App         ║
 * ╚═══════════════════════════════════════════════╝
 *
 * Replace the values below with your own app secret
 * from the SwiftAuth dashboard.
 *
 * Build:
 *   mkdir build && cd build
 *   cmake .. && make
 *   ./swiftauth_example
 */

#include "swiftauth/swiftauth.hpp"

#include <iostream>
#include <string>

static const std::string BASE_URL    = "https://api.swiftauth.net";
static const std::string APP_SECRET  = "YOUR_APP_SECRET_HERE";
static const std::string APP_VERSION = "1.0.0";

// ── Colors ──────────────────────────────────────────────────────────

namespace color {
    const char* cyan    = "\033[96m";
    const char* green   = "\033[92m";
    const char* red     = "\033[91m";
    const char* yellow  = "\033[93m";
    const char* magenta = "\033[95m";
    const char* dim     = "\033[90m";
    const char* bold    = "\033[1m";
    const char* reset   = "\033[0m";
}

void info(const std::string& label, const std::string& msg) {
    std::cout << "  " << color::dim << "[" << label << "]" << color::reset << " " << msg << "\n";
}

void ok(const std::string& msg) {
    std::cout << "  " << color::green << "✓ " << msg << color::reset << "\n";
}

void err(const std::string& msg) {
    std::cout << "  " << color::red << "✗ " << msg << color::reset << "\n";
}

void detail(const std::string& msg) {
    std::cout << "    " << color::cyan << msg << color::reset << "\n";
}

void separator() {
    std::cout << "  " << color::dim << "─────────────────────────────────────────────────" << color::reset << "\n";
}

std::string prompt(const std::string& label) {
    std::string val;
    std::cout << "  " << label;
    std::getline(std::cin, val);
    return val;
}

// ── Main ────────────────────────────────────────────────────────────

int main() {
    std::cout << color::cyan << R"(
  ╔═══════════════════════════════════════════════╗
  ║       SwiftAuth SDK — C++ Example App         ║
  ╚═══════════════════════════════════════════════╝
)" << color::reset << "\n";

    swiftauth::Client client(BASE_URL, APP_SECRET, APP_VERSION);

    try {
        // Step 1: Initialize
        info("Init", "Connecting to SwiftAuth...");
        auto init = client.init();
        ok("Connected to " + init.app.name + " v" + init.app.version);
        detail("Session Token: " + init.session_token.substr(0, 20) + "...");
        detail("HWID Lock: " + std::string(init.app.lock_hwid ? "true" : "false")
             + "  |  IP Lock: " + std::string(init.app.lock_ip ? "true" : "false")
             + "  |  Anti-Debug: " + std::string(init.app.anti_debug ? "true" : "false"));

        separator();

        // Step 2: Choose Auth Method
        std::cout << "  " << color::yellow << "Select authentication method:" << color::reset << "\n";
        std::cout << "    [1] Login with username/password\n";
        std::cout << "    [2] Register a new account\n";
        std::cout << "    [3] License key only\n";
        auto choice = prompt(std::string(color::bold) + "> " + color::reset);

        if (choice == "1") {
            auto username = prompt("Username: ");
            auto password = prompt("Password: ");
            info("Login", "Authenticating as " + username + "...");
            client.login(username, password);

        } else if (choice == "2") {
            auto username = prompt("Username: ");
            auto password = prompt("Password: ");
            auto email    = prompt("Email (optional): ");
            auto license  = prompt("License Key (optional): ");
            info("Register", "Creating account " + username + "...");
            client.register_user(username, password, email, "", license);

        } else if (choice == "3") {
            auto key = prompt("License Key: ");
            info("License", "Validating license...");
            client.license_login(key);

        } else {
            err("Invalid choice.");
            return 1;
        }

        separator();

        // Step 3: Display User Info
        auto user = client.user();
        ok("Authenticated as: " + user.key);
        detail("Level: " + std::to_string(user.level));
        detail("Expires: " + (user.expires_at.empty() ? "Never" : user.expires_at));

        separator();

        // Step 4: Fetch a Variable
        info("Variables", "Fetching app variable...");
        try {
            auto v = client.get_variable("app_name");
            detail(v.key + " = " + v.value + " (" + v.type + ")");
        } catch (const swiftauth::Exception& e) {
            detail(std::string("Variables: ") + e.what());
        }

        separator();

        // Step 5: User Variables
        info("User Vars", "Testing user variable storage...");
        try {
            auto result = client.set_user_variable("last_seen", "now");
            ok("Set user variable: " + result.key + " = " + result.value);
        } catch (const swiftauth::Exception& e) {
            detail(std::string("User Variables: ") + e.what());
        }

        separator();

        // Step 6: Heartbeat
        info("Session", "Sending heartbeat...");
        auto expires = client.heartbeat();
        ok("Session alive until " + expires);

        separator();

        // Step 7: Check for Updates
        info("Updates", "Checking for application updates...");
        auto update = client.check_update(APP_VERSION);
        if (update.update_available) {
            detail("Update available: " + update.latest_version);
        } else {
            ok("Running latest version.");
        }

        separator();

        // Step 8: End Session
        info("Cleanup", "Ending session...");
        client.end_session();
        ok("Session ended. Goodbye.");

    } catch (const swiftauth::Exception& e) {
        err(std::string("[") + e.code + "] " + e.msg);
        return 1;
    } catch (const std::exception& e) {
        err(std::string("Unexpected error: ") + e.what());
        return 1;
    }

    return 0;
}
