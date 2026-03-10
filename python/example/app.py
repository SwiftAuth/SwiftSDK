#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════╗
║       SwiftAuth SDK — Python Example App      ║
╚═══════════════════════════════════════════════╝

Replace the values below with your own app secret
from the SwiftAuth dashboard.
"""

import getpass
import sys
import time

from swiftauth import SwiftAuthClient, SwiftAuthError

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
RESET   = "\033[0m"
BOLD    = "\033[1m"


def banner():
    print(f"""{CYAN}
  ╔═══════════════════════════════════════════════╗
  ║       SwiftAuth SDK — Python Example App      ║
  ╚═══════════════════════════════════════════════╝{RESET}
""")


def info(label: str, msg: str):
    print(f"  {DIM}[{label}]{RESET} {msg}")


def success(msg: str):
    print(f"  {GREEN}✓ {msg}{RESET}")


def error(msg: str):
    print(f"  {RED}✗ {msg}{RESET}")


def detail(msg: str):
    print(f"    {CYAN}{msg}{RESET}")


def ws_msg(msg: str):
    print(f"  {MAGENTA}⚡ {msg}{RESET}")


def separator():
    print(f"  {DIM}─────────────────────────────────────────────────{RESET}")


# ── Main ─────────────────────────────────────────────────────────────

def main():
    banner()

    client = SwiftAuthClient(BASE_URL, APP_SECRET, APP_VERSION)

    try:
        # Step 1: Initialize
        info("Init", "Connecting to SwiftAuth...")
        data = client.init()
        success(f"Connected to {client.app.name} v{client.app.version}")
        detail(f"Session Token: {data['sessionToken'][:20]}...")
        detail(f"HWID Lock: {client.app.lock_hwid}  |  IP Lock: {client.app.lock_ip}  |  Anti-Debug: {client.app.anti_debug}")

        separator()

        # Step 2: Choose Auth Method
        print(f"  {YELLOW}Select authentication method:{RESET}")
        print("    [1] Login with username/password")
        print("    [2] Register a new account")
        print("    [3] License key only")
        choice = input(f"\n  {BOLD}>{RESET} ").strip()

        if choice == "1":
            username = input("\n  Username: ").strip()
            password = getpass.getpass("  Password: ")
            info("Login", f"Authenticating as {username}...")
            client.login(username, password)

        elif choice == "2":
            username = input("\n  Username: ").strip()
            password = getpass.getpass("  Password: ")
            email = input("  Email (optional): ").strip()
            license_key = input("  License Key (optional): ").strip()
            info("Register", f"Creating account {username}...")
            client.register(username, password, email=email, license_key=license_key)

        elif choice == "3":
            key = input("\n  License Key: ").strip()
            info("License", "Validating license...")
            client.license_login(key)

        else:
            error("Invalid choice.")
            return

        separator()

        # Step 3: Display User Info
        success(f"Authenticated as: {client.user.key}")
        detail(f"Level: {client.user.level}")
        detail(f"Expires: {client.user.expires_at or 'Never'}")

        separator()

        # Step 4: Fetch Variables
        info("Variables", "Fetching app variables...")
        try:
            variables = client.get_all_variables()
            if not variables:
                detail("No variables found.")
            else:
                for v in variables:
                    detail(f"  {v.key} = {v.value} ({v.type})")
        except SwiftAuthError as e:
            detail(f"Variables: {e.message}")

        separator()

        # Step 5: User Variables
        info("User Vars", "Testing user variable storage...")
        try:
            result = client.set_user_variable("last_seen", str(int(time.time())))
            success(f"Set user variable: {result.key} = {result.value}")

            all_vars = client.get_all_user_variables()
            for v in all_vars:
                detail(f"  {v.key} = {v.value}")
        except SwiftAuthError as e:
            detail(f"User Variables: {e.message}")

        separator()

        # Step 6: Heartbeat
        info("Session", "Sending heartbeat...")
        hb = client.heartbeat()
        success(f"Session alive until {hb.get('expiresAt', 'unknown')}")

        separator()

        # Step 7: WebSocket Demo
        info("WebSocket", "Connecting real-time channel...")
        try:
            client.on("force_logout", lambda evt: error("Force logout received!"))
            client.on("chat", lambda evt: ws_msg(f"Chat: {evt.get('data', {})}"))
            client.on("pong", lambda evt: ws_msg("Pong received"))
            client.on("*", lambda evt: ws_msg(f"[{evt.get('type', '?')}]"))

            client.connect_ws()
            success("WebSocket connected.")
            detail("Listening for real-time events...")

            client.ws_ping()
            time.sleep(1)

            detail("Press Enter to disconnect...")
            input()
            client.disconnect_ws()
        except Exception as e:
            detail(f"WebSocket: {e}")

        separator()

        # Step 8: End Session
        info("Cleanup", "Ending session...")
        client.end_session()
        success("Session ended. Goodbye.")

    except SwiftAuthError as e:
        error(f"[{e.code}] {e.message}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n  {DIM}Interrupted.{RESET}")
    except Exception as e:
        error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
