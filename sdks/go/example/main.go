// SwiftAuth SDK — Go Example App
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	swiftauth "github.com/swiftauth/swiftauth-go"
)

const (
	baseURL    = "https://api.swiftauth.net"
	appSecret  = "YOUR_APP_SECRET_HERE"
	appVersion = "1.0.0"

	cyan    = "\033[96m"
	green   = "\033[92m"
	red     = "\033[91m"
	yellow  = "\033[93m"
	magenta = "\033[95m"
	dim     = "\033[90m"
	bold    = "\033[1m"
	reset   = "\033[0m"
)

func info(label, msg string)    { fmt.Printf("  %s[%s]%s %s\n", dim, label, reset, msg) }
func success(msg string)        { fmt.Printf("  %s✓ %s%s\n", green, msg, reset) }
func errMsg(msg string)         { fmt.Printf("  %s✗ %s%s\n", red, msg, reset) }
func detail(msg string)         { fmt.Printf("    %s%s%s\n", cyan, msg, reset) }
func wsMsg(msg string)          { fmt.Printf("  %s⚡ %s%s\n", magenta, msg, reset) }
func separator()                { fmt.Printf("  %s─────────────────────────────────────────────────%s\n", dim, reset) }

func ask(prompt string) string {
	fmt.Printf("  %s", prompt)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}

func main() {
	fmt.Printf("%s\n  ╔═══════════════════════════════════════════════╗\n  ║        SwiftAuth SDK — Go Example App         ║\n  ╚═══════════════════════════════════════════════╝\n%s\n", cyan, reset)

	client := swiftauth.NewClient(baseURL, appSecret, appVersion, "")

	// Step 1: Initialize
	info("Init", "Connecting to SwiftAuth...")
	initData, err := client.Init()
	if err != nil {
		errMsg(err.Error())
		os.Exit(1)
	}
	success(fmt.Sprintf("Connected to %s v%s", client.App.Name, client.App.Version))
	token := fmt.Sprintf("%v", initData["sessionToken"])
	if len(token) > 20 {
		token = token[:20] + "..."
	}
	detail(fmt.Sprintf("Session Token: %s", token))
	detail(fmt.Sprintf("HWID Lock: %v  |  IP Lock: %v  |  Anti-Debug: %v", client.App.LockHwid, client.App.LockIp, client.App.AntiDebug))

	separator()

	// Step 2: Choose Auth Method
	fmt.Printf("  %sSelect authentication method:%s\n", yellow, reset)
	fmt.Println("    [1] Login with username/password")
	fmt.Println("    [2] Register a new account")
	fmt.Println("    [3] License key only")
	choice := ask(fmt.Sprintf("%s>%s ", bold, reset))

	switch choice {
	case "1":
		username := ask("Username: ")
		password := ask("Password: ")
		info("Login", fmt.Sprintf("Authenticating as %s...", username))
		_, err = client.Login(username, password, "", "")
	case "2":
		username := ask("Username: ")
		password := ask("Password: ")
		email := ask("Email (optional): ")
		licenseKey := ask("License Key (optional): ")
		info("Register", fmt.Sprintf("Creating account %s...", username))
		_, err = client.Register(username, password, email, "", licenseKey, "")
	case "3":
		key := ask("License Key: ")
		info("License", "Validating license...")
		_, err = client.LicenseLogin(key, "")
	default:
		errMsg("Invalid choice.")
		os.Exit(1)
	}
	if err != nil {
		errMsg(err.Error())
		os.Exit(1)
	}

	separator()

	// Step 3: Display User Info
	success(fmt.Sprintf("Authenticated as: %s", client.User.Key))
	detail(fmt.Sprintf("Level: %d", client.User.Level))
	expires := client.User.ExpiresAt
	if expires == "" {
		expires = "Never"
	}
	detail(fmt.Sprintf("Expires: %s", expires))

	separator()

	// Step 4: Fetch Variables
	info("Variables", "Fetching app variables...")
	vars, err := client.GetAllVariables()
	if err != nil {
		detail(fmt.Sprintf("Variables: %s", err.Error()))
	} else if len(vars) == 0 {
		detail("No variables found.")
	} else {
		for _, v := range vars {
			detail(fmt.Sprintf("  %s = %s (%s)", v.Key, v.Value, v.Type))
		}
	}

	separator()

	// Step 5: User Variables
	info("User Vars", "Testing user variable storage...")
	uv, err := client.SetUserVariable("last_seen", fmt.Sprintf("%d", time.Now().Unix()))
	if err != nil {
		detail(fmt.Sprintf("User Variables: %s", err.Error()))
	} else {
		success(fmt.Sprintf("Set user variable: %s = %s", uv.Key, uv.Value))
		allVars, err := client.GetAllUserVariables()
		if err == nil {
			for _, v := range allVars {
				detail(fmt.Sprintf("  %s = %s", v.Key, v.Value))
			}
		}
	}

	separator()

	// Step 6: Heartbeat
	info("Session", "Sending heartbeat...")
	hb, err := client.Heartbeat()
	if err != nil {
		detail(fmt.Sprintf("Heartbeat: %s", err.Error()))
	} else {
		exp := "unknown"
		if v, ok := hb["expiresAt"].(string); ok {
			exp = v
		}
		success(fmt.Sprintf("Session alive until %s", exp))
	}

	separator()

	// Step 7: WebSocket Demo
	info("WebSocket", "Connecting real-time channel...")
	client.On("pong", func(evt map[string]any) {
		wsMsg("Pong received")
	})
	client.On("chat", func(evt map[string]any) {
		wsMsg(fmt.Sprintf("Chat: %v", evt))
	})
	client.On("force_logout", func(evt map[string]any) {
		errMsg("Force logout received!")
	})

	if wsErr := client.ConnectWs(); wsErr != nil {
		detail(fmt.Sprintf("WebSocket: %s", wsErr.Error()))
	} else {
		success("WebSocket connected.")
		client.WsPing()
		detail("Listening for real-time events...")
		detail("Waiting 5 seconds...")
		time.Sleep(5 * time.Second)
		client.DisconnectWs()
	}

	separator()

	// Step 8: End Session
	info("Cleanup", "Ending session...")
	if err := client.EndSession(); err != nil {
		errMsg(err.Error())
	} else {
		success("Session ended. Goodbye.")
	}
}
