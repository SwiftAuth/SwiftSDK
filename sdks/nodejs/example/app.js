#!/usr/bin/env node
/**
 * ╔═══════════════════════════════════════════════╗
 * ║      SwiftAuth SDK — Node.js Example App      ║
 * ╚═══════════════════════════════════════════════╝
 *
 * Replace the values below with your own app secret
 * from the SwiftAuth dashboard.
 */

const readline = require("readline");
const { SwiftAuthClient, SwiftAuthError } = require("../src/index");

const BASE_URL    = "https://api.swiftauth.net";
const APP_SECRET  = "YOUR_APP_SECRET_HERE";
const APP_VERSION = "1.0.0";

// ── Colors ──────────────────────────────────────────────────────────

const c = {
    cyan:    (s) => `\x1b[96m${s}\x1b[0m`,
    green:   (s) => `\x1b[92m${s}\x1b[0m`,
    red:     (s) => `\x1b[91m${s}\x1b[0m`,
    yellow:  (s) => `\x1b[93m${s}\x1b[0m`,
    magenta: (s) => `\x1b[95m${s}\x1b[0m`,
    dim:     (s) => `\x1b[90m${s}\x1b[0m`,
    bold:    (s) => `\x1b[1m${s}\x1b[0m`,
};

const info      = (label, msg) => console.log(`  ${c.dim(`[${label}]`)} ${msg}`);
const success   = (msg) => console.log(`  ${c.green(`✓ ${msg}`)}`);
const error     = (msg) => console.log(`  ${c.red(`✗ ${msg}`)}`);
const detail    = (msg) => console.log(`    ${c.cyan(msg)}`);
const wsMsg     = (msg) => console.log(`  ${c.magenta(`⚡ ${msg}`)}`);
const separator = ()    => console.log(`  ${c.dim("─────────────────────────────────────────────────")}`);

function ask(question) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve) => {
        rl.question(`  ${question}`, (answer) => {
            rl.close();
            resolve(answer.trim());
        });
    });
}

// ── Main ────────────────────────────────────────────────────────────

async function main() {
    console.log(c.cyan(`
  ╔═══════════════════════════════════════════════╗
  ║      SwiftAuth SDK — Node.js Example App      ║
  ╚═══════════════════════════════════════════════╝
`));

    const client = new SwiftAuthClient({
        baseUrl: BASE_URL,
        appSecret: APP_SECRET,
        appVersion: APP_VERSION,
    });

    try {
        // Step 1: Initialize
        info("Init", "Connecting to SwiftAuth...");
        const init = await client.init();
        success(`Connected to ${client.app.name} v${client.app.version}`);
        detail(`Session Token: ${init.sessionToken.slice(0, 20)}...`);
        detail(`HWID Lock: ${client.app.lockHwid}  |  IP Lock: ${client.app.lockIp}  |  Anti-Debug: ${client.app.antiDebug}`);

        separator();

        // Step 2: Choose Auth Method
        console.log(`  ${c.yellow("Select authentication method:")}`);
        console.log("    [1] Login with username/password");
        console.log("    [2] Register a new account");
        console.log("    [3] License key only");
        const choice = await ask(`${c.bold(">")} `);

        if (choice === "1") {
            const username = await ask("Username: ");
            const password = await ask("Password: ");
            info("Login", `Authenticating as ${username}...`);
            await client.login(username, password);

        } else if (choice === "2") {
            const username = await ask("Username: ");
            const password = await ask("Password: ");
            const email = await ask("Email (optional): ");
            const licenseKey = await ask("License Key (optional): ");
            info("Register", `Creating account ${username}...`);
            await client.register(username, password, { email, licenseKey });

        } else if (choice === "3") {
            const key = await ask("License Key: ");
            info("License", "Validating license...");
            await client.licenseLogin(key);

        } else {
            error("Invalid choice.");
            process.exit(1);
        }

        separator();

        // Step 3: Display User Info
        success(`Authenticated as: ${client.user.key}`);
        detail(`Level: ${client.user.level}`);
        detail(`Expires: ${client.user.expiresAt || "Never"}`);

        separator();

        // Step 4: Fetch Variables
        info("Variables", "Fetching app variables...");
        try {
            const vars = await client.getAllVariables();
            if (!vars || vars.length === 0) {
                detail("No variables found.");
            } else {
                for (const v of vars) {
                    detail(`  ${v.key} = ${v.value} (${v.type})`);
                }
            }
        } catch (e) {
            detail(`Variables: ${e.message}`);
        }

        separator();

        // Step 5: User Variables
        info("User Vars", "Testing user variable storage...");
        try {
            const result = await client.setUserVariable("last_seen", String(Date.now()));
            success(`Set user variable: ${result.key} = ${result.value}`);

            const allVars = await client.getAllUserVariables();
            for (const v of (allVars || [])) {
                detail(`  ${v.key} = ${v.value}`);
            }
        } catch (e) {
            detail(`User Variables: ${e.message}`);
        }

        separator();

        // Step 6: Heartbeat
        info("Session", "Sending heartbeat...");
        const hb = await client.heartbeat();
        success(`Session alive until ${hb.expiresAt || "unknown"}`);

        separator();

        // Step 7: WebSocket Demo
        info("WebSocket", "Connecting real-time channel...");
        try {
            client.on("ws:open", () => success("WebSocket connected."));
            client.on("ws:force_logout", () => error("Force logout received!"));
            client.on("ws:chat", (data) => wsMsg(`Chat: ${JSON.stringify(data)}`));
            client.on("ws:pong", () => wsMsg("Pong received"));
            client.on("ws:message", (evt) => wsMsg(`[${evt.type}]`));
            client.on("ws:close", () => detail("WebSocket closed."));

            client.connectWs();
            client.startWsHeartbeat(25000);

            await new Promise((r) => setTimeout(r, 1000));
            client.wsPing();

            detail("Listening for real-time events...");
            detail("Press Ctrl+C to exit.");

            await new Promise((r) => setTimeout(r, 30000));
            client.disconnectWs();
        } catch (e) {
            detail(`WebSocket: ${e.message}`);
        }

        separator();

        // Step 8: End Session
        info("Cleanup", "Ending session...");
        await client.endSession();
        success("Session ended. Goodbye.");

    } catch (e) {
        if (e instanceof SwiftAuthError) {
            error(`[${e.code}] ${e.message}`);
        } else {
            error(`Unexpected error: ${e.message}`);
        }
        process.exit(1);
    }
}

main().catch(console.error);
