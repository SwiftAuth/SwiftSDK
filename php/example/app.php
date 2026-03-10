#!/usr/bin/env php
<?php
/**
 * ╔═══════════════════════════════════════════════╗
 * ║        SwiftAuth SDK — PHP Example App        ║
 * ╚═══════════════════════════════════════════════╝
 *
 * Replace the values below with your own app secret
 * from the SwiftAuth dashboard.
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/SwiftAuthClient.php';

use SwiftAuth\SwiftAuthClient;
use SwiftAuth\SwiftAuthException;

const BASE_URL    = 'https://api.swiftauth.net';
const APP_SECRET  = 'YOUR_APP_SECRET_HERE';
const APP_VERSION = '1.0.0';

// ── Colors ───────────────────────────────────────────────────────────

const CYAN    = "\033[96m";
const GREEN   = "\033[92m";
const RED     = "\033[91m";
const YELLOW  = "\033[93m";
const MAGENTA = "\033[95m";
const DIM     = "\033[90m";
const BOLD    = "\033[1m";
const RESET   = "\033[0m";

function info(string $label, string $msg): void    { echo "  " . DIM . "[$label]" . RESET . " $msg\n"; }
function success(string $msg): void                { echo "  " . GREEN . "✓ $msg" . RESET . "\n"; }
function error(string $msg): void                  { echo "  " . RED . "✗ $msg" . RESET . "\n"; }
function detail(string $msg): void                 { echo "    " . CYAN . "$msg" . RESET . "\n"; }
function wsMsg(string $msg): void                  { echo "  " . MAGENTA . "⚡ $msg" . RESET . "\n"; }
function separator(): void                         { echo "  " . DIM . str_repeat("─", 49) . RESET . "\n"; }

function ask(string $prompt): string {
    echo "  $prompt";
    return trim(fgets(STDIN) ?: '');
}

// ── Main ─────────────────────────────────────────────────────────────

function main(): void
{
    echo CYAN . "\n";
    echo "  ╔═══════════════════════════════════════════════╗\n";
    echo "  ║        SwiftAuth SDK — PHP Example App        ║\n";
    echo "  ╚═══════════════════════════════════════════════╝\n";
    echo RESET . "\n";

    $client = new SwiftAuthClient(BASE_URL, APP_SECRET, APP_VERSION);

    try {
        // Step 1: Initialize
        info('Init', 'Connecting to SwiftAuth...');
        $data = $client->init();
        success("Connected to {$client->app['name']} v{$client->app['version']}");
        $token = $data['sessionToken'] ?? '';
        detail("Session Token: " . substr($token, 0, 20) . "...");
        detail("HWID Lock: " . ($client->app['lockHwid'] ? 'true' : 'false')
            . "  |  IP Lock: " . ($client->app['lockIp'] ? 'true' : 'false')
            . "  |  Anti-Debug: " . ($client->app['antiDebug'] ? 'true' : 'false'));

        separator();

        // Step 2: Choose Auth Method
        echo "  " . YELLOW . "Select authentication method:" . RESET . "\n";
        echo "    [1] Login with username/password\n";
        echo "    [2] Register a new account\n";
        echo "    [3] License key only\n";
        $choice = ask(BOLD . ">" . RESET . " ");

        switch ($choice) {
            case '1':
                $username = ask('Username: ');
                $password = ask('Password: ');
                info('Login', "Authenticating as $username...");
                $client->login($username, $password);
                break;
            case '2':
                $username = ask('Username: ');
                $password = ask('Password: ');
                $email = ask('Email (optional): ');
                $licenseKey = ask('License Key (optional): ');
                info('Register', "Creating account $username...");
                $client->register($username, $password, $email, '', $licenseKey);
                break;
            case '3':
                $key = ask('License Key: ');
                info('License', 'Validating license...');
                $client->licenseLogin($key);
                break;
            default:
                error('Invalid choice.');
                return;
        }

        separator();

        // Step 3: Display User Info
        success("Authenticated as: {$client->user['key']}");
        detail("Level: {$client->user['level']}");
        detail("Expires: " . ($client->user['expiresAt'] ?? 'Never'));

        separator();

        // Step 4: Fetch Variables
        info('Variables', 'Fetching app variables...');
        try {
            $vars = $client->getAllVariables();
            if (empty($vars) || !is_array($vars)) {
                detail('No variables found.');
            } else {
                foreach ($vars as $v) {
                    detail("  {$v['key']} = {$v['value']} (" . ($v['type'] ?? 'STRING') . ")");
                }
            }
        } catch (SwiftAuthException $e) {
            detail("Variables: {$e->getMessage()}");
        }

        separator();

        // Step 5: User Variables
        info('User Vars', 'Testing user variable storage...');
        try {
            $result = $client->setUserVariable('last_seen', (string) time());
            success("Set user variable: {$result['key']} = {$result['value']}");

            $allVars = $client->getAllUserVariables();
            if (is_array($allVars)) {
                foreach ($allVars as $v) {
                    detail("  {$v['key']} = {$v['value']}");
                }
            }
        } catch (SwiftAuthException $e) {
            detail("User Variables: {$e->getMessage()}");
        }

        separator();

        // Step 6: Heartbeat
        info('Session', 'Sending heartbeat...');
        $hb = $client->heartbeat();
        success("Session alive until " . ($hb['expiresAt'] ?? 'unknown'));

        separator();

        // Step 7: End Session
        info('Cleanup', 'Ending session...');
        $client->endSession();
        success('Session ended. Goodbye.');

    } catch (SwiftAuthException $e) {
        error($e->getMessage());
        exit(1);
    } catch (\Throwable $e) {
        error("Unexpected error: {$e->getMessage()}");
        exit(1);
    }
}

main();
