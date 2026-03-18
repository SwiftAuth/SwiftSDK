#!/usr/bin/env lua
--- ╔═══════════════════════════════════════════════╗
--- ║        SwiftAuth SDK — Lua Example App        ║
--- ╚═══════════════════════════════════════════════╝
---
--- Replace the values below with your own app secret
--- from the SwiftAuth dashboard.
---
--- Requirements: luarocks install lua-cjson luasocket

package.path = package.path .. ";../?.lua;../swiftauth/?.lua"

local SwiftAuth = require("swiftauth")

local BASE_URL    = "https://api.swiftauth.net"
local APP_SECRET  = "YOUR_APP_SECRET_HERE"
local APP_VERSION = "1.0.0"

-- ── Colors ──────────────────────────────────────────────────────────

local CYAN    = "\027[96m"
local GREEN   = "\027[92m"
local RED     = "\027[91m"
local YELLOW  = "\027[93m"
local MAGENTA = "\027[95m"
local DIM     = "\027[90m"
local BOLD    = "\027[1m"
local RESET   = "\027[0m"

local function info(label, msg)    io.write("  " .. DIM .. "[" .. label .. "]" .. RESET .. " " .. msg .. "\n") end
local function success(msg)        io.write("  " .. GREEN .. "✓ " .. msg .. RESET .. "\n") end
local function err(msg)            io.write("  " .. RED .. "✗ " .. msg .. RESET .. "\n") end
local function detail(msg)         io.write("    " .. CYAN .. msg .. RESET .. "\n") end
local function ws_msg(msg)         io.write("  " .. MAGENTA .. "⚡ " .. msg .. RESET .. "\n") end
local function separator()         io.write("  " .. DIM .. string.rep("─", 49) .. RESET .. "\n") end

local function ask(prompt)
    io.write("  " .. prompt)
    io.flush()
    return io.read("*l"):match("^%s*(.-)%s*$")
end

-- ── Main ────────────────────────────────────────────────────────────

local function main()
    io.write(CYAN .. "\n")
    io.write("  ╔═══════════════════════════════════════════════╗\n")
    io.write("  ║        SwiftAuth SDK — Lua Example App        ║\n")
    io.write("  ╚═══════════════════════════════════════════════╝\n")
    io.write(RESET .. "\n")

    local client = SwiftAuth.new(BASE_URL, APP_SECRET, APP_VERSION)

    -- Step 1: Initialize
    info("Init", "Connecting to SwiftAuth...")
    local ok, init_data = pcall(function() return client:init() end)
    if not ok then
        err(tostring(init_data))
        os.exit(1)
    end
    success("Connected to " .. client.app.name .. " v" .. client.app.version)
    local token = init_data.sessionToken or ""
    detail("Session Token: " .. token:sub(1, 20) .. "...")
    detail("HWID Lock: " .. tostring(client.app.lock_hwid) .. "  |  IP Lock: " .. tostring(client.app.lock_ip) .. "  |  Anti-Debug: " .. tostring(client.app.anti_debug))

    separator()

    -- Step 2: Choose Auth Method
    io.write("  " .. YELLOW .. "Select authentication method:" .. RESET .. "\n")
    io.write("    [1] Login with username/password\n")
    io.write("    [2] Register a new account\n")
    io.write("    [3] License key only\n")
    local choice = ask(BOLD .. ">" .. RESET .. " ")

    ok = true
    local auth_err

    if choice == "1" then
        local username = ask("Username: ")
        local password = ask("Password: ")
        info("Login", "Authenticating as " .. username .. "...")
        ok, auth_err = pcall(function() client:login(username, password) end)
    elseif choice == "2" then
        local username = ask("Username: ")
        local password = ask("Password: ")
        local email = ask("Email (optional): ")
        local license_key = ask("License Key (optional): ")
        info("Register", "Creating account " .. username .. "...")
        ok, auth_err = pcall(function() client:register(username, password, email, "", license_key) end)
    elseif choice == "3" then
        local key = ask("License Key: ")
        info("License", "Validating license...")
        ok, auth_err = pcall(function() client:license_login(key) end)
    else
        err("Invalid choice.")
        os.exit(1)
    end

    if not ok then
        err(tostring(auth_err))
        os.exit(1)
    end

    separator()

    -- Step 3: Display User Info
    success("Authenticated as: " .. client.user.key)
    detail("Level: " .. tostring(client.user.level))
    detail("Expires: " .. (client.user.expires_at or "Never"))

    separator()

    -- Step 4: Fetch Variables
    info("Variables", "Fetching app variables...")
    ok, auth_err = pcall(function()
        local vars = client:get_all_variables()
        if type(vars) ~= "table" or #vars == 0 then
            detail("No variables found.")
        else
            for _, v in ipairs(vars) do
                detail("  " .. (v.key or "") .. " = " .. (v.value or "") .. " (" .. (v.type or "STRING") .. ")")
            end
        end
    end)
    if not ok then
        detail("Variables: " .. tostring(auth_err))
    end

    separator()

    -- Step 5: User Variables
    info("User Vars", "Testing user variable storage...")
    ok, auth_err = pcall(function()
        local result = client:set_user_variable("last_seen", tostring(os.time()))
        success("Set user variable: " .. (result.key or "") .. " = " .. (result.value or ""))

        local all_vars = client:get_all_user_variables()
        if type(all_vars) == "table" then
            for _, v in ipairs(all_vars) do
                detail("  " .. (v.key or "") .. " = " .. (v.value or ""))
            end
        end
    end)
    if not ok then
        detail("User Variables: " .. tostring(auth_err))
    end

    separator()

    -- Step 6: Heartbeat
    info("Session", "Sending heartbeat...")
    ok, auth_err = pcall(function()
        local hb = client:heartbeat()
        success("Session alive until " .. (hb.expiresAt or "unknown"))
    end)
    if not ok then
        detail("Heartbeat: " .. tostring(auth_err))
    end

    separator()

    -- Step 7: End Session
    info("Cleanup", "Ending session...")
    ok, auth_err = pcall(function() client:end_session() end)
    if ok then
        success("Session ended. Goodbye.")
    else
        err(tostring(auth_err))
    end
end

main()
