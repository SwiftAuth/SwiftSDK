using System;
using System.Threading.Tasks;
using SwiftAuth;

namespace SwiftAuth.Example
{
    internal class Program
    {
        // ┌─────────────────────────────────────────────────────────┐
        // │   SwiftAuth C# SDK — Example Application               │
        // │                                                         │
        // │   Replace the values below with your own app secret     │
        // │   from the SwiftAuth dashboard.                         │
        // └─────────────────────────────────────────────────────────┘

        private const string BaseUrl    = "https://api.swiftauth.net";
        private const string AppSecret  = "YOUR_APP_SECRET_HERE";
        private const string AppVersion = "1.0.0";

        static async Task Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
  ╔═══════════════════════════════════════════════╗
  ║       SwiftAuth SDK — C# Example App         ║
  ╚═══════════════════════════════════════════════╝");
            Console.ResetColor();

            using var client = new SwiftAuthClient(BaseUrl, AppSecret, AppVersion);

            try
            {
                // ── Step 1: Initialize ──────────────────────────────
                Print("Initializing", "Connecting to SwiftAuth...");
                var init = await client.InitAsync();
                if (client.App == null)
                    throw new Exception("SDK returned null data — Init succeeded but App info is missing");
                PrintSuccess($"Connected to {client.App.Name} v{client.App.Version}");
                PrintInfo($"Session Token: {Truncate(init.SessionToken, 20)}");
                PrintInfo($"HWID Lock: {client.App.LockHwid}  |  IP Lock: {client.App.LockIp}  |  Anti-Debug: {client.App.AntiDebug}");

                Separator();

                // ── Step 2: Choose Auth Method ──────────────────────
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  Select authentication method:");
                Console.ResetColor();
                Console.WriteLine("    [1] Login with username/password");
                Console.WriteLine("    [2] Register a new account");
                Console.WriteLine("    [3] License key only");
                Console.Write("\n  > ");

                var choice = Console.ReadLine()?.Trim();

                switch (choice)
                {
                    case "1":
                        await DoLogin(client);
                        break;
                    case "2":
                        await DoRegister(client);
                        break;
                    case "3":
                        await DoLicense(client);
                        break;
                    default:
                        PrintError("Invalid choice.");
                        return;
                }

                Separator();

                // ── Step 3: Display User Info ───────────────────────
                PrintSuccess($"Authenticated as: {client.CurrentUser.Key}");
                PrintInfo($"Level: {client.CurrentUser.Level}");
                PrintInfo($"Expires: {client.CurrentUser.ExpiresAt ?? "Never"}");

                Separator();

                // ── Step 4: Fetch Variables ─────────────────────────
                Print("Variables", "Fetching app variables...");
                try
                {
                    var vars = await client.GetAllVariablesAsync();
                    if (vars.Count == 0)
                    {
                        PrintInfo("No variables found.");
                    }
                    else
                    {
                        foreach (var v in vars)
                            PrintInfo($"  {v.Key} = {v.Value} ({v.Type})");
                    }
                }
                catch (SwiftAuthException ex)
                {
                    PrintInfo($"Variables: {ex.Message}");
                }

                Separator();

                // ── Step 5: Heartbeat Loop ──────────────────────────
                Print("Session", "Sending heartbeat...");
                var hb = await client.HeartbeatAsync();
                PrintSuccess($"Session alive until {hb.ExpiresAt}");

                Separator();

                // ── Step 6: WebSocket Demo ──────────────────────────
                Print("WebSocket", "Connecting real-time channel...");
                try
                {
                    client.OnMessage += evt => PrintWs($"[{evt.Type}] {evt.Data}");
                    client.OnForceLogout += evt => PrintError("Force logout received!");
                    client.OnChat += evt => PrintWs($"Chat: {evt.Data}");

                    await client.ConnectWebSocketAsync();
                    PrintSuccess("WebSocket connected.");
                    PrintInfo("Listening for real-time events... Press Enter to disconnect.");
                    Console.ReadLine();
                    await client.DisconnectWebSocketAsync();
                }
                catch (Exception ex)
                {
                    PrintInfo($"WebSocket: {ex.Message}");
                }

                Separator();

                // ── Step 7: End Session ─────────────────────────────
                Print("Cleanup", "Ending session...");
                await client.EndSessionAsync();
                PrintSuccess("Session ended. Goodbye.");
            }
            catch (SwiftAuthException ex)
            {
                PrintError($"[{ex.Code}] {ex.Message}");
            }
            catch (NullReferenceException)
            {
                PrintError("Received unexpected response from server");
            }
            catch (Exception ex)
            {
                PrintError($"Unexpected error: {ex.Message}");
            }
        }

        // ── Auth Flows ──────────────────────────────────────────────

        static async Task DoLogin(SwiftAuthClient client)
        {
            Console.Write("\n  Username: ");
            var username = Console.ReadLine()?.Trim();
            Console.Write("  Password: ");
            var password = ReadPassword();

            Print("Login", $"Authenticating as {username}...");
            await client.LoginAsync(username, password);
        }

        static async Task DoRegister(SwiftAuthClient client)
        {
            Console.Write("\n  Username: ");
            var username = Console.ReadLine()?.Trim();
            Console.Write("  Password: ");
            var password = ReadPassword();
            Console.Write("  Email (optional): ");
            var email = Console.ReadLine()?.Trim();
            Console.Write("  License Key (optional): ");
            var license = Console.ReadLine()?.Trim();

            Print("Register", $"Creating account {username}...");
            await client.RegisterAsync(username, password, email, "", license);
        }

        static async Task DoLicense(SwiftAuthClient client)
        {
            Console.Write("\n  License Key: ");
            var key = Console.ReadLine()?.Trim();

            Print("License", "Validating license...");
            await client.LicenseAsync(key);
        }

        // ── UI Helpers ──────────────────────────────────────────────

        static void Print(string label, string msg)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  [{label}] ");
            Console.ResetColor();
            Console.WriteLine(msg);
        }

        static void PrintSuccess(string msg)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ {msg}");
            Console.ResetColor();
        }

        static void PrintError(string msg)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ✗ {msg}");
            Console.ResetColor();
        }

        static void PrintInfo(string msg)
        {
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine($"    {msg}");
            Console.ResetColor();
        }

        static void PrintWs(string msg)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine($"  ⚡ {msg}");
            Console.ResetColor();
        }

        static void Separator()
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ─────────────────────────────────────────────────");
            Console.ResetColor();
        }

        static string Truncate(string s, int len)
            => s?.Length > len ? s[..len] + "..." : s ?? "";

        static string ReadPassword()
        {
            var password = "";
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password = password[..^1];
                    Console.Write("\b \b");
                }
                else if (key.KeyChar != '\0')
                {
                    password += key.KeyChar;
                    Console.Write("*");
                }
            }
            Console.WriteLine();
            return password;
        }
    }
}
