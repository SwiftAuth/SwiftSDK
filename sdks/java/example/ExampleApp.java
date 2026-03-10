import net.swiftauth.SwiftAuthClient;
import net.swiftauth.SwiftAuthException;

import java.util.List;
import java.util.Map;
import java.util.Scanner;

/**
 * SwiftAuth SDK — Java Example App
 *
 * Replace the values below with your own app secret
 * from the SwiftAuth dashboard.
 */
public class ExampleApp {

    static final String BASE_URL    = "https://api.swiftauth.net";
    static final String APP_SECRET  = "YOUR_APP_SECRET_HERE";
    static final String APP_VERSION = "1.0.0";

    static final String CYAN    = "\033[96m";
    static final String GREEN   = "\033[92m";
    static final String RED     = "\033[91m";
    static final String YELLOW  = "\033[93m";
    static final String MAGENTA = "\033[95m";
    static final String DIM     = "\033[90m";
    static final String BOLD    = "\033[1m";
    static final String RESET   = "\033[0m";

    static void info(String label, String msg)   { System.out.printf("  %s[%s]%s %s%n", DIM, label, RESET, msg); }
    static void success(String msg)              { System.out.printf("  %s✓ %s%s%n", GREEN, msg, RESET); }
    static void error(String msg)                { System.out.printf("  %s✗ %s%s%n", RED, msg, RESET); }
    static void detail(String msg)               { System.out.printf("    %s%s%s%n", CYAN, msg, RESET); }
    static void wsMsg(String msg)                { System.out.printf("  %s⚡ %s%s%n", MAGENTA, msg, RESET); }
    static void separator() { System.out.printf("  %s─────────────────────────────────────────────────%s%n", DIM, RESET); }

    public static void main(String[] args) {
        System.out.printf("%s%n  ╔═══════════════════════════════════════════════╗%n  ║       SwiftAuth SDK — Java Example App        ║%n  ╚═══════════════════════════════════════════════╝%n%s%n", CYAN, RESET);

        Scanner scanner = new Scanner(System.in);
        SwiftAuthClient client = new SwiftAuthClient(BASE_URL, APP_SECRET, APP_VERSION);

        try {
            // Step 1: Initialize
            info("Init", "Connecting to SwiftAuth...");
            Map<String, Object> initData = client.init();
            success("Connected to " + client.getApp().name() + " v" + client.getApp().version());
            String token = initData.getOrDefault("sessionToken", "").toString();
            detail("Session Token: " + (token.length() > 20 ? token.substring(0, 20) + "..." : token));
            detail("HWID Lock: " + client.getApp().lockHwid() + "  |  IP Lock: " + client.getApp().lockIp() + "  |  Anti-Debug: " + client.getApp().antiDebug());

            separator();

            // Step 2: Choose Auth Method
            System.out.printf("  %sSelect authentication method:%s%n", YELLOW, RESET);
            System.out.println("    [1] Login with username/password");
            System.out.println("    [2] Register a new account");
            System.out.println("    [3] License key only");
            System.out.printf("  %s>%s ", BOLD, RESET);
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1" -> {
                    System.out.print("  Username: ");
                    String username = scanner.nextLine().trim();
                    System.out.print("  Password: ");
                    String password = scanner.nextLine().trim();
                    info("Login", "Authenticating as " + username + "...");
                    client.login(username, password);
                }
                case "2" -> {
                    System.out.print("  Username: ");
                    String username = scanner.nextLine().trim();
                    System.out.print("  Password: ");
                    String password = scanner.nextLine().trim();
                    System.out.print("  Email (optional): ");
                    String email = scanner.nextLine().trim();
                    System.out.print("  License Key (optional): ");
                    String licenseKey = scanner.nextLine().trim();
                    info("Register", "Creating account " + username + "...");
                    client.register(username, password, email, "", licenseKey, "");
                }
                case "3" -> {
                    System.out.print("  License Key: ");
                    String key = scanner.nextLine().trim();
                    info("License", "Validating license...");
                    client.licenseLogin(key);
                }
                default -> {
                    error("Invalid choice.");
                    return;
                }
            }

            separator();

            // Step 3: Display User Info
            success("Authenticated as: " + client.getUser().key());
            detail("Level: " + client.getUser().level());
            String expires = client.getUser().expiresAt();
            detail("Expires: " + (expires.isEmpty() ? "Never" : expires));

            separator();

            // Step 4: Fetch Variables
            info("Variables", "Fetching app variables...");
            try {
                Map<String, Object> varsData = client.getAllVariables();
                Object list = varsData.get("_list");
                if (list instanceof List<?> varList && !varList.isEmpty()) {
                    for (Object item : varList) {
                        if (item instanceof Map<?,?> v) {
                            detail("  " + v.get("key") + " = " + v.get("value") + " (" + v.getOrDefault("type", "STRING") + ")");
                        }
                    }
                } else {
                    detail("No variables found.");
                }
            } catch (SwiftAuthException e) {
                detail("Variables: " + e.getMessage());
            }

            separator();

            // Step 5: User Variables
            info("User Vars", "Testing user variable storage...");
            try {
                Map<String, Object> result = client.setUserVariable("last_seen", String.valueOf(System.currentTimeMillis() / 1000));
                success("Set user variable: " + result.get("key") + " = " + result.get("value"));

                Map<String, Object> allVars = client.getAllUserVariables();
                Object uvList = allVars.get("_list");
                if (uvList instanceof List<?> userVarList) {
                    for (Object item : userVarList) {
                        if (item instanceof Map<?,?> v) {
                            detail("  " + v.get("key") + " = " + v.get("value"));
                        }
                    }
                }
            } catch (SwiftAuthException e) {
                detail("User Variables: " + e.getMessage());
            }

            separator();

            // Step 6: Heartbeat
            info("Session", "Sending heartbeat...");
            Map<String, Object> hb = client.heartbeat();
            success("Session alive until " + hb.getOrDefault("expiresAt", "unknown"));

            separator();

            // Step 7: WebSocket Demo
            info("WebSocket", "Connecting real-time channel...");
            try {
                client.on("pong", evt -> wsMsg("Pong received"));
                client.on("chat", evt -> wsMsg("Chat: " + evt));
                client.on("force_logout", evt -> error("Force logout received!"));

                client.connectWs();
                success("WebSocket connected.");
                client.wsPing();
                detail("Listening for real-time events...");
                detail("Waiting 5 seconds...");
                Thread.sleep(5000);
                client.disconnectWs();
            } catch (Exception e) {
                detail("WebSocket: " + e.getMessage());
            }

            separator();

            // Step 8: End Session
            info("Cleanup", "Ending session...");
            client.endSession();
            success("Session ended. Goodbye.");

        } catch (SwiftAuthException e) {
            error(e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            error("Unexpected error: " + e.getMessage());
            System.exit(1);
        }
    }
}
