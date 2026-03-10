import net.swiftauth.SwiftAuthClient
import net.swiftauth.SwiftAuthException

/**
 * SwiftAuth SDK — Kotlin Example App
 *
 * Replace the values below with your own app secret
 * from the SwiftAuth dashboard.
 */
const val BASE_URL    = "https://api.swiftauth.net"
const val APP_SECRET  = "YOUR_APP_SECRET_HERE"
const val APP_VERSION = "1.0.0"

const val CYAN    = "\u001b[96m"
const val GREEN   = "\u001b[92m"
const val RED     = "\u001b[91m"
const val YELLOW  = "\u001b[93m"
const val MAGENTA = "\u001b[95m"
const val DIM     = "\u001b[90m"
const val BOLD    = "\u001b[1m"
const val RESET   = "\u001b[0m"

fun info(label: String, msg: String)   = println("  ${DIM}[$label]$RESET $msg")
fun success(msg: String)               = println("  ${GREEN}✓ $msg$RESET")
fun error(msg: String)                 = println("  ${RED}✗ $msg$RESET")
fun detail(msg: String)                = println("    ${CYAN}$msg$RESET")
fun wsMsg(msg: String)                 = println("  ${MAGENTA}⚡ $msg$RESET")
fun separator()                        = println("  ${DIM}${"─".repeat(49)}$RESET")

fun ask(prompt: String): String {
    print("  $prompt")
    return readlnOrNull()?.trim() ?: ""
}

fun main() {
    println("$CYAN")
    println("  ╔═══════════════════════════════════════════════╗")
    println("  ║      SwiftAuth SDK — Kotlin Example App       ║")
    println("  ╚═══════════════════════════════════════════════╝")
    println(RESET)

    val client = SwiftAuthClient(BASE_URL, APP_SECRET, APP_VERSION)

    try {
        // Step 1: Initialize
        info("Init", "Connecting to SwiftAuth...")
        val initData = client.init()
        val app = client.app!!
        success("Connected to ${app.name} v${app.version}")
        val token = (initData["sessionToken"] as? String) ?: ""
        detail("Session Token: ${token.take(20)}...")
        detail("HWID Lock: ${app.lockHwid}  |  IP Lock: ${app.lockIp}  |  Anti-Debug: ${app.antiDebug}")

        separator()

        // Step 2: Choose Auth Method
        println("  ${YELLOW}Select authentication method:$RESET")
        println("    [1] Login with username/password")
        println("    [2] Register a new account")
        println("    [3] License key only")
        val choice = ask("${BOLD}>${RESET} ")

        when (choice) {
            "1" -> {
                val username = ask("Username: ")
                val password = ask("Password: ")
                info("Login", "Authenticating as $username...")
                client.login(username, password)
            }
            "2" -> {
                val username = ask("Username: ")
                val password = ask("Password: ")
                val email = ask("Email (optional): ")
                val licenseKey = ask("License Key (optional): ")
                info("Register", "Creating account $username...")
                client.register(username, password, email, "", licenseKey)
            }
            "3" -> {
                val key = ask("License Key: ")
                info("License", "Validating license...")
                client.licenseLogin(key)
            }
            else -> {
                error("Invalid choice.")
                return
            }
        }

        separator()

        // Step 3: Display User Info
        val user = client.user!!
        success("Authenticated as: ${user.key}")
        detail("Level: ${user.level}")
        detail("Expires: ${user.expiresAt ?: "Never"}")

        separator()

        // Step 4: Fetch Variables
        info("Variables", "Fetching app variables...")
        try {
            val vars = client.getAllVariables()
            if (vars.isEmpty()) detail("No variables found.")
            else vars.forEach { detail("  ${it.key} = ${it.value} (${it.type})") }
        } catch (e: SwiftAuthException) {
            detail("Variables: ${e.message}")
        }

        separator()

        // Step 5: User Variables
        info("User Vars", "Testing user variable storage...")
        try {
            val result = client.setUserVariable("last_seen", "${System.currentTimeMillis() / 1000}")
            success("Set user variable: ${result.key} = ${result.value}")

            val allVars = client.getAllUserVariables()
            allVars.forEach { detail("  ${it.key} = ${it.value}") }
        } catch (e: SwiftAuthException) {
            detail("User Variables: ${e.message}")
        }

        separator()

        // Step 6: Heartbeat
        info("Session", "Sending heartbeat...")
        val hb = client.heartbeat()
        success("Session alive until ${hb["expiresAt"] ?: "unknown"}")

        separator()

        // Step 7: WebSocket Demo
        info("WebSocket", "Connecting real-time channel...")
        try {
            client.on("pong") { wsMsg("Pong received") }
            client.on("chat") { wsMsg("Chat: $it") }
            client.on("force_logout") { error("Force logout received!") }

            client.connectWs()
            success("WebSocket connected.")
            client.wsPing()
            detail("Listening for real-time events...")
            detail("Waiting 5 seconds...")
            Thread.sleep(5000)
            client.disconnectWs()
        } catch (e: Exception) {
            detail("WebSocket: ${e.message}")
        }

        separator()

        // Step 8: End Session
        info("Cleanup", "Ending session...")
        client.endSession()
        success("Session ended. Goodbye.")

    } catch (e: SwiftAuthException) {
        error(e.message ?: "Unknown error")
        kotlin.system.exitProcess(1)
    } catch (e: Exception) {
        error("Unexpected error: ${e.message}")
        kotlin.system.exitProcess(1)
    }
}
