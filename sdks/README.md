# SwiftAuth Official SDKs

Integrate SwiftAuth authentication, licensing, and real-time features into your application in minutes. Each SDK covers the full client API with WebSocket support.

```
sdks/
├── csharp/     C# / .NET 8
├── python/     Python 3.9+
├── nodejs/     Node.js 18+
├── cpp/        C++17 (libcurl)
├── go/         Go 1.21+
├── java/       Java 17+
├── kotlin/     Kotlin 1.9+ (JVM 17+)
├── rust/       Rust (2021 edition)
├── ruby/       Ruby 3.0+
├── php/        PHP 8.1+
├── swift/      Swift 5.9+ (macOS/iOS)
└── lua/        Lua 5.1+ (LuaSocket)
```

---

## Quick Start

Every example app follows the same flow:

1. **Initialize** — connect to your app with the secret key
2. **Authenticate** — login, register, or license-only auth
3. **Use features** — variables, files, heartbeat, WebSocket
4. **End session** — clean disconnect

Replace `YOUR_APP_SECRET_HERE` in the example with your real app secret from the [SwiftAuth Dashboard](https://swiftauth.net/dashboard).

---

## C# / .NET

**Requirements:** .NET 8 SDK

```bash
cd sdks/csharp

# Build the SDK + example
dotnet build Example/Example.csproj

# Run the example
dotnet run --project Example/Example.csproj
```

**Use in your project:**
```bash
# Reference the SDK project
dotnet add reference path/to/SwiftAuth/SwiftAuth.csproj
```

```csharp
using SwiftAuth;

var client = new SwiftAuthClient("https://api.swiftauth.net", "YOUR_SECRET", "1.0.0");
await client.InitAsync();
await client.LoginAsync("user", "pass");

Console.WriteLine($"Welcome {client.CurrentUser.Key}, level {client.CurrentUser.Level}");

// Real-time WebSocket
client.OnChat += evt => Console.WriteLine($"Chat: {evt.Data}");
await client.ConnectWebSocketAsync();
```

---

## Python

**Requirements:** Python 3.9+

```bash
cd sdks/python

# Install dependencies
pip install -r requirements.txt

# Install the SDK (editable mode for development)
pip install -e .

# Run the example
python example/app.py
```

**Use in your project:**
```bash
pip install -e path/to/sdks/python
```

```python
from swiftauth import SwiftAuthClient

client = SwiftAuthClient("https://api.swiftauth.net", "YOUR_SECRET", "1.0.0")
client.init()
client.login("user", "pass")

print(f"Welcome {client.user.key}, level {client.user.level}")

# Real-time WebSocket
client.on("chat", lambda evt: print(f"Chat: {evt}"))
client.connect_ws()
```

---

## Node.js

**Requirements:** Node.js 18+

```bash
cd sdks/nodejs

# Install dependencies
npm install

# Run the example
npm run example
```

**Use in your project:**
```bash
npm install path/to/sdks/nodejs
```

```javascript
const { SwiftAuthClient } = require("swiftauth-sdk");

const client = new SwiftAuthClient({
    baseUrl: "https://api.swiftauth.net",
    appSecret: "YOUR_SECRET",
    appVersion: "1.0.0",
});

await client.init();
await client.login("user", "pass");

console.log(`Welcome ${client.user.key}, level ${client.user.level}`);

// Real-time WebSocket
client.on("ws:chat", (data) => console.log("Chat:", data));
client.connectWs();
```

---

## C++

**Requirements:** CMake 3.16+, C++17 compiler, libcurl

```bash
cd sdks/cpp

# Build
mkdir build && cd build
cmake ..
make

# Run the example
./swiftauth_example
```

**Use in your project (CMake):**
```cmake
add_subdirectory(path/to/sdks/cpp)
target_link_libraries(your_app PRIVATE swiftauth)
```

```cpp
#include "swiftauth/swiftauth.hpp"

swiftauth::Client client("https://api.swiftauth.net", "YOUR_SECRET", "1.0.0");
auto init = client.init();
auto login = client.login("user", "pass");

std::cout << "Welcome " << client.user().key << ", level " << client.user().level << "\n";
```

---

## Go

**Requirements:** Go 1.21+

```bash
cd sdks/go

# Run the example
go run example/main.go
```

**Use in your project:**
```bash
# Copy the sdks/go directory into your project, then import it
```

```go
import swiftauth "your-project/swiftauth"

client := swiftauth.NewClient("https://api.swiftauth.net", "YOUR_SECRET", "1.0.0", "")
client.Init()
client.Login("user", "pass", "", "")

fmt.Printf("Welcome %s, level %d\n", client.User.Key, client.User.Level)

// WebSocket
client.On("chat", func(evt map[string]any) { fmt.Println("Chat:", evt) })
client.ConnectWs()
```

---

## Java

**Requirements:** Java 17+

```bash
cd sdks/java

# Build with Maven
mvn package

# Or compile directly without Maven
javac -d out src/main/java/net/swiftauth/*.java example/ExampleApp.java
java -cp out ExampleApp
```

```java
import net.swiftauth.SwiftAuthClient;

var client = new SwiftAuthClient("https://api.swiftauth.net", "YOUR_SECRET", "1.0.0");
client.init();
client.login("user", "pass");

System.out.println("Welcome " + client.getUser().key() + ", level " + client.getUser().level());

// WebSocket
client.on("chat", evt -> System.out.println("Chat: " + evt));
client.connectWs();
```

---

## Kotlin

**Requirements:** Kotlin 1.9+, JVM 17+

```bash
cd sdks/kotlin

# Build and run with Gradle
./gradlew run
```

```kotlin
import net.swiftauth.SwiftAuthClient

val client = SwiftAuthClient("https://api.swiftauth.net", "YOUR_SECRET", "1.0.0")
client.init()
client.login("user", "pass")

println("Welcome ${client.user!!.key}, level ${client.user!!.level}")

// WebSocket
client.on("chat") { evt -> println("Chat: $evt") }
client.connectWs()
```

---

## Rust

**Requirements:** Rust (2021 edition)

```bash
cd sdks/rust

# Run the example
cargo run --example app
```

**Use in your project:**
```toml
[dependencies]
swiftauth = { path = "path/to/sdks/rust" }
```

```rust
use swiftauth::SwiftAuthClient;

let mut client = SwiftAuthClient::new("https://api.swiftauth.net", "YOUR_SECRET", "1.0.0", None);
client.init()?;
client.login("user", "pass", "", "")?;

let user = client.user.as_ref().unwrap();
println!("Welcome {}, level {}", user.key, user.level);
```

---

## Ruby

**Requirements:** Ruby 3.0+

```bash
cd sdks/ruby

# Run the example
ruby example/app.rb
```

```ruby
require "swiftauth"

client = SwiftAuth::Client.new(base_url: "https://api.swiftauth.net", app_secret: "YOUR_SECRET")
client.init
client.login("user", "pass")

puts "Welcome #{client.user.key}, level #{client.user.level}"
```

---

## PHP

**Requirements:** PHP 8.1+ (ext-json, ext-openssl, ext-gmp, ext-zlib)

```bash
cd sdks/php

# Run the example
php example/app.php
```

```php
use SwiftAuth\SwiftAuthClient;

$client = new SwiftAuthClient("https://api.swiftauth.net", "YOUR_SECRET", "1.0.0");
$client->init();
$client->login("user", "pass");

echo "Welcome {$client->user['key']}, level {$client->user['level']}\n";
```

---

## Swift

**Requirements:** Swift 5.9+, macOS 12+ / iOS 15+

```bash
cd sdks/swift

# Build and run
swift build
swift run Example
```

**Use in your project (SPM):**
```swift
// Add as a local package dependency in your Package.swift
.package(path: "path/to/sdks/swift")
```

```swift
import SwiftAuth

let client = SwiftAuthClient(baseURL: "https://api.swiftauth.net", appSecret: "YOUR_SECRET")
try client.initialize()
try client.login(username: "user", password: "pass")

print("Welcome \(client.user!.key), level \(client.user!.level)")
```

---

## Lua

**Requirements:** Lua 5.1+, LuaSocket, lua-cjson

```bash
cd sdks/lua

# Install dependencies
luarocks install lua-cjson luasocket

# Run the example
lua example/app.lua
```

```lua
local SwiftAuth = require("swiftauth")

local client = SwiftAuth.new("https://api.swiftauth.net", "YOUR_SECRET", "1.0.0")
client:init()
client:login("user", "pass")

print("Welcome " .. client.user.key .. ", level " .. client.user.level)
```

---

## Full API Reference

Every SDK method maps 1:1 to the SwiftAuth Client API:

| Method | Description |
|---|---|
| `init` | Initialize session with app secret |
| `login` | Authenticate with username/password |
| `register` | Create new user account |
| `licenseLogin` | Authenticate with license key only |
| `activate` | Activate a license on current user |
| `validateToken` | Validate a pre-auth access token |
| `getVariable` | Fetch a single app variable |
| `getAllVariables` | Fetch all app variables |
| `getUserVariable` | Fetch a user-scoped variable |
| `getAllUserVariables` | Fetch all user-scoped variables |
| `setUserVariable` | Set/update a user-scoped variable |
| `deleteUserVariable` | Delete a user-scoped variable |
| `downloadFile` | Download a file by name |
| `checkUpdate` | Check for app version updates |
| `heartbeat` | Keep session alive (nonce required) |
| `checkSession` | Verify session is still valid |
| `endSession` | End and invalidate the session |
| `getUser` | Get current user profile info |
| `changePassword` | Change the current user's password |
| `requestReset` | Request HWID/IP reset email |
| `log` | Send a client-side log entry |

### WebSocket Events

| Event | Direction | Description |
|---|---|---|
| `ping` / `pong` | Both | Keep-alive |
| `set_status` | Client > Server | Set user online status |
| `chat` | Both | Chat messages |
| `typing` | Both | Typing indicators |
| `set_metadata` | Client > Server | Attach metadata to session |
| `force_logout` | Server > Client | Forced disconnect |
| `command` | Server > Client | Custom command from dashboard |
| `custom` | Server > Client | Custom JSON payload |
| `message` | Server > Client | Broadcast messages |

---

## Testing Your Integration

1. Create an app in the [SwiftAuth Dashboard](https://swiftauth.net/dashboard)
2. Copy the **App Secret** from the app settings
3. Create a test user or license in the dashboard
4. Replace `YOUR_APP_SECRET_HERE` in the example
5. Run the example for your language
6. Verify you see the authentication success and user info

### Common Errors

| Error Code | Meaning |
|---|---|
| `UNAUTHORIZED` | Invalid secret, credentials, or expired session |
| `NONCE_REQUIRED` | Heartbeat/login requires a fresh nonce |
| `HWID_LOCKED` | Device doesn't match the locked HWID |
| `IP_LOCKED` | IP doesn't match the locked IP |
| `DEVICE_LIMIT` | Too many devices for this user |
| `BANNED` | User or license is banned |
| `EXPIRED` | Subscription or license has expired |
| `VERSION_MISMATCH` | Client version doesn't match app version |
| `PLAN_FEATURE` | Feature requires a higher plan |

---

## License

MIT
