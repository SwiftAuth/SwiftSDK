// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SwiftAuth",
    platforms: [.macOS(.v12), .iOS(.v15)],
    products: [
        .library(name: "SwiftAuth", targets: ["SwiftAuth"]),
    ],
    targets: [
        .target(name: "SwiftAuth", path: "Sources/SwiftAuth"),
        .executableTarget(name: "Example", dependencies: ["SwiftAuth"], path: "example"),
    ]
)
