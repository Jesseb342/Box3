// swift-tools-version: 6.2
import Foundation
import PackageDescription

let packageRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let rustIOSLibrary = packageRoot.appendingPathComponent("../Rust/target/aarch64-apple-ios/release").standardizedFileURL.path
let rustHostLibrary = packageRoot.appendingPathComponent("../Rust/target/release").standardizedFileURL.path
let package = Package(
    name: "ConverterCore",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "ConverterCore", targets: ["ConverterCore"]),
        .executable(name: "nca-header-reference-check", targets: ["NCAHeaderReferenceCheck"])
    ],
    dependencies: [.package(url: "https://github.com/Lakr233/libcapstone-spm.git", exact: "0.1.3")],
    targets: [
        .target(name: "Box3NSOBridge", path: "Sources/Box3NSOBridge", publicHeadersPath: "include", linkerSettings: [
            .unsafeFlags(["-L\\(rustIOSLibrary)", "-lbox3_nso_bridge", "-lbox3_rewrite_bridge", "-lbox3_macho_bridge"], .when(platforms: [.iOS])),
            .unsafeFlags(["-L\\(rustHostLibrary)", "-lbox3_nso_bridge", "-lbox3_rewrite_bridge", "-lbox3_macho_bridge"], .when(platforms: [.macOS]))
        ]),
        .target(name: "ConverterCore", dependencies: ["Box3NSOBridge", .product(name: "Capstone", package: "libcapstone-spm")]),
        .executableTarget(name: "NCAHeaderReferenceCheck", dependencies: ["ConverterCore"]),
        .testTarget(name: "ConverterCoreTests", dependencies: ["ConverterCore"])
    ]
)
