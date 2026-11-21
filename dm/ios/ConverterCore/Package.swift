// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ConverterCore",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "ConverterCore", targets: ["ConverterCore"]),
        .executable(name: "nca-header-reference-check", targets: ["NCAHeaderReferenceCheck"])
    ],
    targets: [
        .target(name: "ConverterCore"),
        .executableTarget(name: "NCAHeaderReferenceCheck", dependencies: ["ConverterCore"]),
        .testTarget(name: "ConverterCoreTests", dependencies: ["ConverterCore"])
    ]
)
