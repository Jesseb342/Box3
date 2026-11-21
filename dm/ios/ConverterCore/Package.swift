// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "ConverterCore",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "ConverterCore", targets: ["ConverterCore"]),
        .executable(name: "nca-header-reference-check", targets: ["NCAHeaderReferenceCheck"])
    ],
    dependencies: [
        .package(url: "https://github.com/Lakr233/libcapstone-spm.git", from: "0.1.3")
    ],
    targets: [
        .target(
            name: "ConverterCore",
            dependencies: [
                .product(name: "Capstone", package: "libcapstone-spm")
            ]
        ),
        .executableTarget(name: "NCAHeaderReferenceCheck", dependencies: ["ConverterCore"]),
        .testTarget(name: "ConverterCoreTests", dependencies: ["ConverterCore"])
    ]
)
