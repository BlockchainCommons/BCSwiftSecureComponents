// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "SecureComponents",
    platforms: [
        .macOS(.v12),
        .iOS(.v15),
        .tvOS(.v15),
        .watchOS(.v8)
    ],
    products: [
        .library(
            name: "SecureComponents",
            targets: ["SecureComponents"]),
    ],
    dependencies: [
        .package(url: "https://github.com/WolfMcNally/WolfBase", from: "5.0.0"),
        .package(url: "https://github.com/BlockchainCommons/URKit.git", from: "11.0.0"),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftCrypto", from: "0.1.0"),
    ],
    targets: [
        .target(
            name: "SecureComponents",
            dependencies: [
                "WolfBase",
                "URKit",
                .product(name: "BCCrypto", package: "BCSwiftCrypto"),
            ]),
        .testTarget(
            name: "SecureComponentsTests",
            dependencies: [
                "SecureComponents",
                "WolfBase"
            ]),
    ]
)
