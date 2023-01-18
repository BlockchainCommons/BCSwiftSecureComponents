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
            targets: ["SecureComponents", "BCWally", "SSKR"]),
    ],
    dependencies: [
        .package(url: "https://github.com/WolfMcNally/WolfBase", from: "5.0.0"),
        .package(url: "https://github.com/BlockchainCommons/URKit.git", from: "9.0.0"),
        .package(url: "https://github.com/BlockchainCommons/blake3-swift.git", from: "0.1.2"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.4.1"),
        .package(url: "https://github.com/BlockchainCommons/secp256k1-zkp.swift.git", from: "0.5.0"),
    ],
    targets: [
        .target(
            name: "SecureComponents",
            dependencies: [
                "WolfBase",
                "CryptoSwift",
                "URKit",
                "BCWally",
                "SSKR",
                .product(name: "BLAKE3", package: "blake3-swift"),
                .product(name: "secp256k1", package: "secp256k1-zkp.swift"),
            ]),
        .binaryTarget(
            name: "BCWally",
            path: "Frameworks/BCWally.xcframework"
        ),
        .binaryTarget(
            name: "SSKR",
            path: "Frameworks/SSKR.xcframework"
        ),
        .testTarget(
            name: "SecureComponentsTests",
            dependencies: [
                "SecureComponents",
                "WolfBase"
            ]),
    ]
)
