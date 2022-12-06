// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "BCSecureComponents",
    platforms: [
        .iOS(.v15),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "BCSecureComponents",
            targets: ["BCSecureComponents", "BCWally", "SSKR"]),
    ],
    dependencies: [
        .package(url: "https://github.com/WolfMcNally/WolfBase", from: "4.0.0"),
        .package(url: "https://github.com/BlockchainCommons/URKit.git", from: "7.0.0"),
        .package(url: "https://github.com/BlockchainCommons/blake3-swift.git", from: "0.1.2"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.4.1"),
        .package(url: "https://github.com/BlockchainCommons/secp256k1-zkp.swift.git", from: "0.5.0"),
        .package(url: "https://github.com/WolfMcNally/Graph.git", branch: "master"),
        .package(url: "https://github.com/WolfMcNally/GraphMermaid.git", branch: "master"),
        .package(url: "https://github.com/WolfMcNally/GraphDot.git", branch: "master"),
        .package(url: "https://github.com/WolfMcNally/WolfLorem.git", from: "2.0.0"),
    ],
    targets: [
        .target(
            name: "BCSecureComponents",
            dependencies: [
                "WolfBase",
                "CryptoSwift",
                "URKit",
                "BCWally",
                "SSKR",
                "Graph",
                "GraphMermaid",
                "GraphDot",
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
            name: "BCSecureComponentsTests",
            dependencies: [
                "BCSecureComponents",
                "WolfBase",
                "WolfLorem"
            ]),
    ]
)
