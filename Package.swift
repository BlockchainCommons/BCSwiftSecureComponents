// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SecureComponents",
    platforms: [
        .macOS(.v13),
        .iOS(.v14),
        .macCatalyst(.v14)
    ],
    products: [
        .library(
            name: "SecureComponents",
            targets: ["SecureComponents"]),
    ],
    dependencies: [
        .package(url: "https://github.com/WolfMcNally/WolfBase", from: "7.0.0"),
        .package(url: "https://github.com/BlockchainCommons/URKit", from: "15.0.0"),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftCrypto", from: "6.0.0"),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftRandom", from: "2.0.0"),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftKeys", from: "0.2.0"),
    ],
    targets: [
        .target(
            name: "SecureComponents",
            dependencies: [
                "WolfBase",
                "URKit",
                .product(name: "BCKeys", package: "BCSwiftKeys"),
                .product(name: "BCCrypto", package: "BCSwiftCrypto"),
                .product(name: "BCRandom", package: "BCSwiftRandom"),
            ]),
        .testTarget(
            name: "SecureComponentsTests",
            dependencies: [
                "SecureComponents",
                "WolfBase"
            ]),
    ]
)
