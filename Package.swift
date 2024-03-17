// swift-tools-version: 5.9

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
        .package(url: "https://github.com/WolfMcNally/WolfBase", from: "6.0.0"),
        .package(url: "https://github.com/BlockchainCommons/URKit", from: "14.0.0"),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftCrypto", from: "4.0.0"),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftRandom", from: "1.0.0"),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftKeys", from: "0.1.0"),
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
