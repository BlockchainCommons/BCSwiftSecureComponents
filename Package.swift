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
        .package(url: "https://github.com/BlockchainCommons/URKit.git", from: "12.0.0"),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftCrypto", from: "1.0.0"),
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
