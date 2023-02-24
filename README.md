# BCSwiftSecureComponents

A collection of useful primitives for cryptography, semantic graphs, and cryptocurrency in Swift.

NOTE: Gordian Envelope has been moved to [its own package](https://github.com/BlockchainCommons/BCSwiftEnvelope) that depends on this package.

Includes an opinionated Swift wrapper around [LibWally](https://github.com/ElementsProject/libwally-core).

Supports particular enhancements used by Blockchain Commons from our fork of libwally-core: [bc-libwally-core](https://github.com/blockchaincommons/bc-libwally-core), in the [bc-maintenance](https://github.com/BlockchainCommons/bc-libwally-core/tree/bc-maintenance) branch.

# Dependencies

Depends on:

* [BCSwiftWally](https://github.com/BlockchainCommons/BCSwiftWally), which is a thin wrapper around LibWally that has a new build system for building a universal XCFramework for use with MacOSX, Mac Catalyst, iOS devices, and the iOS simulator across Intel and Apple Silicon (ARM).
* [bc-sskr](https://github.com/BlockchainCommons/bc-sskr), Sharded Secret Key Reconstruction (SSKR) reference library in C.
* [secp256k1-zkp](https://github.com/BlockchainCommons/secp256k1-zkp.swift), Elliptic Curve public key, ECDSA, and Schnorr for Bitcoin, experimental fork.
* [CryptoSwift](https://github.com/krzyzanowskim/CryptoSwift), a growing collection of standard and secure cryptographic algorithms implemented in Swift

# Building

Add to your project like any other Swift Package.

### Credits

The following people directly contributed to this repository. You can add your name here by getting involved. The first step is learning how to contribute from our [CONTRIBUTING.md](./CONTRIBUTING.md) documentation.

| Name              | Role                | Github                                            | Email                                 | GPG Fingerprint                                    |
| ----------------- | ------------------- | ------------------------------------------------- | ------------------------------------- | -------------------------------------------------- |
| Christopher Allen | Principal Architect | [@ChristopherA](https://github.com/ChristopherA) | \<ChristopherA@LifeWithAlacrity.com\> | FDFE 14A5 4ECB 30FC 5D22  74EF F8D3 6C91 3574 05ED |
| Wolf McNally      | Project Lead        | [@WolfMcNally](https://github.com/wolfmcnally)    | \<Wolf@WolfMcNally.com\>              | 9436 52EE 3844 1760 C3DC  3536 4B6C 2FCF 8947 80AE |
