# BCSwiftSecureComponents

A collection of useful primitives for cryptography, semantic graphs, and cryptocurrency in Swift.

Features `Envelope`, which supports everything from enclosing the most basic of plaintext messages, to innumerable recursive permutations of encryption, signing, sharding, and representing semantic graphs.

Includes an opinionated Swift wrapper around [LibWally](https://github.com/ElementsProject/libwally-core).

Supports particular enhancements used by Blockchain Commons from our fork of libwally-core: [bc-libwally-core](https://github.com/blockchaincommons/bc-libwally-core), in the [bc-maintenance](https://github.com/BlockchainCommons/bc-libwally-core/tree/bc-maintenance) branch.

# Dependencies

Depends on:

* [BCSwiftWally](https://github.com/BlockchainCommons/BCSwiftWally), which is a thin wrapper around LibWally that has a new build system for building a universal XCFramework for use with MacOSX, Mac Catalyst, iOS devices, and the iOS simulator across Intel and Apple Silicon (ARM).
* [bc-sskr](https://github.com/BlockchainCommons/bc-sskr), Sharded Secret Key Reconstruction (SSKR) reference library in C.
* [secp256k1-zkp](https://github.com/BlockchainCommons/secp256k1-zkp.swift), Elliptic Curve public key, ECDSA, and Schnorr for Bitcoin, experimental fork.
* [CryptoSwift](https://github.com/krzyzanowskim/CryptoSwift), a growing collection of standard and secure cryptographic algorithms implemented in Swift
* [BLAKE3](https://github.com/BlockchainCommons/blake3-swift), a Swift implementation of the BLAKE3 cryptographic hash function.

# Building

Add to your project like any other Swift Package.
