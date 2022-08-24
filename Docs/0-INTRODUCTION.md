# Secure Components - Envelope Introduction

**Authors:** Wolf McNally, Christopher Allen, Shannon Appelcline, Blockchain Commons</br>
**Revised:** Aug 24, 2022</br>
**Status:** DRAFT

---

## Contents

* Envelope Introduction: This Document
* [Types](1-TYPES.md)
* [Envelope Overview](2-ENVELOPE.md)
* [Envelope Notation](3-ENVELOPE-NOTATION.md)
* [Envelope Expressions](4-ENVELOPE-EXPRESSIONS.md)
* [Definitions](5-DEFINITIONS.md)
* [Examples](6-EXAMPLES.md)
* [Envelope Test Vectors](7-ENVELOPE-TEST-VECTORS.md)
* [Envelope SSKR Test Vectors](8-ENVELOPE-SSKR-TEST-VECTORS.md)
* [Noncorrelation](9-NONCORRELATION.md)
* [Elision and Redaction](10-ELISION-REDACTION.md)
* [Appendix A: MVA Algorithm Suite](A-ALGORITHMS.md)

---

## Introduction

The Secure Components suite provides tools for easily implementing encryption (symmetric or public key), signing, and sharding of messages, and representation of knowledge graphs, including serialization to and from [CBOR](https://cbor.io/) and [UR](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md) formats.

## Status

**DRAFT.** There is a reference implementation of parts of this document in [BCSwiftFoundation](https://github.com/blockchaincommons/BCSwiftFoundation), but everything is still fluid and subject to change.

## Disclaimer

These documents comprise an alpha-stage proposal. The goal is get feedback and to determine requirements. As a result, this document and the specification it suggests may change without notice.

Even after we settle on a full specification, an architectural security review will be needed. Though we are leveraging mature crypto, we are doing so in a novel way and making specific assumptions about how non-correlation and redaction work. Not only may we have failed in those assumptions, but we suspect there *are* dangers that will need to be either resolved or documented.

Following an architectural review, we will then support the production of code for a variety of languages. Only after individual security reviews will that code be considered fully ready for deployment.

## Overview

[future-proofing]

## Goals

The goal is to create a general purpose, composable suite of data types that:

* Are based on object-centric architecture.
* Represent structured data using [CBOR](https://cbor.io/) and [UR](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md).
* Are based on algorithms and constructs that are considered best practices.
* Make it easy to represent common encryption constructions.
* Support innovative constructs such as [Sharded Secret Key Reconstruction (SSKR)](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-011-sskr.md).
* Interoperate with structures of particular interest to blockchain and cryptocurrency developers, such as [seeds](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md#cryptographic-seed-crypto-seed) and [HD keys](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-007-hdkey.md).
* Support protocols such as [Distributed Identifiers](https://www.w3.org/TR/did-core/) (DIDs).
* Allow for the future extension of functionality to include additional cryptographic algorithms and methods.
* Support complex metadata (assertions about assertions).
* Support semantic knowledge graphs.
* Support mutable and immutable architectures.
* Provide a reference API implementation in Swift that is easy to use and hard to abuse.

Other goals we are considering include:

* Support eventual consistency using [conflict-free replicated datatypes (CRDTs)](https://en.wikipedia.org/wiki/Conflict-free_replicated_data_type).
* Minimize opportunities for correlation without first demonstrating ability to decrypt or provide an adapter signature.
* Correlation resistance leveraging similarities between UUIDs, nonces, hashes, content addressable hashes, signatures, etc.
* Focus first on peer-based, web-of-trust, self-sovereign key models for roots of trust, where peers may be groups.
* Support “Progressive Trust” models:
    * Progressive trust is the ability of an individual to gradually increase the amount of relevant data revealed as trust is built or value generated.
    * [W3C Data Minimization](https://w3c-ccg.github.io/data-minimization/#progressive-trust)
    * [Original concept](http://www.lifewithalacrity.com/2004/08/progressive_tru.html)
* Default and fundamental support of aggregated group multisig signatures, in particular prime-order curves like secp256k1, or point-compressed cofactor solutions like [ristretto255](https://www.ietf.org/archive/id/draft-irtf-cfrg-ristretto255-00.html):
    * Reason? Multisig attacks:
        * [Prime, Order Please! - Revisiting Small Subgroup and Invalid Curve Attacks on Protocols using Diffie-Hellman](https://eprint.iacr.org/2019/526.pdf)
        * [Cofactor Explained: Clearing Elliptic Curves' dirty little secret](https://loup-vaillant.fr/tutorials/cofactor)
        * [Attack on Monero using 25519](https://jonasnick.github.io/blog/2017/05/23/exploiting-low-order-generators-in-one-time-ring-signatures/)
* Fundamental support for redactable signatures, possibly:
    * Bauer, Blough, Cash - [Minimal Information Disclosure with Efficiently Verifiable Credentials](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.153.8662&rep=rep1&type=pdf)
* Support for various modern techniques such as signature aggregation (Musig2 m of m), threshold signatures (FROST n of m), adapter signatures, scriptless scripts, discrete log contracts, Brandian blind signatures (and improvements), smart signature scripts, distributed key generation & verifiable secret sharing.

## Algorithms

The algorithms that Secure Components currently incorporates are listed below. The components include provisions for the future inclusion of additional algorithms and methods.

* **Organization:** Suites
* **Data Size:** 256 Bit
* **Hashing and Key Derivation:** [BLAKE3](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
* **Symmetric Encryption:** [IETF-ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439)
* **Curve:** [Secp256k1](https://en.bitcoin.it/wiki/Secp256k1)
* **Signing:** [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
* **Public Key Encryption:** Schnorr with Secp256k1
* **Sharding**: [SSKR (Sharded Secret Key Reconstruction)](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-011-sskr.md)
* **Password-Based Key Derivation**: [scrypt](https://datatracker.ietf.org/doc/html/rfc7914)
* **Selective Disclosure:** Redaction
* **Data Architecture:** Directed Graph

Please see [Appendix A](A-ALGORITHMS.md) for the reasons behind these decisions.