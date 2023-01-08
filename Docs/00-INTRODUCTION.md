# Secure Components - Envelope Introduction

**Authors:** Wolf McNally, Christopher Allen, Shannon Appelcline, Blockchain Commons</br>
**Revised:** Aug 26, 2022</br>
**Status:** DRAFT

NOTE: Please go here for the latest version of this documentation related specifically to Gordian Envelope: [Envelope](https://blockchaincommons.github.io/BCSwiftEnvelope/documentation/envelope).

---

## Contents

* Envelope Introduction: This document
* [Types](01-TYPES.md)
* [Envelope Overview](02-ENVELOPE.md)
* [Envelope Notation](03-ENVELOPE-NOTATION.md)
* [Output Formats](04-OUTPUT-FORMATS.md)
* [Envelope Expressions](05-ENVELOPE-EXPRESSIONS.md)
* [Definitions](06-DEFINITIONS.md)
* [Examples](07-EXAMPLES.md)
* [Noncorrelation](08-NONCORRELATION.md)
* [Elision and Redaction](09-ELISION-REDACTION.md)
* [Existence Proofs](10-EXISTENCE-PROOFS.md)
* [Diffing Envelopes](11-DIFFING.md)
* [Appendix A: MVA Algorithm Suite](12-A-ALGORITHMS.md)
* [Appendix B: Envelope Test Vectors](13-B-ENVELOPE-TEST-VECTORS.md)
* [Appendix C: Envelope SSKR Test Vectors](14-C-ENVELOPE-SSKR-TEST-VECTORS.md)

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

The core of the Secure Components capability suite is the `Envelope` type. This is a smart-document structure that allows for the easy representation of common cryptographic design patterns, with efficient binary formatting, strong interoperability, and the ability to support cutting-edge cryptographic and decentralized identity specifications.

The prime attributes of an Envelope include:

* The ability to safely encrypt and store seeds and other secrets.
* The possibility to store metadata with those secrets.
* The ability to lock those envelopes with permits that may be opened in a variety of ways, including with SSKR shares and public-key cryptography.

Secure Components, including `Envelope`, is being built so that it is future-proofed (as much as is possible). Though initial algorithm choices are slightly conservative and though initial capabilities are purposefully limited, everything is being designed so that it can be expanded in the future, particularly via newer algorithms that are already known today but which are not sufficiently mature for usage.

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
    * [Progressive trust](https://www.blockchaincommons.com/musings/musings-progressive-trust/) is the ability of an individual to gradually increase the amount of relevant data revealed as trust is built or value generated.
    * [W3C Data Minimization](https://w3c-ccg.github.io/data-minimization/#progressive-trust)
    * [Original concept](http://www.lifewithalacrity.com/2004/08/progressive_tru.html)
* Default and fundamental support for aggregated group multisig signatures, in particular prime-order curves such as secp256k1, or point-compressed cofactor solutions such as [ristretto255](https://www.ietf.org/archive/id/draft-irtf-cfrg-ristretto255-00.html):
    * Reason? Multisig attacks:
        * [Prime, Order Please! - Revisiting Small Subgroup and Invalid Curve Attacks on Protocols using Diffie-Hellman](https://eprint.iacr.org/2019/526.pdf)
        * [Cofactor Explained: Clearing Elliptic Curves' dirty little secret](https://loup-vaillant.fr/tutorials/cofactor)
        * [Attack on Monero using 25519](https://jonasnick.github.io/blog/2017/05/23/exploiting-low-order-generators-in-one-time-ring-signatures/)
* Fundamental support for redactable signatures, possibly:
    * Bauer, Blough, Cash - [Minimal Information Disclosure with Efficiently Verifiable Credentials](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.153.8662&rep=rep1&type=pdf)
* Support for various modern techniques such as signature aggregation (Musig2 m of m), threshold signatures (FROST n of m), adapter signatures, scriptless scripts, discrete log contracts, Brandian blind signatures (and improvements), smart signature scripts, distributed key generation & verifiable secret sharing.

## Algorithms

The algorithms that Secure Components currently incorporates are listed below. The future-proofing of Secure Components also allows for the future inclusion of additional algorithms and methods.

* **Organization:** Suites
* **Data Size:** 256 Bit
* **Hashing and Key Derivation:** [BLAKE3](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
* **Symmetric Encryption:** [IETF-ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439)
* **Curve:** [Secp256k1](https://en.bitcoin.it/wiki/Secp256k1)
* **Signing:** [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
* **Public Key Encryption:** Schnorr with Secp256k1
* **Sharding**: [SSKR (Sharded Secret Key Reconstruction)](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-011-sskr.md)
* **Password-Based Key Derivation**: [scrypt](https://datatracker.ietf.org/doc/html/rfc7914)
* **Selective Disclosure:** Elision
* **Data Architecture:** Directed Graph

Please see [Appendix A](09-A-ALGORITHMS.md) for the reasons behind these algorithmic decisions.
