# Secure Components - Envelope Introduction

**Authors:** Wolf McNally, Christopher Allen, Shannon Appelcline, Blockchain Commons</br>
**Revised:** Aug 24, 2022</br>
**Status:** DRAFT

---

## Contents

* [Envelope Introduction](0-INTRODUCTION.md)
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
* Appendix A: MVA Algorithm Suite — This Document

---

## Introduction

In producing this proposal we made certain opinionated decisions about what algorithms to use by default. What follows is an outline of our opinionated choices.

These choices are specific to a Minimum Viable Architecture (MVA). Other architectures might have different algorithmic choices, such as a constrained hardware architecture, which might use AES, SHA-256, etc.

## MVA Architecture Suite

**Organization: Suites.** We are supportive of cipher-suites, which carefully combine a set of opinionated decisions, rather that agile approaches that can result in disastrous combinations. What follows is effectively the default cipher-suite for this project.

**Data Size: 256-Bit.** Algorithms were chosen in part so that hashes, public key, and other values were largely indistinguishable from each other and from randomness. In the case of this default suite, algorithms were chosen to produce 256-bit values. This does create limits on security, but they currently match those of Bitcoin, and so are considered sufficient. However, they may require an upgrade in the future. Since all our data structure work is based on CBOR, we expect that future format changes and additions will be relatively painless.

**Hash Function: BLAKE3.** BLAKE3 is the newest iteration of BLAKE, a hash function that has over a decade of maturity, though BLAKE3 is only a few years old. Nonetheless, it's supported by people with good experience in the field, including the Zcash Foundation.

The new BLAKE3 implementation uses a Merkle Tree format that allows for streaming and for incremental updates as well as high levels of parallelism. These should all be considered large advantages, providing streaming can can be reasonably programmed without too high of a barrier of entry.

The primary disadvantage of BLAKE3 is that it's not accelerated by hardware chips as is the case for its main competitor, SHA-256. Nonetheless, in a pure software configuration, BLAKE3 beats SHA-256 on speed. Overall, we think BLAKE3 is worthwhile as an evolution over SHA-256.

**AEAD Function: IETF ChaChaPoly.** As an AEAD cipher, ChaChaPoly combines the ChaCha20 cipher with the Poly1305 message authentication code (MAC). We find it a more modern and thus robust cipher than the venerable AES256-GCM function, which is also vulnerable to nonce reuse.

One major competitor is Adiantum, which is well-tested on Google devices and uses the quicker ChaCha12 function, which has fewer rounds. We prefer ChaChaPoly and its use of ChaCha20 for the improved security, provided that the costs of the additional rounds are not too high for the device.

A disadvantage of both for constrained devices is that AES is accelerated in many processors. Jon Callas says Apple uses AES-XTS for FileVault because of its maturity. It is block-oriented (not streaming), but is tweakable & parallelizable. He also like the NIST standard AES CBC with CTS which is fairly universal.

**Curve: Secp256k1.** The secp256 curve is an obvious choice because of its mature use with Bitcoin. It's familiar and well-tested.

The alternative would be Curve25519, but that needs updates to be made multisig safe and there are other problems with inconsistencies on the curve and insufficient specifications to resolve them. So, Secp256 seems like a safer choice.

Ristretto could be a third option, but is much less used than the others.

A deficit of Secp256 is that it's not IETF.

**Signing: Schnorr.** Our signing algorithm, Schnorr, fits into much the same category as BLAKE3. It's relatively new, but it's built on a strong foundation by trustworthy cryptographers. Combined with that, it allows for considerable expansion in the future, including adapter signatures, distributed key generation, half-key aggregation, and integration with FROST.

In addition, public keys aren't embedded in signatures the way they are in ECDSA and other older signaure systems.

**Sharding: Shamir with Groups.** Sharding is used to backup a seed in a safe and secure way. The default methodology here is Shamir's Secret Sharing: it's mature and its limitations are well-known.

However, the Blockchain Commons implementation of Shamir in SSKR has one notable extension: groups, which support layering. This allows scenarios where shares can be arranged into groups, and then reconstruction can depend on receiving a threshold number of shares from a threshold number of groups. This improves resilience by reducing the chance of collusion thanks to the implicit requirement that shares be spread out. It offers similar protection against social engineering. A [Security Review](https://github.com/BlockchainCommons/bc-sskr/blob/master/SECURITY-REVIEW.md) has already verified this implementation of Shamir's Secret Sharing & SSKR.

The main alternative to Shamir's Secret Sharing is the emerging VSS specification, which has great new functionality in the form of verification. However, the technology isn't mature enough yet for integration: it feels unstable. Fortunately, SSKR was built to allow for usage of different sharding technologies. We'll integrate VSS at some future point, and stepping up to VSS should then be simple for anyone using SSKR libraries.

**Password-Based Key Derivation: scrypt.** Currently, the best methodology for usercentric authentication is a classic: scrypt. It remains resource-intensive, though it is coming within reach of brute-force attacks, and its use of salts prevents rainbow-table attacks.

A good next-generation choice may be OPAQUE, which is as strong as public keys, but which doesn't place as much of a load on hardware devices. As a Password-Authenticated Key Exchange (PAKE) protocol, OPAQUE avoids ever giving a password to a server. Once OPAQUE has become sufficiently mature, it will likely supersede scrypt as a password-based key derivation choice.

**Selective Disclosure: Redaction.** Any data in this system can be redacted by supplying a BLAKE3 hash instead of the value. This allows holders to redact arbitrary data elements, even if they're not the issuer or the subject as well as sign blinded documents.

The obvious alternative is Zero-Knowledge Proofs, but the advantages in holders being able to create redactions and in less complexity seem cosiderable. However, an architectural review is definitely required, including a look at how nonces are generated for redacted signatures.

**Data Architecture: Directed Graph.** Storing data in a directed graph is somewhat controversial because of historic problems with RDF, but those generally arise due to implementations using quads instead of triads. To resolve this issue, envelopes have been designed with triads in mind of subject, predicate, and object, while still supporting a high degree of flexibility; this will allow the use of a directed graph architecture with triads instead of quads.
