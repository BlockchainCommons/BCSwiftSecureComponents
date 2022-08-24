# Secure Components - Types

**Authors:** Wolf McNally, Christopher Allen, Blockchain Commons</br>
**Revised:** Aug 13, 2022</br>
**Status:** DRAFT

---

## Contents

* [Envelope Introduction](0-INTRODUCTION.md)
* Types: This document
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

...

## Reserved CBOR Tags

Lower-numbered CBOR tags take fewer bytes to encode, and are hence more desirable "real estate."

* Tags in the range 0-23 require one byte to encode.
* Tags in the range 24-255 require two bytes to encode.
* Tags from 256 and above require three or more bytes to encode.

Although there is no technical restriction on using any tag to represent anything, [tags are assigned by IANA](https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml) to represent many common data types, and avoiding tag collision is generally desirable to facilitate interoperability.

As there are fewer lowered-number tags, IANA has different requirements for recognizing tags reserved in different ranges.

* Tags in the range 0-23 require standards action.
* Tags in the range 24-32767 require a specification.
* Tags in the range 32768 and above are first come, first served.

As of the date of this document, the [IANA Registry of CBOR Tags](https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml) shows the following low-numbered tags as unassigned.

* One byte encoding: 6-15, 19-20
* Two byte encoding: 48-51, 53, 55-60, 62, 88-95, 99, 102, 105-109, 113-119, 128-255

Currently Secure Components would benefit from having 17 of these tags. As we expect to file a specification at some point, we are choosing tags starting at #6.200 for highest-frequency tags.

Blockchain Commons is applying for these numbers to be assigned to the CBOR specification herein, but because these numbers are in a range that is open to other applications, it may change. For now, these low-numbered tags MUST be understood as provisional and subject to change by all implementors.



---

## Top-Level Types

The types defined in the Secure Components suite are designed to be minimal, easy to use, and composable. They can all be used independently, but are designed to work together. Here is a quick summary of these types:

* `Envelope` is the central "top level" type of Secure Components. Envelopes support everything from enclosing the most basic of plaintext messages, to innumerable recursive permutations of encryption, signing, sharding, and the representation of semantic graphs.
* `EncryptedMessage` is a symmetrically-encrypted message and is specified in full in [BCR-2022-001](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2022-001-secure-message.md).
* `PrivateKeyBase` holds key material such as a Seed belonging to an identifiable entity, and can produce all the private and public keys needed to use this suite. It is usually only serialized for purposes of backup.
* `PublicKeyBase` holds the public keys of an identifiable entity, and can be made public. It is not simply called a "public key" because it holds at least _two_ public keys: one for signing and another for encryption.
* `SealedMessage` is a message that has been one-way encrypted to a specific `PublicKeyBase`, and is used to implement multi-recipient public key encryption using `Envelope`.
* `Digest` is a cryptographic hash that uniquely identifies an immutable binary object.
* `CID` is a [Common Identifier](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2022-002-cid-common-identifier.md) that uniquely identifies a mutable set of traits.

Many of the types defined herein are assigned CBOR tags for use when encoding these structures. The types in this section may be used embedded within larger structures as tagged CBOR, or as top-level objects in URs. Note that when encoding URs, a top-level CBOR tag is not used, as the UR type provides that information.

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|200|`envelope`|`Envelope`|
|201|`crypto-msg`|`EncryptedMessage`|
|202|`crypto-cid`|`CID`|
|203|`crypto-digest`|`Digest`|
|204|`crypto-key`|`SymmetricKey`|
|205|`crypto-prvkeys`|`PrivateKeyBase`|
|206|`crypto-pubkeys`|`PublicKeyBase`|
|207|`crypto-sealed`|`SealedMessage`|

## Tagged Types

Types that do not define a UR type generally would never be serialized as a top-level object, but are frequently serialized as part of a larger structure. Some of the types below have a single-byte CBOR tag due to their frequency of use in the `Envelope` type.

|CBOR Tag|Swift Type|
|---|---|
|220|`Plaintext`|
|221|`Assertion`|
|222|`Signature`|
|223|`KnownPredicate`|
|230|`AgreementPublicKey`|
|700|`Password`|
|701|`Permit`|
|702|`AgreementPrivateKey`|
|704|`SigningPrivateKey`|
|705|`SigningPublicKey`|
|707|`Nonce`|

## Untagged Types

A number of types are simply serialized as untagged CBOR byte strings. They do not need tags because they are used in particular contexts where their meaning is fixed and unlikely to change over time. These include:

* `AAD`
* `Auth`
* `Ciphertext`
* `Plaintext`
* `Salt`
* `Tag`

For example, a field called `Auth` is currently only used in the context of the IETF-ChaCha20-Poly1305 encryption algorithm, and therefore does not need to be specifically tagged. If another algorithm also needed a field called `Auth`, it would be used in the context of *that* algorithm, and the two fields would not be considered interchangeable.
