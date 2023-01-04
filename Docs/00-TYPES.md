# Secure Components - Types

**Authors:** Wolf McNally, Christopher Allen, Blockchain Commons</br>
**Revised:** Aug 26, 2022</br>
**Status:** DRAFT

---

## Contents

* Types: This document
* [Definitions](01-DEFINITIONS.md)
* [Appendix A: MVA Algorithm Suite](02-A-ALGORITHMS.md)

---

## Introduction

One of the key design elements in Blockchain Commons' overarching Gordian system is that data be self-identifying. This dramatically reduces the possibility of vendor lock-in: even if an app becomes obsolete, the data can be read by another app that follows the same specifications. This self-identification is maintained in large part through the careful and consistent use of data typing.

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

Types that do not define a UR type generally would never be serialized as a top-level object, but are frequently serialized as part of a larger structure.

|CBOR Tag|type|
|---|---|
|213|`function`|
|214|`parameter`|
|215|`request`|
|216|`response`|
|217|`placeholder`|
|218|`replacement`|
|220|`leaf`|
|221|`assertion`|
|222|`signature`|
|223|`knownValue`|
|224|`wrappedEnvelope`|
|225|`elided`|
|230|`agreementPublicKey`|
|700|`password`|
|702|`agreementPrivateKey`|
|704|`signingPrivateKey`|
|705|`signingPublicKey`|
|707|`nonce`|
|708|`salt`|

## Untagged Types

A number of types are simply serialized as untagged CBOR byte strings. They do not need tags because they are used in particular contexts where their meaning is fixed and unlikely to change over time. These include:

* `AAD`
* `Auth`
* `Ciphertext`
* `Plaintext`
* `Tag`

For example, a field called `Auth` is currently only used in the context of the IETF-ChaCha20-Poly1305 encryption algorithm, and therefore does not need to be specifically tagged. If another algorithm also needed a field called `Auth`, it would be used in the context of *that* algorithm, and the two fields would not be considered interchangeable.

---

## Reservation of CBOR Tags

Lower-numbered CBOR tags take fewer bytes to encode, and are hence more desirable "real estate."

* Tags in the range 0-23 require one byte to encode.
* Tags in the range 24-255 require two bytes to encode.
* Tags from 256 and above require three or more bytes to encode.

Although there is no technical restriction on using any tag to represent anything, [tags are assigned by IANA](https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml) to represent many common data types, and avoiding tag collision is generally desirable to facilitate interoperability.

As there are fewer lowered-number tags, IANA has different requirements for recognizing tags reserved in different ranges:

* Tags in the range 0-23 require standards action.
* Tags in the range 24-32767 require a specification.
* Tags in the range 32768 and above are first come, first served.

As of the date of this document, the [IANA Registry of CBOR Tags](https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml) shows the following low-numbered tags as unassigned.

* One byte encoding: 6-15, 19-20
* Two byte encoding: 48-51, 53, 55-60, 62, 88-95, 99, 102, 105-109, 113-119, 128-255

Currently Secure Components would benefit from having 21 of these tags. As we expect to file a specification at some point, we are choosing tags starting at #6.200 for highest-frequency tags.

Blockchain Commons is applying for these numbers to be assigned to the CBOR specification herein, but because these numbers are in a range that is open to other applications, it may change. For now, these low-numbered tags MUST be understood as provisional and subject to change by all implementors.

---
