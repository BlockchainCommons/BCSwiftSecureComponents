# Secure Components - Definitions

**Authors:** Wolf McNally, Christopher Allen, Blockchain Commons</br>
**Revised:** Mar 20, 2023</br>
**Status:** DRAFT

NOTE: Please go here for the latest version of this documentation related specifically to Gordian Envelope: [Envelope](https://blockchaincommons.github.io/BCSwiftEnvelope/documentation/envelope).

---

## Sections of this Document

* [AgreementPrivateKey](#agreementprivatekey)
* [AgreementPublicKey](#agreementpublickey)
* [CID](#cid)
* [Compressed](#compressed)
* [Digest](#digest)
* [EncryptedMessage](#encryptedmessage)
* [Nonce](#nonce)
* [Password](#password)
* [PrivateKeyBase](#privatekeybase)
* [PublicKeyBase](#publickeybase)
* [Salt](#salt)
* [SealedMessage](#sealedmessage)
* [Signature](#signature)
* [SigningPrivateKey](#signingprivatekey)
* [SigningPublicKey](#signingpublickey)
* [SymmetricKey](#symmetrickey)

---

## Introduction

This section describes each component, and provides its CDDL definition for CBOR serialization.

---

## AgreementPrivateKey

A Curve25519 private key used for [X25519 key agreement](https://datatracker.ietf.org/doc/html/rfc7748).

### AgreementPrivateKey: Swift Definition

```swift
struct AgreementPrivateKey {
    let data: Data
}
```

### AgreementPrivateKey: CDDL

|CBOR Tag|Swift Type|
|---|---|
|300|`AgreementPrivateKey`|

```
agreement-private-key = #6.300(key)

key = bytes .size 32
```

---

## AgreementPublicKey

A Curve25519 public key used for [X25519 key agreement](https://datatracker.ietf.org/doc/html/rfc7748).

### AgreementPublicKey: Swift Definition

```swift
struct AgreementPublicKey {
    let data: Data
}
```

### AgreementPublicKey: CDDL

|CBOR Tag|Swift Type|
|---|---|
|301|`AgreementPublicKey`|

```
agreement-public-key = #6.301(key)

key = bytes .size 230
```

---

## CID

A Common Identifier (CID) is a unique 32-byte identifier that, unlike a `Digest` refers to an object or set of objects that may change depending on who resolves the `CID` or when it is resolved. In other words, the referent of a `CID` may be considered mutable.

### CID: Swift Defintion

```swift
struct CID {
    let data: Data
}
```

### CID: CDDL

```
cid = #6.302(cid-data)

cid-data = bytes .size 32
```

---

## Compressed

A compressed binary object. Implemented using the raw DEFLATE format as described in [IETF RFC 1951](https://www.ietf.org/rfc/rfc1951.txt).

The following obtains the equivalent configuration of the encoder:

```
deflateInit2(zstream,5,Z_DEFLATED,-15,8,Z_DEFAULT_STRATEGY)
```

If the payload is too small to compress, the uncompressed payload is placed in the `compressedData` field and the size of that field will be the same as the `uncompressedSize` field.

### Compressed: Swift Definition

```swift
struct Compressed {
    let checksum: UInt32
    let uncompressedSize: Int
    let compressedData: Data
    let digest: Digest?
}
```

### Compressed: CDDL

```
compressed = #6.206([
    checksum, 
    uncompressed-size, 
    compressed-data, 
    ? digest              ; Optional user-defined digest
])

checksum = crc32          ; CRC-32 checksum of the uncompressed data
uncompressed-size = uint
compressed-data = bytes

crc32 = uint
```

---

## Digest

A Digest is a cryptographic hash of some source data. Currently Secure Components specifies the use of [SHA-256](https://www.rfc-editor.org/rfc/rfc6234), but more algorithms may be supported in the future.

|CBOR Tag|Swift Type|
|---|---|
|204|`Digest`|

### Digest: CDDL

```
digest = #6.204(sha256-digest)

sha256-digest = bytes .size 32
```

---

## EncryptedMessage

`EncryptedMessage` is a symmetrically-encrypted message and is specified in full in [BCR-2022-001](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2022-001-secure-message.md).

When used as part of Secure Components, and particularly with `Envelope`, the `aad` field contains the `Digest` of the encrypted plaintext. If non-correlation is necessary, then add random salt to the plaintext before encrypting.

### EncryptedMessage: Swift Definition

```swift
struct EncryptedMessage {
    let cipherText: Data
    let aad: Data
    let nonce: Data
    let auth: Data
}
```

### EncryptedMessage: CDDL

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|205|`encrypted`|`EncryptedMessage`|

An `encrypted` is an array containing either 3 or 4 elements. If additional authenticated data `aad` is non-empty, it is included as the fourth element, and omitted otherwise. `aad` MUST NOT be present and non-empty.

```
encrypted = #6.205([ ciphertext, nonce, auth, ? aad ])

ciphertext = bytes       ; encrypted using ChaCha20
aad = bytes              ; Additional Authenticated Data
nonce = bytes .size 12   ; Random, generated at encryption-time
auth = bytes .size 16    ; Authentication tag created by Poly1305
```

---

## Nonce

A `Nonce` is a cryptographically strong random "number used once" and is frequently used in algorithms where a random value is needed that should never be reused. Secure Components uses 12-byte nonces.

```swift
struct Nonce {
    let data: Data
}
```

## Nonce: CDDL

```
nonce = #6.307(bytes .size 12)
```

---

## Password

`Password` is a password that has been salted and hashed using [scrypt](https://datatracker.ietf.org/doc/html/rfc7914), and is thereofore suitable for storage and use for authenticating users via password. To validate an entered password, the same hashing algorithm using the same parameters and salt must be performed again, and the hashes compared to determine validity. This way the authenticator never needs to store the password. The processor and memory intensive design of the scrypt algorithm makes such hashes resistant to brute-force attacks.

### Password: Swift Definition

```swift
struct Password {
    let n: Int
    let r: Int
    let p: Int
    let salt: Data
    let data: Data
}
```

### Password: CDDL

|CBOR Tag|Swift Type|
|---|---|
|308|`Password`|

```
password = #6.308([n, r, p, salt, hashed-password])

n = uint                             ; iterations
r = uint                             ; block size
p = uint                             ; parallelism factor
salt = bytes                         ; random salt (16 bytes recommended)
hashed-password = bytes              ; 32 bytes recommended
```

---

## PrivateKeyBase

`PrivateKeyBase` holds key material such as a Seed belonging to an identifiable entity, or an HDKey derived from a Seed. It can produce all the private and public keys needed to use this suite. It is usually only serialized for purposes of backup.

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|309|`crypto-prvkeys`|`PrivateKeyBase`|

### PrivateKeyBase: Swift Definition

```swift
struct PrivateKeyBase {
    data: Data
}
```

### PrivateKeyBase: CDDL

```
crypto-prvkeys = #6.309([key-material])

key-material = bytes
```

### Derivations

* `SigningPrivateKey`: [HKDF](https://www.rfc-editor.org/rfc/rfc6234) with salt: `signing`.
* `AgreementPrivateKey`: [HKDF](https://www.rfc-editor.org/rfc/rfc6234) with salt: `agreement`.
* `SigningPublicKey`: [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) x-only public key or [ECDSA-25519-doublesha256](https://en.bitcoin.it/wiki/BIP_0137) public key.
* `SigningPrivateKey`: [RFC-7748 X25519](https://datatracker.ietf.org/doc/html/rfc7748).

---

## PublicKeyBase

`PublicKeyBase` holds the public keys of an identifiable entity, and can be made public. It is not simply called a "public key" because it holds at least _two_ public keys: one for signing and another for encryption. The `SigningPublicKey` may specifically be for verifying Schnorr or ECDSA signatures.

### PublicKeyBase: Swift Definition

```swift
struct PublicKeyBase {
    let signingPublicKey: SigningPublicKey
    let agreementPublicKey: AgreementPublicKey
}
```

### PublicKeyBase: CDDL

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|310|`crypto-pubkeys`|`PublicKeyBase`|

A `crypto-pubkeys` is a two-element array with the first element being the `signing-public-key` and the second being the `agreement-public-key`.

```
crypto-pubkeys = #6.310([signing-public-key, agreement-public-key])
```

---

## Salt

A `Salt` is random data frequently used as an additional input to one-way algorithms (e.g., password hashing) where similar inputs (the same password) should not yield the same outputs (the hashed password.) Salts are not usually secret.

```swift
struct Salt {
    let data: Data
}
```

## Salt: CDDL

```
salt = #6.311(bytes)
```

---

## SealedMessage

`SealedMessage` is a message that has been one-way encrypted to a particular `PublicKeyBase`, and is used to implement multi-recipient public key encryption using `Envelope`. The sender of the message is generated at encryption time, and the ephemeral sender's public key is included, enabling the receipient to decrypt the message without identifying the real sender.

### SealedMessage: Swift Definition

```swift
struct SealedMessage {
    let message: EncryptedMessage
    let ephemeralPublicKey: AgreementPublicKey
}
```

### SealedMessage: CDDL

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|312|`crypto-sealed`|`SealedMessage`|

```
crypto-sealed = #6.312([crypto-message, ephemeral-public-key])

ephemeral-public-key = agreement-public-key
```

---

## Signature

A cryptographic signature. It has two variants:

* A [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) signature.
* An ECDSA signature [ECDSA-25519-doublesha256](https://en.bitcoin.it/wiki/BIP_0137) signatures.

### Signature: Swift Definition

```swift
public enum Signature {
    case schnorr(data: Data, tag: Data)
    case ecdsa(data: Data)
}
```

### Signature: CDDL

|CBOR Tag|Swift Type|
|---|---|
|313|`Signature`|

A `signature` has two variants. The Schnorr variant is preferred. Schnorr signatures may include tag data of arbitrary length.

If the `signature-variant-schnorr` is selected and has no tag, it will appear directly as a byte string of length 64. If it includes tag data, it will appear as a two-element array where the first element is the signature and the second element is the tag. The second form MUST NOT be used if the tag data is empty.

If the `signature-variant-ecdsa` is selected, it will appear as a two-element array where the first element is `1` and the second element is a byte string of length 64.

```
signature = #6.313([ signature-variant-schnorr / signature-variant-ecdsa ])

signature-variant-schnorr = signature-schnorr / signature-schnorr-tagged
signature-schnorr = bytes .size 64
signature-schnorr-tagged = [signature-schnorr, schnorr-tag]
schnorr-tag = bytes .size ne 0

signature-variant-ecdsa = [ 1, signature-ecdsa ]
signature-ecdsa = bytes .size 64
```

---

## SigningPrivateKey

A private key for creating [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) or [ECDSA-25519-doublesha256](https://en.bitcoin.it/wiki/BIP_0137) signatures.

### SigningPrivateKey: Swift Definition

```swift
struct SigningPrivateKey {
    let data: Data
}
```

### SigningPrivateKey: CDDL

|CBOR Tag|Swift Type|
|---|---|
|314|`SigningPrivateKey`|

```
private-signing-key = #6.314(key)

key = bytes .size 32
```

---

## SigningPublicKey

A public key for verifying signatures. It has two variants:

* An x-only public key for verifying [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) signatures.
* An ECDSA public key [ECDSA-25519-doublesha256](https://en.bitcoin.it/wiki/BIP_0137) signatures.

### SigningPublicKey: Swift Definition

```swift
public enum SigningPublicKey {
    case schnorr(SchnorrPublicKey)
    case ecdsa(ECPublicKey)
}
```

### SigningPublicKey: CDDL

|CBOR Tag|Swift Type|
|---|---|
|315|`SigningPublicKey`|

A signing public key has two variants: Schnorr or ECDSA. The Schnorr variant is preferred, so it appears as a byte string of length 32. If ECDSA is selected, it appears as a 2-element array where the first element is `1` and the second element is the compressed ECDSA key as a byte string of length 33.

```
signing-public-key = #6.315(key-variant-schnorr / key-variant-ecdsa)

key-variant-schnorr = key-schnorr
key-schnorr = bytes .size 32

key-variant-ecdsa = [1, key-ecdsa]
key-ecdsa = bytes .size 33
```

---

## SymmetricKey

A symmetric key for encryption and decryption of [IETF-ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439) messages.

### SymmetricKey: Swift Definition

```swift
public struct SymmetricKey {
    let data: Data
}
```

### SymmetricKey: CDDL

|CBOR Tag|Swift Type|
|---|---|
|316|`SymmetricKey`|

```
symmetric-key = #6.316( symmetric-key-data )
symmetric-key-data = bytes .size 32
```
