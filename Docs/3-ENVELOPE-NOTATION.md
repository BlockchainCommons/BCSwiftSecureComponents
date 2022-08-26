# Secure Components - Envelope Notation

**Authors:** Wolf McNally, Christopher Allen, Blockchain Commons</br>
**Revised:** May 16, 2022</br>
**Status:** DRAFT

---

## Contents

* [Envelope Introduction](0-INTRODUCTION.md)
* [Types](1-TYPES.md)
* [Envelope Overview](2-ENVELOPE.md)
* Envelope Notation: This document
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

We provide a simplified textual notation for pretty-printing instances of the `Envelope` type.

## Status

This document is a draft with a reference implementation in [BCSwiftSecureComponents](https://github.com/blockchaincommons/BCSwiftSecureComponents).

* Braces `{ }` are used to delimit the contents of a nested `Envelope`.
* Top-level braces representing the outermost `Envelope` are omitted.
* Square brackets `[ ]` may come after the `subject` of an `Envelope` and are used to delimit the list of `Assertion`s.
* Type names, enumeration cases, and empty assertion lists are elided.

For example, instead of writing:

```
{
    subject: .leaf("Hello"),
    assertions: [ ]
}
```

we simply write:

```
"Hello"
```

If we were to output the [CBOR diagnostic notation](https://www.rfc-editor.org/rfc/rfc8949.html#name-diagnostic-notation) for the above, we'd see:

```
200(
   220("Hello.")
)
```

`200` is the CBOR tag for `Envelope` and `220` is the tag for `.leaf`. Wrapping this 5-byte UTF-8 string in an `Envelope` only adds 4 bytes (2 for each tag) and 1 byte that identifies the string's type and length, for a total of 10 bytes. CBOR (and hence `Envelope`) is therefore completely self-describing.

Generally, a `Envelope` output in Envelope Notation looks like this:

```
Subject [
    Predicate: Object
    Predicate: Object
    ...
]
```

The four roles `Assertion`, `Subject`, `Predicate`, and `Object` are *themselves* Envelopes, allowing for *complex metadata*, i.e., meta assertions about any part of a Envelope:

```
{
    Subject [
        note: "A note about the subject."
        Predicate [
            note: "A note about the predicate."
        ] : Object [
            note: "A note about the object."
        ]
    ]
} [
    note: "A note about the Envelope as a whole."
]
```

Even leaf objects like strings and numbers can be transformed into Envelopes with their own assertions:

```
{
    Subject [
        note: {
            "A note about the subject." [
                lang: "en"
            ]
        }
        Predicate [
            note: {
                "A note about the predicate." [
                    lang: "en"
                ]
            }
        ] : Object [
            note: {
                "A note about the object." [
                    lang: "en"
                ]
            }
        ]
    ]
} [
    note: {
        "A note about the Envelope as a whole." [
            lang: "en"
        ]
    }
]
```

Thus, the `Envelope` type provides a flexible foundation for constructing solutions for various applications. Here are some high-level schematics of such applications in Envelope Notation. See the [EXAMPLES](6-EXAMPLES.md) chapter for more detail.

## Examples

---

## An envelope containing plaintext.

```
"Hello."
```

---

## An envelope containing signed plaintext.

This is the `.leaf` string with a single `Assertion` whose predicate is a well-known integer with a CBOR tag meaning `predicate`, while the object is a `Signature`.

```
"Hello." [
    verifiedBy: Signature
]
```

---

## An envelope containing plaintext signed by several parties.

Although you cannot have duplicate assertions every signature is unique, hence these are two *different* assertions.

```
"Hello." [
    verifiedBy: Signature
    verifiedBy: Signature
]
```

---

## An envelope containing a symmetrically encrypted message.

The subject is just an `EncryptedMessage`. Because this `EncryptedMessage` is the `subject` of an `Envelope`, we do know that its plaintext MUST be CBOR. This CBOR plaintext may be a leaf or another `Envelope` with more layers of assertions possibly  including signatures, but the receiver will have to decrypt it to find out.

```
EncryptedMessage
```

---

## A message that has been encrypted then signed.

The sender has first encrypted a message, then signed it. The signature can be verified before the actual message is decrypted because an encrypted `subject` carries the hash of the plaintext with it, and it is this hash that is used with the signature for verification.

```
EncryptedMessage [
    verifiedBy: Signature
]
```

---

## A message that can only be opened by specific receivers.

An ephemeral "content key" has been used to encrypt the message and the content key itself has been encrypted to one or more receipients' public keys. Therefore, only the intended recipients can decrypt and read the message, without the sender and receivers having to exchange a secret symmetric key first.

```
EncryptedMessage [
    hasRecipient: SealedMessage
    hasRecipient: SealedMessage
]
```

---

## A signed envelope that can only be opened by specific receivers.

As before, the signature can be outside the `subject` message, as below, or inside it, requiring decryption before verification.

```
EncryptedMessage [
    verifiedBy: Signature
    hasRecipient: SealedMessage
    hasRecipient: SealedMessage
]
```

---

## Several Envelopes containing a message split into several SSKR shares.

A message has been split into a three shares using SSKR and distributed to three trustees. Two of these shares must be recovered to reconstruct the original message.

```
EncryptedMessage [
    sskrShare: SSKRShare
]

EncryptedMessage [
    sskrShare: SSKRShare
]

EncryptedMessage [
    sskrShare: SSKRShare
]
```

---

## Complex Metadata

A specific digital object is identified and several layers of metadata are attributed to it. In this example some predicates are specified as strings (indicated by quotes) while other predicates use tagged well-known integers (no quotes).

This structure uses the `dereferenceVia` predicate to indicate that the full book in EPUB format may be retrieved using ExampleStore, and that its hash will match the hash provided, while more information about the author may be retrieved from the Library of Congress, and this information may change over time.

```
Digest(e8aa201db4044168d05b77d7b36648fb7a97db2d3e72f5babba9817911a52809) [
    "format": "EPUB"
    "work": CID(7fb90a9d96c07f39f75ea6acf392d79f241fac4ec0be2120f7c82489711e3e80) [
        "author": CID(9c747ace78a4c826392510dd6285551e7df4e5164729a1b36198e56e017666c8) [
            dereferenceVia: "LibraryOfCongress"
            hasName: "Ayn Rand"
        ]
        "isbn": "9780451191144"
        dereferenceVia: "LibraryOfCongress"
        hasName: "Atlas Shrugged" [
            language: "en"
        ]
        hasName: "La rebelión de Atlas" [
            language: "es"
        ]
        isA: "novel"
    ]
    dereferenceVia: "IPFS"
]
```

---

## Verifiable Credential

A government wishes to issue a verifiable credential for permanent residency to an individual using a Common Identifier (CID) provided by that person.

```
{
    CID(174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8) [
        "dateIssued": 2022-04-27
        holder: CID(78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc) [
            "birthCountry": "bs" [
                note: "The Bahamas"
            ]
            "birthDate": 1974-02-18
            "familyName": "SMITH"
            "givenName": "JOHN"
            "image": Digest(36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999) [
                dereferenceVia: "https://exampleledger.com/digest/36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999"
                note: "This is an image of John Smith."
            ]
            "lprCategory": "C09"
            "lprNumber": "999-999-999"
            "residentSince": 2018-01-07
            "sex": "MALE"
            isA: "Permanent Resident"
            isA: "Person"
        ]
        isA: "credential"
        issuer: CID(04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8) [
            dereferenceVia: URI(https://exampleledger.com/cid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8)
            note: "Issued by the State of Example"
        ]
        note: "The State of Example recognizes JOHN SMITH as a Permanent Resident."
    ]
} [
    verifiedBy: Signature [
        note: "Made by the State of Example."
    ]
]
```

---

## Redaction/Elision

The holder of a credential can then selectively reveal any of the micro-claims in this document. For instance, the holder could reveal just their name, their photo, and the issuer's signature, thereby proving that the issuer did indeed certify those facts.

Elision is performed by building a target set of `Digest`s that will be revealed. All digests not present in the target will be replaced with elision markers containing only the digest of what has been elided, thus preserving the Merkle tree including revealed signatures. If a higher-level object is elided, then everything it contains will also be elided, so if a deeper object is to be revealed, all of its parent objects up to the level of the verifying signature also need to be revealed, even though not everything *about* the parent objects must be revealed.

See [Elision & Redaction](10-ELISION-REDACTION.md) for more on this topic.

```
{
    CID(174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8) [
        ELIDED
        ELIDED
        holder: CID(78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc) [
            ELIDED
            ELIDED
            ELIDED
            ELIDED
            ELIDED
            ELIDED
            ELIDED
            ELIDED
            "familyName": "SMITH"
            "givenName": "JOHN"
            "image": Digest(36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999) [
                dereferenceVia: "https://exampleledger.com/digest/36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999"
                note: "This is an image of John Smith."
            ]
        ]
        isA: "credential"
        issuer: CID(04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8) [
            dereferenceVia: URI(https://exampleledger.com/cid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8)
            note: "Issued by the State of Example"
        ]
    ]
} [
    verifiedBy: Signature [
        note: "Made by the State of Example."
    ]
]
```

