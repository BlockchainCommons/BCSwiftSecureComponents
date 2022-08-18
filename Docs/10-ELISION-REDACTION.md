# Secure Components - Elision and Redaction

**Authors:** Wolf McNally, Christopher Allen, Blockchain Commons</br>
**Revised:** Aug 17, 2022</br>
**Status:** DRAFT

---

## Contents

* [Overview](1-OVERVIEW.md)
* [Envelope Overview](2-ENVELOPE.md)
* [Envelope Notation](3-ENVELOPE-NOTATION.md)
* [Envelope Expressions](4-ENVELOPE-EXPRESSIONS.md)
* [Definitions](5-DEFINITIONS.md)
* [Examples](6-EXAMPLES.md)
* [Envelope Test Vectors](7-ENVELOPE-TEST-VECTORS.md)
* [Envelope SSKR Test Vectors](8-ENVELOPE-SSKR-TEST-VECTORS.md)
* [Noncorrelation](9-NONCORRELATION.md)
* Elision and Redaction: This document

---

# Introduction

One common use case for a general hierarchical container structure such as `Envelope` is *data minimization*, which is the privacy-preserving of only revealing what is necessary and sufficient for parties to trust each other and transact together.

One way of providing data minimization is *selective disclosure*. If I wish to prove my birth date to you, I could show you my drivers license:

```
{
  CID(xxx) [
      "firstName": "John"
      "lastName": "Smith"
      "address": "123 Main Street"
      "birthDate": 1970-01-01
      "photo": CBOR
      "dlNunber": "123-456-789"
      "noncommercialVehicleEndorsement": true
      "motorcycleEndorsement": true
  ]
} [
    verifiedBy: Signature
]
```

If you trust the authenticity of the document (i.e., that it is not forged and that it is issued by an authority you trust), you can indeed verify my birth date by correlating that fact in the document with my photograph in the document. However, showing you my drivers license also unintentionally reveals other information such as my name, home address, and drivers license number that can potentially be used to find correlate even more information held by third parties. Selective disclosure would be like handing you my drivers license where you could see the issuing authority, my photograph, my birth date, and nothing else; not even my name.

```
{
  ELIDED [
      ELIDED
      ELIDED
      ELIDED
      "birthDate": 1970-01-01
      "photo": CBOR
      ELIDED
      ELIDED
      ELIDED
  ]
} [
    verifiedBy: Signature
]
```

The Blockchain Commons `Envelope` type is designed for the construction of verifiable digital documents that can be as long-lived as a blockchain transaction or government-issued credential, or as ephemeral as a function call. Among its capabilities, `Envelope` includes affordances for `elision`, which is the selective withholding of specified information in a document, while still maintaining its integrity and verifiability.

# Use Cases for Elision

The term "elide" means "to leave out." In an `Envelope`, elided items are replaced by their merkle tree digest, therefore allowing the same digests to be calculated for the entire tree. Among other things, this allows signatures to be verified against documents that have been partially elided. It even allows "blind signatures" to be produced on documents that have been partially or completely elided.

The difference between "elision" and "redaction" is not functional, but semantic: elision is *what* is accomplished, while *redaction* is one purpose that data might be elided. When one *redacts*, one is choosing to withhold information with no affordance or expectation that the receiving party can or will recover it.

In fact there is another common use case for elision: *referencing*. In this case, information is elided with every affordance and expectation that the receiving party can and might choose to recover the elided information.

My photo might be embedded within my digital drivers license. Embedding has the advantage that it's right there to be interpreted by anyone who reads the document. In this case there are two reasons I might want a version of my credential with the photo elided.

First, I might redact it because it is priviledged or irrelevant to the transaction I want to perform.

Alternatively, I want the data to be smaller, while still allowing the retrieval of the photo by interested parties. In this case, *dereferencing method* would need to be included as to *how* to retrieve the information.

```
{
  CID(xxx) [
      ...
      "photo": ELIDED [
          dereferenceVia: "IPFS"
      ]
      ...
  ]
} [
    verifiedBy: Signature
]
```

In this case, the photo has not been *redacted*, it has been *referenced*, because an affordance to recover it is present. And because `Envelope` supports a number of Merkle tree-preserving actions, the actual photo data can be retrieved using the digest and the credential can transormed to its *dereferenced* version while still preserving the signature:

```
{
  CID(xxx) [
      ...
      "photo": CBOR [
          dereferenceVia: "IPFS"
      ]
      ...
  ]
} [
    verifiedBy: Signature
]
```

If I wanted to fully redact my photo, I would just elide the entire assertion. There is then no way the receiver would be able to know whether the credential contains a photo or anything about it:

```
{
  CID(xxx) [
      ...
      ELIDED
      ...
  ]
} [
    verifiedBy: Signature
]
```

## Immutable References

When an element of an `Envelope` is elided for the purpose of referencing, the only object that can be used to dereference it the identical image from which the digest was generated. This means that *a digest's referent is immutable*. Therefore, every time a particular digest is dereferenced, the exact same referent must be returned.

Unlike a generic binary file, which is treated as a simple sequence of bits for the purpose of computing its digest, an `Envelope` is treated as a *tree* of objects, each of which produces a digest, and which may be selectively elided without affecting the digests upwards toward the root. So in the case of `Envelope`, it is possible, even useful, that dereferencing a digest through a particular authority might return an `Envelope` that has the same top-level digest, but which has been partially or completely elided either for purposes of redaction or referencing.

So it's important to realize that while information may be *elided* in in an envelope, no underlying information can have been *mutated* (i.e., added, removed, or altered). Furthermore, any elided document could still be transformed to the un-elided version if the elided parts could be retrieved.

When referencing a document by digest, the referent must be considered an immutable "snapshot" of a document.

## Mutable References

Of course, many documents change over time, or may look different depending on who's doing the recordkeeping. Databases all have the concept of a "unique key" for a record, such as a drivers license or passport number. Different databases can use the same numbers as keys referencing different records, and the records they keep may change.

Secure Components introduces the [Common Identifier (CID)](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2022-002-cid-common-identifier.md) as a universal way of identifying mutable objects. Relative to `Envelope` the use of CIDs is optional, but we feel they have some unique strengths (seed the CID paper for more).

"Mutability" occurs when dereferencing an identifier might return a different set of information over time, or depending on the
A Common Identifier (CID) is used when a mutable reference is needed. Since CIDs are not tied to a specific binary object, dereferencing a CID may yield different versions of a document, or even completely disparate information, depending on when and from whom the dereferencing is requested.

# Performing Elision

Consider an `Envelope` with two assertion. "Alice" is the subject, "knows" is a predicate, and "Bob" and "Carol" are the objects. Here is the Swift code to construct it:

```
let e = Envelope("Alice")
    .addAssertion("knows", "Bob")
    .addAssertion("knows", "Carol")
```

And here it is in Envelope Notation:

```
"Alice" [
    "knows": "Bob"
    "knows": "Carol"
]
```

Here is a representation of the Merkle Tree for that `Envelope`. Each line represents a unique digest, and therefore a potential *elision point*.

```
Subject
Assertion
    Predicate
    Object
Assertion
    Predicate
    Object
```

By selecting a set of elision points, or *target*, Secure Components can perform automatic elision, either by eliding everything identified in the target, or *not* eliding (revealing) everything not in the target.

The interesting thing to note in the above example is that the "knows" predicate occurs twice. So if your target set included only the digest of the "knows" predicate, it would be elided everywhere it appears. Here is the Swift code to perform that elision:

```
let target2: [DigestProvider] = [Envelope("knows")]
let e2 = e.elideRemoving(target2)
print(e2.format)
```

And here is the result:

```
"Alice" [
    ELIDED: "Bob"
    ELIDED: "Carol"
]
```

There are several ways of addressing this. First, eliding a predicate by itself is not very useful. Each assertion must be unique, for example, the `"knows": "Bob"` assertion can never appear twice. So within this structure it can be uniquely identified by its assertion digest. So normally one would elide an entire assertion:

```
let target3: [DigestProvider] = [Envelope(predicate: "knows", object: "Bob")]
let e3 = e.elideRemoving(target3)
print(e3.format)
```

```
"Alice" [
    ELIDED
    "knows": "Carol"
]
```

Frequently we wish to specify that everything *but* a target is to be elided:


MORE TO COME
