# Secure Components - Mermaid Output

**Authors:** Wolf McNally, Christopher Allen, Blockchain Commons</br>
**Revised:** Oct 18, 2022</br>
**Status:** DRAFT

---

## Contents

* [Envelope Introduction](00-INTRODUCTION.md)
* [Types](01-TYPES.md)
* [Envelope Overview](02-ENVELOPE.md)
* [Envelope Notation](03-ENVELOPE-NOTATION.md)
* Mermaid Output: This document
* [Envelope Expressions](05-ENVELOPE-EXPRESSIONS.md)
* [Definitions](06-DEFINITIONS.md)
* [Examples](07-EXAMPLES.md)
* [Noncorrelation](08-NONCORRELATION.md)
* [Elision and Redaction](09-ELISION-REDACTION.md)
* [Existence Proofs](10-EXISTENCE-PROOFS.md)
* [Appendix A: MVA Algorithm Suite](11-A-ALGORITHMS.md)
* [Appendix B: Envelope Test Vectors](12-B-ENVELOPE-TEST-VECTORS.md)
* [Appendix C: Envelope SSKR Test Vectors](13-C-ENVELOPE-SSKR-TEST-VECTORS.md)

---

## Introduction

These examples compare a series of Gordian Envelopes output first in "envelope notation" and then in [Mermaid](https://mermaid-js.github.io/mermaid/#/) format.

## Plaintext

```
"Hello."
```

```mermaid
graph LR
    1["886a0c85<br/>#quot;Hello.#quot;"]
    style 1 stroke:#55f,stroke-width:3.0px
```

* Leaf elements (elements having no children) have blue outlines.
* CBOR leaf elements (like strings, but they can be of any complexity) are represented by rectangles.
* The digests shown in each element are the first four bytes of the 32-byte digest associated with each element.
* Every element you see is *itself* an envelope that can be extracted and manipulated. If two digests match, the contents of the envelopes they represent also necessarily match.

## Signed Plaintext

```
"Hello." [
    verifiedBy: Signature
]
```

```mermaid
graph LR
    1(("c3915ed3<br/>NODE"))
    2["886a0c85<br/>#quot;Hello.#quot;"]
    3(["5f656bf5<br/>ASSERTION"])
    4[/"d59f8c0f<br/>verifiedBy"/]
    5["9f388294<br/>Signature"]
    1 -->|subj| 2
    1 --> 3
    3 -->|pred| 4
    3 -->|obj| 5
    style 1 stroke:red,stroke-width:3.0px
    style 2 stroke:#55f,stroke-width:3.0px
    style 3 stroke:red,stroke-width:3.0px
    style 4 stroke:#55f,stroke-width:3.0px
    style 5 stroke:#55f,stroke-width:3.0px
    linkStyle 0 stroke:red,stroke-width:2.0px
    linkStyle 1 stroke-width:2.0px
    linkStyle 2 stroke:green,stroke-width:2.0px
    linkStyle 3 stroke:#55f,stroke-width:2.0px
```

* Internal elements (elements with children) are represented with red outlines.
* A `NODE` element appears when one or more assertions are present on a subject. They are represented by circles. They have one arm for the `subject` and an additional arm for each assertion.
* An `ASSERTION` element is represented by the Mermaid `stadium`  shape, and has exactly two arms: `predicate` and `object`.
* Well-known values like the `verifiedBy` are represented by trapezoids, and are encoded as short integers.

## Encrypted Subject

```
ENCRYPTED [
    "knows": "Bob"
]
```

```mermaid
graph LR
    1(("e54d6fd3<br/>NODE"))
    2>"27840350<br/>ENCRYPTED"]
    3(["55560bdf<br/>ASSERTION"])
    4["7092d620<br/>#quot;knows#quot;"]
    5["9a771715<br/>#quot;Bob#quot;"]
    1 -->|subj| 2
    1 --> 3
    3 -->|pred| 4
    3 -->|obj| 5
    style 1 stroke:red,stroke-width:3.0px
    style 2 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
    style 3 stroke:red,stroke-width:3.0px
    style 4 stroke:#55f,stroke-width:3.0px
    style 5 stroke:#55f,stroke-width:3.0px
    linkStyle 0 stroke:red,stroke-width:2.0px
    linkStyle 1 stroke-width:2.0px
    linkStyle 2 stroke:green,stroke-width:2.0px
    linkStyle 3 stroke:#55f,stroke-width:2.0px
```

* `ENCRYPTED` and `ELIDED` elements appear with dotted outlines in the Mermaid output, to indicate that they may be replaced with their unencrypted/unelided counterparts without invalidating the digest tree.
* `ENCRYPTED` elements are represented by the Mermaid `asymmetric` shape.

## Elided Object

```
"Alice" [
    "knows": ELIDED
]
```

```mermaid
graph LR
    1(("e54d6fd3<br/>NODE"))
    2["27840350<br/>#quot;Alice#quot;"]
    3(["55560bdf<br/>ASSERTION"])
    4["7092d620<br/>#quot;knows#quot;"]
    5{{"9a771715<br/>ELIDED"}}
    1 -->|subj| 2
    1 --> 3
    3 -->|pred| 4
    3 -->|obj| 5
    style 1 stroke:red,stroke-width:3.0px
    style 2 stroke:#55f,stroke-width:3.0px
    style 3 stroke:red,stroke-width:3.0px
    style 4 stroke:#55f,stroke-width:3.0px
    style 5 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
    linkStyle 0 stroke:red,stroke-width:2.0px
    linkStyle 1 stroke-width:2.0px
    linkStyle 2 stroke:green,stroke-width:2.0px
    linkStyle 3 stroke:#55f,stroke-width:2.0px
```

* `ELIDED` elements are represented by dotted hexagons.
* Note that the digest of the element "Bob" in the previous example matches the digest of the elided element above.
* Likewise, note that the digest of the subject "Alice" matches the encrypted version in the previous example.
* In fact, *all* the digests in this envelope match those in the previous example, indicating that the unencrypted/unelided form of this envelope has the exact same content.

## Top-Level Assertion

```
"knows": "Bob"
```

```mermaid
graph LR
    1(["55560bdf<br/>ASSERTION"])
    2["7092d620<br/>#quot;knows#quot;"]
    3["9a771715<br/>#quot;Bob#quot;"]
    1 -->|pred| 2
    1 -->|obj| 3
    style 1 stroke:red,stroke-width:3.0px
    style 2 stroke:#55f,stroke-width:3.0px
    style 3 stroke:#55f,stroke-width:3.0px
    linkStyle 0 stroke:green,stroke-width:2.0px
    linkStyle 1 stroke:#55f,stroke-width:2.0px
```

* As mentioned previously, all of the element types are themselves envelopes, and can therefore stand alone. In this case, we have extracted a single assertion.


## Signed Subject

```
"Alice" [
    "knows": "Bob"
    "knows": "Carol"
    verifiedBy: Signature
]
```

```mermaid
graph LR
    1(("efed9563<br/>NODE"))
    2["27840350<br/>#quot;Alice#quot;"]
    3(["55560bdf<br/>ASSERTION"])
    4["7092d620<br/>#quot;knows#quot;"]
    5["9a771715<br/>#quot;Bob#quot;"]
    6(["71a30690<br/>ASSERTION"])
    7["7092d620<br/>#quot;knows#quot;"]
    8["ad2c454b<br/>#quot;Carol#quot;"]
    9(["dbb0ad16<br/>ASSERTION"])
    10[/"d59f8c0f<br/>verifiedBy"/]
    11["858d19e2<br/>Signature"]
    1 -->|subj| 2
    1 --> 3
    3 -->|pred| 4
    3 -->|obj| 5
    1 --> 6
    6 -->|pred| 7
    6 -->|obj| 8
    1 --> 9
    9 -->|pred| 10
    9 -->|obj| 11
    style 1 stroke:red,stroke-width:3.0px
    style 2 stroke:#55f,stroke-width:3.0px
    style 3 stroke:red,stroke-width:3.0px
    style 4 stroke:#55f,stroke-width:3.0px
    style 5 stroke:#55f,stroke-width:3.0px
    style 6 stroke:red,stroke-width:3.0px
    style 7 stroke:#55f,stroke-width:3.0px
    style 8 stroke:#55f,stroke-width:3.0px
    style 9 stroke:red,stroke-width:3.0px
    style 10 stroke:#55f,stroke-width:3.0px
    style 11 stroke:#55f,stroke-width:3.0px
    linkStyle 0 stroke:red,stroke-width:2.0px
    linkStyle 1 stroke-width:2.0px
    linkStyle 2 stroke:green,stroke-width:2.0px
    linkStyle 3 stroke:#55f,stroke-width:2.0px
    linkStyle 4 stroke-width:2.0px
    linkStyle 5 stroke:green,stroke-width:2.0px
    linkStyle 6 stroke:#55f,stroke-width:2.0px
    linkStyle 7 stroke-width:2.0px
    linkStyle 8 stroke:green,stroke-width:2.0px
    linkStyle 9 stroke:#55f,stroke-width:2.0px
```

* A signature signs only the digest of the subject, in this case "Alice". So in this case, the "knows" assertions are not signed.
* Note that for every internal element, the children are displayed in the order that their digests are combined to form the parent's digest. In particular a `NODE`'s, `ASSERTION` elements are ordered by ascending digest value, so the order of the three assertion digests here: `3ed95464`, `55560bdf`, `71a30690` reflects that ascending order.

## Elided Assertions

```
"Alice" [
    ELIDED (3)
]
```

```mermaid
graph LR
    1(("efed9563<br/>NODE"))
    2["27840350<br/>#quot;Alice#quot;"]
    3{{"55560bdf<br/>ELIDED"}}
    4{{"71a30690<br/>ELIDED"}}
    5{{"dbb0ad16<br/>ELIDED"}}
    1 -->|subj| 2
    1 --> 3
    1 --> 4
    1 --> 5
    style 1 stroke:red,stroke-width:3.0px
    style 2 stroke:#55f,stroke-width:3.0px
    style 3 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
    style 4 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
    style 5 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
    linkStyle 0 stroke:red,stroke-width:2.0px
    linkStyle 1 stroke-width:2.0px
    linkStyle 2 stroke-width:2.0px
    linkStyle 3 stroke-width:2.0px
```

* This is the same envelope from the previous example with its assertions elided. Note that the digests at every level still present are all the same.

## Wrapped Then Signed

```
{
    "Alice" [
        "knows": "Bob"
        "knows": "Carol"
    ]
} [
    verifiedBy: Signature
]
```

```mermaid
graph LR
    1(("fde86f77<br/>NODE"))
    2[/"3cc750a3<br/>WRAPPED"\]
    3(("c733401e<br/>NODE"))
    4["27840350<br/>#quot;Alice#quot;"]
    5(["55560bdf<br/>ASSERTION"])
    6["7092d620<br/>#quot;knows#quot;"]
    7["9a771715<br/>#quot;Bob#quot;"]
    8(["71a30690<br/>ASSERTION"])
    9["7092d620<br/>#quot;knows#quot;"]
    10["ad2c454b<br/>#quot;Carol#quot;"]
    11(["ab430e79<br/>ASSERTION"])
    12[/"d59f8c0f<br/>verifiedBy"/]
    13["2a13e7f6<br/>Signature"]
    1 -->|subj| 2
    2 -->|subj| 3
    3 -->|subj| 4
    3 --> 5
    5 -->|pred| 6
    5 -->|obj| 7
    3 --> 8
    8 -->|pred| 9
    8 -->|obj| 10
    1 --> 11
    11 -->|pred| 12
    11 -->|obj| 13
    style 1 stroke:red,stroke-width:3.0px
    style 2 stroke:red,stroke-width:3.0px
    style 3 stroke:red,stroke-width:3.0px
    style 4 stroke:#55f,stroke-width:3.0px
    style 5 stroke:red,stroke-width:3.0px
    style 6 stroke:#55f,stroke-width:3.0px
    style 7 stroke:#55f,stroke-width:3.0px
    style 8 stroke:red,stroke-width:3.0px
    style 9 stroke:#55f,stroke-width:3.0px
    style 10 stroke:#55f,stroke-width:3.0px
    style 11 stroke:red,stroke-width:3.0px
    style 12 stroke:#55f,stroke-width:3.0px
    style 13 stroke:#55f,stroke-width:3.0px
    linkStyle 0 stroke:red,stroke-width:2.0px
    linkStyle 1 stroke:red,stroke-width:2.0px
    linkStyle 2 stroke:red,stroke-width:2.0px
    linkStyle 3 stroke-width:2.0px
    linkStyle 4 stroke:green,stroke-width:2.0px
    linkStyle 5 stroke:#55f,stroke-width:2.0px
    linkStyle 6 stroke-width:2.0px
    linkStyle 7 stroke:green,stroke-width:2.0px
    linkStyle 8 stroke:#55f,stroke-width:2.0px
    linkStyle 9 stroke-width:2.0px
    linkStyle 10 stroke:green,stroke-width:2.0px
    linkStyle 11 stroke:#55f,stroke-width:2.0px
```

* In this case the signature still only signs the subject, but the subject is an entire envelope that's been wrapped.
* `WRAPPED` elements are represented by trapezoids. They have exactly one arm, which is the root of the wrapped envelope.

## Encrypt to Recipients

```
ENCRYPTED [
    hasRecipient: SealedMessage
    hasRecipient: SealedMessage
]
```

```mermaid
graph TB
    1(("fd42b5f0<br/>NODE"))
    2>"886a0c85<br/>ENCRYPTED"]
    3(["6c23d690<br/>ASSERTION"])
    4[/"f4af70d6<br/>hasRecipient"/]
    5["b2aa6ce6<br/>SealedMessage"]
    6(["f99f7424<br/>ASSERTION"])
    7[/"f4af70d6<br/>hasRecipient"/]
    8["93c8e2de<br/>SealedMessage"]
    1 -->|subj| 2
    1 --> 3
    3 -->|pred| 4
    3 -->|obj| 5
    1 --> 6
    6 -->|pred| 7
    6 -->|obj| 8
    style 1 stroke:red,stroke-width:3.0px
    style 2 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
    style 3 stroke:red,stroke-width:3.0px
    style 4 stroke:#55f,stroke-width:3.0px
    style 5 stroke:#55f,stroke-width:3.0px
    style 6 stroke:red,stroke-width:3.0px
    style 7 stroke:#55f,stroke-width:3.0px
    style 8 stroke:#55f,stroke-width:3.0px
    linkStyle 0 stroke:red,stroke-width:2.0px
    linkStyle 1 stroke-width:2.0px
    linkStyle 2 stroke:green,stroke-width:2.0px
    linkStyle 3 stroke:#55f,stroke-width:2.0px
    linkStyle 4 stroke-width:2.0px
    linkStyle 5 stroke:green,stroke-width:2.0px
    linkStyle 6 stroke:#55f,stroke-width:2.0px
```

* Top-to-bottom layout is also supported.

## Complex Metadata

```
Digest(e8aa201d) [
    "format": "EPUB"
    "work": CID(7fb90a9d) [
        "author": CID(9c747ace) [
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

```mermaid
graph LR
    1(("72fdea85<br/>NODE"))
    2["ec067552<br/>Digest(e8aa201d)"]
    3(["71573ec4<br/>ASSERTION"])
    4[/"f191c6ea<br/>dereferenceVia"/]
    5["920da73e<br/>#quot;IPFS#quot;"]
    6(["c2856abd<br/>ASSERTION"])
    7["48bb1df6<br/>#quot;format#quot;"]
    8["9afbbb54<br/>#quot;EPUB#quot;"]
    9(["eaa72721<br/>ASSERTION"])
    10["8ea19b98<br/>#quot;work#quot;"]
    11(("f70de543<br/>NODE"))
    12["734250ee<br/>CID(7fb90a9d)"]
    13(["049bbd66<br/>ASSERTION"])
    14[/"f191c6ea<br/>dereferenceVia"/]
    15["b4580455<br/>#quot;LibraryOfCongress#quot;"]
    16(["1f908002<br/>ASSERTION"])
    17["d8c1566f<br/>#quot;author#quot;"]
    18(("b51b535c<br/>NODE"))
    19["306a5d76<br/>CID(9c747ace)"]
    20(["049bbd66<br/>ASSERTION"])
    21[/"f191c6ea<br/>dereferenceVia"/]
    22["b4580455<br/>#quot;LibraryOfCongress#quot;"]
    23(["e7441f7c<br/>ASSERTION"])
    24[/"bf166e5d<br/>hasName"/]
    25["5bb41313<br/>#quot;Ayn Rand#quot;"]
    26(["91ec8590<br/>ASSERTION"])
    27[/"bf166e5d<br/>hasName"/]
    28(("59cd2799<br/>NODE"))
    29["9d76964a<br/>#quot;Atlas Shrugged#quot;"]
    30(["02d3e92e<br/>ASSERTION"])
    31[/"556c14a4<br/>language"/]
    32["409b5893<br/>#quot;en#quot;"]
    33(["c1029b07<br/>ASSERTION"])
    34[/"8982354d<br/>isA"/]
    35["9066de8c<br/>#quot;novel#quot;"]
    36(["c1785e1a<br/>ASSERTION"])
    37[/"bf166e5d<br/>hasName"/]
    38(("0412cf19<br/>NODE"))
    39["5a42d004<br/>#quot;La rebelión de Atlas#quot;"]
    40(["a5243b41<br/>ASSERTION"])
    41[/"556c14a4<br/>language"/]
    42["dd2f866d<br/>#quot;es#quot;"]
    43(["efb00f5e<br/>ASSERTION"])
    44["b95d2849<br/>#quot;isbn#quot;"]
    45["2e8d4edd<br/>#quot;9780451191144#quot;"]
    1 -->|subj| 2
    1 --> 3
    3 -->|pred| 4
    3 -->|obj| 5
    1 --> 6
    6 -->|pred| 7
    6 -->|obj| 8
    1 --> 9
    9 -->|pred| 10
    9 -->|obj| 11
    11 -->|subj| 12
    11 --> 13
    13 -->|pred| 14
    13 -->|obj| 15
    11 --> 16
    16 -->|pred| 17
    16 -->|obj| 18
    18 -->|subj| 19
    18 --> 20
    20 -->|pred| 21
    20 -->|obj| 22
    18 --> 23
    23 -->|pred| 24
    23 -->|obj| 25
    11 --> 26
    26 -->|pred| 27
    26 -->|obj| 28
    28 -->|subj| 29
    28 --> 30
    30 -->|pred| 31
    30 -->|obj| 32
    11 --> 33
    33 -->|pred| 34
    33 -->|obj| 35
    11 --> 36
    36 -->|pred| 37
    36 -->|obj| 38
    38 -->|subj| 39
    38 --> 40
    40 -->|pred| 41
    40 -->|obj| 42
    11 --> 43
    43 -->|pred| 44
    43 -->|obj| 45
    style 1 stroke:red,stroke-width:3.0px
    style 2 stroke:#55f,stroke-width:3.0px
    style 3 stroke:red,stroke-width:3.0px
    style 4 stroke:#55f,stroke-width:3.0px
    style 5 stroke:#55f,stroke-width:3.0px
    style 6 stroke:red,stroke-width:3.0px
    style 7 stroke:#55f,stroke-width:3.0px
    style 8 stroke:#55f,stroke-width:3.0px
    style 9 stroke:red,stroke-width:3.0px
    style 10 stroke:#55f,stroke-width:3.0px
    style 11 stroke:red,stroke-width:3.0px
    style 12 stroke:#55f,stroke-width:3.0px
    style 13 stroke:red,stroke-width:3.0px
    style 14 stroke:#55f,stroke-width:3.0px
    style 15 stroke:#55f,stroke-width:3.0px
    style 16 stroke:red,stroke-width:3.0px
    style 17 stroke:#55f,stroke-width:3.0px
    style 18 stroke:red,stroke-width:3.0px
    style 19 stroke:#55f,stroke-width:3.0px
    style 20 stroke:red,stroke-width:3.0px
    style 21 stroke:#55f,stroke-width:3.0px
    style 22 stroke:#55f,stroke-width:3.0px
    style 23 stroke:red,stroke-width:3.0px
    style 24 stroke:#55f,stroke-width:3.0px
    style 25 stroke:#55f,stroke-width:3.0px
    style 26 stroke:red,stroke-width:3.0px
    style 27 stroke:#55f,stroke-width:3.0px
    style 28 stroke:red,stroke-width:3.0px
    style 29 stroke:#55f,stroke-width:3.0px
    style 30 stroke:red,stroke-width:3.0px
    style 31 stroke:#55f,stroke-width:3.0px
    style 32 stroke:#55f,stroke-width:3.0px
    style 33 stroke:red,stroke-width:3.0px
    style 34 stroke:#55f,stroke-width:3.0px
    style 35 stroke:#55f,stroke-width:3.0px
    style 36 stroke:red,stroke-width:3.0px
    style 37 stroke:#55f,stroke-width:3.0px
    style 38 stroke:red,stroke-width:3.0px
    style 39 stroke:#55f,stroke-width:3.0px
    style 40 stroke:red,stroke-width:3.0px
    style 41 stroke:#55f,stroke-width:3.0px
    style 42 stroke:#55f,stroke-width:3.0px
    style 43 stroke:red,stroke-width:3.0px
    style 44 stroke:#55f,stroke-width:3.0px
    style 45 stroke:#55f,stroke-width:3.0px
    linkStyle 0 stroke:red,stroke-width:2.0px
    linkStyle 1 stroke-width:2.0px
    linkStyle 2 stroke:green,stroke-width:2.0px
    linkStyle 3 stroke:#55f,stroke-width:2.0px
    linkStyle 4 stroke-width:2.0px
    linkStyle 5 stroke:green,stroke-width:2.0px
    linkStyle 6 stroke:#55f,stroke-width:2.0px
    linkStyle 7 stroke-width:2.0px
    linkStyle 8 stroke:green,stroke-width:2.0px
    linkStyle 9 stroke:#55f,stroke-width:2.0px
    linkStyle 10 stroke:red,stroke-width:2.0px
    linkStyle 11 stroke-width:2.0px
    linkStyle 12 stroke:green,stroke-width:2.0px
    linkStyle 13 stroke:#55f,stroke-width:2.0px
    linkStyle 14 stroke-width:2.0px
    linkStyle 15 stroke:green,stroke-width:2.0px
    linkStyle 16 stroke:#55f,stroke-width:2.0px
    linkStyle 17 stroke:red,stroke-width:2.0px
    linkStyle 18 stroke-width:2.0px
    linkStyle 19 stroke:green,stroke-width:2.0px
    linkStyle 20 stroke:#55f,stroke-width:2.0px
    linkStyle 21 stroke-width:2.0px
    linkStyle 22 stroke:green,stroke-width:2.0px
    linkStyle 23 stroke:#55f,stroke-width:2.0px
    linkStyle 24 stroke-width:2.0px
    linkStyle 25 stroke:green,stroke-width:2.0px
    linkStyle 26 stroke:#55f,stroke-width:2.0px
    linkStyle 27 stroke:red,stroke-width:2.0px
    linkStyle 28 stroke-width:2.0px
    linkStyle 29 stroke:green,stroke-width:2.0px
    linkStyle 30 stroke:#55f,stroke-width:2.0px
    linkStyle 31 stroke-width:2.0px
    linkStyle 32 stroke:green,stroke-width:2.0px
    linkStyle 33 stroke:#55f,stroke-width:2.0px
    linkStyle 34 stroke-width:2.0px
    linkStyle 35 stroke:green,stroke-width:2.0px
    linkStyle 36 stroke:#55f,stroke-width:2.0px
    linkStyle 37 stroke:red,stroke-width:2.0px
    linkStyle 38 stroke-width:2.0px
    linkStyle 39 stroke:green,stroke-width:2.0px
    linkStyle 40 stroke:#55f,stroke-width:2.0px
    linkStyle 41 stroke-width:2.0px
    linkStyle 42 stroke:green,stroke-width:2.0px
    linkStyle 43 stroke:#55f,stroke-width:2.0px
```

## Verifiable Credential

```
{
    CID(4676635a) [
        "certificateNumber": "123-456-789"
        "continuingEducationUnits": 1.5
        "expirationDate": 2028-01-01
        "firstName": "James"
        "issueDate": 2020-01-01
        "lastName": "Maxwell"
        "photo": "This is James Maxwell's photo."
        "professionalDevelopmentHours": 15
        "subject": "RF and Microwave Engineering"
        "topics": CBOR
        controller: "Example Electrical Engineering Board"
        isA: "Certificate of Completion"
        issuer: "Example Electrical Engineering Board"
    ]
} [
    note: "Signed by Example Electrical Engineering Board"
    verifiedBy: Signature
]
```

```mermaid
graph LR
    1(("6b879639<br/>NODE"))
    2[/"dbd70e79<br/>WRAPPED"\]
    3(("b750a45f<br/>NODE"))
    4["bdd347d4<br/>CID(4676635a)"]
    5(["0536afd8<br/>ASSERTION"])
    6["a791d0c7<br/>#quot;photo#quot;"]
    7["9e77bb70<br/>#quot;This is James Maxwell's photo.#quot;"]
    8(["1d598c65<br/>ASSERTION"])
    9["eb62836d<br/>#quot;lastName#quot;"]
    10["997a0e2d<br/>#quot;Maxwell#quot;"]
    11(["34f8f7d3<br/>ASSERTION"])
    12["b1e12d58<br/>#quot;issueDate#quot;"]
    13["2511c0df<br/>2020-01-01"]
    14(["3d00d64f<br/>ASSERTION"])
    15[/"2f9bee2f<br/>controller"/]
    16["4035b4bd<br/>#quot;Example Electrical Engineering Board#quot;"]
    17(["44736993<br/>ASSERTION"])
    18["05651934<br/>#quot;topics#quot;"]
    19["264aec65<br/>CBOR"]
    20(["46d6cfea<br/>ASSERTION"])
    21[/"8982354d<br/>isA"/]
    22["112e2cdb<br/>#quot;Certificate of Completion#quot;"]
    23(["4a69fca3<br/>ASSERTION"])
    24["b6d5ea01<br/>#quot;continuingEducationUnits#quot;"]
    25["02a61366<br/>1.5"]
    26(["5545f6e2<br/>ASSERTION"])
    27[/"954c8356<br/>issuer"/]
    28["4035b4bd<br/>#quot;Example Electrical Engineering Board#quot;"]
    29(["61689bb7<br/>ASSERTION"])
    30["e6c2932d<br/>#quot;expirationDate#quot;"]
    31["b91eea18<br/>2028-01-01"]
    32(["a0274d1c<br/>ASSERTION"])
    33["62c0a26e<br/>#quot;certificateNumber#quot;"]
    34["ac0b465a<br/>#quot;123-456-789#quot;"]
    35(["d4f678a9<br/>ASSERTION"])
    36["c4d5323d<br/>#quot;firstName#quot;"]
    37["bfe9d39b<br/>#quot;James#quot;"]
    38(["e0070876<br/>ASSERTION"])
    39["0eb38394<br/>#quot;subject#quot;"]
    40["b059b0f2<br/>#quot;RF and Microwave Engineering#quot;"]
    41(["e96b24d9<br/>ASSERTION"])
    42["c8c1a6dd<br/>#quot;professionalDevelopmentHours#quot;"]
    43["0bf6b955<br/>15"]
    44(["42fd806a<br/>ASSERTION"])
    45[/"d59f8c0f<br/>verifiedBy"/]
    46["dcfa430e<br/>Signature"]
    47(["afe231cc<br/>ASSERTION"])
    48[/"61fb6a6b<br/>note"/]
    49["f4bf011f<br/>#quot;Signed by Example Electrical Engineering Board#quot;"]
    1 -->|subj| 2
    2 -->|subj| 3
    3 -->|subj| 4
    3 --> 5
    5 -->|pred| 6
    5 -->|obj| 7
    3 --> 8
    8 -->|pred| 9
    8 -->|obj| 10
    3 --> 11
    11 -->|pred| 12
    11 -->|obj| 13
    3 --> 14
    14 -->|pred| 15
    14 -->|obj| 16
    3 --> 17
    17 -->|pred| 18
    17 -->|obj| 19
    3 --> 20
    20 -->|pred| 21
    20 -->|obj| 22
    3 --> 23
    23 -->|pred| 24
    23 -->|obj| 25
    3 --> 26
    26 -->|pred| 27
    26 -->|obj| 28
    3 --> 29
    29 -->|pred| 30
    29 -->|obj| 31
    3 --> 32
    32 -->|pred| 33
    32 -->|obj| 34
    3 --> 35
    35 -->|pred| 36
    35 -->|obj| 37
    3 --> 38
    38 -->|pred| 39
    38 -->|obj| 40
    3 --> 41
    41 -->|pred| 42
    41 -->|obj| 43
    1 --> 44
    44 -->|pred| 45
    44 -->|obj| 46
    1 --> 47
    47 -->|pred| 48
    47 -->|obj| 49
    style 1 stroke:red,stroke-width:3.0px
    style 2 stroke:red,stroke-width:3.0px
    style 3 stroke:red,stroke-width:3.0px
    style 4 stroke:#55f,stroke-width:3.0px
    style 5 stroke:red,stroke-width:3.0px
    style 6 stroke:#55f,stroke-width:3.0px
    style 7 stroke:#55f,stroke-width:3.0px
    style 8 stroke:red,stroke-width:3.0px
    style 9 stroke:#55f,stroke-width:3.0px
    style 10 stroke:#55f,stroke-width:3.0px
    style 11 stroke:red,stroke-width:3.0px
    style 12 stroke:#55f,stroke-width:3.0px
    style 13 stroke:#55f,stroke-width:3.0px
    style 14 stroke:red,stroke-width:3.0px
    style 15 stroke:#55f,stroke-width:3.0px
    style 16 stroke:#55f,stroke-width:3.0px
    style 17 stroke:red,stroke-width:3.0px
    style 18 stroke:#55f,stroke-width:3.0px
    style 19 stroke:#55f,stroke-width:3.0px
    style 20 stroke:red,stroke-width:3.0px
    style 21 stroke:#55f,stroke-width:3.0px
    style 22 stroke:#55f,stroke-width:3.0px
    style 23 stroke:red,stroke-width:3.0px
    style 24 stroke:#55f,stroke-width:3.0px
    style 25 stroke:#55f,stroke-width:3.0px
    style 26 stroke:red,stroke-width:3.0px
    style 27 stroke:#55f,stroke-width:3.0px
    style 28 stroke:#55f,stroke-width:3.0px
    style 29 stroke:red,stroke-width:3.0px
    style 30 stroke:#55f,stroke-width:3.0px
    style 31 stroke:#55f,stroke-width:3.0px
    style 32 stroke:red,stroke-width:3.0px
    style 33 stroke:#55f,stroke-width:3.0px
    style 34 stroke:#55f,stroke-width:3.0px
    style 35 stroke:red,stroke-width:3.0px
    style 36 stroke:#55f,stroke-width:3.0px
    style 37 stroke:#55f,stroke-width:3.0px
    style 38 stroke:red,stroke-width:3.0px
    style 39 stroke:#55f,stroke-width:3.0px
    style 40 stroke:#55f,stroke-width:3.0px
    style 41 stroke:red,stroke-width:3.0px
    style 42 stroke:#55f,stroke-width:3.0px
    style 43 stroke:#55f,stroke-width:3.0px
    style 44 stroke:red,stroke-width:3.0px
    style 45 stroke:#55f,stroke-width:3.0px
    style 46 stroke:#55f,stroke-width:3.0px
    style 47 stroke:red,stroke-width:3.0px
    style 48 stroke:#55f,stroke-width:3.0px
    style 49 stroke:#55f,stroke-width:3.0px
    linkStyle 0 stroke:red,stroke-width:2.0px
    linkStyle 1 stroke:red,stroke-width:2.0px
    linkStyle 2 stroke:red,stroke-width:2.0px
    linkStyle 3 stroke-width:2.0px
    linkStyle 4 stroke:green,stroke-width:2.0px
    linkStyle 5 stroke:#55f,stroke-width:2.0px
    linkStyle 6 stroke-width:2.0px
    linkStyle 7 stroke:green,stroke-width:2.0px
    linkStyle 8 stroke:#55f,stroke-width:2.0px
    linkStyle 9 stroke-width:2.0px
    linkStyle 10 stroke:green,stroke-width:2.0px
    linkStyle 11 stroke:#55f,stroke-width:2.0px
    linkStyle 12 stroke-width:2.0px
    linkStyle 13 stroke:green,stroke-width:2.0px
    linkStyle 14 stroke:#55f,stroke-width:2.0px
    linkStyle 15 stroke-width:2.0px
    linkStyle 16 stroke:green,stroke-width:2.0px
    linkStyle 17 stroke:#55f,stroke-width:2.0px
    linkStyle 18 stroke-width:2.0px
    linkStyle 19 stroke:green,stroke-width:2.0px
    linkStyle 20 stroke:#55f,stroke-width:2.0px
    linkStyle 21 stroke-width:2.0px
    linkStyle 22 stroke:green,stroke-width:2.0px
    linkStyle 23 stroke:#55f,stroke-width:2.0px
    linkStyle 24 stroke-width:2.0px
    linkStyle 25 stroke:green,stroke-width:2.0px
    linkStyle 26 stroke:#55f,stroke-width:2.0px
    linkStyle 27 stroke-width:2.0px
    linkStyle 28 stroke:green,stroke-width:2.0px
    linkStyle 29 stroke:#55f,stroke-width:2.0px
    linkStyle 30 stroke-width:2.0px
    linkStyle 31 stroke:green,stroke-width:2.0px
    linkStyle 32 stroke:#55f,stroke-width:2.0px
    linkStyle 33 stroke-width:2.0px
    linkStyle 34 stroke:green,stroke-width:2.0px
    linkStyle 35 stroke:#55f,stroke-width:2.0px
    linkStyle 36 stroke-width:2.0px
    linkStyle 37 stroke:green,stroke-width:2.0px
    linkStyle 38 stroke:#55f,stroke-width:2.0px
    linkStyle 39 stroke-width:2.0px
    linkStyle 40 stroke:green,stroke-width:2.0px
    linkStyle 41 stroke:#55f,stroke-width:2.0px
    linkStyle 42 stroke-width:2.0px
    linkStyle 43 stroke:green,stroke-width:2.0px
    linkStyle 44 stroke:#55f,stroke-width:2.0px
    linkStyle 45 stroke-width:2.0px
    linkStyle 46 stroke:green,stroke-width:2.0px
    linkStyle 47 stroke:#55f,stroke-width:2.0px
```

## Warranty

This is the same credential above that has been elided, had additional assertions added, and then been signed by the employer.

```
{
    {
        {
            CID(4676635a) [
                "expirationDate": 2028-01-01
                "firstName": "James"
                "lastName": "Maxwell"
                "subject": "RF and Microwave Engineering"
                isA: "Certificate of Completion"
                issuer: "Example Electrical Engineering Board"
                ELIDED (7)
            ]
        } [
            note: "Signed by Example Electrical Engineering Board"
            verifiedBy: Signature
        ]
    } [
        "employeeHiredDate": 2022-01-01
        "employeeStatus": "active"
    ]
} [
    note: "Signed by Employer Corp."
    verifiedBy: Signature
]
```

```mermaid
graph LR
    1(("ec038a13<br/>NODE"))
    2[/"a182e8b4<br/>WRAPPED"\]
    3(("1de7ddc0<br/>NODE"))
    4[/"03e5d69f<br/>WRAPPED"\]
    5(("7d1be7c0<br/>NODE"))
    6[/"dbd70e79<br/>WRAPPED"\]
    7(("b750a45f<br/>NODE"))
    8["bdd347d4<br/>CID(4676635a)"]
    9{{"0536afd8<br/>ELIDED"}}
    10(["1d598c65<br/>ASSERTION"])
    11["eb62836d<br/>#quot;lastName#quot;"]
    12["997a0e2d<br/>#quot;Maxwell#quot;"]
    13{{"34f8f7d3<br/>ELIDED"}}
    14{{"3d00d64f<br/>ELIDED"}}
    15{{"44736993<br/>ELIDED"}}
    16(["46d6cfea<br/>ASSERTION"])
    17[/"8982354d<br/>isA"/]
    18["112e2cdb<br/>#quot;Certificate of Completion#quot;"]
    19{{"4a69fca3<br/>ELIDED"}}
    20(["5545f6e2<br/>ASSERTION"])
    21[/"954c8356<br/>issuer"/]
    22["4035b4bd<br/>#quot;Example Electrical Engineering Board#quot;"]
    23(["61689bb7<br/>ASSERTION"])
    24["e6c2932d<br/>#quot;expirationDate#quot;"]
    25["b91eea18<br/>2028-01-01"]
    26{{"a0274d1c<br/>ELIDED"}}
    27(["d4f678a9<br/>ASSERTION"])
    28["c4d5323d<br/>#quot;firstName#quot;"]
    29["bfe9d39b<br/>#quot;James#quot;"]
    30(["e0070876<br/>ASSERTION"])
    31["0eb38394<br/>#quot;subject#quot;"]
    32["b059b0f2<br/>#quot;RF and Microwave Engineering#quot;"]
    33{{"e96b24d9<br/>ELIDED"}}
    34(["7cfa7977<br/>ASSERTION"])
    35[/"d59f8c0f<br/>verifiedBy"/]
    36["4529a775<br/>Signature"]
    37(["afe231cc<br/>ASSERTION"])
    38[/"61fb6a6b<br/>note"/]
    39["f4bf011f<br/>#quot;Signed by Example Electrical Engineering Board#quot;"]
    40(["310b027f<br/>ASSERTION"])
    41["f942ee55<br/>#quot;employeeStatus#quot;"]
    42["919eb85d<br/>#quot;active#quot;"]
    43(["5901b070<br/>ASSERTION"])
    44["134a1704<br/>#quot;employeeHiredDate#quot;"]
    45["24c173c5<br/>2022-01-01"]
    46(["3160f0dc<br/>ASSERTION"])
    47[/"d59f8c0f<br/>verifiedBy"/]
    48["2b42cab7<br/>Signature"]
    49(["648b2cc3<br/>ASSERTION"])
    50[/"61fb6a6b<br/>note"/]
    51["46f4bfd7<br/>#quot;Signed by Employer Corp.#quot;"]
    1 -->|subj| 2
    2 -->|subj| 3
    3 -->|subj| 4
    4 -->|subj| 5
    5 -->|subj| 6
    6 -->|subj| 7
    7 -->|subj| 8
    7 --> 9
    7 --> 10
    10 -->|pred| 11
    10 -->|obj| 12
    7 --> 13
    7 --> 14
    7 --> 15
    7 --> 16
    16 -->|pred| 17
    16 -->|obj| 18
    7 --> 19
    7 --> 20
    20 -->|pred| 21
    20 -->|obj| 22
    7 --> 23
    23 -->|pred| 24
    23 -->|obj| 25
    7 --> 26
    7 --> 27
    27 -->|pred| 28
    27 -->|obj| 29
    7 --> 30
    30 -->|pred| 31
    30 -->|obj| 32
    7 --> 33
    5 --> 34
    34 -->|pred| 35
    34 -->|obj| 36
    5 --> 37
    37 -->|pred| 38
    37 -->|obj| 39
    3 --> 40
    40 -->|pred| 41
    40 -->|obj| 42
    3 --> 43
    43 -->|pred| 44
    43 -->|obj| 45
    1 --> 46
    46 -->|pred| 47
    46 -->|obj| 48
    1 --> 49
    49 -->|pred| 50
    49 -->|obj| 51
    style 1 stroke:red,stroke-width:3.0px
    style 2 stroke:red,stroke-width:3.0px
    style 3 stroke:red,stroke-width:3.0px
    style 4 stroke:red,stroke-width:3.0px
    style 5 stroke:red,stroke-width:3.0px
    style 6 stroke:red,stroke-width:3.0px
    style 7 stroke:red,stroke-width:3.0px
    style 8 stroke:#55f,stroke-width:3.0px
    style 9 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
    style 10 stroke:red,stroke-width:3.0px
    style 11 stroke:#55f,stroke-width:3.0px
    style 12 stroke:#55f,stroke-width:3.0px
    style 13 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
    style 14 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
    style 15 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
    style 16 stroke:red,stroke-width:3.0px
    style 17 stroke:#55f,stroke-width:3.0px
    style 18 stroke:#55f,stroke-width:3.0px
    style 19 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
    style 20 stroke:red,stroke-width:3.0px
    style 21 stroke:#55f,stroke-width:3.0px
    style 22 stroke:#55f,stroke-width:3.0px
    style 23 stroke:red,stroke-width:3.0px
    style 24 stroke:#55f,stroke-width:3.0px
    style 25 stroke:#55f,stroke-width:3.0px
    style 26 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
    style 27 stroke:red,stroke-width:3.0px
    style 28 stroke:#55f,stroke-width:3.0px
    style 29 stroke:#55f,stroke-width:3.0px
    style 30 stroke:red,stroke-width:3.0px
    style 31 stroke:#55f,stroke-width:3.0px
    style 32 stroke:#55f,stroke-width:3.0px
    style 33 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
    style 34 stroke:red,stroke-width:3.0px
    style 35 stroke:#55f,stroke-width:3.0px
    style 36 stroke:#55f,stroke-width:3.0px
    style 37 stroke:red,stroke-width:3.0px
    style 38 stroke:#55f,stroke-width:3.0px
    style 39 stroke:#55f,stroke-width:3.0px
    style 40 stroke:red,stroke-width:3.0px
    style 41 stroke:#55f,stroke-width:3.0px
    style 42 stroke:#55f,stroke-width:3.0px
    style 43 stroke:red,stroke-width:3.0px
    style 44 stroke:#55f,stroke-width:3.0px
    style 45 stroke:#55f,stroke-width:3.0px
    style 46 stroke:red,stroke-width:3.0px
    style 47 stroke:#55f,stroke-width:3.0px
    style 48 stroke:#55f,stroke-width:3.0px
    style 49 stroke:red,stroke-width:3.0px
    style 50 stroke:#55f,stroke-width:3.0px
    style 51 stroke:#55f,stroke-width:3.0px
    linkStyle 0 stroke:red,stroke-width:2.0px
    linkStyle 1 stroke:red,stroke-width:2.0px
    linkStyle 2 stroke:red,stroke-width:2.0px
    linkStyle 3 stroke:red,stroke-width:2.0px
    linkStyle 4 stroke:red,stroke-width:2.0px
    linkStyle 5 stroke:red,stroke-width:2.0px
    linkStyle 6 stroke:red,stroke-width:2.0px
    linkStyle 7 stroke-width:2.0px
    linkStyle 8 stroke-width:2.0px
    linkStyle 9 stroke:green,stroke-width:2.0px
    linkStyle 10 stroke:#55f,stroke-width:2.0px
    linkStyle 11 stroke-width:2.0px
    linkStyle 12 stroke-width:2.0px
    linkStyle 13 stroke-width:2.0px
    linkStyle 14 stroke-width:2.0px
    linkStyle 15 stroke:green,stroke-width:2.0px
    linkStyle 16 stroke:#55f,stroke-width:2.0px
    linkStyle 17 stroke-width:2.0px
    linkStyle 18 stroke-width:2.0px
    linkStyle 19 stroke:green,stroke-width:2.0px
    linkStyle 20 stroke:#55f,stroke-width:2.0px
    linkStyle 21 stroke-width:2.0px
    linkStyle 22 stroke:green,stroke-width:2.0px
    linkStyle 23 stroke:#55f,stroke-width:2.0px
    linkStyle 24 stroke-width:2.0px
    linkStyle 25 stroke-width:2.0px
    linkStyle 26 stroke:green,stroke-width:2.0px
    linkStyle 27 stroke:#55f,stroke-width:2.0px
    linkStyle 28 stroke-width:2.0px
    linkStyle 29 stroke:green,stroke-width:2.0px
    linkStyle 30 stroke:#55f,stroke-width:2.0px
    linkStyle 31 stroke-width:2.0px
    linkStyle 32 stroke-width:2.0px
    linkStyle 33 stroke:green,stroke-width:2.0px
    linkStyle 34 stroke:#55f,stroke-width:2.0px
    linkStyle 35 stroke-width:2.0px
    linkStyle 36 stroke:green,stroke-width:2.0px
    linkStyle 37 stroke:#55f,stroke-width:2.0px
    linkStyle 38 stroke-width:2.0px
    linkStyle 39 stroke:green,stroke-width:2.0px
    linkStyle 40 stroke:#55f,stroke-width:2.0px
    linkStyle 41 stroke-width:2.0px
    linkStyle 42 stroke:green,stroke-width:2.0px
    linkStyle 43 stroke:#55f,stroke-width:2.0px
    linkStyle 44 stroke-width:2.0px
    linkStyle 45 stroke:green,stroke-width:2.0px
    linkStyle 46 stroke:#55f,stroke-width:2.0px
    linkStyle 47 stroke-width:2.0px
    linkStyle 48 stroke:green,stroke-width:2.0px
    linkStyle 49 stroke:#55f,stroke-width:2.0px
```
