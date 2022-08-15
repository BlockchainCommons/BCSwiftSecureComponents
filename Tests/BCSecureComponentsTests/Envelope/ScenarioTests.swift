import XCTest
import BCSecureComponents
import WolfBase

class ScenarioTests: XCTestCase {
    func testComplexMetadata() throws {
        // Assertions made about an CID are considered part of a distributed set. Which
        // assertions are returned depends on who resolves the CID and when it is
        // resolved. In other words, the referent of a CID is mutable.
        let author = Envelope(CID(‡"9c747ace78a4c826392510dd6285551e7df4e5164729a1b36198e56e017666c8")!)
            .add(.dereferenceVia, "LibraryOfCongress")
            .add(.hasName, "Ayn Rand")
        
        // Assertions made on a literal value are considered part of the same set of
        // assertions made on the digest of that value.
        let name_en = Envelope("Atlas Shrugged")
            .add(.language, "en")

        let name_es = Envelope("La rebelión de Atlas")
            .add(.language, "es")
        
        let work = Envelope(CID(‡"7fb90a9d96c07f39f75ea6acf392d79f241fac4ec0be2120f7c82489711e3e80")!)
            .add(.isA, "novel")
            .add("isbn", "9780451191144")
            .add("author", author)
            .add(.dereferenceVia, "LibraryOfCongress")
            .add(.hasName, name_en)
            .add(.hasName, name_es)

        let bookData = "This is the entire book “Atlas Shrugged” in EPUB format."
        // Assertions made on a digest are considered associated with that specific binary
        // object and no other. In other words, the referent of a Digest is immutable.
        let bookMetadata = Envelope(Digest(bookData))
            .add("work", work)
            .add("format", "EPUB")
            .add(.dereferenceVia, "IPFS")
        
        let expectedFormat =
        """
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
        """
        XCTAssertEqual(bookMetadata.format, expectedFormat)
    }
    
    func testIdentifier() throws {
        // An analogue of a DID document, which identifies an entity. The
        // document itself can be referred to by its CID, while the signed document
        // can be referred to by its digest.
        
        let aliceUnsignedDocument = Envelope(aliceIdentifier)
            .add(.controller, aliceIdentifier)
            .add(.publicKeys, alicePublicKeys)
        
        let aliceSignedDocument = aliceUnsignedDocument
            .enclose()
            .sign(with: alicePrivateKeys, note: "Made by Alice.")
        
        let expectedFormat =
        """
        {
            CID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f) [
                controller: CID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
                publicKeys: PublicKeyBase
            ]
        } [
            verifiedBy: Signature [
                note: "Made by Alice."
            ]
        ]
        """
        XCTAssertEqual(aliceSignedDocument.format, expectedFormat)
        
        // Signatures have a random component, so anything with a signature will have a
        // non-deterministic digest. Therefore, the two results of signing the same object
        // twice with the same private key will not compare as equal. This means that each
        // signing is a particular event that can never be repeated.

        let aliceSignedDocument2 = aliceUnsignedDocument
            .enclose()
            .sign(with: alicePrivateKeys, note: "Made by Alice.")

        XCTAssertNotEqual(aliceSignedDocument, aliceSignedDocument2)
        
        // ➡️ ☁️ ➡️

        // A registrar checks the signature on Alice's submitted identifier document,
        // performs any other necessary validity checks, and then extracts her CID from
        // it.
        let aliceCID = try aliceSignedDocument.validateSignature(from: alicePublicKeys)
            .extract()
            // other validity checks here
            .extract(CID.self)
        
        // The registrar creates its own registration document using Alice's CID as the
        // subject, incorporating Alice's signed document, and adding its own signature.
        let aliceURL = URL(string: "https://exampleledger.com/cid/\(aliceCID.data.hex)")!
        let aliceRegistration = Envelope(aliceCID)
            .add(.entity, aliceSignedDocument)
            .add(.dereferenceVia, aliceURL)
            .enclose()
            .sign(with: exampleLedgerPrivateKeys, note: "Made by ExampleLedger.")
        
        let expectedRegistrationFormat =
        """
        {
            CID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f) [
                dereferenceVia: URI(https://exampleledger.com/cid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
                entity: {
                    CID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f) [
                        controller: CID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
                        publicKeys: PublicKeyBase
                    ]
                } [
                    verifiedBy: Signature [
                        note: "Made by Alice."
                    ]
                ]
            ]
        } [
            verifiedBy: Signature [
                note: "Made by ExampleLedger."
            ]
        ]
        """
        XCTAssertEqual(aliceRegistration.format, expectedRegistrationFormat)
        
        // Alice receives the registration document back, validates its signature, and
        // extracts the URI that now points to her record.
        let aliceURI = try aliceRegistration
            .validateSignature(from: exampleLedgerPublicKeys)
            .extract()
            .extract(URL.self, predicate: .dereferenceVia)
        XCTAssertEqual(aliceURI†, "https://exampleledger.com/cid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f")
        
        // Alice wants to introduce herself to Bob, so Bob needs to know she controls her
        // identifier. Bob sends a challenge:
        let aliceChallenge = Envelope(Nonce())
            .add(.note, "Challenge to Alice from Bob.")
        
        let aliceChallengeExpectedFormat =
        """
        Nonce [
            note: "Challenge to Alice from Bob."
        ]
        """
        XCTAssertEqual(aliceChallenge.format, aliceChallengeExpectedFormat)

        // Alice responds by adding her registered URI to the nonce, and signing it.
        let aliceChallengeResponse = aliceChallenge
            .enclose()
            .add(.dereferenceVia, aliceURI)
            .enclose()
            .sign(with: alicePrivateKeys, note: "Made by Alice.")
        
        let aliceChallengeResponseExpectedFormat =
        """
        {
            {
                Nonce [
                    note: "Challenge to Alice from Bob."
                ]
            } [
                dereferenceVia: URI(https://exampleledger.com/cid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
            ]
        } [
            verifiedBy: Signature [
                note: "Made by Alice."
            ]
        ]
        """
        XCTAssertEqual(aliceChallengeResponse.format, aliceChallengeResponseExpectedFormat)

        // Bob receives Alice's response, and first checks that the nonce is the once he sent.
        let responseNonce = try aliceChallengeResponse
            .extract()
            .extract()
        XCTAssertEqual(aliceChallenge, responseNonce)
        
        // Bob then extracts Alice's registered URI
        let responseURI = try aliceChallengeResponse
            .extract()
            .extract(URL.self, predicate: .dereferenceVia)
        XCTAssertEqual(responseURI.absoluteString, "https://exampleledger.com/cid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f")
        
        // Bob uses the URI to ask ExampleLedger for Alice's identifier document, then
        // checks ExampleLedgers's signature. Bob trusts ExampleLedger's validation of
        // Alice's original document, so doesn't bother to check it for internal
        // consistency, and instead goes ahead and extracts Alice's public keys from it.
        let aliceDocumentPublicKeys = try aliceRegistration
            .validateSignature(from: exampleLedgerPublicKeys)
            .extract()
            .extract(predicate: .entity)
            .extract()
            .extract(PublicKeyBase.self, predicate: .publicKeys)
        
        // Finally, Bob uses Alice's public keys to validate the challenge he sent her.
        try aliceChallengeResponse.validateSignature(from: aliceDocumentPublicKeys)
    }
    
    func testCredential() throws {
        // John Smith's identifier
        let johnSmithIdentifier = CID(‡"78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc")!

        // A photo of John Smith
        let johnSmithImage = Envelope(Digest("John Smith smiling"))
            .add(.note, "This is an image of John Smith.")
            .add(.dereferenceVia, "https://exampleledger.com/digest/36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999")
        
        // John Smith's Permanent Resident Card issued by the State of Example
        let johnSmithResidentCard = try Envelope(CID(‡"174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8")!)
            .add(.isA, "credential")
            .add("dateIssued", Date(iso8601: "2022-04-27"))
            .add(.issuer, Envelope(stateIdentifier)
                .add(.note, "Issued by the State of Example")
                .add(.dereferenceVia, URL(string: "https://exampleledger.com/cid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8")!)
            )
            .add(.holder, Envelope(johnSmithIdentifier)
                .add(.isA, "Person")
                .add(.isA, "Permanent Resident")
                .add("givenName", "JOHN")
                .add("familyName", "SMITH")
                .add("sex", "MALE")
                .add("birthDate", Date(iso8601: "1974-02-18"))
                .add("image", johnSmithImage)
                .add("lprCategory", "C09")
                .add("lprNumber", "999-999-999")
                .add("birthCountry", Envelope("bs").add(.note, "The Bahamas"))
                .add("residentSince", Date(iso8601: "2018-01-07"))
            )
            .add(.note, "The State of Example recognizes JOHN SMITH as a Permanent Resident.")
            .enclose()
            .sign(with: statePrivateKeys, note: "Made by the State of Example.")

        // Validate the state's signature
        try johnSmithResidentCard.validateSignature(from: statePublicKeys)
        
        let expectedFormat =
        """
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
        """
        XCTAssertEqual(johnSmithResidentCard.format, expectedFormat)
        
        print(johnSmithResidentCard.taggedCBOR.diagAnnotated)
        
        // John wishes to identify himself to a third party using his government-issued
        // credential, but does not wish to reveal more than his name, his photo, and the
        // fact that the state has verified his identity.

        // Redaction is performed by building a set of `Digest`s that will be revealed. All
        // digests not present in the reveal-set will be replaced with redaction markers
        // containing only the hash of what has been redacted, thus preserving the hash
        // tree including revealed signatures. If a higher-level object is redacted, then
        // everything it contains will also be redacted, so if a deeper object is to be
        // revealed, all of its parent objects also need to be revealed, even though not
        // everything *about* the parent objects must be revealed.

        // Start a reveal-set
        var target: Set<Digest> = []

        // Reveal the card. Without this, everything about the card would be redacted.
        let top = johnSmithResidentCard
        target.insert(top)

        // Reveal everything about the state's signature on the card
        try target.insert(top.assertion(predicate: .verifiedBy).deepDigests)

        // Reveal the top level subject of the card. This is John Smith's CID.
        let topContent = top.subject.envelope!
        target.insert(topContent.shallowDigests)

        // Reveal everything about the `isA` and `issuer` assertions at the top level of the card.
        try target.insert(topContent.assertion(predicate: .isA).deepDigests)
        try target.insert(topContent.assertion(predicate: .issuer).deepDigests)

        // Reveal the `holder` assertion on the card, but not any of its sub-assertions.
        let holder = try topContent.assertion(predicate: .holder)
        target.insert(holder.shallowDigests)

        // Within the `holder` assertion, reveal everything about just the `givenName`, `familyName`, and `image` assertions.
        let holderObject = holder.object!
        try target.insert(holderObject.assertion(predicate: "givenName").deepDigests)
        try target.insert(holderObject.assertion(predicate: "familyName").deepDigests)
        try target.insert(holderObject.assertion(predicate: "image").deepDigests)
        
        // Perform the redaction
        let redactedCredential = top.redact(revealing: target)
        
        // Verify that the redacted credential compares equal to the original credential.
        XCTAssertEqual(redactedCredential, johnSmithResidentCard)
        
        // Verify that the state's signature on the redacted card is still valid.
        try redactedCredential.validateSignature(from: statePublicKeys)
        
        let expectedRedactedFormat =
        """
        {
            CID(174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8) [
                REDACTED
                REDACTED
                holder: CID(78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc) [
                    REDACTED
                    REDACTED
                    REDACTED
                    REDACTED
                    REDACTED
                    REDACTED
                    REDACTED
                    REDACTED
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
        """
        XCTAssertEqual(redactedCredential.format, expectedRedactedFormat)
    }
    
    /// See [The Art of Immutable Architecture, by Michael L. Perry](https://amzn.to/3Kszr1p).
    func testHistoricalModeling() throws {
        //
        // Declare Actors
        //

//        let johnSmithIdentifier = CID(‡"78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc")!
//        let johnSmithPrivateKeys = PrivateKeyBase(Seed(data: ‡"3e9271f46cdb85a3b584e7220b976918")!)
//        let johnSmithPublicKeys = johnSmithPrivateKeys.publicKeys
//        let johnSmithDocument = Envelope(johnSmithIdentifier)
//            .add(.hasName, "John Smith")
//            .add(.dereferenceVia, URL(string: "https://exampleledger.com/cid/78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc")!)

//        let acmeCorpPrivateKeys = PrivateKeyBase(Seed(data: ‡"3e9271f46cdb85a3b584e7220b976918")!)
//        let acmeCorpPublicKeys = acmeCorpPrivateKeys.publicKeys
        let acmeCorpIdentifier = CID(‡"361235424efc81cedec7eb983a97bbe74d7972f778486f93881e5eed577d0aa7")!
        let acmeCorpDocument = Envelope(acmeCorpIdentifier)
            .add(.hasName, "Acme Corp.")
            .add(.dereferenceVia, URL(string: "https://exampleledger.com/cid/361235424efc81cedec7eb983a97bbe74d7972f778486f93881e5eed577d0aa7")!)
        
        //
        // Declare Products
        //

        let qualityProduct = Envelope(CID(‡"5bcca01f5f370ceb3b7365f076e9600e294d4da6ddf7a616976c87775ea8f0f1")!)
            .add(.isA, "Product")
            .add(.hasName, "Quality Widget")
            .add("seller", acmeCorpDocument)
            .add("priceEach", "10.99")

        let cheapProduct = Envelope(CID(‡"ae464c5f9569ae23ff9a75e83caf485fb581d1ef9da147ca086d10e3d6f93e64")!)
            .add(.isA, "Product")
            .add(.hasName, "Cheap Widget")
            .add("seller", acmeCorpDocument)
            .add("priceEach", "4.99")

        //
        // Declare a Purchase Order
        //

        // Since the line items of a PurchaseOrder may be mutated before being finalized,
        // they are not declared as part of the creation of the PurchaseOrder itself.
        
        let purchaseOrder = Envelope(CID(‡"1bebb5b6e447f819d5a4cb86409c5da1207d1460672dfe903f55cde833549625")!)
            .add(.isA, "PurchaseOrder")
            .add(.hasName, "PO 123")
        
        //
        // Add Line Items to the Purchase Order
        //

        // A line item's subject is a reference to the digest of the specific purchase
        // order object. This forms a successor -> predecessor relationship to the purchase
        // order.
        //
        // A line item's product is the CID of the product. The product document found by
        // referencing the product's CID may change over time, for instance the price may
        // be updated. The line item therefore captures the current price from the product
        // document in its priceEach assertion.
        
        let line1 = try Envelope(purchaseOrder.digest)
            .add(.isA, "PurchaseOrderLineItem")
            .add("product", qualityProduct.extract(CID.self))
            .add(.hasName, qualityProduct.extract(predicate: .hasName))
            .add("priceEach", qualityProduct.extract(predicate: "priceEach"))
            .add("quantity", 4)

        let line2 = try Envelope(purchaseOrder.digest)
            .add(.isA, "PurchaseOrderLineItem")
            .add("product", cheapProduct.extract(CID.self))
            .add(.hasName, cheapProduct.extract(predicate: .hasName))
            .add("priceEach", cheapProduct.extract(predicate: "priceEach"))
            .add("quantity", 3)

        let line2ExpectedFormat =
        """
        Digest(1f18068a4cd7302d52541b1000d6266e57b707adcaa6958e2d1c042df956e161) [
            "priceEach": "4.99"
            "product": CID(ae464c5f9569ae23ff9a75e83caf485fb581d1ef9da147ca086d10e3d6f93e64)
            "quantity": 3
            hasName: "Cheap Widget"
            isA: "PurchaseOrderLineItem"
        ]
        """
        XCTAssertEqual(line2.format, line2ExpectedFormat)
        
//        let revokeLine1 = Envelope(purchaseOrder.digest)
//            .add(Assertion(revoke: Reference(digest: line1.digest)))
//        print(revokeLine1.format)
        
        let purchaseOrderProjection = purchaseOrder
            .add("lineItem", line1)
            .add("lineItem", line2)
//            .revoke(line1.digest)
        
        let purchaseOrderProjectionExpectedFormat =
        """
        CID(1bebb5b6e447f819d5a4cb86409c5da1207d1460672dfe903f55cde833549625) [
            "lineItem": Digest(1f18068a4cd7302d52541b1000d6266e57b707adcaa6958e2d1c042df956e161) [
                "priceEach": "10.99"
                "product": CID(5bcca01f5f370ceb3b7365f076e9600e294d4da6ddf7a616976c87775ea8f0f1)
                "quantity": 4
                hasName: "Quality Widget"
                isA: "PurchaseOrderLineItem"
            ]
            "lineItem": Digest(1f18068a4cd7302d52541b1000d6266e57b707adcaa6958e2d1c042df956e161) [
                "priceEach": "4.99"
                "product": CID(ae464c5f9569ae23ff9a75e83caf485fb581d1ef9da147ca086d10e3d6f93e64)
                "quantity": 3
                hasName: "Cheap Widget"
                isA: "PurchaseOrderLineItem"
            ]
            hasName: "PO 123"
            isA: "PurchaseOrder"
        ]
        """
        XCTAssertEqual(purchaseOrderProjection.format, purchaseOrderProjectionExpectedFormat)
    }
}
