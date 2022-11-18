import XCTest
import BCSecureComponents
import WolfBase

class ScenarioTests: XCTestCase {
    func testComplexMetadata() throws {
        // Assertions made about an CID are considered part of a distributed set. Which
        // assertions are returned depends on who resolves the CID and when it is
        // resolved. In other words, the referent of a CID is mutable.
        let author = try Envelope(CID(‡"9c747ace78a4c826392510dd6285551e7df4e5164729a1b36198e56e017666c8")!)
            .addAssertion(.dereferenceVia, "LibraryOfCongress")
            .addAssertion(.hasName, "Ayn Rand")
            .checkEncoding()

        // Assertions made on a literal value are considered part of the same set of
        // assertions made on the digest of that value.
        let name_en = Envelope("Atlas Shrugged")
            .addAssertion(.language, "en")

        let name_es = Envelope("La rebelión de Atlas")
            .addAssertion(.language, "es")

        let work = try Envelope(CID(‡"7fb90a9d96c07f39f75ea6acf392d79f241fac4ec0be2120f7c82489711e3e80")!)
            .addAssertion(.isA, "novel")
            .addAssertion("isbn", "9780451191144")
            .addAssertion("author", author)
            .addAssertion(.dereferenceVia, "LibraryOfCongress")
            .addAssertion(.hasName, name_en)
            .addAssertion(.hasName, name_es)
            .checkEncoding()

        let bookData = "This is the entire book “Atlas Shrugged” in EPUB format."
        // Assertions made on a digest are considered associated with that specific binary
        // object and no other. In other words, the referent of a Digest is immutable.
        let bookMetadata = try Envelope(Digest(bookData))
            .addAssertion("work", work)
            .addAssertion("format", "EPUB")
            .addAssertion(.dereferenceVia, "IPFS")
            .checkEncoding()

        let expectedFormat =
        """
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
        """
        XCTAssertEqual(bookMetadata.format, expectedFormat)
    }

    func testIdentifier() throws {
        // An analogue of a DID document, which identifies an entity. The
        // document itself can be referred to by its CID, while the signed document
        // can be referred to by its digest.

        let aliceUnsignedDocument = try Envelope(aliceIdentifier)
            .addAssertion(.controller, aliceIdentifier)
            .addAssertion(.publicKeys, alicePublicKeys)
            .checkEncoding()

        let aliceSignedDocument = try aliceUnsignedDocument
            .wrap()
            .sign(with: alicePrivateKeys, note: "Made by Alice.")
            .checkEncoding()

        let expectedFormat =
        """
        {
            CID(d44c5e0a) [
                controller: CID(d44c5e0a)
                publicKeys: PublicKeyBase
            ]
        } [
            verifiedBy: Signature [
                note: "Made by Alice."
            ]
        ]
        """
        print(aliceSignedDocument.format)
        XCTAssertEqual(aliceSignedDocument.format, expectedFormat)

        // Signatures have a random component, so anything with a signature will have a
        // non-deterministic digest. Therefore, the two results of signing the same object
        // twice with the same private key will not compare as equal. This means that each
        // signing is a particular event that can never be repeated.

        let aliceSignedDocument2 = try aliceUnsignedDocument
            .wrap()
            .sign(with: alicePrivateKeys, note: "Made by Alice.")
            .checkEncoding()

        XCTAssertNotEqual(aliceSignedDocument, aliceSignedDocument2)

        // ➡️ ☁️ ➡️

        // A registrar checks the signature on Alice's submitted identifier document,
        // performs any other necessary validity checks, and then extracts her CID from
        // it.
        let aliceCID = try aliceSignedDocument.verifySignature(from: alicePublicKeys)
            .unwrap()
            // other validity checks here
            .extractSubject(CID.self)

        // The registrar creates its own registration document using Alice's CID as the
        // subject, incorporating Alice's signed document, and adding its own signature.
        let aliceURL = URL(string: "https://exampleledger.com/cid/\(aliceCID.data.hex)")!
        let aliceRegistration = try Envelope(aliceCID)
            .addAssertion(.entity, aliceSignedDocument)
            .addAssertion(.dereferenceVia, aliceURL)
            .wrap()
            .sign(with: exampleLedgerPrivateKeys, note: "Made by ExampleLedger.")
            .checkEncoding()

        let expectedRegistrationFormat =
        """
        {
            CID(d44c5e0a) [
                dereferenceVia: URI(https://exampleledger.com/cid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
                entity: {
                    CID(d44c5e0a) [
                        controller: CID(d44c5e0a)
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
            .verifySignature(from: exampleLedgerPublicKeys)
            .unwrap()
            .extractObject(URL.self, forPredicate: .dereferenceVia)
        XCTAssertEqual(aliceURI†, "https://exampleledger.com/cid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f")

        // Alice wants to introduce herself to Bob, so Bob needs to know she controls her
        // identifier. Bob sends a challenge:
        let aliceChallenge = try Envelope(Nonce())
            .addAssertion(.note, "Challenge to Alice from Bob.")
            .checkEncoding()

        let aliceChallengeExpectedFormat =
        """
        Nonce [
            note: "Challenge to Alice from Bob."
        ]
        """
        XCTAssertEqual(aliceChallenge.format, aliceChallengeExpectedFormat)

        // Alice responds by adding her registered URI to the nonce, and signing it.
        let aliceChallengeResponse = try aliceChallenge
            .wrap()
            .addAssertion(.dereferenceVia, aliceURI)
            .wrap()
            .sign(with: alicePrivateKeys, note: "Made by Alice.")
            .checkEncoding()

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
            .unwrap()
            .unwrap()
        XCTAssertEqual(aliceChallenge, responseNonce)

        // Bob then extracts Alice's registered URI
        let responseURI = try aliceChallengeResponse
            .unwrap()
            .extractObject(URL.self, forPredicate: .dereferenceVia)
        XCTAssertEqual(responseURI.absoluteString, "https://exampleledger.com/cid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f")

        // Bob uses the URI to ask ExampleLedger for Alice's identifier document, then
        // checks ExampleLedgers's signature. Bob trusts ExampleLedger's validation of
        // Alice's original document, so doesn't bother to check it for internal
        // consistency, and instead goes ahead and extracts Alice's public keys from it.
        let aliceDocumentPublicKeys = try aliceRegistration
            .verifySignature(from: exampleLedgerPublicKeys)
            .unwrap()
            .extractObject(forPredicate: .entity)
            .unwrap()
            .extractObject(PublicKeyBase.self, forPredicate: .publicKeys)

        // Finally, Bob uses Alice's public keys to validate the challenge he sent her.
        try aliceChallengeResponse.verifySignature(from: aliceDocumentPublicKeys)
    }

    func testCredential() throws {
        // John Smith's identifier
        let johnSmithIdentifier = CID(‡"78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc")!

        // A photo of John Smith
        let johnSmithImage = Envelope("John Smith smiling")
            .addAssertion(.note, "This is an image of John Smith.")
            .addAssertion(.dereferenceVia, "https://exampleledger.com/digest/36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999")

        // John Smith's Permanent Resident Card issued by the State of Example
        let johnSmithResidentCard = try Envelope(CID(‡"174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8")!)
            .addAssertion(.isA, "credential")
            .addAssertion("dateIssued", Date(iso8601: "2022-04-27"))
            .addAssertion(.issuer, Envelope(stateIdentifier)
                .addAssertion(.note, "Issued by the State of Example")
                .addAssertion(.dereferenceVia, URL(string: "https://exampleledger.com/cid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8")!)
            )
            .addAssertion(.holder, Envelope(johnSmithIdentifier)
                .addAssertion(.isA, "Person")
                .addAssertion(.isA, "Permanent Resident")
                .addAssertion("givenName", "JOHN")
                .addAssertion("familyName", "SMITH")
                .addAssertion("sex", "MALE")
                .addAssertion("birthDate", Date(iso8601: "1974-02-18"))
                .addAssertion("image", johnSmithImage)
                .addAssertion("lprCategory", "C09")
                .addAssertion("lprNumber", "999-999-999")
                .addAssertion("birthCountry", Envelope("bs").addAssertion(.note, "The Bahamas"))
                .addAssertion("residentSince", Date(iso8601: "2018-01-07"))
            )
            .addAssertion(.note, "The State of Example recognizes JOHN SMITH as a Permanent Resident.")
            .wrap()
            .sign(with: statePrivateKeys, note: "Made by the State of Example.", randomGenerator: generateFakeRandomNumbers)
            .checkEncoding()

        // Validate the state's signature
        try johnSmithResidentCard.verifySignature(from: statePublicKeys)

        //print(johnSmithResidentCard.format)
        
        let expectedFormat =
        """
        {
            CID(174842ea) [
                "dateIssued": 2022-04-27
                holder: CID(78bc3000) [
                    "birthCountry": "bs" [
                        note: "The Bahamas"
                    ]
                    "birthDate": 1974-02-18
                    "familyName": "SMITH"
                    "givenName": "JOHN"
                    "image": "John Smith smiling" [
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
                issuer: CID(04363d5f) [
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

        //print(johnSmithResidentCard.diagAnnotated)

        // John wishes to identify himself to a third party using his government-issued
        // credential, but does not wish to reveal more than his name, his photo, and the
        // fact that the state has verified his identity.

        // Redaction is performed by building a set of `Digest`s that will be revealed. All
        // digests not present in the target set will be replaced with elision markers
        // containing only the hash of what has been elided, thus preserving the hash
        // tree including revealed signatures. If a higher-level object is elided, then
        // everything it contains will also be elided, so if a deeper object is to be
        // revealed, all of its parent objects also need to be revealed, even though not
        // everything *about* the parent objects must be revealed.

        // Start a target set
        var target: Set<Digest> = []

        // Reveal the card. Without this, everything about the card would be elided.
        let top = johnSmithResidentCard
        target.insert(top)

        // Reveal everything about the state's signature on the card
        try target.insert(top.assertion(withPredicate: .verifiedBy).deepDigests)

        // Reveal the top level of the card.
        target.insert(top.shallowDigests)

        let card = try top.unwrap()
        target.insert(card)
        target.insert(card.subject)

        // Reveal everything about the `isA` and `issuer` assertions at the top level of the card.
        try target.insert(card.assertion(withPredicate: .isA).deepDigests)
        try target.insert(card.assertion(withPredicate: .issuer).deepDigests)

        // Reveal the `holder` assertion on the card, but not any of its sub-assertions.
        let holder = try card.assertion(withPredicate: .holder)
        target.insert(holder.shallowDigests)

        // Within the `holder` assertion, reveal everything about just the `givenName`, `familyName`, and `image` assertions.
        let holderObject = holder.object!
        try target.insert(holderObject.assertion(withPredicate: "givenName").deepDigests)
        try target.insert(holderObject.assertion(withPredicate: "familyName").deepDigests)
        try target.insert(holderObject.assertion(withPredicate: "image").deepDigests)

        // Perform the elision
        let elidedCredential = try top.elideRevealing(target).checkEncoding()

        // Verify that the elided credential compares equal to the original credential.
        XCTAssertEqual(elidedCredential, johnSmithResidentCard)

        // Verify that the state's signature on the elided card is still valid.
        try elidedCredential.verifySignature(from: statePublicKeys)

        let expectedElidedFormat =
        """
        {
            CID(174842ea) [
                holder: CID(78bc3000) [
                    "familyName": "SMITH"
                    "givenName": "JOHN"
                    "image": "John Smith smiling" [
                        dereferenceVia: "https://exampleledger.com/digest/36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999"
                        note: "This is an image of John Smith."
                    ]
                    ELIDED (8)
                ]
                isA: "credential"
                issuer: CID(04363d5f) [
                    dereferenceVia: URI(https://exampleledger.com/cid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8)
                    note: "Issued by the State of Example"
                ]
                ELIDED (2)
            ]
        } [
            verifiedBy: Signature [
                note: "Made by the State of Example."
            ]
        ]
        """
        XCTAssertEqual(elidedCredential.format, expectedElidedFormat)

        // Encrypt instead of elide
        let key = SymmetricKey()
        let encryptedCredential = try top.elideRevealing(target, encryptingWith: key).checkEncoding()
        //print(encryptedCredential.format)
        let expectedEncryptedFormat =
        """
        {
            CID(174842ea) [
                holder: CID(78bc3000) [
                    "familyName": "SMITH"
                    "givenName": "JOHN"
                    "image": "John Smith smiling" [
                        dereferenceVia: "https://exampleledger.com/digest/36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999"
                        note: "This is an image of John Smith."
                    ]
                    ENCRYPTED (8)
                ]
                isA: "credential"
                issuer: CID(04363d5f) [
                    dereferenceVia: URI(https://exampleledger.com/cid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8)
                    note: "Issued by the State of Example"
                ]
                ENCRYPTED (2)
            ]
        } [
            verifiedBy: Signature [
                note: "Made by the State of Example."
            ]
        ]
        """
        XCTAssertEqual(encryptedCredential.format, expectedEncryptedFormat)
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
        let acmeCorpDocument = try Envelope(acmeCorpIdentifier)
            .addAssertion(.hasName, "Acme Corp.")
            .addAssertion(.dereferenceVia, URL(string: "https://exampleledger.com/cid/361235424efc81cedec7eb983a97bbe74d7972f778486f93881e5eed577d0aa7")!)
            .checkEncoding()

        //
        // Declare Products
        //

        let qualityProduct = try Envelope(CID(‡"5bcca01f5f370ceb3b7365f076e9600e294d4da6ddf7a616976c87775ea8f0f1")!)
            .addAssertion(.isA, "Product")
            .addAssertion(.hasName, "Quality Widget")
            .addAssertion("seller", acmeCorpDocument)
            .addAssertion("priceEach", "10.99")
            .checkEncoding()

        let cheapProduct = try Envelope(CID(‡"ae464c5f9569ae23ff9a75e83caf485fb581d1ef9da147ca086d10e3d6f93e64")!)
            .addAssertion(.isA, "Product")
            .addAssertion(.hasName, "Cheap Widget")
            .addAssertion("seller", acmeCorpDocument)
            .addAssertion("priceEach", "4.99")
            .checkEncoding()

        //
        // Declare a Purchase Order
        //

        // Since the line items of a PurchaseOrder may be mutated before being finalized,
        // they are not declared as part of the creation of the PurchaseOrder itself.

        let purchaseOrder = try Envelope(CID(‡"1bebb5b6e447f819d5a4cb86409c5da1207d1460672dfe903f55cde833549625")!)
            .addAssertion(.isA, "PurchaseOrder")
            .addAssertion(.hasName, "PO 123")
            .checkEncoding()

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
            .addAssertion(.isA, "PurchaseOrderLineItem")
            .addAssertion("product", qualityProduct.extractSubject(CID.self))
            .addAssertion(.hasName, qualityProduct.extractObject(forPredicate: .hasName))
            .addAssertion("priceEach", qualityProduct.extractObject(forPredicate: "priceEach"))
            .addAssertion("quantity", 4)
            .checkEncoding()

        let line2 = try Envelope(purchaseOrder.digest)
            .addAssertion(.isA, "PurchaseOrderLineItem")
            .addAssertion("product", cheapProduct.extractSubject(CID.self))
            .addAssertion(.hasName, cheapProduct.extractObject(forPredicate: .hasName))
            .addAssertion("priceEach", cheapProduct.extractObject(forPredicate: "priceEach"))
            .addAssertion("quantity", 3)
            .checkEncoding()

        let line2ExpectedFormat =
        """
        Digest(9be5259b) [
            "priceEach": "4.99"
            "product": CID(ae464c5f)
            "quantity": 3
            hasName: "Cheap Widget"
            isA: "PurchaseOrderLineItem"
        ]
        """
        XCTAssertEqual(line2.format, line2ExpectedFormat)

//        let revokeLine1 = Envelope(purchaseOrder.digest)
//            .add(Assertion(revoke: Reference(digest: line1.digest)))
//        print(revokeLine1.format)

        let purchaseOrderProjection = try purchaseOrder
            .addAssertion("lineItem", line1)
            .addAssertion("lineItem", line2)
//            .revoke(line1.digest)
            .checkEncoding()

        let purchaseOrderProjectionExpectedFormat =
        """
        CID(1bebb5b6) [
            "lineItem": Digest(9be5259b) [
                "priceEach": "10.99"
                "product": CID(5bcca01f)
                "quantity": 4
                hasName: "Quality Widget"
                isA: "PurchaseOrderLineItem"
            ]
            "lineItem": Digest(9be5259b) [
                "priceEach": "4.99"
                "product": CID(ae464c5f)
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
    
    func testExampleCredential() {
        let omarCID = CID()
        let omarPrivateKey = PrivateKeyBase()
        let omar = Envelope(omarCID)
            .addAssertion(.hasName, "Omar Chaim")
            .addAssertion("githubID", "omarc-bc-guy")
            .addAssertion("pubkeyURL", "https://github.com/omarc-bc-guy.keys")
            .wrap()
            .sign(with: omarPrivateKey, note: "Self-signed by Omar.")
        
        let jonathanCID = CID()
        let jonathanPrivateKey = PrivateKeyBase()
        let jonathanPublicKey = jonathanPrivateKey.publicKeys
        let ur = jonathanPublicKey.ur
        let jonathan = Envelope(jonathanCID)
            .addAssertion(.hasName, "Jonathan Jakes")
            .addAssertion("githubID", "jojokes")
            .addAssertion("pubkey", ur.string)
            .wrap()
            .sign(with: jonathanPrivateKey, note: "Self-signed by Jonathan")

        let certCID = CID()
        let cert = Envelope(certCID)
            .addAssertion(.issuer, Envelope(omarCID).addAssertion(.note, "Omar's CID"))
            .addAssertion("subject", Envelope(jonathanCID).addAssertion(.note, "Jonathan's CID"))
            .addAssertion(.isA, "Assessment of Blockchain Tech Writing Expertise")
            .wrap()
            .sign(with: omarPrivateKey, note: "Signed by Omar")
        
        print(omar.format)
        print(jonathan.format)
        print(cert.format)
    }
}
