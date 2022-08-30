import XCTest
import BCSecureComponents
import WolfBase

class BasicTests: XCTestCase {
    static let basicEnvelope = Envelope("Hello.")
    static let knownPredicateEnvelope = Envelope(KnownPredicate.note)
    static let wrappedEnvelope = Envelope(basicEnvelope)
    static let doubleWrappedEnvelope = Envelope(wrappedEnvelope)
    static let assertionEnvelope = Envelope(predicate: "knows", object: "Bob")
    
    static let singleAssertionEnvelope = Envelope("Alice")
        .addAssertion("knows", "Bob")
    static let doubleAssertionEnvelope = singleAssertionEnvelope
        .addAssertion("knows", "Carol")
    
    override class func setUp() {
        addKnownTags()
    }
    
    func testIntSubject() throws {
        let e = try Envelope(42).checkEncoding()
        
        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           220(42)   ; leaf
        )
        """)

        XCTAssertEqual(e.digest†, "Digest(b828e7bda50941d5618ae287093288dd06a229250fca262764a408defd29f91c)")

        XCTAssertEqual(e.format,
        """
        42
        """
        )

        XCTAssertEqual(try e.extractSubject(Int.self), 42)
    }
    
    func testNegativeIntSubject() throws {
        let e = try Envelope(-42).checkEncoding()
        
        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           220(-42)   ; leaf
        )
        """)

        XCTAssertEqual(e.digest†, "Digest(a5deb6e4c1b034cfc4027271e4a2c777f08ced8060fa77156c4f0e494b03b741)")

        XCTAssertEqual(e.format,
        """
        -42
        """
        )

        XCTAssertEqual(try e.extractSubject(Int.self), -42)
    }

    func testCBOREncodableSubject() throws {
        let e = try Self.basicEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           220("Hello.")   ; leaf
        )
        """)
        
        try e.checkEncoding()
        
        XCTAssertEqual(e.digest†, "Digest(886a0c85832fa119d5dc3a195308bf13547f1f16aef032f6c2ef9912cd5992e5)")
        
        XCTAssertEqual(e.format,
        """
        "Hello."
        """
        )
        
        XCTAssertEqual(try e.extractSubject(String.self), "Hello.")
    }
    
    func testKnownPredicateSubject() throws {
        let e = try Self.knownPredicateEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           223(4)   ; known-predicate
        )
        """)
        
        try e.checkEncoding()

        XCTAssertEqual(e.digest†, "Digest(61fb6a6b9699d363cafbd309506125c95234b64479f5671cb45cbe7013ffdcf5)")

        XCTAssertEqual(e.format,
        """
        note
        """)

        XCTAssertEqual(try e.extractSubject(KnownPredicate.self), .note)
    }
    
    func testAssertionSubject() throws {
        let e = try Self.assertionEnvelope.checkEncoding()

        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           221(   ; assertion
              [
                 200(   ; envelope
                    220("knows")   ; leaf
                 ),
                 200(   ; envelope
                    220("Bob")   ; leaf
                 )
              ]
           )
        )
        """)
        
        try e.checkEncoding()

        XCTAssertEqual(e.digest†, "Digest(55560bdf060f1220199c87e84e29cecef96ef811de4f399dab2fde9425d0d418)")

        XCTAssertEqual(e.format,
        """
        "knows": "Bob"
        """)

        XCTAssertEqual(try e.extractSubject(Assertion.self), Assertion(predicate: "knows", object: "Bob"))
    }
    
    func testSubjectWithAssertion() throws {
        let e = Self.singleAssertionEnvelope
        
        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           [
              200(   ; envelope
                 220("Alice")   ; leaf
              ),
              200(   ; envelope
                 221(   ; assertion
                    [
                       200(   ; envelope
                          220("knows")   ; leaf
                       ),
                       200(   ; envelope
                          220("Bob")   ; leaf
                       )
                    ]
                 )
              )
           ]
        )
        """)
        
        try e.checkEncoding()

        XCTAssertEqual(e.digest†, "Digest(e54d6fd38e9952f0d781a08549934cffd28c8e1ef407917fa8e96df69f5f2a90)")
        
        XCTAssertEqual(e.format,
        """
        "Alice" [
            "knows": "Bob"
        ]
        """)

        XCTAssertEqual(try e.extractSubject(String.self), "Alice")
    }
    
    func testSubjectWithTwoAssertions() throws {
        let e = Self.doubleAssertionEnvelope
        
        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           [
              200(   ; envelope
                 220("Alice")   ; leaf
              ),
              200(   ; envelope
                 221(   ; assertion
                    [
                       200(   ; envelope
                          220("knows")   ; leaf
                       ),
                       200(   ; envelope
                          220("Bob")   ; leaf
                       )
                    ]
                 )
              ),
              200(   ; envelope
                 221(   ; assertion
                    [
                       200(   ; envelope
                          220("knows")   ; leaf
                       ),
                       200(   ; envelope
                          220("Carol")   ; leaf
                       )
                    ]
                 )
              )
           ]
        )
        """)

        try e.checkEncoding()

        XCTAssertEqual(e.digest†, "Digest(c733401eaf0c41cd0b3a44b568d4d4dd07e46e481bd3ef6eb457cd6674590614)")

        XCTAssertEqual(e.format,
        """
        "Alice" [
            "knows": "Bob"
            "knows": "Carol"
        ]
        """)

        XCTAssertEqual(try e.extractSubject(String.self), "Alice")
    }

    func testWrapped() throws {
        let e = try Self.wrappedEnvelope.checkEncoding()

        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           224(   ; wrapped-envelope
              220("Hello.")   ; leaf
           )
        )
        """)

        try e.checkEncoding()

        XCTAssertEqual(e.digest†, "Digest(5c0cf317b53dec87641ed2ca7944b900e18e936496c73b42866d29657aeb3a14)")

        XCTAssertEqual(e.format,
        """
        {
            "Hello."
        }
        """)
    }
    
    func testDoubleWrapped() throws {
        let e = try Self.doubleWrappedEnvelope.checkEncoding()

        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           224(   ; wrapped-envelope
              224(   ; wrapped-envelope
                 220("Hello.")   ; leaf
              )
           )
        )
        """)

        try e.checkEncoding()

        XCTAssertEqual(e.digest†, "Digest(c4d50ab4bb904e68d2cf9cd6ca3f65b535f822d7e4a817c9eef0fc75eb83170a)")

        XCTAssertEqual(e.format,
        """
        {
            {
                "Hello."
            }
        }
        """)
    }
    
    func encryptedTest(_ e1: Envelope) throws {
        let e2 = try e1
            .encryptSubject(with: symmetricKey, testNonce: fakeNonce)
            .checkEncoding()
        
        XCTAssertEqual(e1, e2)
        XCTAssertEqual(e1.subject.digest, e2.subject.digest)
        
        let encryptedMessage = try e2.extractSubject(EncryptedMessage.self)
        XCTAssertEqual(encryptedMessage.digest, e1.subject.digest)
        
        let e3 = try e2
            .decryptSubject(with: symmetricKey)

        XCTAssertEqual(e1, e3)
    }
    
    func testEncrypted() throws {
        try encryptedTest(Self.basicEnvelope)
        try encryptedTest(Self.wrappedEnvelope)
        try encryptedTest(Self.doubleWrappedEnvelope)
        try encryptedTest(Self.knownPredicateEnvelope)
        try encryptedTest(Self.assertionEnvelope)
        try encryptedTest(Self.singleAssertionEnvelope)
        try encryptedTest(Self.doubleAssertionEnvelope)
    }
    
    func testSignWrapEncrypt() throws {
        let e1 = Self.basicEnvelope
        //print(e1.format)

        let e2 = e1
            .sign(with: alicePrivateKeys)
        //print(e2.format)

        let e3 = e2
            .wrap()
        //print(e3.format)

        let e4 = try e3
            .encryptSubject(with: symmetricKey)
        //print(e4.format)
        
        let d3 = try e4
            .decryptSubject(with: symmetricKey)
        //print(d3.format)
        XCTAssertEqual(d3, e3)
        
        let d2 = try d3
            .unwrap()
        //print(d2.format)
        XCTAssertEqual(d2, e2)
        
        try d2.validateSignature(from: alicePublicKeys)
        
        let d1 = d2.subject
        //print(d1.format)
        XCTAssertEqual(d1, e1)
    }
    
    func testSignWrapEncryptToRecipient() throws {
        let e1 = Self.basicEnvelope
            .sign(with: alicePrivateKeys)
            .wrap()
        //print(e1.format)

        let e2 = try e1
            .encryptSubject(with: symmetricKey)
        //print(e2.format)

        let e3 = e2
            .addRecipient(bobPublicKeys, contentKey: symmetricKey)
        //print(e3.format)
        
        let d1 = try e3.decrypt(to: bobPrivateKeys)
        //print(d1.format)
        XCTAssertEqual(d1, e1)
    }
    
    func testEncryptDecryptWithOrderedMapKeys() throws {
        var danSeed = Seed(data: ‡"59f2293a5bce7d4de59e71b4207ac5d2")!
        danSeed.name = "Dark Purple Aqua Love"
        danSeed.creationDate = try! Date(iso8601: "2021-02-24")
        danSeed.note = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

        let seedEnvelope = try Envelope(danSeed).checkEncoding()
        let encryptedSeedEnvelope = try seedEnvelope
            .encryptSubject(with: symmetricKey)
            .checkEncoding()
        XCTAssertEqual(seedEnvelope.subject.digest, encryptedSeedEnvelope.subject.digest)
        XCTAssertEqual(seedEnvelope.digest, encryptedSeedEnvelope.digest)

        let decryptedSeedEnvelope = try encryptedSeedEnvelope
            .decryptSubject(with: symmetricKey)
        XCTAssertEqual(seedEnvelope, decryptedSeedEnvelope)
    }
    
    func testDigestLeaf() throws {
        let digest = Self.basicEnvelope.digest
        let e = try Envelope(digest).checkEncoding()
        
        XCTAssertEqual(e.format,
        """
        Digest(886a0c85832fa119d5dc3a195308bf13547f1f16aef032f6c2ef9912cd5992e5)
        """
        )
        
        XCTAssertEqual(e.digest†, "Digest(9fbec3ea6c65e4b190ec35c7e461f75285202fe5556cc6a60eccac3d012f01a6)")
        
        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           220(   ; leaf
              203(   ; crypto-digest
                 h'886a0c85832fa119d5dc3a195308bf13547f1f16aef032f6c2ef9912cd5992e5'
              )
           )
        )
        """
        )
    }
    
    func testEnvelopeElision() throws {
        let e1 = Self.basicEnvelope
        
        let e2 = e1.elide()
        XCTAssertEqual(e1, e2)
        
        XCTAssertEqual(e2.format,
        """
        ELIDED
        """
        )
        
        XCTAssertEqual(e2.diagAnnotated,
        """
        200(   ; envelope
           203(   ; crypto-digest
              h'886a0c85832fa119d5dc3a195308bf13547f1f16aef032f6c2ef9912cd5992e5'
           )
        )
        """
        )
        
        let e3 = try e2.unelide(e1)
        XCTAssertEqual(e3, e1)
        XCTAssertEqual(e3.format,
        """
        "Hello."
        """
        )
    }

    func testSingleAssertionRemoveElision() throws {
        // The original Envelope
        let e1 = Self.singleAssertionEnvelope
        XCTAssertEqual(e1.format,
        """
        "Alice" [
            "knows": "Bob"
        ]
        """
        )

        // Elide the entire envelope
        let e2 = try e1.elideRemoving(e1).checkEncoding()
        XCTAssertEqual(e2.format,
        """
        ELIDED
        """
        )

        // Elide just the envelope's subject
        let e3 = try e1.elideRemoving(Envelope("Alice")).checkEncoding()
        XCTAssertEqual(e3.format,
        """
        ELIDED [
            "knows": "Bob"
        ]
        """
        )

        // Elide just the assertion's predicate
        let e4 = try e1.elideRemoving(Envelope("knows")).checkEncoding()
        XCTAssertEqual(e4.format,
        """
        "Alice" [
            ELIDED: "Bob"
        ]
        """
        )

        // Elide just the assertion's object
        let e5 = try e1.elideRemoving(Envelope("Bob")).checkEncoding()
        XCTAssertEqual(e5.format,
        """
        "Alice" [
            "knows": ELIDED
        ]
        """
        )

        // Elide the entire assertion
        let e6 = try e1.elideRemoving(Self.assertionEnvelope).checkEncoding()
        XCTAssertEqual(e6.format,
        """
        "Alice" [
            ELIDED
        ]
        """
        )
    }

    func testDoubleAssertionRemoveElision() throws {
        // The original Envelope
        let e1 = Self.doubleAssertionEnvelope
        XCTAssertEqual(e1.format,
        """
        "Alice" [
            "knows": "Bob"
            "knows": "Carol"
        ]
        """
        )

        // Elide the entire envelope
        let e2 = try e1.elideRemoving(e1).checkEncoding()
        XCTAssertEqual(e2.format,
        """
        ELIDED
        """
        )

        // Elide just the envelope's subject
        let e3 = try e1.elideRemoving(Envelope("Alice")).checkEncoding()
        XCTAssertEqual(e3.format,
        """
        ELIDED [
            "knows": "Bob"
            "knows": "Carol"
        ]
        """
        )

        // Elide just the assertion's predicate
        let e4 = try e1.elideRemoving(Envelope("knows")).checkEncoding()
        XCTAssertEqual(e4.format,
        """
        "Alice" [
            ELIDED: "Bob"
            ELIDED: "Carol"
        ]
        """
        )

        // Elide just the assertion's object
        let e5 = try e1.elideRemoving(Envelope("Bob")).checkEncoding()
        XCTAssertEqual(e5.format,
        """
        "Alice" [
            "knows": "Carol"
            "knows": ELIDED
        ]
        """
        )

        // Elide the entire assertion
        let e6 = try e1.elideRemoving(Self.assertionEnvelope).checkEncoding()
        XCTAssertEqual(e6.format,
        """
        "Alice" [
            "knows": "Carol"
            ELIDED
        ]
        """
        )
    }
    
    func testSingleAssertionRevealElision() throws {
        // The original Envelope
        let e1 = Self.singleAssertionEnvelope
        XCTAssertEqual(e1.format,
        """
        "Alice" [
            "knows": "Bob"
        ]
        """
        )
        
        // Elide revealing nothing
        let e2 = try e1.elideRevealing([]).checkEncoding()
        XCTAssertEqual(e2.format,
        """
        ELIDED
        """
        )
        
        // Reveal just the envelope's structure
        let e3 = try e1.elideRevealing(e1).checkEncoding()
        XCTAssertEqual(e3.format,
        """
        ELIDED [
            ELIDED
        ]
        """
        )

        // Reveal just the envelope's subject
        let e4 = try e1.elideRevealing([e1, Envelope("Alice")]).checkEncoding()
        XCTAssertEqual(e4.format,
        """
        "Alice" [
            ELIDED
        ]
        """
        )
        
        // Reveal just the assertion's structure.
        let e5 = try e1.elideRevealing([e1, Self.assertionEnvelope]).checkEncoding()
        XCTAssertEqual(e5.format,
        """
        ELIDED [
            ELIDED: ELIDED
        ]
        """
        )

        // Reveal just the assertion's predicate
        let e6 = try e1.elideRevealing([e1, Self.assertionEnvelope, Envelope("knows")]).checkEncoding()
        XCTAssertEqual(e6.format,
        """
        ELIDED [
            "knows": ELIDED
        ]
        """
        )

        // Reveal just the assertion's object
        let e7 = try e1.elideRevealing([e1, Self.assertionEnvelope, Envelope("Bob")]).checkEncoding()
        XCTAssertEqual(e7.format,
        """
        ELIDED [
            ELIDED: "Bob"
        ]
        """
        )
    }
    
    func testDoubleAssertionRevealElision() throws {
        // The original Envelope
        let e1 = Self.doubleAssertionEnvelope
        XCTAssertEqual(e1.format,
        """
        "Alice" [
            "knows": "Bob"
            "knows": "Carol"
        ]
        """
        )
        
        // Elide revealing nothing
        let e2 = try e1.elideRevealing([]).checkEncoding()
        XCTAssertEqual(e2.format,
        """
        ELIDED
        """
        )
        
        // Reveal just the envelope's structure
        let e3 = try e1.elideRevealing(e1).checkEncoding()
        XCTAssertEqual(e3.format,
        """
        ELIDED [
            ELIDED (2)
        ]
        """
        )

        // Reveal just the envelope's subject
        let e4 = try e1.elideRevealing([e1, Envelope("Alice")]).checkEncoding()
        XCTAssertEqual(e4.format,
        """
        "Alice" [
            ELIDED (2)
        ]
        """
        )
        
        // Reveal just the assertion's structure.
        let e5 = try e1.elideRevealing([e1, Self.assertionEnvelope]).checkEncoding()
        XCTAssertEqual(e5.format,
        """
        ELIDED [
            ELIDED: ELIDED
            ELIDED
        ]
        """
        )

        // Reveal just the assertion's predicate
        let e6 = try e1.elideRevealing([e1, Self.assertionEnvelope, Envelope("knows")]).checkEncoding()
        XCTAssertEqual(e6.format,
        """
        ELIDED [
            "knows": ELIDED
            ELIDED
        ]
        """
        )

        // Reveal just the assertion's object
        let e7 = try e1.elideRevealing([e1, Self.assertionEnvelope, Envelope("Bob")]).checkEncoding()
        XCTAssertEqual(e7.format,
        """
        ELIDED [
            ELIDED: "Bob"
            ELIDED
        ]
        """
        )
    }
    
    func testDigests() throws {
        let e1 = Self.doubleAssertionEnvelope
        XCTAssertEqual(e1.format,
        """
        "Alice" [
            "knows": "Bob"
            "knows": "Carol"
        ]
        """
        )
        
        let e2 = try e1.elideRevealing(e1.digests(levels: 0)).checkEncoding()
        XCTAssertEqual(e2.format,
        """
        ELIDED
        """
        )

        let e3 = try e1.elideRevealing(e1.digests(levels: 1)).checkEncoding()
        XCTAssertEqual(e3.format,
        """
        ELIDED [
            ELIDED (2)
        ]
        """
        )

        let e4 = try e1.elideRevealing(e1.digests(levels: 2)).checkEncoding()
        XCTAssertEqual(e4.format,
        """
        "Alice" [
            ELIDED: ELIDED
            ELIDED: ELIDED
        ]
        """
        )

        let e5 = try e1.elideRevealing(e1.digests(levels: 3)).checkEncoding()
        XCTAssertEqual(e5.format,
        """
        "Alice" [
            "knows": "Bob"
            "knows": "Carol"
        ]
        """
        )
    }
    
    func testTargetedReveal() throws {
        let e1 = Self.doubleAssertionEnvelope
            .addAssertion("livesAt", "123 Main St.")
        XCTAssertEqual(e1.format,
        """
        "Alice" [
            "knows": "Bob"
            "knows": "Carol"
            "livesAt": "123 Main St."
        ]
        """
        )
        
        var target: Set<Digest> = []
        // Reveal the Envelope structure
        target.formUnion(e1.digests(levels: 1))
        // Reveal everything about the subject
        target.formUnion(e1.subject.deepDigests)
        // Reveal everything about one of the assertions
        target.formUnion(Self.assertionEnvelope.deepDigests)
        // Reveal the specific `livesAt` assertion
        target.formUnion(try e1.assertion(withPredicate: "livesAt").deepDigests)
        let e2 = try e1.elideRevealing(target).checkEncoding()
        XCTAssertEqual(e2.format,
        """
        "Alice" [
            "knows": "Bob"
            "livesAt": "123 Main St."
            ELIDED
        ]
        """
        )
    }
    
    func testTargetedRemove() throws {
        let e1 = Self.doubleAssertionEnvelope
            .addAssertion("livesAt", "123 Main St.")
        XCTAssertEqual(e1.format,
        """
        "Alice" [
            "knows": "Bob"
            "knows": "Carol"
            "livesAt": "123 Main St."
        ]
        """
        )
        
        var target2: Set<Digest> = []
        // Hide one of the assertions
        target2.formUnion(Self.assertionEnvelope.digests(levels: 1))
        let e2 = try e1.elideRemoving(target2).checkEncoding()
        XCTAssertEqual(e2.format,
        """
        "Alice" [
            "knows": "Carol"
            "livesAt": "123 Main St."
            ELIDED
        ]
        """
        )

        var target3: Set<Digest> = []
        // Hide one of the assertions by finding its predicate
        target3.formUnion(try e1.assertion(withPredicate: "livesAt").deepDigests)
        let e3 = try e1.elideRemoving(target3).checkEncoding()
        XCTAssertEqual(e3.format,
        """
        "Alice" [
            "knows": "Bob"
            "knows": "Carol"
            ELIDED
        ]
        """
        )
    }
}
