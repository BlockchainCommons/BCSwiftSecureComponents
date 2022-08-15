import XCTest
import BCSecureComponents
import WolfBase

class NestingTests: XCTestCase {
    func testPredicateEnclosures() throws {
        let alice = Envelope("Alice")
        let knows = Envelope("knows")
        let bob = Envelope("Bob")
        
        let a = Envelope("A")
        let b = Envelope("B")

        let knowsBob = Envelope(predicate: knows, object: bob)
//        print(knowsBob.taggedCBOR.diagAnnotated)
        XCTAssertEqual(knowsBob.format,
            """
            "knows": "Bob"
            """
        )
        
        let ab = Envelope(predicate: a, object: b)
        XCTAssertEqual(ab.format,
            """
            "A": "B"
            """
        )

        let knowsABBob = try Envelope(predicate: knows.add(ab), object: bob).checkEncoding()
        XCTAssertEqual(knowsABBob.format,
            """
            "knows" [
                "A": "B"
            ]
            : "Bob"
            """
        )

        let knowsBobAB = try Envelope(predicate: knows, object: bob.add(ab)).checkEncoding()
        XCTAssertEqual(knowsBobAB.format,
            """
            "knows": "Bob" [
                "A": "B"
            ]
            """
        )
        
        let knowsBobEncloseAB = try knowsBob
            .add(ab)
            .checkEncoding()
        XCTAssertEqual(knowsBobEncloseAB.format,
            """
            {
                "knows": "Bob"
            } [
                "A": "B"
            ]
            """
        )

        let aliceKnowsBob = try alice
            .add(knowsBob)
            .checkEncoding()
        XCTAssertEqual(aliceKnowsBob.format,
            """
            "Alice" [
                "knows": "Bob"
            ]
            """
        )

        let aliceABKnowsBob = try aliceKnowsBob
            .add(ab)
            .checkEncoding()
        XCTAssertEqual(aliceABKnowsBob.format,
            """
            "Alice" [
                "A": "B"
                "knows": "Bob"
            ]
            """
        )

        let aliceKnowsABBob = try alice
            .add(Envelope(predicate: knows.add(ab), object: bob))
            .checkEncoding()
        XCTAssertEqual(aliceKnowsABBob.format,
            """
            "Alice" [
                "knows" [
                    "A": "B"
                ]
                : "Bob"
            ]
            """
        )

        let aliceKnowsBobAB = try alice
            .add(Envelope(predicate: knows, object: bob.add(ab)))
            .checkEncoding()
        XCTAssertEqual(aliceKnowsBobAB.format,
            """
            "Alice" [
                "knows": "Bob" [
                    "A": "B"
                ]
            ]
            """
        )

        let aliceKnowsABBobAB = try alice
            .add(Envelope(predicate: knows.add(ab), object: bob.add(ab)))
            .checkEncoding()
        XCTAssertEqual(aliceKnowsABBobAB.format,
            """
            "Alice" [
                "knows" [
                    "A": "B"
                ]
                : "Bob" [
                    "A": "B"
                ]
            ]
            """
        )

        let aliceABKnowsABBobAB = try alice
            .add(ab)
            .add(Envelope(predicate: knows.add(ab), object: bob.add(ab)))
            .checkEncoding()
//        print(aliceABKnowsABBobAB.format)
        XCTAssertEqual(aliceABKnowsABBobAB.format,
            """
            "Alice" [
                "A": "B"
                "knows" [
                    "A": "B"
                ]
                : "Bob" [
                    "A": "B"
                ]
            ]
            """
        )

        let aliceABKnowsABBobABEncloseAB = try alice
            .add(ab)
            .add(
                Envelope(predicate: knows.add(ab), object: bob.add(ab))
                    .add(ab)
            )
            .checkEncoding()
        XCTAssertEqual(aliceABKnowsABBobABEncloseAB.format,
            """
            "Alice" [
                {
                    "knows" [
                        "A": "B"
                    ]
                    : "Bob" [
                        "A": "B"
                    ]
                } [
                    "A": "B"
                ]
                "A": "B"
            ]
            """
        )
    }
    
    func testNestingPlaintext() {
        let envelope = Envelope(plaintextHello)

        let expectedFormat =
        """
        "Hello."
        """
        XCTAssertEqual(envelope.format, expectedFormat)
        
        let elidedEnvelope = envelope.elide()
        XCTAssertEqual(elidedEnvelope, envelope)

        let expectedElidedFormat =
        """
        ELIDED
        """
        XCTAssertEqual(elidedEnvelope.format, expectedElidedFormat)
    }
    
    func testNestingOnce() throws {
        let envelope = try Envelope(plaintextHello)
            .enclose()
            .checkEncoding()

        let expectedFormat =
        """
        {
            "Hello."
        }
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        let elidedEnvelope = try Envelope(plaintextHello)
            .elide()
            .enclose()
            .checkEncoding()

        XCTAssertEqual(elidedEnvelope, envelope)

        let expectedElidedFormat =
        """
        {
            ELIDED
        }
        """
        XCTAssertEqual(elidedEnvelope.format, expectedElidedFormat)
    }
    
    func testNestingTwice() throws {
        let envelope = try Envelope(plaintextHello)
            .enclose()
            .enclose()
            .checkEncoding()

        let expectedFormat =
        """
        {
            {
                "Hello."
            }
        }
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        let target = try envelope.extract().extract()
        let elidedEnvelope = envelope.elide(removing: target)
        
        let expectedElidedFormat =
        """
        {
            ELIDED
        }
        """
        XCTAssertEqual(elidedEnvelope.format, expectedElidedFormat)
        XCTAssertEqual(envelope.digest, elidedEnvelope.digest)
        try XCTAssertEqual(envelope.extract().digest, elidedEnvelope.extract().digest)
    }
    
    func testNestingSigned() throws {
        let envelope = try Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)
            .checkEncoding()

        let expectedFormat =
        """
        "Hello." [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        let target = envelope.subject
        let elidedEnvelope = try envelope.elide(removing: target).checkEncoding()
        try elidedEnvelope.validateSignature(from: alicePublicKeys)
        let expectedElidedFormat =
        """
        ELIDED [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(elidedEnvelope.format, expectedElidedFormat)
    }
    
    func testNestingEncloseThenSign() throws {
        let envelope = try Envelope(plaintextHello)
            .enclose()
            .sign(with: alicePrivateKeys)
            .checkEncoding()

        let expectedFormat =
        """
        {
            "Hello."
        } [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        let target = try envelope.extract().subject
        let elidedEnvelope = try envelope.elide(removing: target).checkEncoding()
        XCTAssertEqual(elidedEnvelope, envelope)
        try elidedEnvelope.validateSignature(from: alicePublicKeys)
        let expectedElidedFormat =
        """
        {
            ELIDED
        } [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(elidedEnvelope.format, expectedElidedFormat)
        
        let p1 = envelope
        let p2 = try p1.extract()
        let p3 = p2.subject
        let revealedEnvelope = try envelope.elide(revealing: [p1, p2, p3]).checkEncoding()
        XCTAssertEqual(revealedEnvelope, envelope)
        let expectedRevealedFormat =
        """
        {
            "Hello."
        } [
            ELIDED
        ]
        """
        XCTAssertEqual(revealedEnvelope.format, expectedRevealedFormat)
    }
    
    func testNestingSignThenEnclose() {
        let envelope = Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)
            .enclose()

        let expectedFormat =
        """
        {
            "Hello." [
                verifiedBy: Signature
            ]
        }
        """
        XCTAssertEqual(envelope.format, expectedFormat)
    }

    func testAssertionsOnAllPartsOfEnvelope() throws {
        let predicate = Envelope("predicate")
            .add("predicate-predicate", "predicate-object")
        let object = Envelope("object")
            .add("object-predicate", "object-object")
        let envelope = try Envelope("subject")
            .add(predicate, object)
            .checkEncoding()

        let expectedFormat =
        """
        "subject" [
            "predicate" [
                "predicate-predicate": "predicate-object"
            ]
            : "object" [
                "object-predicate": "object-object"
            ]
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)
    }
}
