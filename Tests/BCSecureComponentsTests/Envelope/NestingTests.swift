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

        let knowsABBob = try Envelope(predicate: knows.add(ab), object: bob)
        XCTAssertEqual(knowsABBob.format,
            """
            "knows" [
                "A": "B"
            ]
            : "Bob"
            """
        )

        let knowsBobAB = try Envelope(predicate: knows, object: bob.add(ab))
        XCTAssertEqual(knowsBobAB.format,
            """
            "knows": "Bob" [
                "A": "B"
            ]
            """
        )
        
        let knowsBobEncloseAB = try knowsBob
            .add(ab)
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
        XCTAssertEqual(aliceKnowsBob.format,
            """
            "Alice" [
                "knows": "Bob"
            ]
            """
        )

        let aliceABKnowsBob = try aliceKnowsBob
            .add(ab)
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
        print(aliceABKnowsABBobAB.format)
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
        
        let redactedEnvelope = envelope.redact()
        XCTAssertEqual(redactedEnvelope, envelope)

        let expectedRedactedFormat =
        """
        REDACTED
        """
        XCTAssertEqual(redactedEnvelope.format, expectedRedactedFormat)
    }
    
    func testNestingOnce() {
        let envelope = Envelope(plaintextHello)
            .enclose()

        let expectedFormat =
        """
        {
            "Hello."
        }
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        let redactedEnvelope = Envelope(plaintextHello)
            .redact()
            .enclose()

        XCTAssertEqual(redactedEnvelope, envelope)

        let expectedRedactedFormat =
        """
        {
            REDACTED
        }
        """
        XCTAssertEqual(redactedEnvelope.format, expectedRedactedFormat)
    }
    
    func testNestingTwice() throws {
        let envelope = Envelope(plaintextHello)
            .enclose()
            .enclose()

        let expectedFormat =
        """
        {
            {
                "Hello."
            }
        }
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        let redaction = try envelope
            .extract()
            .extract()
            .digest
        let redactedEnvelope = envelope.redact(items: [redaction])
        
        let expectedRedactedFormat =
        """
        {
            REDACTED
        }
        """
        XCTAssertEqual(redactedEnvelope.format, expectedRedactedFormat)
        XCTAssertEqual(envelope.digest, redactedEnvelope.digest)
        try XCTAssertEqual(envelope.extract().digest, redactedEnvelope.extract().digest)
    }
    
    func testNestingSigned() throws {
        let envelope = Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)

        let expectedFormat =
        """
        "Hello." [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        let redaction = envelope
            .subject
            .digest
        let redactedEnvelope = envelope.redact(items: Set([redaction]))
        try redactedEnvelope.validateSignature(from: alicePublicKeys)
        let expectedRedactedFormat =
        """
        REDACTED [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(redactedEnvelope.format, expectedRedactedFormat)
    }
    
    func testNestingEncloseThenSign() throws {
        let envelope = Envelope(plaintextHello)
            .enclose()
            .sign(with: alicePrivateKeys)

        let expectedFormat =
        """
        {
            "Hello."
        } [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        let redaction = try envelope
            .extract()
            .subject
            .digest
        let redactedEnvelope = envelope.redact(items: Set([redaction]))
        XCTAssertEqual(redactedEnvelope, envelope)
        try redactedEnvelope.validateSignature(from: alicePublicKeys)
        let expectedRedactedFormat =
        """
        {
            REDACTED
        } [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(redactedEnvelope.format, expectedRedactedFormat)
        
        let p1 = envelope
        let p2 = try p1.extract()
        let p3 = p2.subject
        let revealSet: Set<Digest> = [p1.digest, p2.digest, p3.digest]
        let revealedEnvelope = envelope.redact(revealing: revealSet)
        XCTAssertEqual(revealedEnvelope, envelope)
        let expectedRevealedFormat =
        """
        {
            "Hello."
        } [
            REDACTED
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
        let envelope = Envelope("subject")
            .add(predicate, object)

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
