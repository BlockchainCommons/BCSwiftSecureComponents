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

        let knowsBob = Envelope(knows, bob)
        XCTAssertEqual(knowsBob.format,
            """
            "knows": "Bob"
            """
        )

        let ab = Envelope(a, b)
        XCTAssertEqual(ab.format,
            """
            "A": "B"
            """
        )

        let knowsABBob = try Envelope(knows.addAssertion(ab), bob).checkEncoding()
        XCTAssertEqual(knowsABBob.format,
            """
            "knows" [
                "A": "B"
            ]
            : "Bob"
            """
        )

        let knowsBobAB = try Envelope(knows, bob.addAssertion(ab)).checkEncoding()
        XCTAssertEqual(knowsBobAB.format,
            """
            "knows": "Bob" [
                "A": "B"
            ]
            """
        )

        let knowsBobEncloseAB = try knowsBob
            .addAssertion(ab)
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
            .addAssertion(knowsBob)
            .checkEncoding()
        XCTAssertEqual(aliceKnowsBob.format,
            """
            "Alice" [
                "knows": "Bob"
            ]
            """
        )

        let aliceABKnowsBob = try aliceKnowsBob
            .addAssertion(ab)
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
            .addAssertion(Envelope(knows.addAssertion(ab), bob))
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
            .addAssertion(Envelope(knows, bob.addAssertion(ab)))
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
            .addAssertion(Envelope(knows.addAssertion(ab), bob.addAssertion(ab)))
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
            .addAssertion(ab)
            .addAssertion(Envelope(knows.addAssertion(ab), bob.addAssertion(ab)))
            .checkEncoding()
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
            .addAssertion(ab)
            .addAssertion(
                Envelope(knows.addAssertion(ab), bob.addAssertion(ab))
                    .addAssertion(ab)
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
        XCTAssert(elidedEnvelope.isEquivalent(to: envelope))

        let expectedElidedFormat =
        """
        ELIDED
        """
        XCTAssertEqual(elidedEnvelope.format, expectedElidedFormat)
    }

    func testNestingOnce() throws {
        let envelope = try Envelope(plaintextHello)
            .wrap()
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
            .wrap()
            .checkEncoding()

        XCTAssert(elidedEnvelope.isEquivalent(to: envelope))

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
            .wrap()
            .wrap()
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

        let target = try envelope
            .unwrap()
            .unwrap()
        let elidedEnvelope = try envelope.elideRemoving(target)

        let expectedElidedFormat =
        """
        {
            {
                ELIDED
            }
        }
        """
        XCTAssertEqual(elidedEnvelope.format, expectedElidedFormat)
        XCTAssert(envelope.isEquivalent(to: elidedEnvelope))
        XCTAssert(envelope.isEquivalent(to: elidedEnvelope))
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
        let elidedEnvelope = try envelope.elideRemoving(target).checkEncoding()
        try elidedEnvelope.verifySignature(from: alicePublicKeys)
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
            .wrap()
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

        let target = try envelope.unwrap().subject
        let elidedEnvelope = try envelope.elideRemoving(target).checkEncoding()
        XCTAssert(elidedEnvelope.isEquivalent(to: envelope))
        try elidedEnvelope.verifySignature(from: alicePublicKeys)
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
        let p2 = envelope.subject
        let p3 = try p1.unwrap()
        let revealedEnvelope = try envelope.elideRevealing([p1, p2, p3]).checkEncoding()
        XCTAssert(revealedEnvelope.isEquivalent(to: envelope))
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
            .wrap()

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
            .addAssertion("predicate-predicate", "predicate-object")
        let object = Envelope("object")
            .addAssertion("object-predicate", "object-object")
        let envelope = try Envelope("subject")
            .addAssertion(predicate, object)
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
    
    func testAssertionOnBareAssertion() throws {
        let envelope = try Envelope("predicate", "object")
            .addAssertion(Envelope("assertion-predicate", "assertion-object"))
        let expectedFormat =
        """
        {
            "predicate": "object"
        } [
            "assertion-predicate": "assertion-object"
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)
    }
}
