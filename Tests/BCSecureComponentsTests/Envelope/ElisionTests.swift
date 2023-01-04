import XCTest
import BCSecureComponents
import WolfBase

class ElisionTests: XCTestCase {
    static let basicEnvelope = Envelope("Hello.")
    static let assertionEnvelope = Envelope("knows", "Bob")

    static let singleAssertionEnvelope = Envelope("Alice")
        .addAssertion("knows", "Bob")
    static let doubleAssertionEnvelope = singleAssertionEnvelope
        .addAssertion("knows", "Carol")

    func testEnvelopeElision() throws {
        let e1 = Self.basicEnvelope

        let e2 = e1.elide()
        XCTAssert(e1.isEquivalent(to: e2))
        XCTAssertFalse(e1.isIdentical(to: e2))

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
        XCTAssert(e3.isEquivalent(to: e1))
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

        let e2 = try e1.elideRevealing(e1.digests(levelLimit: 0)).checkEncoding()
        XCTAssertEqual(e2.format,
        """
        ELIDED
        """
        )

        let e3 = try e1.elideRevealing(e1.digests(levelLimit: 1)).checkEncoding()
        XCTAssertEqual(e3.format,
        """
        "Alice" [
            ELIDED (2)
        ]
        """
        )

        let e4 = try e1.elideRevealing(e1.digests(levelLimit: 2)).checkEncoding()
        XCTAssertEqual(e4.format,
        """
        "Alice" [
            ELIDED: ELIDED
            ELIDED: ELIDED
        ]
        """
        )

        let e5 = try e1.elideRevealing(e1.digests(levelLimit: 3)).checkEncoding()
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
        target.formUnion(e1.digests(levelLimit: 1))
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
        target2.formUnion(Self.assertionEnvelope.digests(levelLimit: 1))
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
        
        // Semantically equivalent
        XCTAssert(e1.isEquivalent(to: e3))
        
        // Structurally different
        XCTAssertFalse(e1.isIdentical(to: e3))
    }
}
