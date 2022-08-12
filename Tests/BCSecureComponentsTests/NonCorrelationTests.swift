import XCTest
import BCSecureComponents
import WolfBase

class NonCorrelationTests: XCTestCase {
    func testEnvelopeNonCorrelation() {
        let e1 = Envelope("Hello.")
        
        // e1 correlates with its redaction
        XCTAssertEqual(e1, e1.redact())

        // e2 is the same message, but with random salt
        let e2 = e1.addSalt()

        let e2ExpectedFormat = """
        "Hello." [
            salt: CBOR
        ]
        """
        XCTAssertEqual(e2.format, e2ExpectedFormat)

        // So even though its content is the same, it doesn't correlate.
        XCTAssertNotEqual(e1, e2)

        // And of course, neither does its redaction.
        XCTAssertNotEqual(e1, e2.redact())
    }
    
    func testPredicateCorrelation() {
        let e1 = Envelope("Foo")
            .add(.note, "Bar")
        let e2 = Envelope("Baz")
            .add(.note, "Quux")

        let e1ExpectedFormat = """
        "Foo" [
            note: "Bar"
        ]
        """
        XCTAssertEqual(e1.format, e1ExpectedFormat)

        // e1 and e2 have the same predicate
        XCTAssertEqual(e1.assertions.first!.predicate, e2.assertions.first!.predicate)
        
        // Redact the entire contents of e1 without
        // redacting the envelope itself.
        let e1Redacted = e1.redact(revealing: [e1.digest])
        
        let redactedExpectedFormat = """
        REDACTED [
            REDACTED: REDACTED
        ]
        """
        XCTAssertEqual(e1Redacted.format, redactedExpectedFormat)
        
        // Envelopes always have the same digest in their redacted form.
        // Predicates are just envelopes, and often very simple ones at taht.
        // This is a problem if we want complete non-correlation.
        let notePredicate = Envelope(predicate: .note)
        let notePredicateRedacted = notePredicate.redact()
        XCTAssertEqual(notePredicate, notePredicateRedacted)
        
        // We can tell that the redacted object's first assertion has
        // a "note" predicate, because even though it's been redacted,
        // it still has the same digest.
        XCTAssertEqual(e1Redacted.assertions.first!.predicate, notePredicate)
        
        // Create an envelope where the note predicate's assertion is salted.
        let e3 = Envelope("Alpha")
            .add(Envelope(predicate: .note).addSalt(), "Beta")
        let e3ExpectedFormat = """
        "Alpha" [
            note [
                salt: CBOR
            ]
            : "Beta"
        ]
        """
        XCTAssertEqual(e3.format, e3ExpectedFormat)
        
        // The redacted e3 has the same form as the redacted e1.
        let e3Redacted = e3.redact(revealing: [e3.digest])
        XCTAssertEqual(e3, e3Redacted)
        XCTAssertEqual(e3Redacted.format, redactedExpectedFormat)
        
        // But its first assertion's predicate can no longer be recognized.
        XCTAssertNotEqual(e3Redacted.assertions.first!.predicate, notePredicate)
    }
}
