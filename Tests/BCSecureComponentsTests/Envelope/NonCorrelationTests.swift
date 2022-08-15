import XCTest
import BCSecureComponents
import WolfBase

class NonCorrelationTests: XCTestCase {
    func testEnvelopeNonCorrelation() throws {
        let e1 = Envelope("Hello.")
        
        // e1 correlates with its redaction
        XCTAssertEqual(e1, e1.redact())

        // e2 is the same message, but with random salt
        let e2 = try e1.addSalt().checkEncoding()

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
    
    func testPredicateCorrelation() throws {
        let e1 = try Envelope("Foo")
            .add(.note, "Bar").checkEncoding()
        let e2 = try Envelope("Baz")
            .add(.note, "Quux").checkEncoding()

        let e1ExpectedFormat = """
        "Foo" [
            note: "Bar"
        ]
        """
        XCTAssertEqual(e1.format, e1ExpectedFormat)

        // e1 and e2 have the same predicate
        XCTAssertEqual(e1.assertions.first!.predicate!, e2.assertions.first!.predicate!)
        
        // Redact the entire contents of e1 without
        // redacting the envelope itself.
        let e1Redacted = try e1.redact(revealing: e1).checkEncoding()
        
        let redactedExpectedFormat = """
        REDACTED [
            REDACTED
        ]
        """
        XCTAssertEqual(e1Redacted.format, redactedExpectedFormat)
    }
    
    func testAddSalt() throws {
        // Add salt to every part of an envelope.
        let e1 = try Envelope(Envelope("Alpha").addSalt().checkEncoding()).checkEncoding()
            .add(Envelope(predicate: .note).addSalt().checkEncoding(), Envelope("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.").addSalt().checkEncoding())
        let e1ExpectedFormat = """
        {
            "Alpha" [
                salt: CBOR
            ]
        } [
            note [
                salt: CBOR
            ]
            : "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum." [
                salt: CBOR
            ]
        ]
        """
        XCTAssertEqual(e1.format, e1ExpectedFormat)

        let e1Redacted = try e1.redact(revealing: e1).checkEncoding()
        
        let redactedExpectedFormat = """
        REDACTED [
            REDACTED
        ]
        """
        XCTAssertEqual(e1Redacted.format, redactedExpectedFormat)
    }
}
