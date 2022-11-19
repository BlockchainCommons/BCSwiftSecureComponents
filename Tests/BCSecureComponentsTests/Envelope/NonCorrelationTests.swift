import XCTest
import BCSecureComponents
import WolfBase

class NonCorrelationTests: XCTestCase {
    func testEnvelopeNonCorrelation() throws {
        let e1 = Envelope("Hello.")
        
        // e1 correlates with its elision
        XCTAssertEqual(e1, e1.elide())

        // e2 is the same message, but with random salt
        let e2 = try e1.addSalt().checkEncoding()

        let e2ExpectedFormat = """
        "Hello." [
            salt: Salt
        ]
        """
        XCTAssertEqual(e2.format, e2ExpectedFormat)

        // So even though its content is the same, it doesn't correlate.
        XCTAssertNotEqual(e1, e2)

        // And of course, neither does its elision.
        XCTAssertNotEqual(e1, e2.elide())
    }
    
    func testPredicateCorrelation() throws {
        let e1 = try Envelope("Foo")
            .addAssertion(.note, "Bar").checkEncoding()
        let e2 = try Envelope("Baz")
            .addAssertion(.note, "Quux").checkEncoding()

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
        let e1Elided = try e1.elideRevealing(e1).checkEncoding()
        
        let redactedExpectedFormat = """
        ELIDED [
            ELIDED
        ]
        """
        XCTAssertEqual(e1Elided.format, redactedExpectedFormat)
    }
    
    func testAddSalt() throws {
        // Add salt to every part of an envelope.
        let e1 = try Envelope(Envelope("Alpha").addSalt().checkEncoding()).checkEncoding()
            .addAssertion(Envelope(KnownValue.note).addSalt().checkEncoding(), Envelope("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.").addSalt().checkEncoding())
        let e1ExpectedFormat = """
        {
            "Alpha" [
                salt: Salt
            ]
        } [
            note [
                salt: Salt
            ]
            : "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum." [
                salt: Salt
            ]
        ]
        """
        XCTAssertEqual(e1.format, e1ExpectedFormat)

        let e1Elided = try e1.elideRevealing(e1).checkEncoding()
        
        let redactedExpectedFormat = """
        ELIDED [
            ELIDED
        ]
        """
        XCTAssertEqual(e1Elided.format, redactedExpectedFormat)
    }
}
