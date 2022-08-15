import XCTest
import BCSecureComponents
import WolfBase

class RedactionTests: XCTestCase {
    func testRedaction() throws {
        let alice = Envelope("Alice")
        let knows = Envelope("knows")
        let bob = Envelope("Bob")
        
        let knowsBob = try Envelope(predicate: knows, object: bob).checkEncoding()

        let aliceKnowsBob = try alice
            .add(knowsBob)
        XCTAssertEqual(aliceKnowsBob.format,
        """
        "Alice" [
            "knows": "Bob"
        ]
        """
        )
        
        let allRedacted = try aliceKnowsBob
            .enclose()
            .redact()
            .checkEncoding()
        XCTAssertEqual(allRedacted.format,
        """
        REDACTED
        """
        )
        
        let aliceRedacted = try aliceKnowsBob
            .redact(removing: aliceKnowsBob.subject)
            .checkEncoding()
        XCTAssertEqual(aliceRedacted.format,
        """
        REDACTED [
            "knows": "Bob"
        ]
        """
        )
        
        let assertion = try aliceKnowsBob.assertion(predicate: "knows")
        let assertionRedacted = try aliceKnowsBob
            .redact(removing: assertion)
            .checkEncoding()
        XCTAssertEqual(assertionRedacted.format,
        """
        "Alice" [
            REDACTED
        ]
        """
        )
        
        let predicate = assertion.predicate!
        let predicateRedacted = try aliceKnowsBob
            .redact(removing: predicate)
            .checkEncoding()
        XCTAssertEqual(predicateRedacted.format,
        """
        "Alice" [
            REDACTED: "Bob"
        ]
        """
        )
        
        let object = assertion.object!
        let objectRedacted = try aliceKnowsBob
            .redact(removing: object)
            .checkEncoding()
        XCTAssertEqual(objectRedacted.format,
        """
        "Alice" [
            "knows": REDACTED
        ]
        """
        )
        
        let predicateObjectRedacted = try aliceKnowsBob
            .redact(removing: [predicate, object])
            .checkEncoding()
        XCTAssertEqual(predicateObjectRedacted.format,
        """
        "Alice" [
            REDACTED: REDACTED
        ]
        """
        )
    }
}
