import XCTest
import BCSecureComponents
import WolfBase

class RedactionTests: XCTestCase {
    func testRedaction() throws {
        let alice = Envelope("Alice")
        let knows = Envelope("knows")
        let bob = Envelope("Bob")
        
        let knowsBob = Envelope(predicate: knows, object: bob)

        let aliceKnowsBob = try alice
            .add(knowsBob)
        XCTAssertEqual(aliceKnowsBob.format,
        """
        "Alice" [
            "knows": "Bob"
        ]
        """
        )
        
        let allRedacted = aliceKnowsBob.redact()
        XCTAssertEqual(allRedacted.format,
        """
        REDACTED
        """
        )
        
        let aliceRedacted = aliceKnowsBob.redact(removing: aliceKnowsBob.subject)
        XCTAssertEqual(aliceRedacted.format,
        """
        REDACTED [
            "knows": "Bob"
        ]
        """
        )
        
        let assertion = try aliceKnowsBob.assertion(predicate: "knows")
        let assertionRedacted = aliceKnowsBob.redact(removing: assertion)
        XCTAssertEqual(assertionRedacted.format,
        """
        "Alice" [
            REDACTED
        ]
        """
        )
        
        let predicate = assertion.predicate!
        let predicateRedacted = aliceKnowsBob.redact(removing: predicate)
        XCTAssertEqual(predicateRedacted.format,
        """
        "Alice" [
            REDACTED: "Bob"
        ]
        """
        )
        
        let object = assertion.object!
        let objectRedacted = aliceKnowsBob.redact(removing: object)
        XCTAssertEqual(objectRedacted.format,
        """
        "Alice" [
            "knows": REDACTED
        ]
        """
        )
        
        let predicateObjectRedacted = aliceKnowsBob.redact(removing: [predicate, object])
        XCTAssertEqual(predicateObjectRedacted.format,
        """
        "Alice" [
            REDACTED: REDACTED
        ]
        """
        )
    }
}
