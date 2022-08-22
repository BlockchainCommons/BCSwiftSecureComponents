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
            .addAssertion(knowsBob)
        XCTAssertEqual(aliceKnowsBob.format,
        """
        "Alice" [
            "knows": "Bob"
        ]
        """
        )
        
        let allElided = try aliceKnowsBob
            .wrap()
            .elide()
            .checkEncoding()
        XCTAssertEqual(allElided.format,
        """
        ELIDED
        """
        )
        
        let aliceElided = try aliceKnowsBob
            .elideRemoving(aliceKnowsBob.subject)
            .checkEncoding()
        XCTAssertEqual(aliceElided.format,
        """
        ELIDED [
            "knows": "Bob"
        ]
        """
        )
        
        let assertion = try aliceKnowsBob.assertion(withPredicate: "knows")
        let assertionElided = try aliceKnowsBob
            .elideRemoving(assertion)
            .checkEncoding()
        XCTAssertEqual(assertionElided.format,
        """
        "Alice" [
            ELIDED
        ]
        """
        )
        
        let predicate = assertion.predicate!
        let predicateElided = try aliceKnowsBob
            .elideRemoving(predicate)
            .checkEncoding()
        XCTAssertEqual(predicateElided.format,
        """
        "Alice" [
            ELIDED: "Bob"
        ]
        """
        )
        
        let object = assertion.object!
        let objectElided = try aliceKnowsBob
            .elideRemoving(object)
            .checkEncoding()
        XCTAssertEqual(objectElided.format,
        """
        "Alice" [
            "knows": ELIDED
        ]
        """
        )
        
        let predicateObjectElided = try aliceKnowsBob
            .elideRemoving([predicate, object])
            .checkEncoding()
        XCTAssertEqual(predicateObjectElided.format,
        """
        "Alice" [
            ELIDED: ELIDED
        ]
        """
        )
    }
}
