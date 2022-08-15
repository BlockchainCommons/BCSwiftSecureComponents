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
        
        let allElided = try aliceKnowsBob
            .enclose()
            .elide()
            .checkEncoding()
        XCTAssertEqual(allElided.format,
        """
        ELIDED
        """
        )
        
        let aliceElided = try aliceKnowsBob
            .elide(removing: aliceKnowsBob.subject)
            .checkEncoding()
        XCTAssertEqual(aliceElided.format,
        """
        ELIDED [
            "knows": "Bob"
        ]
        """
        )
        
        let assertion = try aliceKnowsBob.assertion(predicate: "knows")
        let assertionElided = try aliceKnowsBob
            .elide(removing: assertion)
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
            .elide(removing: predicate)
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
            .elide(removing: object)
            .checkEncoding()
        XCTAssertEqual(objectElided.format,
        """
        "Alice" [
            "knows": ELIDED
        ]
        """
        )
        
        let predicateObjectElided = try aliceKnowsBob
            .elide(removing: [predicate, object])
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
