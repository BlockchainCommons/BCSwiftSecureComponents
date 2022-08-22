import XCTest
import BCSecureComponents
import WolfBase

class ElisionExampleTests: XCTestCase {
    func testRedactionExample() throws {
        let credential = try Envelope(CID(‡"4676635a6e6068c2ef3ffd8ff726dd401fd341036e920f136a1d8af5e829496d")!)
            .addAssertion("firstName", "John")
            .addAssertion("lastName", "Smith")
            .addAssertion("address", "123 Main St.")
            .addAssertion("birthDate", Date(iso8601: "1970-01-01"))
            .addAssertion("photo", "This is John Smith's photo.")
            .addAssertion("dlNumber", "123-456-789")
            .addAssertion("nonCommercialVehicleEndorsement", true)
            .addAssertion("motorocycleEndorsement", true)
            .addAssertion(.issuer, "State of Example")
            .addAssertion(.controller, "State of Example")
            .wrap()
            .sign(with: alicePrivateKeys)
            .addAssertion(.note, "Signed by the State of Example")
            .checkEncoding()
        XCTAssertEqual(credential.format,
        """
        {
            CID(4676635a6e6068c2ef3ffd8ff726dd401fd341036e920f136a1d8af5e829496d) [
                "address": "123 Main St."
                "birthDate": 1970-01-01
                "dlNumber": "123-456-789"
                "firstName": "John"
                "lastName": "Smith"
                "motorocycleEndorsement": true
                "nonCommercialVehicleEndorsement": true
                "photo": "This is John Smith's photo."
                controller: "State of Example"
                issuer: "State of Example"
            ]
        } [
            note: "Signed by the State of Example"
            verifiedBy: Signature
        ]
        """
        )
        
        var target: Set<Digest> = []

        /// With an empty target, the entire document is elided.
        let e2 = credential.elideRevealing(target)
        XCTAssertEqual(e2.format,
        """
        ELIDED
        """
        )

        /// By adding the top-level digest of the document, its macro structure is revealed. The subject of the document is the drivers license proper. The two assertions are the `.note` and `.verifiedBy` assertions.
        target.insert(credential)
        let e3 = credential.elideRevealing(target)
        XCTAssertEqual(e3.format,
        """
        ELIDED [
            ELIDED (2)
        ]
        """
        )
        
        /// We add the complete hierarchy of digests that comprise all the assertions on the document. This reveals the signature.
        for assertion in credential.assertions {
            target.insert(assertion.deepDigests)
        }
        let e4 = credential.elideRevealing(target)
        XCTAssertEqual(e4.format,
        """
        ELIDED [
            note: "Signed by the State of Example"
            verifiedBy: Signature
        ]
        """
        )
        
        /// We insert the digest of the document's subject. The subject is a wrapped envelope, which is still elided.
        target.insert(credential.subject)
        let e5 = credential.elideRevealing(target)
        XCTAssertEqual(e5.format,
        """
        {
            ELIDED
        } [
            note: "Signed by the State of Example"
            verifiedBy: Signature
        ]
        """
        )

        /// We insert the digest of the wrapped envelope, revealing its macro structure. This is the actual content of the document.
        let content = try credential.subject.unwrap()
        target.insert(content)
        let e6 = credential.elideRevealing(target)
        XCTAssertEqual(e6.format,
        """
        {
            ELIDED [
                ELIDED (10)
            ]
        } [
            note: "Signed by the State of Example"
            verifiedBy: Signature
        ]
        """
        )
        
        /// The only actual assertions we want to reveal are `birthDate` and `photo`, so we do this by finding those specific assertions by their predicate. The `shallowDigests` attribute returns just a necessary set of attributes to reveal the assertion, its predicate, and its object (yes, all three of them need to be revealed) but *not* any deeper assertions on them.
        target.insert(try content.assertion(withPredicate: "birthDate").shallowDigests)
        target.insert(try content.assertion(withPredicate: "photo").shallowDigests)
        let e7 = credential.elideRevealing(target)
        print(e7.format)
        XCTAssertEqual(e7.format,
        """
        {
            ELIDED [
                "birthDate": 1970-01-01
                "photo": "This is John Smith's photo."
                ELIDED (8)
            ]
        } [
            note: "Signed by the State of Example"
            verifiedBy: Signature
        ]
        """
        )
        
        // print(target.count) // 15
    }
    
    func testPositions() throws {
        let envelope = Envelope("Alice")
            .addAssertion("knows", "Bob")
        print(envelope.format)
        XCTAssertEqual(envelope.format,
        """
        "Alice" [
            "knows": "Bob"
        ]
        """
        )

        let e1 = envelope.elideRemoving(envelope)
        print(e1.format)
        XCTAssertEqual(e1.format,
        """
        ELIDED
        """
        )

        let e2 = envelope.elideRemoving(envelope.subject)
        print(e2.format)
        XCTAssertEqual(e2.format,
        """
        ELIDED [
            "knows": "Bob"
        ]
        """
        )

        let assertion = envelope.assertions.first!
        let e3 = envelope.elideRemoving(assertion)
        print(e3.format)
        XCTAssertEqual(e3.format,
        """
        "Alice" [
            ELIDED
        ]
        """
        )

        let e4 = envelope.elideRemoving(assertion.predicate!)
        print(e4.format)
        XCTAssertEqual(e4.format,
        """
        "Alice" [
            ELIDED: "Bob"
        ]
        """
        )

        let e5 = envelope.elideRemoving(assertion.object!)
        print(e5.format)
        XCTAssertEqual(e5.format,
        """
        "Alice" [
            "knows": ELIDED
        ]
        """
        )
    }
}
