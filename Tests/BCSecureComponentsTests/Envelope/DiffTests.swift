import XCTest
import BCSecureComponents
import WolfBase

//class DiffTests: XCTestCase {
//    // No change.
//    func testIdentical() throws {
//        let a = Envelope("Alice")
//        let b = Envelope("Alice")
//        let diff = a.diff(target: b)
//        XCTAssertEqual(diff.format,
//        """
//        noChange
//        """)
//        let c = try a.applyDiff(diff)
//        XCTAssertEqual(b, c)
//    }
//
//    // Change the subject.
//    func testDiffSubjects() throws {
//        let a = Envelope("Alice")
//        let b = Envelope("Bob")
//        let diff = a.diff(target: b)
//        XCTAssertEqual(diff.format,
//        """
//        "Bob"
//        """)
//        let c = try a.applyDiff(diff)
//        XCTAssertEqual(b, c)
//    }
//
//    // Change the type of the subject
//    func test3() throws {
//        let a = Envelope("Alice")
//        let b = Envelope(KnownValue.verifiedBy)
//        let diff = a.diff(target: b)
//        XCTAssertEqual(diff.format,
//        """
//        verifiedBy
//        """)
//        let c = try a.applyDiff(diff)
//        XCTAssertEqual(b, c)
//    }
//
//    // Keep one assertion, modify another, and delete a third
//    func test4() throws {
//        let a = Envelope("Alice")
//            .addAssertion("knows", "Bob")
//            .addAssertion("knows", "Carol")
//            .addAssertion("knows", "Edward")
//        let b = Envelope("Alice")
//            .addAssertion("knows", "Bob")
//            .addAssertion("knows", "Dan")
//        let diff = a.diff(target: b)
//        XCTAssertEqual(diff.format,
//        """
//        noChange [
//            {
//                edit: Digest(1e0b049b)
//            } [
//                object: "Dan"
//            ]
//            delete: Digest(71a30690)
//        ]
//        """)
//        let c = try a.applyDiff(diff)
//        XCTAssertEqual(b, c)
//    }
//
//    // Keep one assertion, modify another, and add a third
//    func test5() throws {
//        let a = Envelope("Alice")
//            .addAssertion("knows", "Bob")
//            .addAssertion("knows", "Carol")
//        let b = Envelope("Alice")
//            .addAssertion("knows", "Bob")
//            .addAssertion("knows", "Dan")
//            .addAssertion("knows", "Edward")
//        let diff = a.diff(target: b)
//        XCTAssertEqual(diff.format,
//        """
//        noChange [
//            {
//                edit: Digest(71a30690)
//            } [
//                object: "Edward"
//            ]
//            add: "knows": "Dan"
//        ]
//        """)
//        let c = try a.applyDiff(diff)
//        XCTAssertEqual(b, c)
//    }
//
//    // Delete all assertions
//    func test6() throws {
//        let a = Envelope("Alice")
//            .addAssertion("knows", "Bob")
//            .addAssertion("knows", "Carol")
//        let b = Envelope("Alice")
//        let diff = a.diff(target: b)
//        XCTAssertEqual(diff.format,
//        """
//        noChange [
//            delete: Digest(55560bdf)
//            delete: Digest(71a30690)
//        ]
//        """)
//        let c = try a.applyDiff(diff)
//        XCTAssertEqual(b, c)
//    }
//
//    // Change the subject and delete all assertions
//    func test7() throws {
//        let a = Envelope("Alice")
//            .addAssertion("knows", "Bob")
//            .addAssertion("knows", "Carol")
//        let b = Envelope("Edward")
//        let diff = a.diff(target: b)
//        XCTAssertEqual(diff.format,
//        """
//        "Edward" [
//            delete: Digest(55560bdf)
//            delete: Digest(71a30690)
//        ]
//        """)
//        let c = try a.applyDiff(diff)
//        XCTAssertEqual(b, c)
//    }
//
//    // Merge signatures
//    func test8() throws {
//        // The doc to be signed. It is pre-wrapped.
//        let doc = Envelope("Alice")
//            .addAssertion("knows", "Bob")
//            .addAssertion("knows", "Carol")
//            .wrap()
//
//        // First signer signs the document
//        let bobPrivateKey = PrivateKeyBase()
//        let signedDoc1 = doc
//            .sign(with: bobPrivateKey)
//
//        // Second signer signs the document
//        let carolPrivateKey = PrivateKeyBase()
//        let signedDoc2 = doc
//            .sign(with: carolPrivateKey)
//
//        // Make sure that both parties signed the original doc.
//        XCTAssertEqual(doc, signedDoc1.subject)
//        XCTAssertEqual(doc, signedDoc2.subject)
//
//        // Extract the signatures from the signed documents
//        let signature1Diff = doc.diff(target: signedDoc1)
//        let signature2Diff = doc.diff(target: signedDoc2)
//
//        // Merge the signatures into the original doc
//        let merged = try doc
//            .applyDiff(signature1Diff)
//            .applyDiff(signature2Diff)
//
//        XCTAssertEqual(merged.format,
//        """
//        {
//            "Alice" [
//                "knows": "Bob"
//                "knows": "Carol"
//            ]
//        } [
//            verifiedBy: Signature
//            verifiedBy: Signature
//        ]
//        """)
//
//        // Check that both signatures verify the document.
//        try merged.verifySignature(from: bobPrivateKey.publicKeys)
//        try merged.verifySignature(from: carolPrivateKey.publicKeys)
//    }
//
//    func test9() throws {
//        let doc = Envelope("Alice")
//            .addAssertion("knows", "Bob")
//            .addAssertion("knows", "Carol")
//            .wrap()
//
//        let bobPrivateKey = PrivateKeyBase()
//        let bobSignature = try doc.sign(with: bobPrivateKey, coveredAssertions: [
//            Envelope("signedBy", "Bob"),
//            Envelope(.date, Date())
//        ])
//        print(bobSignature.format)
//
////        print(doc.treeFormat)
////        print(doc.digest)
////
////        print(bobSignature.treeFormat)
////        try XCTAssertEqual(bobSignature.subject.unwrap().subject, doc)
//
////        print(bobSignature.subject.digest)
//
////        let carolPrivateKey = PrivateKeyBase()
////        let signedDoc2 = doc
////            .addAssertion("signedBy", "Carol")
////            .wrap()
////            .sign(with: carolPrivateKey)
////
////        print(signedDoc1.format)
////        print(signedDoc2.format)
////
////        print(signedDoc1.diff(target: signedDoc2).format)
//    }
//}
