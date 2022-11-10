import XCTest
import BCSecureComponents
import WolfBase

class FormatTests: XCTestCase {
    func testPlaintext() throws {
        let envelope = Envelope(plaintextHello)
        XCTAssertEqual(envelope.format,
        """
        "Hello."
        """)
        XCTAssertEqual(envelope.treeFormat,
        """
        886a0c85 "Hello."
        """)
        XCTAssertEqual(envelope.elementsCount, envelope.treeFormat.split(separator: "\n").count)
        XCTAssertEqual(envelope.mermaidFormat,
        """
        graph LR
            1["886a0c85<br/>#quot;Hello.#quot;"]
            style 1 stroke:#55f,stroke-width:3.0px
        """)
    }
    
    func testSignedPlaintext() throws {
        let envelope = Envelope(plaintextHello)
            .sign(with: alicePrivateKeys, randomGenerator: generateFakeRandomNumbers)
        XCTAssertEqual(envelope.format,
        """
        "Hello." [
            verifiedBy: Signature
        ]
        """)
        XCTAssertEqual(envelope.treeFormat,
        """
        542a4152 NODE
            886a0c85 subj "Hello."
            97a092fc ASSERTION
                d59f8c0f pred verifiedBy
                4edea99f obj Signature
        """)
        XCTAssertEqual(envelope.elementsCount, envelope.treeFormat.split(separator: "\n").count)
        XCTAssertEqual(envelope.mermaidFormat,
        """
        graph LR
            1(("542a4152<br/>NODE"))
            2["886a0c85<br/>#quot;Hello.#quot;"]
            3(["97a092fc<br/>ASSERTION"])
            4[/"d59f8c0f<br/>verifiedBy"/]
            5["4edea99f<br/>Signature"]
            1 -->|subj| 2
            1 --> 3
            3 -->|pred| 4
            3 -->|obj| 5
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke:green,stroke-width:2.0px
            linkStyle 3 stroke:#55f,stroke-width:2.0px
        """)
    }
    
    func testEncryptSubject() throws {
        let envelope = try Envelope("Alice")
            .addAssertion("knows", "Bob")
            .encryptSubject(with: SymmetricKey(), testNonce: fakeNonce)
        XCTAssertEqual(envelope.format,
        """
        ENCRYPTED [
            "knows": "Bob"
        ]
        """)
        XCTAssertEqual(envelope.treeFormat,
        """
        e54d6fd3 NODE
            27840350 subj ENCRYPTED
            55560bdf ASSERTION
                7092d620 pred "knows"
                9a771715 obj "Bob"
        """)
        XCTAssertEqual(envelope.elementsCount, envelope.treeFormat.split(separator: "\n").count)
        XCTAssertEqual(envelope.mermaidFormat,
        """
        graph LR
            1(("e54d6fd3<br/>NODE"))
            2>"27840350<br/>ENCRYPTED"]
            3(["55560bdf<br/>ASSERTION"])
            4["7092d620<br/>#quot;knows#quot;"]
            5["9a771715<br/>#quot;Bob#quot;"]
            1 -->|subj| 2
            1 --> 3
            3 -->|pred| 4
            3 -->|obj| 5
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke:green,stroke-width:2.0px
            linkStyle 3 stroke:#55f,stroke-width:2.0px
        """)
    }
    
    func testTopLevelAssertion() throws {
        let envelope = Envelope("knows", "Bob")
        XCTAssertEqual(envelope.format,
        """
        "knows": "Bob"
        """)
        XCTAssertEqual(envelope.treeFormat,
        """
        55560bdf ASSERTION
            7092d620 pred "knows"
            9a771715 obj "Bob"
        """)
        XCTAssertEqual(envelope.elementsCount, envelope.treeFormat.split(separator: "\n").count)
        XCTAssertEqual(envelope.mermaidFormat,
        """
        graph LR
            1(["55560bdf<br/>ASSERTION"])
            2["7092d620<br/>#quot;knows#quot;"]
            3["9a771715<br/>#quot;Bob#quot;"]
            1 -->|pred| 2
            1 -->|obj| 3
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:green,stroke-width:2.0px
            linkStyle 1 stroke:#55f,stroke-width:2.0px
        """)
    }

    func testElidedObject() throws {
        let envelope = Envelope("Alice")
            .addAssertion("knows", "Bob")
        let elided = try envelope.elideRemoving(Envelope("Bob"))
        XCTAssertEqual(elided.format,
        """
        "Alice" [
            "knows": ELIDED
        ]
        """)
        XCTAssertEqual(elided.treeFormat,
        """
        e54d6fd3 NODE
            27840350 subj "Alice"
            55560bdf ASSERTION
                7092d620 pred "knows"
                9a771715 obj ELIDED
        """)
        XCTAssertEqual(elided.elementsCount, elided.treeFormat.split(separator: "\n").count)
        XCTAssertEqual(elided.mermaidFormat,
        """
        graph LR
            1(("e54d6fd3<br/>NODE"))
            2["27840350<br/>#quot;Alice#quot;"]
            3(["55560bdf<br/>ASSERTION"])
            4["7092d620<br/>#quot;knows#quot;"]
            5{{"9a771715<br/>ELIDED"}}
            1 -->|subj| 2
            1 --> 3
            3 -->|pred| 4
            3 -->|obj| 5
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke:green,stroke-width:2.0px
            linkStyle 3 stroke:#55f,stroke-width:2.0px
        """)
    }

    func testSignedSubject() throws {
        let envelope = Envelope("Alice")
            .addAssertion("knows", "Bob")
            .addAssertion("knows", "Carol")
            .sign(with: alicePrivateKeys, randomGenerator: generateFakeRandomNumbers)
        XCTAssertEqual(envelope.format,
        """
        "Alice" [
            "knows": "Bob"
            "knows": "Carol"
            verifiedBy: Signature
        ]
        """)
        XCTAssertEqual(envelope.treeFormat,
        """
        686d2c59 NODE
            27840350 subj "Alice"
            55560bdf ASSERTION
                7092d620 pred "knows"
                9a771715 obj "Bob"
            71a30690 ASSERTION
                7092d620 pred "knows"
                ad2c454b obj "Carol"
            d575c6a9 ASSERTION
                d59f8c0f pred verifiedBy
                85fa379f obj Signature
        """)
        XCTAssertEqual(envelope.elementsCount, envelope.treeFormat.split(separator: "\n").count)
        XCTAssertEqual(envelope.mermaidFormat,
        """
        graph LR
            1(("686d2c59<br/>NODE"))
            2["27840350<br/>#quot;Alice#quot;"]
            3(["55560bdf<br/>ASSERTION"])
            4["7092d620<br/>#quot;knows#quot;"]
            5["9a771715<br/>#quot;Bob#quot;"]
            6(["71a30690<br/>ASSERTION"])
            7["7092d620<br/>#quot;knows#quot;"]
            8["ad2c454b<br/>#quot;Carol#quot;"]
            9(["d575c6a9<br/>ASSERTION"])
            10[/"d59f8c0f<br/>verifiedBy"/]
            11["85fa379f<br/>Signature"]
            1 -->|subj| 2
            1 --> 3
            3 -->|pred| 4
            3 -->|obj| 5
            1 --> 6
            6 -->|pred| 7
            6 -->|obj| 8
            1 --> 9
            9 -->|pred| 10
            9 -->|obj| 11
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px
            style 6 stroke:red,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:#55f,stroke-width:3.0px
            style 9 stroke:red,stroke-width:3.0px
            style 10 stroke:#55f,stroke-width:3.0px
            style 11 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke:green,stroke-width:2.0px
            linkStyle 3 stroke:#55f,stroke-width:2.0px
            linkStyle 4 stroke-width:2.0px
            linkStyle 5 stroke:green,stroke-width:2.0px
            linkStyle 6 stroke:#55f,stroke-width:2.0px
            linkStyle 7 stroke-width:2.0px
            linkStyle 8 stroke:green,stroke-width:2.0px
            linkStyle 9 stroke:#55f,stroke-width:2.0px
        """)

        // Elided Assertions
        var target = Set<Digest>()
        target.insert(envelope)
        target.insert(envelope.subject)
        let elided = try envelope.elideRevealing(target)
        XCTAssertEqual(elided.format,
        """
        "Alice" [
            ELIDED (3)
        ]
        """)
        XCTAssertEqual(elided.treeFormat,
        """
        686d2c59 NODE
            27840350 subj "Alice"
            55560bdf ELIDED
            71a30690 ELIDED
            d575c6a9 ELIDED
        """)
        XCTAssertEqual(elided.elementsCount, elided.treeFormat.split(separator: "\n").count)
        XCTAssertEqual(elided.mermaidFormat,
        """
        graph LR
            1(("686d2c59<br/>NODE"))
            2["27840350<br/>#quot;Alice#quot;"]
            3{{"55560bdf<br/>ELIDED"}}
            4{{"71a30690<br/>ELIDED"}}
            5{{"d575c6a9<br/>ELIDED"}}
            1 -->|subj| 2
            1 --> 3
            1 --> 4
            1 --> 5
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 4 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 5 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke-width:2.0px
            linkStyle 3 stroke-width:2.0px
        """)
    }

    func testWrapThenSign() throws {
        let envelope = Envelope("Alice")
            .addAssertion("knows", "Bob")
            .addAssertion("knows", "Carol")
            .wrap()
            .sign(with: alicePrivateKeys, randomGenerator: generateFakeRandomNumbers)
        XCTAssertEqual(envelope.format,
        """
        {
            "Alice" [
                "knows": "Bob"
                "knows": "Carol"
            ]
        } [
            verifiedBy: Signature
        ]
        """)
        XCTAssertEqual(envelope.treeFormat,
        """
        df50a73a NODE
            3cc750a3 subj WRAPPED
                c733401e subj NODE
                    27840350 subj "Alice"
                    55560bdf ASSERTION
                        7092d620 pred "knows"
                        9a771715 obj "Bob"
                    71a30690 ASSERTION
                        7092d620 pred "knows"
                        ad2c454b obj "Carol"
            2a079b36 ASSERTION
                d59f8c0f pred verifiedBy
                c690bdf9 obj Signature
        """)
        XCTAssertEqual(envelope.elementsCount, envelope.treeFormat.split(separator: "\n").count)
        XCTAssertEqual(envelope.mermaidFormat,
        #"""
        graph LR
            1(("df50a73a<br/>NODE"))
            2[/"3cc750a3<br/>WRAPPED"\]
            3(("c733401e<br/>NODE"))
            4["27840350<br/>#quot;Alice#quot;"]
            5(["55560bdf<br/>ASSERTION"])
            6["7092d620<br/>#quot;knows#quot;"]
            7["9a771715<br/>#quot;Bob#quot;"]
            8(["71a30690<br/>ASSERTION"])
            9["7092d620<br/>#quot;knows#quot;"]
            10["ad2c454b<br/>#quot;Carol#quot;"]
            11(["2a079b36<br/>ASSERTION"])
            12[/"d59f8c0f<br/>verifiedBy"/]
            13["c690bdf9<br/>Signature"]
            1 -->|subj| 2
            2 -->|subj| 3
            3 -->|subj| 4
            3 --> 5
            5 -->|pred| 6
            5 -->|obj| 7
            3 --> 8
            8 -->|pred| 9
            8 -->|obj| 10
            1 --> 11
            11 -->|pred| 12
            11 -->|obj| 13
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:red,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:red,stroke-width:3.0px
            style 6 stroke:#55f,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:red,stroke-width:3.0px
            style 9 stroke:#55f,stroke-width:3.0px
            style 10 stroke:#55f,stroke-width:3.0px
            style 11 stroke:red,stroke-width:3.0px
            style 12 stroke:#55f,stroke-width:3.0px
            style 13 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke:red,stroke-width:2.0px
            linkStyle 2 stroke:red,stroke-width:2.0px
            linkStyle 3 stroke-width:2.0px
            linkStyle 4 stroke:green,stroke-width:2.0px
            linkStyle 5 stroke:#55f,stroke-width:2.0px
            linkStyle 6 stroke-width:2.0px
            linkStyle 7 stroke:green,stroke-width:2.0px
            linkStyle 8 stroke:#55f,stroke-width:2.0px
            linkStyle 9 stroke-width:2.0px
            linkStyle 10 stroke:green,stroke-width:2.0px
            linkStyle 11 stroke:#55f,stroke-width:2.0px
        """#)
    }
    
    func testEncryptToRecipients() throws {
        // Alice encrypts a message so that it can only be decrypted by Bob or Carol.
        let envelope = try Envelope(plaintextHello)
            .encryptSubject(with: fakeContentKey, testNonce: fakeNonce).checkEncoding()
            .addRecipient(bobPublicKeys, contentKey: fakeContentKey, testKeyMaterial: fakeContentKey, testNonce: fakeNonce).checkEncoding()
            .addRecipient(carolPublicKeys, contentKey: fakeContentKey, testKeyMaterial: fakeContentKey, testNonce: fakeNonce).checkEncoding()
        XCTAssertEqual(envelope.format,
        """
        ENCRYPTED [
            hasRecipient: SealedMessage
            hasRecipient: SealedMessage
        ]
        """)
        XCTAssertEqual(envelope.treeFormat,
        """
        003c3d15 NODE
            886a0c85 subj ENCRYPTED
            9de6ec19 ASSERTION
                f4af70d6 pred hasRecipient
                0eef002e obj SealedMessage
            b05bfebd ASSERTION
                f4af70d6 pred hasRecipient
                b65acdd8 obj SealedMessage
        """)
        XCTAssertEqual(envelope.elementsCount, envelope.treeFormat.split(separator: "\n").count)
        XCTAssertEqual(envelope.mermaidFormat,
        """
        graph LR
            1(("003c3d15<br/>NODE"))
            2>"886a0c85<br/>ENCRYPTED"]
            3(["9de6ec19<br/>ASSERTION"])
            4[/"f4af70d6<br/>hasRecipient"/]
            5["0eef002e<br/>SealedMessage"]
            6(["b05bfebd<br/>ASSERTION"])
            7[/"f4af70d6<br/>hasRecipient"/]
            8["b65acdd8<br/>SealedMessage"]
            1 -->|subj| 2
            1 --> 3
            3 -->|pred| 4
            3 -->|obj| 5
            1 --> 6
            6 -->|pred| 7
            6 -->|obj| 8
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px
            style 6 stroke:red,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke:green,stroke-width:2.0px
            linkStyle 3 stroke:#55f,stroke-width:2.0px
            linkStyle 4 stroke-width:2.0px
            linkStyle 5 stroke:green,stroke-width:2.0px
            linkStyle 6 stroke:#55f,stroke-width:2.0px
        """)
    }

    func testAssertionPositions() throws {
        let predicate = Envelope("predicate")
            .addAssertion("predicate-predicate", "predicate-object")
        let object = Envelope("object")
            .addAssertion("object-predicate", "object-object")
        let envelope = try Envelope("subject")
            .addAssertion(predicate, object)
            .checkEncoding()
        XCTAssertEqual(envelope.format,
        """
        "subject" [
            "predicate" [
                "predicate-predicate": "predicate-object"
            ]
            : "object" [
                "object-predicate": "object-object"
            ]
        ]
        """)
        XCTAssertEqual(envelope.treeFormat,
        """
        6e23f835 NODE
            0eb38394 subj "subject"
            174a3f14 ASSERTION
                e167f27b pred NODE
                    c392f840 subj "predicate"
                    9ddb7a7f ASSERTION
                        7bf4a146 pred "predicate-predicate"
                        b5f234ee obj "predicate-object"
                0dcae47d obj NODE
                    b6417f1a subj "object"
                    d1d716fd ASSERTION
                        f24609db pred "object-predicate"
                        5c7b47fb obj "object-object"
        """)
        XCTAssertEqual(envelope.elementsCount, envelope.treeFormat.split(separator: "\n").count)
        XCTAssertEqual(envelope.mermaidFormat,
        """
        graph LR
            1(("6e23f835<br/>NODE"))
            2["0eb38394<br/>#quot;subject#quot;"]
            3(["174a3f14<br/>ASSERTION"])
            4(("e167f27b<br/>NODE"))
            5["c392f840<br/>#quot;predicate#quot;"]
            6(["9ddb7a7f<br/>ASSERTION"])
            7["7bf4a146<br/>#quot;predicate-predicate#quot;"]
            8["b5f234ee<br/>#quot;predicate-object#quot;"]
            9(("0dcae47d<br/>NODE"))
            10["b6417f1a<br/>#quot;object#quot;"]
            11(["d1d716fd<br/>ASSERTION"])
            12["f24609db<br/>#quot;object-predicate#quot;"]
            13["5c7b47fb<br/>#quot;object-object#quot;"]
            1 -->|subj| 2
            1 --> 3
            3 -->|pred| 4
            4 -->|subj| 5
            4 --> 6
            6 -->|pred| 7
            6 -->|obj| 8
            3 -->|obj| 9
            9 -->|subj| 10
            9 --> 11
            11 -->|pred| 12
            11 -->|obj| 13
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:red,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px
            style 6 stroke:red,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:#55f,stroke-width:3.0px
            style 9 stroke:red,stroke-width:3.0px
            style 10 stroke:#55f,stroke-width:3.0px
            style 11 stroke:red,stroke-width:3.0px
            style 12 stroke:#55f,stroke-width:3.0px
            style 13 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke:green,stroke-width:2.0px
            linkStyle 3 stroke:red,stroke-width:2.0px
            linkStyle 4 stroke-width:2.0px
            linkStyle 5 stroke:green,stroke-width:2.0px
            linkStyle 6 stroke:#55f,stroke-width:2.0px
            linkStyle 7 stroke:#55f,stroke-width:2.0px
            linkStyle 8 stroke:red,stroke-width:2.0px
            linkStyle 9 stroke-width:2.0px
            linkStyle 10 stroke:green,stroke-width:2.0px
            linkStyle 11 stroke:#55f,stroke-width:2.0px
        """)
    }

    func testComplexMetadata() throws {
        // Assertions made about an CID are considered part of a distributed set. Which
        // assertions are returned depends on who resolves the CID and when it is
        // resolved. In other words, the referent of a CID is mutable.
        let author = try Envelope(CID(‡"9c747ace78a4c826392510dd6285551e7df4e5164729a1b36198e56e017666c8")!)
            .addAssertion(.dereferenceVia, "LibraryOfCongress")
            .addAssertion(.hasName, "Ayn Rand")
            .checkEncoding()

        // Assertions made on a literal value are considered part of the same set of
        // assertions made on the digest of that value.
        let name_en = Envelope("Atlas Shrugged")
            .addAssertion(.language, "en")

        let name_es = Envelope("La rebelión de Atlas")
            .addAssertion(.language, "es")

        let work = try Envelope(CID(‡"7fb90a9d96c07f39f75ea6acf392d79f241fac4ec0be2120f7c82489711e3e80")!)
            .addAssertion(.isA, "novel")
            .addAssertion("isbn", "9780451191144")
            .addAssertion("author", author)
            .addAssertion(.dereferenceVia, "LibraryOfCongress")
            .addAssertion(.hasName, name_en)
            .addAssertion(.hasName, name_es)
            .checkEncoding()

        let bookData = "This is the entire book “Atlas Shrugged” in EPUB format."
        // Assertions made on a digest are considered associated with that specific binary
        // object and no other. In other words, the referent of a Digest is immutable.
        let bookMetadata = try Envelope(Digest(bookData))
            .addAssertion("work", work)
            .addAssertion("format", "EPUB")
            .addAssertion(.dereferenceVia, "IPFS")
            .checkEncoding()
        
        XCTAssertEqual(bookMetadata.format,
        """
        Digest(e8aa201d) [
            "format": "EPUB"
            "work": CID(7fb90a9d) [
                "author": CID(9c747ace) [
                    dereferenceVia: "LibraryOfCongress"
                    hasName: "Ayn Rand"
                ]
                "isbn": "9780451191144"
                dereferenceVia: "LibraryOfCongress"
                hasName: "Atlas Shrugged" [
                    language: "en"
                ]
                hasName: "La rebelión de Atlas" [
                    language: "es"
                ]
                isA: "novel"
            ]
            dereferenceVia: "IPFS"
        ]
        """)
        XCTAssertEqual(bookMetadata.treeFormat,
        """
        72fdea85 NODE
            ec067552 subj Digest(e8aa201d)
            71573ec4 ASSERTION
                f191c6ea pred dereferenceVia
                920da73e obj "IPFS"
            c2856abd ASSERTION
                48bb1df6 pred "format"
                9afbbb54 obj "EPUB"
            eaa72721 ASSERTION
                8ea19b98 pred "work"
                f70de543 obj NODE
                    734250ee subj CID(7fb90a9d)
                    049bbd66 ASSERTION
                        f191c6ea pred dereferenceVia
                        b4580455 obj "LibraryOfCongress"
                    1f908002 ASSERTION
                        d8c1566f pred "author"
                        b51b535c obj NODE
                            306a5d76 subj CID(9c747ace)
                            049bbd66 ASSERTION
                                f191c6ea pred dereferenceVia
                                b4580455 obj "LibraryOfCongress"
                            e7441f7c ASSERTION
                                bf166e5d pred hasName
                                5bb41313 obj "Ayn Rand"
                    91ec8590 ASSERTION
                        bf166e5d pred hasName
                        59cd2799 obj NODE
                            9d76964a subj "Atlas Shrugged"
                            02d3e92e ASSERTION
                                556c14a4 pred language
                                409b5893 obj "en"
                    c1029b07 ASSERTION
                        8982354d pred isA
                        9066de8c obj "novel"
                    c1785e1a ASSERTION
                        bf166e5d pred hasName
                        0412cf19 obj NODE
                            5a42d004 subj "La rebelión de Atlas"
                            a5243b41 ASSERTION
                                556c14a4 pred language
                                dd2f866d obj "es"
                    efb00f5e ASSERTION
                        b95d2849 pred "isbn"
                        2e8d4edd obj "9780451191144"
        """)
        XCTAssertEqual(bookMetadata.elementsCount, bookMetadata.treeFormat.split(separator: "\n").count)
        XCTAssertEqual(bookMetadata.mermaidFormat,
        """
        graph LR
            1(("72fdea85<br/>NODE"))
            2["ec067552<br/>Digest(e8aa201d)"]
            3(["71573ec4<br/>ASSERTION"])
            4[/"f191c6ea<br/>dereferenceVia"/]
            5["920da73e<br/>#quot;IPFS#quot;"]
            6(["c2856abd<br/>ASSERTION"])
            7["48bb1df6<br/>#quot;format#quot;"]
            8["9afbbb54<br/>#quot;EPUB#quot;"]
            9(["eaa72721<br/>ASSERTION"])
            10["8ea19b98<br/>#quot;work#quot;"]
            11(("f70de543<br/>NODE"))
            12["734250ee<br/>CID(7fb90a9d)"]
            13(["049bbd66<br/>ASSERTION"])
            14[/"f191c6ea<br/>dereferenceVia"/]
            15["b4580455<br/>#quot;LibraryOfCongress#quot;"]
            16(["1f908002<br/>ASSERTION"])
            17["d8c1566f<br/>#quot;author#quot;"]
            18(("b51b535c<br/>NODE"))
            19["306a5d76<br/>CID(9c747ace)"]
            20(["049bbd66<br/>ASSERTION"])
            21[/"f191c6ea<br/>dereferenceVia"/]
            22["b4580455<br/>#quot;LibraryOfCongress#quot;"]
            23(["e7441f7c<br/>ASSERTION"])
            24[/"bf166e5d<br/>hasName"/]
            25["5bb41313<br/>#quot;Ayn Rand#quot;"]
            26(["91ec8590<br/>ASSERTION"])
            27[/"bf166e5d<br/>hasName"/]
            28(("59cd2799<br/>NODE"))
            29["9d76964a<br/>#quot;Atlas Shrugged#quot;"]
            30(["02d3e92e<br/>ASSERTION"])
            31[/"556c14a4<br/>language"/]
            32["409b5893<br/>#quot;en#quot;"]
            33(["c1029b07<br/>ASSERTION"])
            34[/"8982354d<br/>isA"/]
            35["9066de8c<br/>#quot;novel#quot;"]
            36(["c1785e1a<br/>ASSERTION"])
            37[/"bf166e5d<br/>hasName"/]
            38(("0412cf19<br/>NODE"))
            39["5a42d004<br/>#quot;La rebelión de Atlas#quot;"]
            40(["a5243b41<br/>ASSERTION"])
            41[/"556c14a4<br/>language"/]
            42["dd2f866d<br/>#quot;es#quot;"]
            43(["efb00f5e<br/>ASSERTION"])
            44["b95d2849<br/>#quot;isbn#quot;"]
            45["2e8d4edd<br/>#quot;9780451191144#quot;"]
            1 -->|subj| 2
            1 --> 3
            3 -->|pred| 4
            3 -->|obj| 5
            1 --> 6
            6 -->|pred| 7
            6 -->|obj| 8
            1 --> 9
            9 -->|pred| 10
            9 -->|obj| 11
            11 -->|subj| 12
            11 --> 13
            13 -->|pred| 14
            13 -->|obj| 15
            11 --> 16
            16 -->|pred| 17
            16 -->|obj| 18
            18 -->|subj| 19
            18 --> 20
            20 -->|pred| 21
            20 -->|obj| 22
            18 --> 23
            23 -->|pred| 24
            23 -->|obj| 25
            11 --> 26
            26 -->|pred| 27
            26 -->|obj| 28
            28 -->|subj| 29
            28 --> 30
            30 -->|pred| 31
            30 -->|obj| 32
            11 --> 33
            33 -->|pred| 34
            33 -->|obj| 35
            11 --> 36
            36 -->|pred| 37
            36 -->|obj| 38
            38 -->|subj| 39
            38 --> 40
            40 -->|pred| 41
            40 -->|obj| 42
            11 --> 43
            43 -->|pred| 44
            43 -->|obj| 45
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px
            style 6 stroke:red,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:#55f,stroke-width:3.0px
            style 9 stroke:red,stroke-width:3.0px
            style 10 stroke:#55f,stroke-width:3.0px
            style 11 stroke:red,stroke-width:3.0px
            style 12 stroke:#55f,stroke-width:3.0px
            style 13 stroke:red,stroke-width:3.0px
            style 14 stroke:#55f,stroke-width:3.0px
            style 15 stroke:#55f,stroke-width:3.0px
            style 16 stroke:red,stroke-width:3.0px
            style 17 stroke:#55f,stroke-width:3.0px
            style 18 stroke:red,stroke-width:3.0px
            style 19 stroke:#55f,stroke-width:3.0px
            style 20 stroke:red,stroke-width:3.0px
            style 21 stroke:#55f,stroke-width:3.0px
            style 22 stroke:#55f,stroke-width:3.0px
            style 23 stroke:red,stroke-width:3.0px
            style 24 stroke:#55f,stroke-width:3.0px
            style 25 stroke:#55f,stroke-width:3.0px
            style 26 stroke:red,stroke-width:3.0px
            style 27 stroke:#55f,stroke-width:3.0px
            style 28 stroke:red,stroke-width:3.0px
            style 29 stroke:#55f,stroke-width:3.0px
            style 30 stroke:red,stroke-width:3.0px
            style 31 stroke:#55f,stroke-width:3.0px
            style 32 stroke:#55f,stroke-width:3.0px
            style 33 stroke:red,stroke-width:3.0px
            style 34 stroke:#55f,stroke-width:3.0px
            style 35 stroke:#55f,stroke-width:3.0px
            style 36 stroke:red,stroke-width:3.0px
            style 37 stroke:#55f,stroke-width:3.0px
            style 38 stroke:red,stroke-width:3.0px
            style 39 stroke:#55f,stroke-width:3.0px
            style 40 stroke:red,stroke-width:3.0px
            style 41 stroke:#55f,stroke-width:3.0px
            style 42 stroke:#55f,stroke-width:3.0px
            style 43 stroke:red,stroke-width:3.0px
            style 44 stroke:#55f,stroke-width:3.0px
            style 45 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke:green,stroke-width:2.0px
            linkStyle 3 stroke:#55f,stroke-width:2.0px
            linkStyle 4 stroke-width:2.0px
            linkStyle 5 stroke:green,stroke-width:2.0px
            linkStyle 6 stroke:#55f,stroke-width:2.0px
            linkStyle 7 stroke-width:2.0px
            linkStyle 8 stroke:green,stroke-width:2.0px
            linkStyle 9 stroke:#55f,stroke-width:2.0px
            linkStyle 10 stroke:red,stroke-width:2.0px
            linkStyle 11 stroke-width:2.0px
            linkStyle 12 stroke:green,stroke-width:2.0px
            linkStyle 13 stroke:#55f,stroke-width:2.0px
            linkStyle 14 stroke-width:2.0px
            linkStyle 15 stroke:green,stroke-width:2.0px
            linkStyle 16 stroke:#55f,stroke-width:2.0px
            linkStyle 17 stroke:red,stroke-width:2.0px
            linkStyle 18 stroke-width:2.0px
            linkStyle 19 stroke:green,stroke-width:2.0px
            linkStyle 20 stroke:#55f,stroke-width:2.0px
            linkStyle 21 stroke-width:2.0px
            linkStyle 22 stroke:green,stroke-width:2.0px
            linkStyle 23 stroke:#55f,stroke-width:2.0px
            linkStyle 24 stroke-width:2.0px
            linkStyle 25 stroke:green,stroke-width:2.0px
            linkStyle 26 stroke:#55f,stroke-width:2.0px
            linkStyle 27 stroke:red,stroke-width:2.0px
            linkStyle 28 stroke-width:2.0px
            linkStyle 29 stroke:green,stroke-width:2.0px
            linkStyle 30 stroke:#55f,stroke-width:2.0px
            linkStyle 31 stroke-width:2.0px
            linkStyle 32 stroke:green,stroke-width:2.0px
            linkStyle 33 stroke:#55f,stroke-width:2.0px
            linkStyle 34 stroke-width:2.0px
            linkStyle 35 stroke:green,stroke-width:2.0px
            linkStyle 36 stroke:#55f,stroke-width:2.0px
            linkStyle 37 stroke:red,stroke-width:2.0px
            linkStyle 38 stroke-width:2.0px
            linkStyle 39 stroke:green,stroke-width:2.0px
            linkStyle 40 stroke:#55f,stroke-width:2.0px
            linkStyle 41 stroke-width:2.0px
            linkStyle 42 stroke:green,stroke-width:2.0px
            linkStyle 43 stroke:#55f,stroke-width:2.0px
        """)
    }

    static let credential = try! Envelope(CID(‡"4676635a6e6068c2ef3ffd8ff726dd401fd341036e920f136a1d8af5e829496d")!)
        .addAssertion(.isA, "Certificate of Completion")
        .addAssertion(.issuer, "Example Electrical Engineering Board")
        .addAssertion(.controller, "Example Electrical Engineering Board")
        .addAssertion("firstName", "James")
        .addAssertion("lastName", "Maxwell")
        .addAssertion("issueDate", Date(iso8601: "2020-01-01"))
        .addAssertion("expirationDate", Date(iso8601: "2028-01-01"))
        .addAssertion("photo", "This is James Maxwell's photo.")
        .addAssertion("certificateNumber", "123-456-789")
        .addAssertion("subject", "RF and Microwave Engineering")
        .addAssertion("continuingEducationUnits", 1.5)
        .addAssertion("professionalDevelopmentHours", 15)
        .addAssertion("topics", ["Subject 1", "Subject 2"])
        .wrap()
        .sign(with: alicePrivateKeys, randomGenerator: generateFakeRandomNumbers)
        .addAssertion(.note, "Signed by Example Electrical Engineering Board")
        .checkEncoding()

    func testCredential() throws {
        XCTAssertEqual(Self.credential.format,
        """
        {
            CID(4676635a) [
                "certificateNumber": "123-456-789"
                "continuingEducationUnits": 1.5
                "expirationDate": 2028-01-01
                "firstName": "James"
                "issueDate": 2020-01-01
                "lastName": "Maxwell"
                "photo": "This is James Maxwell's photo."
                "professionalDevelopmentHours": 15
                "subject": "RF and Microwave Engineering"
                "topics": CBOR
                controller: "Example Electrical Engineering Board"
                isA: "Certificate of Completion"
                issuer: "Example Electrical Engineering Board"
            ]
        } [
            note: "Signed by Example Electrical Engineering Board"
            verifiedBy: Signature
        ]
        """)
        XCTAssertEqual(Self.credential.treeFormat,
        """
        e9bce5a5 NODE
            dbd70e79 subj WRAPPED
                b750a45f subj NODE
                    bdd347d4 subj CID(4676635a)
                    0536afd8 ASSERTION
                        a791d0c7 pred "photo"
                        9e77bb70 obj "This is James Maxwell's photo."
                    1d598c65 ASSERTION
                        eb62836d pred "lastName"
                        997a0e2d obj "Maxwell"
                    34f8f7d3 ASSERTION
                        b1e12d58 pred "issueDate"
                        2511c0df obj 2020-01-01
                    3d00d64f ASSERTION
                        2f9bee2f pred controller
                        4035b4bd obj "Example Electrical Engineering Board"
                    44736993 ASSERTION
                        05651934 pred "topics"
                        264aec65 obj CBOR
                    46d6cfea ASSERTION
                        8982354d pred isA
                        112e2cdb obj "Certificate of Completion"
                    4a69fca3 ASSERTION
                        b6d5ea01 pred "continuingEducationUnits"
                        02a61366 obj 1.5
                    5545f6e2 ASSERTION
                        954c8356 pred issuer
                        4035b4bd obj "Example Electrical Engineering Board"
                    61689bb7 ASSERTION
                        e6c2932d pred "expirationDate"
                        b91eea18 obj 2028-01-01
                    a0274d1c ASSERTION
                        62c0a26e pred "certificateNumber"
                        ac0b465a obj "123-456-789"
                    d4f678a9 ASSERTION
                        c4d5323d pred "firstName"
                        bfe9d39b obj "James"
                    e0070876 ASSERTION
                        0eb38394 pred "subject"
                        b059b0f2 obj "RF and Microwave Engineering"
                    e96b24d9 ASSERTION
                        c8c1a6dd pred "professionalDevelopmentHours"
                        0bf6b955 obj 15
            afe231cc ASSERTION
                61fb6a6b pred note
                f4bf011f obj "Signed by Example Electrical Engineering Board"
            e0b4f467 ASSERTION
                d59f8c0f pred verifiedBy
                7f1fd17b obj Signature
        """)
        XCTAssertEqual(Self.credential.elementsCount, Self.credential.treeFormat.split(separator: "\n").count)
        XCTAssertEqual(Self.credential.mermaidFormat,
        #"""
        graph LR
            1(("e9bce5a5<br/>NODE"))
            2[/"dbd70e79<br/>WRAPPED"\]
            3(("b750a45f<br/>NODE"))
            4["bdd347d4<br/>CID(4676635a)"]
            5(["0536afd8<br/>ASSERTION"])
            6["a791d0c7<br/>#quot;photo#quot;"]
            7["9e77bb70<br/>#quot;This is James Maxwell's photo.#quot;"]
            8(["1d598c65<br/>ASSERTION"])
            9["eb62836d<br/>#quot;lastName#quot;"]
            10["997a0e2d<br/>#quot;Maxwell#quot;"]
            11(["34f8f7d3<br/>ASSERTION"])
            12["b1e12d58<br/>#quot;issueDate#quot;"]
            13["2511c0df<br/>2020-01-01"]
            14(["3d00d64f<br/>ASSERTION"])
            15[/"2f9bee2f<br/>controller"/]
            16["4035b4bd<br/>#quot;Example Electrical Engineering Board#quot;"]
            17(["44736993<br/>ASSERTION"])
            18["05651934<br/>#quot;topics#quot;"]
            19["264aec65<br/>CBOR"]
            20(["46d6cfea<br/>ASSERTION"])
            21[/"8982354d<br/>isA"/]
            22["112e2cdb<br/>#quot;Certificate of Completion#quot;"]
            23(["4a69fca3<br/>ASSERTION"])
            24["b6d5ea01<br/>#quot;continuingEducationUnits#quot;"]
            25["02a61366<br/>1.5"]
            26(["5545f6e2<br/>ASSERTION"])
            27[/"954c8356<br/>issuer"/]
            28["4035b4bd<br/>#quot;Example Electrical Engineering Board#quot;"]
            29(["61689bb7<br/>ASSERTION"])
            30["e6c2932d<br/>#quot;expirationDate#quot;"]
            31["b91eea18<br/>2028-01-01"]
            32(["a0274d1c<br/>ASSERTION"])
            33["62c0a26e<br/>#quot;certificateNumber#quot;"]
            34["ac0b465a<br/>#quot;123-456-789#quot;"]
            35(["d4f678a9<br/>ASSERTION"])
            36["c4d5323d<br/>#quot;firstName#quot;"]
            37["bfe9d39b<br/>#quot;James#quot;"]
            38(["e0070876<br/>ASSERTION"])
            39["0eb38394<br/>#quot;subject#quot;"]
            40["b059b0f2<br/>#quot;RF and Microwave Engineering#quot;"]
            41(["e96b24d9<br/>ASSERTION"])
            42["c8c1a6dd<br/>#quot;professionalDevelopmentHours#quot;"]
            43["0bf6b955<br/>15"]
            44(["afe231cc<br/>ASSERTION"])
            45[/"61fb6a6b<br/>note"/]
            46["f4bf011f<br/>#quot;Signed by Example Electrical Engineering Board#quot;"]
            47(["e0b4f467<br/>ASSERTION"])
            48[/"d59f8c0f<br/>verifiedBy"/]
            49["7f1fd17b<br/>Signature"]
            1 -->|subj| 2
            2 -->|subj| 3
            3 -->|subj| 4
            3 --> 5
            5 -->|pred| 6
            5 -->|obj| 7
            3 --> 8
            8 -->|pred| 9
            8 -->|obj| 10
            3 --> 11
            11 -->|pred| 12
            11 -->|obj| 13
            3 --> 14
            14 -->|pred| 15
            14 -->|obj| 16
            3 --> 17
            17 -->|pred| 18
            17 -->|obj| 19
            3 --> 20
            20 -->|pred| 21
            20 -->|obj| 22
            3 --> 23
            23 -->|pred| 24
            23 -->|obj| 25
            3 --> 26
            26 -->|pred| 27
            26 -->|obj| 28
            3 --> 29
            29 -->|pred| 30
            29 -->|obj| 31
            3 --> 32
            32 -->|pred| 33
            32 -->|obj| 34
            3 --> 35
            35 -->|pred| 36
            35 -->|obj| 37
            3 --> 38
            38 -->|pred| 39
            38 -->|obj| 40
            3 --> 41
            41 -->|pred| 42
            41 -->|obj| 43
            1 --> 44
            44 -->|pred| 45
            44 -->|obj| 46
            1 --> 47
            47 -->|pred| 48
            47 -->|obj| 49
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:red,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:red,stroke-width:3.0px
            style 6 stroke:#55f,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:red,stroke-width:3.0px
            style 9 stroke:#55f,stroke-width:3.0px
            style 10 stroke:#55f,stroke-width:3.0px
            style 11 stroke:red,stroke-width:3.0px
            style 12 stroke:#55f,stroke-width:3.0px
            style 13 stroke:#55f,stroke-width:3.0px
            style 14 stroke:red,stroke-width:3.0px
            style 15 stroke:#55f,stroke-width:3.0px
            style 16 stroke:#55f,stroke-width:3.0px
            style 17 stroke:red,stroke-width:3.0px
            style 18 stroke:#55f,stroke-width:3.0px
            style 19 stroke:#55f,stroke-width:3.0px
            style 20 stroke:red,stroke-width:3.0px
            style 21 stroke:#55f,stroke-width:3.0px
            style 22 stroke:#55f,stroke-width:3.0px
            style 23 stroke:red,stroke-width:3.0px
            style 24 stroke:#55f,stroke-width:3.0px
            style 25 stroke:#55f,stroke-width:3.0px
            style 26 stroke:red,stroke-width:3.0px
            style 27 stroke:#55f,stroke-width:3.0px
            style 28 stroke:#55f,stroke-width:3.0px
            style 29 stroke:red,stroke-width:3.0px
            style 30 stroke:#55f,stroke-width:3.0px
            style 31 stroke:#55f,stroke-width:3.0px
            style 32 stroke:red,stroke-width:3.0px
            style 33 stroke:#55f,stroke-width:3.0px
            style 34 stroke:#55f,stroke-width:3.0px
            style 35 stroke:red,stroke-width:3.0px
            style 36 stroke:#55f,stroke-width:3.0px
            style 37 stroke:#55f,stroke-width:3.0px
            style 38 stroke:red,stroke-width:3.0px
            style 39 stroke:#55f,stroke-width:3.0px
            style 40 stroke:#55f,stroke-width:3.0px
            style 41 stroke:red,stroke-width:3.0px
            style 42 stroke:#55f,stroke-width:3.0px
            style 43 stroke:#55f,stroke-width:3.0px
            style 44 stroke:red,stroke-width:3.0px
            style 45 stroke:#55f,stroke-width:3.0px
            style 46 stroke:#55f,stroke-width:3.0px
            style 47 stroke:red,stroke-width:3.0px
            style 48 stroke:#55f,stroke-width:3.0px
            style 49 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke:red,stroke-width:2.0px
            linkStyle 2 stroke:red,stroke-width:2.0px
            linkStyle 3 stroke-width:2.0px
            linkStyle 4 stroke:green,stroke-width:2.0px
            linkStyle 5 stroke:#55f,stroke-width:2.0px
            linkStyle 6 stroke-width:2.0px
            linkStyle 7 stroke:green,stroke-width:2.0px
            linkStyle 8 stroke:#55f,stroke-width:2.0px
            linkStyle 9 stroke-width:2.0px
            linkStyle 10 stroke:green,stroke-width:2.0px
            linkStyle 11 stroke:#55f,stroke-width:2.0px
            linkStyle 12 stroke-width:2.0px
            linkStyle 13 stroke:green,stroke-width:2.0px
            linkStyle 14 stroke:#55f,stroke-width:2.0px
            linkStyle 15 stroke-width:2.0px
            linkStyle 16 stroke:green,stroke-width:2.0px
            linkStyle 17 stroke:#55f,stroke-width:2.0px
            linkStyle 18 stroke-width:2.0px
            linkStyle 19 stroke:green,stroke-width:2.0px
            linkStyle 20 stroke:#55f,stroke-width:2.0px
            linkStyle 21 stroke-width:2.0px
            linkStyle 22 stroke:green,stroke-width:2.0px
            linkStyle 23 stroke:#55f,stroke-width:2.0px
            linkStyle 24 stroke-width:2.0px
            linkStyle 25 stroke:green,stroke-width:2.0px
            linkStyle 26 stroke:#55f,stroke-width:2.0px
            linkStyle 27 stroke-width:2.0px
            linkStyle 28 stroke:green,stroke-width:2.0px
            linkStyle 29 stroke:#55f,stroke-width:2.0px
            linkStyle 30 stroke-width:2.0px
            linkStyle 31 stroke:green,stroke-width:2.0px
            linkStyle 32 stroke:#55f,stroke-width:2.0px
            linkStyle 33 stroke-width:2.0px
            linkStyle 34 stroke:green,stroke-width:2.0px
            linkStyle 35 stroke:#55f,stroke-width:2.0px
            linkStyle 36 stroke-width:2.0px
            linkStyle 37 stroke:green,stroke-width:2.0px
            linkStyle 38 stroke:#55f,stroke-width:2.0px
            linkStyle 39 stroke-width:2.0px
            linkStyle 40 stroke:green,stroke-width:2.0px
            linkStyle 41 stroke:#55f,stroke-width:2.0px
            linkStyle 42 stroke-width:2.0px
            linkStyle 43 stroke:green,stroke-width:2.0px
            linkStyle 44 stroke:#55f,stroke-width:2.0px
            linkStyle 45 stroke-width:2.0px
            linkStyle 46 stroke:green,stroke-width:2.0px
            linkStyle 47 stroke:#55f,stroke-width:2.0px
        """#)
    }
    
    func testRedactedCredential() throws {
        let credential = Self.credential
        var target: Set<Digest> = []
        target.insert(credential)
        for assertion in credential.assertions {
            target.insert(assertion.deepDigests)
        }
        target.insert(credential.subject)
        let content = try credential.subject.unwrap()
        target.insert(content)
        target.insert(content.subject)
        target.insert(try content.assertion(withPredicate: "firstName").shallowDigests)
        target.insert(try content.assertion(withPredicate: "lastName").shallowDigests)
        target.insert(try content.assertion(withPredicate: .isA).shallowDigests)
        target.insert(try content.assertion(withPredicate: .issuer).shallowDigests)
        target.insert(try content.assertion(withPredicate: "subject").shallowDigests)
        target.insert(try content.assertion(withPredicate: "expirationDate").shallowDigests)
        let redactedCredential = try credential.elideRevealing(target)
        let warranty = try redactedCredential
            .wrap()
            .addAssertion("employeeHiredDate", Date(iso8601: "2022-01-01"))
            .addAssertion("employeeStatus", "active")
            .wrap()
            .addAssertion(.note, "Signed by Employer Corp.")
            .sign(with: bobPrivateKeys, randomGenerator: generateFakeRandomNumbers)
            .checkEncoding()
        XCTAssertEqual(warranty.format,
        """
        {
            {
                {
                    CID(4676635a) [
                        "expirationDate": 2028-01-01
                        "firstName": "James"
                        "lastName": "Maxwell"
                        "subject": "RF and Microwave Engineering"
                        isA: "Certificate of Completion"
                        issuer: "Example Electrical Engineering Board"
                        ELIDED (7)
                    ]
                } [
                    note: "Signed by Example Electrical Engineering Board"
                    verifiedBy: Signature
                ]
            } [
                "employeeHiredDate": 2022-01-01
                "employeeStatus": "active"
            ]
        } [
            note: "Signed by Employer Corp."
            verifiedBy: Signature
        ]
        """)
        XCTAssertEqual(warranty.treeFormat,
        """
        d72fefb6 NODE
            75f35220 subj WRAPPED
                9a57fbda subj NODE
                    bd7d68b8 subj WRAPPED
                        e9bce5a5 subj NODE
                            dbd70e79 subj WRAPPED
                                b750a45f subj NODE
                                    bdd347d4 subj CID(4676635a)
                                    0536afd8 ELIDED
                                    1d598c65 ASSERTION
                                        eb62836d pred "lastName"
                                        997a0e2d obj "Maxwell"
                                    34f8f7d3 ELIDED
                                    3d00d64f ELIDED
                                    44736993 ELIDED
                                    46d6cfea ASSERTION
                                        8982354d pred isA
                                        112e2cdb obj "Certificate of Completion"
                                    4a69fca3 ELIDED
                                    5545f6e2 ASSERTION
                                        954c8356 pred issuer
                                        4035b4bd obj "Example Electrical Engineering Board"
                                    61689bb7 ASSERTION
                                        e6c2932d pred "expirationDate"
                                        b91eea18 obj 2028-01-01
                                    a0274d1c ELIDED
                                    d4f678a9 ASSERTION
                                        c4d5323d pred "firstName"
                                        bfe9d39b obj "James"
                                    e0070876 ASSERTION
                                        0eb38394 pred "subject"
                                        b059b0f2 obj "RF and Microwave Engineering"
                                    e96b24d9 ELIDED
                            afe231cc ASSERTION
                                61fb6a6b pred note
                                f4bf011f obj "Signed by Example Electrical Engineering Board"
                            e0b4f467 ASSERTION
                                d59f8c0f pred verifiedBy
                                7f1fd17b obj Signature
                    310b027f ASSERTION
                        f942ee55 pred "employeeStatus"
                        919eb85d obj "active"
                    5901b070 ASSERTION
                        134a1704 pred "employeeHiredDate"
                        24c173c5 obj 2022-01-01
            648b2cc3 ASSERTION
                61fb6a6b pred note
                46f4bfd7 obj "Signed by Employer Corp."
            f23b1fe1 ASSERTION
                d59f8c0f pred verifiedBy
                af01dd65 obj Signature
        """)
        XCTAssertEqual(warranty.elementsCount, warranty.treeFormat.split(separator: "\n").count)
        XCTAssertEqual(warranty.mermaidFormat,
        #"""
        graph LR
            1(("d72fefb6<br/>NODE"))
            2[/"75f35220<br/>WRAPPED"\]
            3(("9a57fbda<br/>NODE"))
            4[/"bd7d68b8<br/>WRAPPED"\]
            5(("e9bce5a5<br/>NODE"))
            6[/"dbd70e79<br/>WRAPPED"\]
            7(("b750a45f<br/>NODE"))
            8["bdd347d4<br/>CID(4676635a)"]
            9{{"0536afd8<br/>ELIDED"}}
            10(["1d598c65<br/>ASSERTION"])
            11["eb62836d<br/>#quot;lastName#quot;"]
            12["997a0e2d<br/>#quot;Maxwell#quot;"]
            13{{"34f8f7d3<br/>ELIDED"}}
            14{{"3d00d64f<br/>ELIDED"}}
            15{{"44736993<br/>ELIDED"}}
            16(["46d6cfea<br/>ASSERTION"])
            17[/"8982354d<br/>isA"/]
            18["112e2cdb<br/>#quot;Certificate of Completion#quot;"]
            19{{"4a69fca3<br/>ELIDED"}}
            20(["5545f6e2<br/>ASSERTION"])
            21[/"954c8356<br/>issuer"/]
            22["4035b4bd<br/>#quot;Example Electrical Engineering Board#quot;"]
            23(["61689bb7<br/>ASSERTION"])
            24["e6c2932d<br/>#quot;expirationDate#quot;"]
            25["b91eea18<br/>2028-01-01"]
            26{{"a0274d1c<br/>ELIDED"}}
            27(["d4f678a9<br/>ASSERTION"])
            28["c4d5323d<br/>#quot;firstName#quot;"]
            29["bfe9d39b<br/>#quot;James#quot;"]
            30(["e0070876<br/>ASSERTION"])
            31["0eb38394<br/>#quot;subject#quot;"]
            32["b059b0f2<br/>#quot;RF and Microwave Engineering#quot;"]
            33{{"e96b24d9<br/>ELIDED"}}
            34(["afe231cc<br/>ASSERTION"])
            35[/"61fb6a6b<br/>note"/]
            36["f4bf011f<br/>#quot;Signed by Example Electrical Engineering Board#quot;"]
            37(["e0b4f467<br/>ASSERTION"])
            38[/"d59f8c0f<br/>verifiedBy"/]
            39["7f1fd17b<br/>Signature"]
            40(["310b027f<br/>ASSERTION"])
            41["f942ee55<br/>#quot;employeeStatus#quot;"]
            42["919eb85d<br/>#quot;active#quot;"]
            43(["5901b070<br/>ASSERTION"])
            44["134a1704<br/>#quot;employeeHiredDate#quot;"]
            45["24c173c5<br/>2022-01-01"]
            46(["648b2cc3<br/>ASSERTION"])
            47[/"61fb6a6b<br/>note"/]
            48["46f4bfd7<br/>#quot;Signed by Employer Corp.#quot;"]
            49(["f23b1fe1<br/>ASSERTION"])
            50[/"d59f8c0f<br/>verifiedBy"/]
            51["af01dd65<br/>Signature"]
            1 -->|subj| 2
            2 -->|subj| 3
            3 -->|subj| 4
            4 -->|subj| 5
            5 -->|subj| 6
            6 -->|subj| 7
            7 -->|subj| 8
            7 --> 9
            7 --> 10
            10 -->|pred| 11
            10 -->|obj| 12
            7 --> 13
            7 --> 14
            7 --> 15
            7 --> 16
            16 -->|pred| 17
            16 -->|obj| 18
            7 --> 19
            7 --> 20
            20 -->|pred| 21
            20 -->|obj| 22
            7 --> 23
            23 -->|pred| 24
            23 -->|obj| 25
            7 --> 26
            7 --> 27
            27 -->|pred| 28
            27 -->|obj| 29
            7 --> 30
            30 -->|pred| 31
            30 -->|obj| 32
            7 --> 33
            5 --> 34
            34 -->|pred| 35
            34 -->|obj| 36
            5 --> 37
            37 -->|pred| 38
            37 -->|obj| 39
            3 --> 40
            40 -->|pred| 41
            40 -->|obj| 42
            3 --> 43
            43 -->|pred| 44
            43 -->|obj| 45
            1 --> 46
            46 -->|pred| 47
            46 -->|obj| 48
            1 --> 49
            49 -->|pred| 50
            49 -->|obj| 51
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:red,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:red,stroke-width:3.0px
            style 5 stroke:red,stroke-width:3.0px
            style 6 stroke:red,stroke-width:3.0px
            style 7 stroke:red,stroke-width:3.0px
            style 8 stroke:#55f,stroke-width:3.0px
            style 9 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 10 stroke:red,stroke-width:3.0px
            style 11 stroke:#55f,stroke-width:3.0px
            style 12 stroke:#55f,stroke-width:3.0px
            style 13 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 14 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 15 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 16 stroke:red,stroke-width:3.0px
            style 17 stroke:#55f,stroke-width:3.0px
            style 18 stroke:#55f,stroke-width:3.0px
            style 19 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 20 stroke:red,stroke-width:3.0px
            style 21 stroke:#55f,stroke-width:3.0px
            style 22 stroke:#55f,stroke-width:3.0px
            style 23 stroke:red,stroke-width:3.0px
            style 24 stroke:#55f,stroke-width:3.0px
            style 25 stroke:#55f,stroke-width:3.0px
            style 26 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 27 stroke:red,stroke-width:3.0px
            style 28 stroke:#55f,stroke-width:3.0px
            style 29 stroke:#55f,stroke-width:3.0px
            style 30 stroke:red,stroke-width:3.0px
            style 31 stroke:#55f,stroke-width:3.0px
            style 32 stroke:#55f,stroke-width:3.0px
            style 33 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 34 stroke:red,stroke-width:3.0px
            style 35 stroke:#55f,stroke-width:3.0px
            style 36 stroke:#55f,stroke-width:3.0px
            style 37 stroke:red,stroke-width:3.0px
            style 38 stroke:#55f,stroke-width:3.0px
            style 39 stroke:#55f,stroke-width:3.0px
            style 40 stroke:red,stroke-width:3.0px
            style 41 stroke:#55f,stroke-width:3.0px
            style 42 stroke:#55f,stroke-width:3.0px
            style 43 stroke:red,stroke-width:3.0px
            style 44 stroke:#55f,stroke-width:3.0px
            style 45 stroke:#55f,stroke-width:3.0px
            style 46 stroke:red,stroke-width:3.0px
            style 47 stroke:#55f,stroke-width:3.0px
            style 48 stroke:#55f,stroke-width:3.0px
            style 49 stroke:red,stroke-width:3.0px
            style 50 stroke:#55f,stroke-width:3.0px
            style 51 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke:red,stroke-width:2.0px
            linkStyle 2 stroke:red,stroke-width:2.0px
            linkStyle 3 stroke:red,stroke-width:2.0px
            linkStyle 4 stroke:red,stroke-width:2.0px
            linkStyle 5 stroke:red,stroke-width:2.0px
            linkStyle 6 stroke:red,stroke-width:2.0px
            linkStyle 7 stroke-width:2.0px
            linkStyle 8 stroke-width:2.0px
            linkStyle 9 stroke:green,stroke-width:2.0px
            linkStyle 10 stroke:#55f,stroke-width:2.0px
            linkStyle 11 stroke-width:2.0px
            linkStyle 12 stroke-width:2.0px
            linkStyle 13 stroke-width:2.0px
            linkStyle 14 stroke-width:2.0px
            linkStyle 15 stroke:green,stroke-width:2.0px
            linkStyle 16 stroke:#55f,stroke-width:2.0px
            linkStyle 17 stroke-width:2.0px
            linkStyle 18 stroke-width:2.0px
            linkStyle 19 stroke:green,stroke-width:2.0px
            linkStyle 20 stroke:#55f,stroke-width:2.0px
            linkStyle 21 stroke-width:2.0px
            linkStyle 22 stroke:green,stroke-width:2.0px
            linkStyle 23 stroke:#55f,stroke-width:2.0px
            linkStyle 24 stroke-width:2.0px
            linkStyle 25 stroke-width:2.0px
            linkStyle 26 stroke:green,stroke-width:2.0px
            linkStyle 27 stroke:#55f,stroke-width:2.0px
            linkStyle 28 stroke-width:2.0px
            linkStyle 29 stroke:green,stroke-width:2.0px
            linkStyle 30 stroke:#55f,stroke-width:2.0px
            linkStyle 31 stroke-width:2.0px
            linkStyle 32 stroke-width:2.0px
            linkStyle 33 stroke:green,stroke-width:2.0px
            linkStyle 34 stroke:#55f,stroke-width:2.0px
            linkStyle 35 stroke-width:2.0px
            linkStyle 36 stroke:green,stroke-width:2.0px
            linkStyle 37 stroke:#55f,stroke-width:2.0px
            linkStyle 38 stroke-width:2.0px
            linkStyle 39 stroke:green,stroke-width:2.0px
            linkStyle 40 stroke:#55f,stroke-width:2.0px
            linkStyle 41 stroke-width:2.0px
            linkStyle 42 stroke:green,stroke-width:2.0px
            linkStyle 43 stroke:#55f,stroke-width:2.0px
            linkStyle 44 stroke-width:2.0px
            linkStyle 45 stroke:green,stroke-width:2.0px
            linkStyle 46 stroke:#55f,stroke-width:2.0px
            linkStyle 47 stroke-width:2.0px
            linkStyle 48 stroke:green,stroke-width:2.0px
            linkStyle 49 stroke:#55f,stroke-width:2.0px
        """#)
    }
}
