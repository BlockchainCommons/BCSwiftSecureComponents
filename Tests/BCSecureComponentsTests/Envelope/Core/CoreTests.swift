import XCTest
import BCSecureComponents
import WolfBase

class CoreTests: XCTestCase {
    static let basicEnvelope = Envelope("Hello.")
    static let knownValueEnvelope = Envelope(KnownValue.note)
    static let wrappedEnvelope = Envelope(basicEnvelope)
    static let doubleWrappedEnvelope = Envelope(wrappedEnvelope)
    static let assertionEnvelope = Envelope("knows", "Bob")

    static let singleAssertionEnvelope = Envelope("Alice")
        .addAssertion("knows", "Bob")
    static let doubleAssertionEnvelope = singleAssertionEnvelope
        .addAssertion("knows", "Carol")
    
    override class func setUp() {
        addKnownTags()
    }
    
    func testIntSubject() throws {
        let e = try Envelope(42).checkEncoding()
        
        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           24(42)   ; leaf
        )
        """)
        
        XCTAssertEqual(e.digest†, "Digest(b828e7bda50941d5618ae287093288dd06a229250fca262764a408defd29f91c)")
        
        XCTAssertEqual(e.format,
        """
        42
        """
        )
        
        XCTAssertEqual(try e.extractSubject(Int.self), 42)
    }
    
    func testNegativeIntSubject() throws {
        let e = try Envelope(-42).checkEncoding()
        
        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           24(-42)   ; leaf
        )
        """)
        
        XCTAssertEqual(e.digest†, "Digest(a5deb6e4c1b034cfc4027271e4a2c777f08ced8060fa77156c4f0e494b03b741)")
        
        XCTAssertEqual(e.format,
        """
        -42
        """
        )
        
        XCTAssertEqual(try e.extractSubject(Int.self), -42)
    }
    
    func testCBOREncodableSubject() throws {
        let e = try Self.basicEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           24("Hello.")   ; leaf
        )
        """)
        
        try e.checkEncoding()
        
        XCTAssertEqual(e.digest†, "Digest(886a0c85832fa119d5dc3a195308bf13547f1f16aef032f6c2ef9912cd5992e5)")
        
        XCTAssertEqual(e.format,
        """
        "Hello."
        """
        )
        
        XCTAssertEqual(try e.extractSubject(String.self), "Hello.")
    }
    
    func testKnownValueSubject() throws {
        let e = try Self.knownValueEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           223(4)   ; known-value
        )
        """)
        
        try e.checkEncoding()
        
        XCTAssertEqual(e.digest†, "Digest(61fb6a6b9699d363cafbd309506125c95234b64479f5671cb45cbe7013ffdcf5)")
        
        XCTAssertEqual(e.format,
        """
        note
        """)
        
        XCTAssertEqual(try e.extractSubject(KnownValue.self), .note)
    }
    
    func testAssertionSubject() throws {
        let e = try Self.assertionEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           221(   ; assertion
              [
                 200(   ; envelope
                    24("knows")   ; leaf
                 ),
                 200(   ; envelope
                    24("Bob")   ; leaf
                 )
              ]
           )
        )
        """)
        
        try e.checkEncoding()
        
        XCTAssertEqual(e.digest†, "Digest(55560bdf060f1220199c87e84e29cecef96ef811de4f399dab2fde9425d0d418)")
        
        XCTAssertEqual(e.format,
        """
        "knows": "Bob"
        """)
        
        XCTAssertEqual(e.subject.digest, Envelope("knows", "Bob").digest)
    }
    
    func testSubjectWithAssertion() throws {
        let e = Self.singleAssertionEnvelope
        
        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           [
              200(   ; envelope
                 24("Alice")   ; leaf
              ),
              200(   ; envelope
                 221(   ; assertion
                    [
                       200(   ; envelope
                          24("knows")   ; leaf
                       ),
                       200(   ; envelope
                          24("Bob")   ; leaf
                       )
                    ]
                 )
              )
           ]
        )
        """)
        
        try e.checkEncoding()
        
        XCTAssertEqual(e.digest†, "Digest(e54d6fd38e9952f0d781a08549934cffd28c8e1ef407917fa8e96df69f5f2a90)")
        
        XCTAssertEqual(e.format,
        """
        "Alice" [
            "knows": "Bob"
        ]
        """)
        
        XCTAssertEqual(try e.extractSubject(String.self), "Alice")
    }
    
    func testSubjectWithTwoAssertions() throws {
        let e = Self.doubleAssertionEnvelope
        
        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           [
              200(   ; envelope
                 24("Alice")   ; leaf
              ),
              200(   ; envelope
                 221(   ; assertion
                    [
                       200(   ; envelope
                          24("knows")   ; leaf
                       ),
                       200(   ; envelope
                          24("Bob")   ; leaf
                       )
                    ]
                 )
              ),
              200(   ; envelope
                 221(   ; assertion
                    [
                       200(   ; envelope
                          24("knows")   ; leaf
                       ),
                       200(   ; envelope
                          24("Carol")   ; leaf
                       )
                    ]
                 )
              )
           ]
        )
        """)
        
        try e.checkEncoding()
        
        XCTAssertEqual(e.digest†, "Digest(c733401eaf0c41cd0b3a44b568d4d4dd07e46e481bd3ef6eb457cd6674590614)")
        
        XCTAssertEqual(e.format,
        """
        "Alice" [
            "knows": "Bob"
            "knows": "Carol"
        ]
        """)
        
        XCTAssertEqual(try e.extractSubject(String.self), "Alice")
    }
    
    func testWrapped() throws {
        let e = try Self.wrappedEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           224(   ; wrapped-envelope
              24("Hello.")   ; leaf
           )
        )
        """)
        
        try e.checkEncoding()
        
        XCTAssertEqual(e.digest†, "Digest(5c0cf317b53dec87641ed2ca7944b900e18e936496c73b42866d29657aeb3a14)")
        
        XCTAssertEqual(e.format,
        """
        {
            "Hello."
        }
        """)
    }
    
    func testDoubleWrapped() throws {
        let e = try Self.doubleWrappedEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           224(   ; wrapped-envelope
              224(   ; wrapped-envelope
                 24("Hello.")   ; leaf
              )
           )
        )
        """)
        
        try e.checkEncoding()
        
        XCTAssertEqual(e.digest†, "Digest(c4d50ab4bb904e68d2cf9cd6ca3f65b535f822d7e4a817c9eef0fc75eb83170a)")
        
        XCTAssertEqual(e.format,
        """
        {
            {
                "Hello."
            }
        }
        """)
    }
    
    func testAssertionWithAssertions() throws {
        let a = try Envelope(1, 2)
            .addAssertion(Envelope(3, 4))
            .addAssertion(Envelope(5, 6))
        let e = try Envelope(7)
            .addAssertion(a)
        XCTAssertEqual(e.format,
        """
        7 [
            {
                1: 2
            } [
                3: 4
                5: 6
            ]
        ]
        """)
    }

    func testDigestLeaf() throws {
        let digest = Self.basicEnvelope.digest
        let e = try Envelope(digest).checkEncoding()

        XCTAssertEqual(e.format,
        """
        Digest(886a0c85)
        """
        )

        XCTAssertEqual(e.digest†, "Digest(9fbec3ea6c65e4b190ec35c7e461f75285202fe5556cc6a60eccac3d012f01a6)")

        XCTAssertEqual(e.diagAnnotated,
        """
        200(   ; envelope
           24(   ; leaf
              203(   ; crypto-digest
                 h'886a0c85832fa119d5dc3a195308bf13547f1f16aef032f6c2ef9912cd5992e5'
              )
           )
        )
        """
        )
    }
}

