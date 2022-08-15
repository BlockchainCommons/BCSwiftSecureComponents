import XCTest
import BCSecureComponents
import WolfBase

class EncodingTests: XCTestCase {
    func testDigest() throws {
        try Envelope(Digest("Hello.")).checkEncoding()
    }

    func test1() throws {
        let e = try Envelope(plaintextHello).checkEncoding()
        XCTAssertEqual(e.taggedCBOR.diagAnnotated,
            """
            200("Hello.")   ; envelope
            """
        )
    }
    
    func test2() throws {
        let array: CBOR = [1, 2, 3]
        let e = try Envelope(array).checkEncoding()
        XCTAssertEqual(e.taggedCBOR.diagAnnotated,
            """
            200(   ; envelope
               220(   ; leaf
                  [1, 2, 3]
               )
            )
            """
        )
    }
    
    func test3() throws {
        let e1 = Envelope(predicate: "A", object: "B")
        let e2 = Envelope(predicate: "C", object: "D")
        let e3 = Envelope(predicate: "E", object: "F")
        
        let e4 = try e2.add(e3)
        let e5 = try e1.add(e4)
        
        XCTAssertEqual(e5.format,
            """
            {
                "A": "B"
            } [
                {
                    "C": "D"
                } [
                    "E": "F"
                ]
            ]
            """
        )

        XCTAssertEqual(e5.taggedCBOR.diagAnnotated,
            """
            200(   ; envelope
               [
                  221(   ; assertion
                     ["A", "B"]
                  ),
                  [
                     221(   ; assertion
                        ["C", "D"]
                     ),
                     221(   ; assertion
                        ["E", "F"]
                     )
                  ]
               ]
            )
            """
        )
        
        try e5.checkEncoding()
    }
}
