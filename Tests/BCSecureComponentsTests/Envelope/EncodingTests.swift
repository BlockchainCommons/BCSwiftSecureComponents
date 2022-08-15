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
}
