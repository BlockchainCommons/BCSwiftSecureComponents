import XCTest
import BCSecureComponents
import WolfBase

class EncodingTests: XCTestCase {
    func test1() throws {
        let e = try Envelope(plaintextHello).checkEncoding()
        XCTAssertEqual(e.taggedCBOR.diagAnnotated,
            """
            200("Hello.")   ; envelope
            """
        )

        let array: CBOR = [1, 2, 3]
        let e2 = try Envelope(array).checkEncoding()
        XCTAssertEqual(e2.taggedCBOR.diagAnnotated,
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
