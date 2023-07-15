import XCTest
import WolfBase
import SecureComponents

class SSKRTests: XCTestCase {
    func testDecodeBytewords() throws {
        let inputShare = "tuna acid epic gyro loud monk able acid able echo belt scar skew paid duty when also idea acid cola vast trip belt stub wolf frog free horn waxy"
        let share = try SSKRShare(bytewords: inputShare)!
        XCTAssertEqual(Data(share.data), ‡"8998000100330dc3c6a830f10263011de0d80dcbf3")
    }
}
