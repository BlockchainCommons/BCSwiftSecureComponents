import XCTest
import WolfBase
import SecureComponents

class DigestTests: XCTestCase {
    func test1() {
        XCTAssertEqual(
            Digest("abc").hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        XCTAssertEqual(
            Digest("").hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        XCTAssertEqual(
            Digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").hex,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        )
        XCTAssertEqual(
            Digest("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu").hex,
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        )
        XCTAssertEqual(
            Digest(String(repeating: "a", count: 1_000_000)).hex,
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        )
    }
}
