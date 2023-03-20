import XCTest
import WolfBase
import SecureComponents

class CompressedTests: XCTestCase {
    func test1() throws {
        let source = """
            Lorem ipsum dolor sit amet consectetur adipiscing elit mi
            nibh ornare proin blandit diam ridiculus, faucibus mus
            dui eu vehicula nam donec dictumst sed vivamus bibendum
            aliquet efficitur. Felis imperdiet sodales dictum morbi
            vivamus augue dis duis aliquet velit ullamcorper porttitor,
            lobortis dapibus hac purus aliquam natoque iaculis blandit
            montes nunc pretium.
            """.utf8Data
        let compressed = Compressed(uncompressedData: source)
        XCTAssertEqual(compressed†, "Compressed(digest: 5a7251ba, size: 222/364, ratio: 0.61)")
        XCTAssertEqual(try compressed.uncompressedData, source)
    }
    
    func test2() {
        let source = "Lorem ipsum dolor sit amet consectetur adipiscing".utf8Data
        let compressed = Compressed(uncompressedData: source)
        XCTAssertEqual(compressed†, "Compressed(digest: b7cfd6f0, size: 47/49, ratio: 0.96)")
        XCTAssertEqual(try compressed.uncompressedData, source)
    }
    
    func test3() {
        let source = "Lorem".utf8Data
        let compressed = Compressed(uncompressedData: source)
        XCTAssertEqual(compressed†, "Compressed(digest: 1b7f8466, size: 5/5, ratio: 1)")
        XCTAssertEqual(try compressed.uncompressedData, source)
    }
    
    func test4() {
        let source = "".utf8Data
        let compressed = Compressed(uncompressedData: source)
        XCTAssertEqual(compressed†, "Compressed(digest: e3b0c442, size: 0/0, ratio: NaN)")
        XCTAssertEqual(try compressed.uncompressedData, source)
    }
}
