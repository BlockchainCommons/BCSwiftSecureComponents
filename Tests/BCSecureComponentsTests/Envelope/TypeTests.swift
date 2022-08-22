import XCTest
import BCSecureComponents
import WolfBase

class TypeTests: XCTestCase {
    func testKnownPredicate() throws {
        let envelope = try Envelope(KnownPredicate.verifiedBy).checkEncoding()
        XCTAssertEqual(envelope.format, "verifiedBy")
    }

    func testDate() throws {
        let envelope = try Envelope(Date(iso8601: "2018-01-07")).checkEncoding()
        XCTAssertEqual(envelope.format, "2018-01-07")
    }
}
