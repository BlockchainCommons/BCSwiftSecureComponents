import XCTest
import BCSecureComponents
import WolfBase

class TypeTests: XCTestCase {
    func testKnownPredicate() {
        let envelope = Envelope(predicate: .verifiedBy)
        XCTAssertEqual(envelope.format, "verifiedBy")
    }
    
    func testDate() throws {
        let envelope = try Envelope(Date(iso8601: "2018-01-07"))
        XCTAssertEqual(envelope.format, "2018-01-07")
    }
}
