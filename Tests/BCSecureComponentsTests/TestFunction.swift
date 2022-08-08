import XCTest
import BCSecureComponents
import WolfBase

class TestFunction: XCTestCase {
    private func twoPlusThree() -> Envelope {
        return Envelope(function: .add)
            .add(.parameter(.lhs, value: 2))
            .add(.parameter(.rhs, value: 3))
    }
    
    func testWellKnown() {
        let envelope = twoPlusThree()
        let expectedFormat = """
        «add» [
            ❰lhs❱: 2
            ❰rhs❱: 3
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)
    }
    
    func testQuoted() {
        let envelope = Envelope(function: "foo")
            .add(.parameter("bar", value: 2))
            .add(.parameter("baz", value: 3))
        
        let expectedFormat = """
        «"foo"» [
            ❰"bar"❱: 2
            ❰"baz"❱: 3
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)
    }
    
    func testRequest() {
        let scid = SCID(‡"66071f80a93735adc7f06713cca8b6026dabd7ede03914a6b7b97dde898f1d79")!
        
        let requestEnvelope = Envelope(request: scid, body: twoPlusThree())
        let expectedRequestFormat = """
        request(SCID(66071f80a93735adc7f06713cca8b6026dabd7ede03914a6b7b97dde898f1d79)) [
            body: «add» [
                ❰lhs❱: 2
                ❰rhs❱: 3
            ]
        ]
        """
        XCTAssertEqual(requestEnvelope.format, expectedRequestFormat)

        let responseEnvelope = Envelope(response: scid, result: 5)
        let expectedResponseFormat = """
        response(SCID(66071f80a93735adc7f06713cca8b6026dabd7ede03914a6b7b97dde898f1d79)) [
            result: 5
        ]
        """
        XCTAssertEqual(responseEnvelope.format, expectedResponseFormat)
    }
}
