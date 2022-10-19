import XCTest
import BCSecureComponents
import WolfBase

class TestFunction: XCTestCase {
    private func twoPlusThree() -> Envelope {
        return Envelope(function: .add)
            .addParameter(.lhs, value: 2)
            .addParameter(.rhs, value: 3)
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
            .addParameter("bar", value: 2)
            .addParameter("baz", value: 3)
        
        let expectedFormat = """
        «"foo"» [
            ❰"bar"❱: 2
            ❰"baz"❱: 3
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)
    }
    
    func testRequest() {
        let uuid = CID(‡"c66be27dbad7cd095ca77647406d07976dc0f35f0d4d654bb0e96dd227a1e9fc")!
        
        let requestEnvelope = Envelope(request: uuid, body: twoPlusThree())
        let expectedRequestFormat = """
        request(CID(c66be27d)) [
            body: «add» [
                ❰lhs❱: 2
                ❰rhs❱: 3
            ]
        ]
        """
        XCTAssertEqual(requestEnvelope.format, expectedRequestFormat)

        let responseEnvelope = Envelope(response: uuid, result: 5)
        let expectedResponseFormat = """
        response(CID(c66be27d)) [
            result: 5
        ]
        """
        XCTAssertEqual(responseEnvelope.format, expectedResponseFormat)
    }
}
