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
        let uuid = UUID(uuidString: "F741A43F-6091-456D-A0DD-6108651DF751")!
        
        let requestEnvelope = Envelope(request: uuid, body: twoPlusThree())
        let expectedRequestFormat = """
        request(UUID(F741A43F-6091-456D-A0DD-6108651DF751)) [
            body: «add» [
                ❰lhs❱: 2
                ❰rhs❱: 3
            ]
        ]
        """
        XCTAssertEqual(requestEnvelope.format, expectedRequestFormat)

        let responseEnvelope = Envelope(response: uuid, result: 5)
        let expectedResponseFormat = """
        response(UUID(F741A43F-6091-456D-A0DD-6108651DF751)) [
            result: 5
        ]
        """
        XCTAssertEqual(responseEnvelope.format, expectedResponseFormat)
    }
}
