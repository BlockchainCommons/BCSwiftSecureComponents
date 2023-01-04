import XCTest
import BCSecureComponents
import WolfBase

class NestingTests: XCTestCase {
    func testNestingSigned() throws {
        let envelope = try Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)
            .checkEncoding()

        let expectedFormat =
        """
        "Hello." [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        let target = envelope.subject
        let elidedEnvelope = try envelope.elideRemoving(target).checkEncoding()
        try elidedEnvelope.verifySignature(from: alicePublicKeys)
        let expectedElidedFormat =
        """
        ELIDED [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(elidedEnvelope.format, expectedElidedFormat)
    }

    func testNestingEncloseThenSign() throws {
        let envelope = try Envelope(plaintextHello)
            .wrap()
            .sign(with: alicePrivateKeys)
            .checkEncoding()

        let expectedFormat =
        """
        {
            "Hello."
        } [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        let target = try envelope.unwrap().subject
        let elidedEnvelope = try envelope.elideRemoving(target).checkEncoding()
        XCTAssert(elidedEnvelope.isEquivalent(to: envelope))
        try elidedEnvelope.verifySignature(from: alicePublicKeys)
        let expectedElidedFormat =
        """
        {
            ELIDED
        } [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(elidedEnvelope.format, expectedElidedFormat)

        let p1 = envelope
        let p2 = envelope.subject
        let p3 = try p1.unwrap()
        let revealedEnvelope = try envelope.elideRevealing([p1, p2, p3]).checkEncoding()
        XCTAssert(revealedEnvelope.isEquivalent(to: envelope))
        let expectedRevealedFormat =
        """
        {
            "Hello."
        } [
            ELIDED
        ]
        """
        XCTAssertEqual(revealedEnvelope.format, expectedRevealedFormat)
    }

    func testNestingSignThenEnclose() {
        let envelope = Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)
            .wrap()

        let expectedFormat =
        """
        {
            "Hello." [
                verifiedBy: Signature
            ]
        }
        """
        XCTAssertEqual(envelope.format, expectedFormat)
    }
}
