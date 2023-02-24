import XCTest
import SecureComponents
import WolfBase

class SealedMessageTests: XCTestCase {
    func testSealedMessage() throws {
        // Alice constructs a message for Bob's eyes only.
        let sealedMessage = SealedMessage(plaintext: plaintextMysteries, recipient: bobPublicKeys)
        
        // Bob decrypts and reads the message.
        XCTAssertEqual(try sealedMessage.plaintext(with: bobPrivateKeys), plaintextMysteries.utf8Data)
        
        // No one else can decrypt the message, not even the sender.
        XCTAssertThrowsError(try sealedMessage.plaintext(with: alicePrivateKeys))
        XCTAssertThrowsError(try sealedMessage.plaintext(with: carolPrivateKeys))
    }
}
