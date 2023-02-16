import XCTest
import SecureComponents
import WolfBase

class SealedMessageTests: XCTestCase {
    func testSealedMessage() {
        // Alice constructs a message for Bob's eyes only.
        let sealedMessage = SealedMessage(plaintext: plaintextMysteries, recipient: bobPublicKeys)
        
        // Bob decrypts and reads the message.
        XCTAssertEqual(sealedMessage.plaintext(with: bobPrivateKeys), plaintextMysteries.utf8Data)
        
        // No one else can decrypt the message, not even the sender.
        XCTAssertNil(sealedMessage.plaintext(with: alicePrivateKeys))
        XCTAssertNil(sealedMessage.plaintext(with: carolPrivateKeys))
    }
}
