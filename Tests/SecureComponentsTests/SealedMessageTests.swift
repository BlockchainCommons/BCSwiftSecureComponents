import Testing
import SecureComponents
import WolfBase

struct SealedMessageTests {
    @Test func testSealedMessage() throws {
        // Alice constructs a message for Bob's eyes only.
        let sealedMessage = SealedMessage(plaintext: plaintextMysteries, recipient: bobPublicKeys)
        
        // Bob decrypts and reads the message.
        #expect(try sealedMessage.decrypt(with: bobPrivateKeys) == plaintextMysteries.utf8Data)
        
        // No one else can decrypt the message, not even the sender.
        #expect(throws: (any Error).self) { try sealedMessage.decrypt(with: alicePrivateKeys) }
        #expect(throws: (any Error).self) { try sealedMessage.decrypt(with: carolPrivateKeys) }
    }
}
