import Testing
import SecureComponents
import WolfBase
import Foundation

// Test vector from: https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
fileprivate let plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8Data
fileprivate let aad = ‡"50515253c0c1c2c3c4c5c6c7"
fileprivate let key = SymmetricKey(‡"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")!
fileprivate let nonce = Nonce(‡"070000004041424344454647")!
fileprivate let encryptedMessage = key.encrypt(plaintext: plaintext, aad: aad, nonce: nonce)
fileprivate let ciphertext = ‡"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
fileprivate let auth = EncryptedMessage.Auth(‡"1ae10b594f09e26a7e902ecbd0600691")!

@MainActor
struct EncryptedMessageTests {
    init() {
        addKnownTags()
    }
    
    @Test func testRFCTestVector() throws {
        #expect(encryptedMessage.ciphertext == ciphertext)
        #expect(encryptedMessage.auth == auth)

        let decryptedPlaintext = try key.decrypt(message: encryptedMessage)
        #expect(plaintext == decryptedPlaintext)
    }
    
    @Test func testRandomKeyAndNonce() throws {
        let key = SymmetricKey()
        let nonce = Nonce()
        let encryptedMessage = key.encrypt(plaintext: plaintext, aad: aad, nonce: nonce)
        let decryptedPlaintext = try key.decrypt(message: encryptedMessage)
        #expect(plaintext == decryptedPlaintext)
    }
    
    @Test func testEmptyData() throws {
        let key = SymmetricKey()
        let encryptedMessage = key.encrypt(plaintext: Data(), aad: Data())
        let decryptedPlaintext = try key.decrypt(message: encryptedMessage)
        #expect(decryptedPlaintext.isEmpty)
    }
    
    @Test func testCBOR() {
        #expect(encryptedMessage.cborData.hex == "d99c42845872d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61164c070000004041424344454647501ae10b594f09e26a7e902ecbd06006914c50515253c0c1c2c3c4c5c6c7")

        #expect(encryptedMessage.cbor.diagnostic(tags: globalTags) ==
        """
        40002(   / encrypted /
           [
              h'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116',
              h'070000004041424344454647',
              h'1ae10b594f09e26a7e902ecbd0600691',
              h'50515253c0c1c2c3c4c5c6c7'
           ]
        )
        """
        )
        
        #expect(encryptedMessage.cbor.hex(tags: globalTags) ==
        """
        d9 9c42                                  # tag(40002) encrypted
           84                                    # array(4)
              5872                               # bytes(114)
                 d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116
              4c                                 # bytes(12)
                 070000004041424344454647        # "....@ABCDEFG"
              50                                 # bytes(16)
                 1ae10b594f09e26a7e902ecbd0600691
              4c                                 # bytes(12)
                 50515253c0c1c2c3c4c5c6c7
        """
        )
    }
    
    @Test func testUR() {
//        print(encryptedMessage.ur)
        let expectedUR = try! UR(urString: "ur:encrypted/lrhdjptecylgeeiemnhnuykglnperfguwskbsaoxpmwegydtjtayzeptvoreosenwyidtbfsrnoxhylkptiobglfzszointnmojplucyjsuebknnambddtahtbonrpkbsnfrenmoutrylbdpktlulkmkaxplvldeascwhdzsqddkvezstbkpmwgolplalufdehtsrffhwkuewtmngrknntvwkotdihlntoswgrhscmgsataeaeaefzfpfwfxfyfefgflgdcyvybdhkgwasvoimkbmhdmsbtihnammegsgdgygmgurtsesasrssskswstcfnbpdct")
        #expect(encryptedMessage.ur == expectedUR)
    }
}
