import Foundation
import WolfBase
import URKit

/// An encrypted message that can only be opened by its intended recipient.
///
/// It is encrypted using an ephemeral private key that is thrown away, and encapsulates
/// the ephemeral public key and the receiver's public key needed for decryption.
public struct SealedMessage {
    public let message: EncryptedMessage
    public let ephemeralPublicKey: AgreementPublicKey
    
    public init(plaintext: DataProvider, recipient: PublicKeyBase, aad: Data? = nil, testKeyMaterial: DataProvider? = nil, testNonce: Nonce? = nil) {
        let ephemeralSender = PrivateKeyBase(testKeyMaterial?.providedData)
        let recipientPublicKey = recipient.agreementPublicKey
        let key = EncryptedMessage.sharedKey(agreementPrivateKey: ephemeralSender.agreementPrivateKey, agreementPublicKey: recipientPublicKey)
        self.message = key.encrypt(plaintext: plaintext, aad: aad, nonce: testNonce)
        self.ephemeralPublicKey = ephemeralSender.agreementPrivateKey.publicKey
    }
    
    public init(message: EncryptedMessage, ephemeralPublicKey: AgreementPublicKey) {
        self.message = message
        self.ephemeralPublicKey = ephemeralPublicKey
    }
    
    public func plaintext(with privateKeys: PrivateKeyBase) -> Data? {
        let key = EncryptedMessage.sharedKey(agreementPrivateKey: privateKeys.agreementPrivateKey, agreementPublicKey: ephemeralPublicKey)
        return key.decrypt(message: message)
    }
    
    public static func firstPlaintext(in sealedMessages: [SealedMessage], for privateKeys: PrivateKeyBase) -> Data? {
        for sealedMessage in sealedMessages {
            if let plaintext = sealedMessage.plaintext(with: privateKeys) {
                return plaintext
            }
        }
        return nil
    }
}

extension SealedMessage: URCodable {
    public static let urType = "crypto-sealed"
    public static let cborTag: UInt64 = 207

    public var untaggedCBOR: CBOR {
        let message = self.message.taggedCBOR
        let ephemeralPublicKey = self.ephemeralPublicKey.taggedCBOR

        return [message, ephemeralPublicKey]
    }
    
    public static func decodeUntaggedCBOR(_ cbor: CBOR) throws -> SealedMessage {
        guard
            case let CBOR.array(elements) = cbor,
            elements.count == 2,
            let message = try? EncryptedMessage.decodeTaggedCBOR(elements[0]),
            let ephemeralPublicKey = try? AgreementPublicKey.decodeTaggedCBOR(elements[1])
        else {
            throw DecodeError.invalidFormat
        }

        return SealedMessage(message: message, ephemeralPublicKey: ephemeralPublicKey)
    }
}
