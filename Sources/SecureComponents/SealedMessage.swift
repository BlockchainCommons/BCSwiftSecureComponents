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
        let sharedKey = ephemeralSender.agreementPrivateKey.sharedKey(with: recipientPublicKey)
        self.message = sharedKey.encrypt(plaintext: plaintext, aad: aad, nonce: testNonce)
        self.ephemeralPublicKey = ephemeralSender.agreementPrivateKey.publicKey
    }
    
    public init(message: EncryptedMessage, ephemeralPublicKey: AgreementPublicKey) {
        self.message = message
        self.ephemeralPublicKey = ephemeralPublicKey
    }
    
    public func decrypt(with privateKeys: PrivateKeyBase) throws -> Data {
        let sharedKey = privateKeys.agreementPrivateKey.sharedKey(with: ephemeralPublicKey)
        return try sharedKey.decrypt(message: message)
    }
}

extension SealedMessage: URCodable {
    public static let cborTags = [Tag.sealedMessage]

    public var untaggedCBOR: CBOR {
        let message = self.message.taggedCBOR
        let ephemeralPublicKey = self.ephemeralPublicKey.taggedCBOR

        return [message, ephemeralPublicKey]
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.array(elements) = untaggedCBOR,
            elements.count == 2,
            let message = try? EncryptedMessage(taggedCBOR: elements[0]),
            let ephemeralPublicKey = try? AgreementPublicKey(taggedCBOR: elements[1])
        else {
            throw CBORError.invalidFormat
        }

        self = SealedMessage(message: message, ephemeralPublicKey: ephemeralPublicKey)
    }
}
