import Foundation
import WolfBase

public extension Envelope {
    static func hasRecipient(_ recipient: PublicKeyBase, contentKey: SymmetricKey, testKeyMaterial: DataProvider? = nil, testNonce: Nonce? = nil) -> Envelope {
        let sealedMessage = SealedMessage(plaintext: contentKey.taggedCBOR, recipient: recipient, testKeyMaterial: testKeyMaterial, testNonce: testNonce)
        return Envelope(.hasRecipient, sealedMessage)
    }
}

public extension Envelope {
    func addRecipient(_ recipient: PublicKeyBase, contentKey: SymmetricKey, testKeyMaterial: DataProvider? = nil, testNonce: Nonce? = nil) -> Envelope {
        try! addAssertion(.hasRecipient(recipient, contentKey: contentKey, testKeyMaterial: testKeyMaterial, testNonce: testNonce))
    }
}

public extension Envelope {
    var recipients: [SealedMessage] {
        get throws {
            try assertions(withPredicate: .hasRecipient)
                .map { try $0.object!.extractSubject(SealedMessage.self) }
        }
    }
    
    func encryptSubject(to recipients: [PublicKeyBase]) throws -> Envelope {
        let contentKey = SymmetricKey()
        var e = try encryptSubject(with: contentKey)
        for recipient in recipients {
            e = e.addRecipient(recipient, contentKey: contentKey)
        }
        return e
    }
    
    func encryptSubject(to recipient: PublicKeyBase) throws -> Envelope {
        try encryptSubject(to: [recipient])
    }

    func decrypt(to recipient: PrivateKeyBase) throws -> Envelope {
        guard
            let contentKeyData = try SealedMessage.firstPlaintext(in: recipients, for: recipient)
        else {
            throw EnvelopeError.invalidRecipient
        }

        let cbor = try CBOR(contentKeyData)
        let contentKey = try SymmetricKey(taggedCBOR: cbor)
        return try decryptSubject(with: contentKey).subject
    }
}
