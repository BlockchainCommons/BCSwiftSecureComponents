import Foundation
import protocol WolfBase.DataProvider
import CryptoSwift
import URKit

/// A symmetric key for encryption and decryption of IETF-ChaCha20-Poly1305 messages.
///
/// https://datatracker.ietf.org/doc/html/rfc8439
public struct SymmetricKey: CustomStringConvertible, Equatable, Hashable, DataProvider {
    public let data: Data
    
    public init?(_ data: Data) {
        guard data.count == 32 else {
            return nil
        }
        self.data = data
    }
    
    public init() {
        self.init(SecureRandomNumberGenerator.shared.data(count: 32))!
    }
    
    public var bytes: [UInt8] {
        data.bytes
    }
    
    public var description: String {
        data.description.flanked("Key(", ")")
    }
    
    public func encrypt(plaintext: DataProvider, aad: Data? = nil, nonce: Nonce? = nil) -> EncryptedMessage {
        let plaintext = plaintext.providedData
        let aad = aad ?? Data()
        let nonce = nonce ?? Nonce()
        let (ciphertext, auth) = try! AEADChaCha20Poly1305.encrypt(plaintext.bytes, key: self.bytes, iv: nonce.bytes, authenticationHeader: aad.bytes)
        return EncryptedMessage(ciphertext: Data(ciphertext), aad: aad, nonce: nonce, auth: EncryptedMessage.Auth(Data(auth))!)!
    }
    
    public func encrypt(plaintext: DataProvider, digest: Digest, nonce: Nonce? = nil) -> EncryptedMessage {
        encrypt(plaintext: plaintext, aad: digest.taggedCBOR.cborEncode, nonce: nonce)
    }
    
    public func decrypt(message: EncryptedMessage) -> Data? {
        guard let (plaintext, success) =
                try? AEADChaCha20Poly1305.decrypt(message.ciphertext.bytes, key: self.bytes, iv: message.nonce.bytes, authenticationHeader: message.aad.bytes, authenticationTag: message.auth.bytes),
                success
        else {
            return nil
        }
        return Data(plaintext)
    }
    
    public var providedData: Data {
        data
    }
}

extension SymmetricKey {
    public var untaggedCBOR: CBOR {
        CBOR.data(self.data)
    }

    public var taggedCBOR: CBOR {
        CBOR.tagged(.symmetricKey, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard case let CBOR.data(data) = untaggedCBOR,
              let key = SymmetricKey(data)
        else {
            throw CBORError.invalidFormat
        }
        self = key
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.symmetricKey, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension SymmetricKey {
    public var ur: UR {
        return try! UR(type: .symmetricKey, cbor: untaggedCBOR)
    }
    
    public init(ur: UR) throws {
        try ur.checkType(.symmetricKey)
        let cbor = try CBOR(ur.cbor)
        try self.init(untaggedCBOR: cbor)
    }
    
    init(urString: String) throws {
        try self.init(ur: UR(urString: urString))
    }
}

extension SymmetricKey: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}
