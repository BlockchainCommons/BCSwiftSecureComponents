import Foundation
import protocol WolfBase.DataProvider
import URKit
import BCCrypto
import BCRandom

/// A symmetric key for encryption and decryption of IETF-ChaCha20-Poly1305 messages.
///
/// https://datatracker.ietf.org/doc/html/rfc8439
public struct SymmetricKey: CustomStringConvertible, Equatable, Hashable, Sendable, DataProvider {
    public let data: Data
    
    public init?(_ data: Data) {
        guard data.count == 32 else {
            return nil
        }
        self.data = data
    }
    
    public init<T: RandomNumberGenerator>(using rng: inout T) {
        self.init(rng.randomData(32))!
    }
    
    public init() {
        var rng = SecureRandomNumberGenerator()
        self.init(using: &rng)
    }
    
    public var bytes: [UInt8] {
        data.bytes
    }
    
    public var description: String {
        "SymmetricKey"
    }
    
    public func encrypt(plaintext: DataProvider, aad: Data? = nil, nonce: Nonce? = nil) -> EncryptedMessage {
        let plaintext = plaintext.providedData
        let aad = aad ?? Data()
        let nonce = nonce ?? Nonce()
        let (ciphertext, auth) = try! AEADChaCha20Poly1305.encrypt(plaintext: plaintext, key: data, nonce: nonce.data, aad: aad)
        return EncryptedMessage(ciphertext: ciphertext, aad: aad, nonce: nonce, auth: EncryptedMessage.Auth(auth)!)
    }
    
    public func encrypt(plaintext: DataProvider, digest: Digest, nonce: Nonce? = nil) -> EncryptedMessage {
        encrypt(plaintext: plaintext, aad: digest.taggedCBOR.cborData, nonce: nonce)
    }

    public func decrypt(message: EncryptedMessage) throws -> Data {
        let plaintext = try AEADChaCha20Poly1305.decrypt(ciphertext: message.ciphertext, key: data, nonce: message.nonce.data, aad: message.aad.data, auth: message.auth.data)
        return Data(plaintext)
    }
    
    public var providedData: Data {
        data
    }
}

extension SymmetricKey: URCodable {
    public static let cborTags = [Tag.symmetricKey]
    
    public var untaggedCBOR: CBOR {
        CBOR.bytes(data)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard case let CBOR.bytes(data) = untaggedCBOR,
              let key = SymmetricKey(data)
        else {
            throw CBORError.invalidFormat
        }
        self = key
    }
}
