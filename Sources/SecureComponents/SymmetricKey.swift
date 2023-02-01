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
        return EncryptedMessage(ciphertext: Data(ciphertext), aad: aad, nonce: nonce, auth: EncryptedMessage.Auth(Data(auth))!)
    }
    
    public func encrypt(plaintext: DataProvider, digest: Digest, nonce: Nonce? = nil) -> EncryptedMessage {
        encrypt(plaintext: plaintext, aad: digest.taggedCBOR.encodeCBOR(), nonce: nonce)
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

extension SymmetricKey: URCodable {
    public static let cborTag = Tag(204, "crypto-key")
    
    public var untaggedCBOR: CBOR {
        CBOR(bytes: data)
    }
    
    public static func decodeUntaggedCBOR(_ cbor: CBOR) throws -> SymmetricKey {
        guard case let CBOR.bytes(data) = cbor,
              let key = SymmetricKey(data)
        else {
            throw CBORDecodingError.invalidFormat
        }
        return key
    }
}
