import Foundation
import URKit
import BLAKE3
import protocol WolfBase.DataProvider

/// A secure encrypted message.
///
/// Implemented using the IETF ChaCha20-Poly1305 encryption.
///
/// https://datatracker.ietf.org/doc/html/rfc8439
///
/// To facilitate decoding, it is recommended that the plaintext of an `EncryptedMessage` be
/// tagged CBOR.
public struct EncryptedMessage: CustomStringConvertible, Equatable {
    public let ciphertext: Data
    public let aad: Data // Additional authenticated data (AAD) per RFC8439
    public let nonce: Nonce
    public let auth: Auth
    
    public init(ciphertext: Data, aad: Data, nonce: Nonce, auth: Auth) {
        self.ciphertext = ciphertext
        self.aad = aad
        self.nonce = nonce
        self.auth = auth
    }
    
    public var description: String {
        "Message(ciphertext: \(ciphertext.hex), aad: \(aad.hex), nonce: \(nonce), auth: \(auth))"
    }
    
    public struct Auth: CustomStringConvertible, Equatable, Hashable {
        public let data: Data
        
        public init?(_ data: Data) {
            guard data.count == 16 else {
                return nil
            }
            self.data = data
        }
        
        public init?(_ bytes: [UInt8]) {
            self.init(Data(bytes))
        }
        
        public var bytes: [UInt8] {
            data.bytes
        }
        
        public var description: String {
            data.hex.flanked("auth(", ")")
        }
    }
}

extension EncryptedMessage {
    public static func sharedKey(agreementPrivateKey: AgreementPrivateKey, agreementPublicKey: AgreementPublicKey) -> SymmetricKey {
        let sharedSecret = try! agreementPrivateKey.cryptoKitForm.sharedSecretFromKeyAgreement(with: agreementPublicKey.cryptoKitForm)
        let keyData = sharedSecret.withUnsafeBytes {
            BLAKE3.deriveKey(fromContentsOf: $0, withContext: "agreement")
        }.data
        return SymmetricKey(keyData)!
    }
}

extension EncryptedMessage {
    public var digest: Digest? {
        try? Digest.decodeTaggedCBOR(aad)
    }
}

extension EncryptedMessage: URCodable {
    public static let cborTag = Tag(201, "crypto-msg")

    public var untaggedCBOR: CBOR {
        if self.aad.isEmpty {
            return [ciphertext.cbor, nonce.data.cbor, auth.data.cbor]
        } else {
            return [ciphertext.cbor, nonce.data.cbor, auth.data.cbor, aad.cbor]
        }
    }
    
    public static func decodeUntaggedCBOR(_ cbor: CBOR) throws -> EncryptedMessage {
        let (ciphertext, aad, nonce, auth) = try Self.decode(cbor: cbor)
        return EncryptedMessage(ciphertext: ciphertext, aad: aad, nonce: nonce, auth: auth)
    }

    public static func decode(cbor: CBOR) throws -> (ciphertext: Data, aad: Data, nonce: Nonce, auth: Auth)
    {
        guard
            case let CBOR.array(elements) = cbor,
            (3...4).contains(elements.count),
            case let CBOR.bytes(ciphertext) = elements[0],
            case let CBOR.bytes(nonceData) = elements[1],
            let nonce = Nonce(nonceData),
            case let CBOR.bytes(authData) = elements[2],
            let auth = Auth(authData)
        else {
            throw CBORDecodingError.invalidFormat
        }

        if elements.count == 4 {
            guard
                case let CBOR.bytes(aad) = elements[3],
                !aad.isEmpty
            else {
                throw CBORDecodingError.invalidFormat
            }
            return (ciphertext, aad, nonce, auth)
        } else {
            return (ciphertext, Data(), nonce, auth)
        }
    }
}
