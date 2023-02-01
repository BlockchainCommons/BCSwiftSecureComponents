import Foundation
import CryptoKit
import WolfBase
import URKit

/// A Curve25519 public key used for X25519 key agreement.
///
/// https://datatracker.ietf.org/doc/html/rfc7748
public struct AgreementPublicKey: CustomStringConvertible, Hashable {
    public let data: Data
    
    public init?(data: DataProvider) {
        let data = data.providedData
        guard
            data.count == 32
        else {
            return nil
        }
        self.data = data
    }
    
    public var description: String {
        "AgreementPublicKey(\(data.hex))"
    }
    
    public var cryptoKitForm: Curve25519.KeyAgreement.PublicKey {
        try! .init(rawRepresentation: data)
    }
}

extension AgreementPublicKey: URCodable {
    public static let cborTag = Tag(230, "agreement-public-key")
    
    public var untaggedCBOR: CBOR {
        CBOR.bytes(data)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.bytes(data) = untaggedCBOR,
            let key = AgreementPublicKey(data: data)
        else {
            throw CBORDecodingError.invalidFormat
        }
        self = key
    }
}
