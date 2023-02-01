import Foundation
import CryptoKit
import WolfBase
import URKit

/// A Curve25519 private key used for X25519 key agreement.
///
/// https://datatracker.ietf.org/doc/html/rfc7748
public struct AgreementPrivateKey: CustomStringConvertible, Hashable {
    public let data: Data
    
    public init?(_ data: DataProvider) {
        let data = data.providedData
        guard data.count == 32 else {
            return nil
        }
        self.data = data
    }
    
    public init() {
        self.data = Curve25519.KeyAgreement.PrivateKey().rawRepresentation
    }

    public var publicKey: AgreementPublicKey {
        AgreementPublicKey(data: cryptoKitForm.publicKey.rawRepresentation)!
    }
    
    public var description: String {
        "PrivateAgreementKey\(data)"
    }

    public var cryptoKitForm: Curve25519.KeyAgreement.PrivateKey {
        try! .init(rawRepresentation: data)
    }
}

extension AgreementPrivateKey: URCodable {
    public static let cborTag = Tag(702, "agreement-private-key")
    
    public var untaggedCBOR: CBOR {
        CBOR.bytes(data)
    }

    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.bytes(data) = untaggedCBOR,
            let key = AgreementPrivateKey(data)
        else {
            throw CBORDecodingError.invalidFormat
        }
        self = key
    }
}
