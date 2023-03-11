import Foundation
import BCCrypto
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
        self.data = Crypto.newAgreementPrivateKeyX25519()
    }

    public var publicKey: AgreementPublicKey {
        AgreementPublicKey(data: Crypto.agreementPublicKeyFromPrivateKeyX25519(agreementPrivateKey: data))!
    }
    
    public var description: String {
        "PrivateAgreementKey\(data)"
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
            throw CBORError.invalidFormat
        }
        self = key
    }
}
