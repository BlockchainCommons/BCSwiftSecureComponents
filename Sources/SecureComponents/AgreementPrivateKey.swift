import Foundation
import BCCrypto
import WolfBase
import URKit
import BCRandom

/// A Curve25519 private key used for X25519 key agreement.
///
/// https://datatracker.ietf.org/doc/html/rfc7748
public struct AgreementPrivateKey: CustomStringConvertible, Hashable, Sendable {
    public let data: Data
    
    public init?(_ data: DataProvider) {
        let data = data.providedData
        guard data.count == 32 else {
            return nil
        }
        self.data = data
    }

    public init<T: RandomNumberGenerator>(using rng: inout T) {
        self.data = rng.randomData(32)
    }
    
    public init() {
        var rng = SecureRandomNumberGenerator()
        self.init(using: &rng)
    }

    public init(keyMaterial: DataProvider) {
        self.init(X25519.deriveAgreementPrivateKey(keyMaterial: keyMaterial.providedData))!
    }

    public var publicKey: AgreementPublicKey {
        AgreementPublicKey(data: X25519.deriveAgreementPublicKey(agreementPrivateKey: data))!
    }
    
    public func sharedKey(with publicKey: AgreementPublicKey) -> SymmetricKey {
        let keyData = X25519.deriveAgreementSharedKey(agreementPrivateKey: self.data, agreementPublicKey: publicKey.data)
        return SymmetricKey(keyData)!
    }
    
    public var description: String {
        "AgreementPrivateKey"
    }
}

extension AgreementPrivateKey: URCodable {
    public static let cborTags = [Tag.agreementPrivateKey]
    
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
