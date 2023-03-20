import Foundation
import WolfBase
import URKit

/// Holds information used to communicate cryptographically with a remote entity.
///
/// Includes the entity's public signing key for verifying signatures, and
/// the entity's public agreement key and salt used for X25519 key agreement.
public struct PublicKeyBase: CustomStringConvertible, Hashable {
    public let signingPublicKey: SigningPublicKey
    public let agreementPublicKey: AgreementPublicKey
    
    public init(signingPublicKey: SigningPublicKey, agreementPublicKey: AgreementPublicKey) {
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
    }
    
    public var description: String {
        "PublicKeyBase(signingKey: \(signingPublicKey), agreementKey: \(agreementPublicKey)"
    }
}

extension PublicKeyBase: URCodable {
    public static let cborTag = Tag.publicKeyBase
    
    public var untaggedCBOR: CBOR {
        [signingPublicKey, agreementPublicKey]
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.array(elements) = untaggedCBOR,
            elements.count == 2
        else {
            throw CBORError.invalidFormat
        }

        let signingKey = try SigningPublicKey(taggedCBOR: elements[0])
        let agreementKey = try AgreementPublicKey(taggedCBOR: elements[1])

        self = PublicKeyBase(signingPublicKey: signingKey, agreementPublicKey: agreementKey)
    }
}
