import Foundation
import WolfBase
import URKit
import BCCrypto

/// Types can conform to `PrivateKeysDataProvider` to indicate that they will provide
/// unique data from which keys for signing and encryption can be derived.
///
/// Conforming types include `Data`, `Seed`, `HDKey`, and `Password`.
public protocol PrivateKeysDataProvider {
    var privateKeysData: Data { get }
}

extension Data: PrivateKeysDataProvider {
    public var privateKeysData: Data {
        self
    }
}

/// Holds unique data from which keys for signing and encryption can be derived.
public struct PrivateKeyBase {
    public let data: Data
    
    public init(_ provider: PrivateKeysDataProvider? = nil) {
        let provider = provider ?? secureRandomData(32)
        self.data = provider.privateKeysData
    }
    
    public var signingPrivateKey: SigningPrivateKey {
        SigningPrivateKey(Crypto.deriveSigningPrivateKeyX25519(keyMaterial: data))!
    }
    
    public var agreementPrivateKey: AgreementPrivateKey {
        AgreementPrivateKey(Crypto.deriveAgreementPrivateKeyX25519(keyMaterial: data))!
    }
    
    public var publicKeys: PublicKeyBase {
        PublicKeyBase(signingPublicKey: signingPrivateKey.schnorrPublicKey, agreementPublicKey: agreementPrivateKey.publicKey)
    }
    
    public var ecdsaPublicKeys: PublicKeyBase {
        PublicKeyBase(signingPublicKey: signingPrivateKey.ecdsaPublicKey, agreementPublicKey: agreementPrivateKey.publicKey)
    }
}

extension PrivateKeyBase: URCodable {
    public static let cborTag = Tag.privateKeyBase

    public var untaggedCBOR: CBOR {
        data.cbor
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard case let CBOR.bytes(data) = untaggedCBOR else {
            throw CBORError.invalidFormat
        }
        self = PrivateKeyBase(data)
    }
}
