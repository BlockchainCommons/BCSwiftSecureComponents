import Foundation
import CryptoKit
import WolfBase
import BLAKE3
import URKit

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
///
/// Derivation is performed used BLAKE3.
///
/// https://datatracker.ietf.org/doc/html/rfc5869
public struct PrivateKeyBase {
    public let data: Data
    
    public init(_ provider: PrivateKeysDataProvider? = nil) {
        let provider = provider ?? SecureRandomNumberGenerator.shared.data(count: 32)
        self.data = provider.privateKeysData
    }
    
    public var signingPrivateKey: SigningPrivateKey {
        .init(BLAKE3.deriveKey(fromContentsOf: data, withContext: "signing").data)!
    }
    
    public var agreementPrivateKey: AgreementPrivateKey {
        .init(BLAKE3.deriveKey(fromContentsOf: data, withContext: "agreement").data)!
    }
    
    public var publicKeys: PublicKeyBase {
        PublicKeyBase(signingPublicKey: signingPrivateKey.schnorrPublicKey, agreementPublicKey: agreementPrivateKey.publicKey)
    }
    
    public var ecdsaPublicKeys: PublicKeyBase {
        PublicKeyBase(signingPublicKey: signingPrivateKey.ecdsaPublicKey, agreementPublicKey: agreementPrivateKey.publicKey)
    }
}

extension PrivateKeyBase: URCodable {
    public static let cborTag = Tag(205, "crypto-prvkeys")

    public var untaggedCBOR: CBOR {
        data.cbor
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard case let CBOR.bytes(data) = untaggedCBOR else {
            throw CBORDecodingError.invalidFormat
        }
        self = PrivateKeyBase(data)
    }
}
