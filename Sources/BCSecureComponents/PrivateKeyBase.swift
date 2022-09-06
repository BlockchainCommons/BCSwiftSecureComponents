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

extension PrivateKeyBase {
    public var untaggedCBOR: CBOR {
        data.cbor
    }

    public var taggedCBOR: CBOR {
        CBOR.tagged(.privateKeyBase, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard case let CBOR.data(data) = untaggedCBOR else {
            throw CBORError.invalidFormat
        }
        self.init(data)
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.privateKeyBase, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension PrivateKeyBase {
    public var ur: UR {
        return try! UR(type: .privateKeyBase, cbor: untaggedCBOR)
    }
    
    public init(ur: UR) throws {
        try ur.checkType(.privateKeyBase)
        let cbor = try CBOR(ur.cbor)
        try self.init(untaggedCBOR: cbor)
    }
    
    init(urString: String) throws {
        try self.init(ur: UR(urString: urString))
    }
}

extension PrivateKeyBase: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}
