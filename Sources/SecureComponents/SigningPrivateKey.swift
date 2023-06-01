import Foundation
import WolfBase
import URKit
import BCCrypto

public struct SigningPrivateKey: CustomStringConvertible, Hashable {
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
        self.init(x25519DeriveSigningPrivateKey(keyMaterial: keyMaterial.providedData))!
    }

    public func ecdsaSign(_ message: DataProvider) -> Signature {
        let privateKey = ECPrivateKey(data)!
        let sig = privateKey.ecdsaSign(message.providedData)
        return Signature(ecdsaData: sig)!
    }

    public func schnorrSignUsing<T>(_ message: DataProvider, tag: DataProvider? = nil, rng: inout T) -> Signature
        where T: RandomNumberGenerator
    {
        let privateKey = ECPrivateKey(data)!
        let tag = tag ?? Data()
        let sig = privateKey.schnorrSignUsing(message.providedData, tag: tag.providedData, rng: &rng)
        return Signature(schnorrData: sig, tag: tag)!
    }
    
    public func schnorrSign(_ message: DataProvider, tag: DataProvider? = nil) -> Signature {
        var rng = SecureRandomNumberGenerator()
        return schnorrSignUsing(message, tag: tag, rng: &rng)
    }
    
    public var ecdsaPublicKey: SigningPublicKey {
        SigningPublicKey(ECPrivateKey(data)!.publicKey)
    }
    
    public var schnorrPublicKey: SigningPublicKey {
        SigningPublicKey(ECPrivateKey(data)!.schnorrPublicKey)
    }
    
    public var description: String {
        "SigningPrivateKey"
    }
}

extension SigningPrivateKey: URCodable {
    public static let cborTag = Tag.signingPrivateKey

    public var untaggedCBOR: CBOR {
        data.cbor
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.bytes(data) = untaggedCBOR,
            let key = SigningPrivateKey(data)
        else {
            throw CBORError.invalidFormat
        }
        self = key
    }
}
