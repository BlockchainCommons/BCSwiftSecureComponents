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

    public func schnorrSign<T>(_ message: DataProvider, tag: DataProvider?, using rng: inout T) -> Signature
        where T: RandomNumberGenerator
    {
        let privateKey = ECPrivateKey(data)!
        let tag = tag ?? Data()
        let sig = privateKey.schnorrSign(message, tag: tag, using: &rng)
        return Signature(schnorrData: sig, tag: tag)!
    }
    
    public func schnorrSign(_ message: DataProvider, tag: DataProvider?) -> Signature {
        var rng = SecureRandomNumberGenerator()
        return schnorrSign(message, tag: tag, using: &rng)
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
    public static let cborTags = [Tag.signingPrivateKey]

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
