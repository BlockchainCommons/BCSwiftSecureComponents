import Foundation
import WolfBase
import URKit
import BCCrypto
import BCRandom

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
        self.init(Secp256k1.derivePrivateKey(keyMaterial: keyMaterial.providedData))!
    }

    public func secp256k1ECDSASign(_ message: DataProvider) -> Signature {
        let privateKey = SecP256K1PrivateKey(data)!
        let sig = privateKey.secp256k1ecdsaSign(message.providedData)
        return Signature(ecdsaData: sig)!
    }

    public func secp256k1SchnorrSign<T>(_ message: DataProvider, tag: DataProvider?, using rng: inout T) -> Signature
        where T: RandomNumberGenerator
    {
        let privateKey = SecP256K1PrivateKey(data)!
        let tag = tag ?? Data()
        let sig = privateKey.secp256k1schnorrSign(message, tag: tag, using: &rng)
        return Signature(schnorrData: sig, tag: tag)!
    }
    
    public func secp256k1SchnorrSign(_ message: DataProvider, tag: DataProvider?) -> Signature {
        var rng = SecureRandomNumberGenerator()
        return secp256k1SchnorrSign(message, tag: tag, using: &rng)
    }
    
    public var secp256k1ECDSAPublicKey: SigningPublicKey {
        SigningPublicKey(SecP256K1PrivateKey(data)!.secp256k1PublicKey)
    }
    
    public var secp256k1SchnorrPublicKey: SigningPublicKey {
        SigningPublicKey(SecP256K1PrivateKey(data)!.secp256k1SchnorrPublicKey)
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
