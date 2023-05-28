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

    public init() {
        self.data = secureRandomData(32)
    }
    
    public func ecdsaSign(_ message: DataProvider) -> Signature {
        let privateKey = ECPrivateKey(data)!
        let sig = privateKey.ecdsaSign(message: message.providedData)
        return Signature(ecdsaData: sig)!
    }

    public func schnorrSign(_ message: DataProvider, tag: DataProvider? = nil, rng: RandomDataFunc = secureRandomData) -> Signature {
        let privateKey = ECPrivateKey(data)!
        let tag = tag ?? Data()
        let sig = privateKey.schnorrSign(message: message.providedData, tag: tag.providedData, rng: rng)
        return Signature(schnorrData: sig, tag: tag)!
    }
    
    public var ecdsaPublicKey: SigningPublicKey {
        SigningPublicKey(ECPrivateKey(data)!.public)
    }
    
    public var schnorrPublicKey: SigningPublicKey {
        SigningPublicKey(ECPrivateKey(data)!.xOnlyPublic)
    }
    
    public var description: String {
        "PrivateSigningKey(\(data))"
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
