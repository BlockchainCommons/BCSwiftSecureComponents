import Foundation
import CryptoKit
import WolfBase
import URKit

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
        self.data = SecureRandomNumberGenerator.shared.data(count: 32)
    }
    
    public func ecdsaSign(_ message: DataProvider) -> Signature {
        let privateKey = ECPrivateKey(data)!
        let sig = privateKey.ecdsaSign(message: message.providedData)
        return Signature(ecdsaData: sig)!
    }

    public func schnorrSign(_ message: DataProvider, tag: DataProvider? = nil, randomGenerator: ((Int) -> Data)? = nil) -> Signature {
        let privateKey = ECPrivateKey(data)!
        let tag = tag ?? Data()
        let sig = privateKey.schnorrSign(message: message.providedData, tag: tag.providedData, randomGenerator: randomGenerator)
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
    public static let urType = "signing-private-key"
    public static let cborTag: UInt64 = 704

    public var untaggedCBOR: CBOR {
        data.cbor
    }
    
    public static func decodeUntaggedCBOR(_ cbor: CBOR) throws -> SigningPrivateKey {
        guard
            case let CBOR.bytes(data) = cbor,
            let key = SigningPrivateKey(data)
        else {
            throw DecodeError.invalidFormat
        }
        return key
    }
}
