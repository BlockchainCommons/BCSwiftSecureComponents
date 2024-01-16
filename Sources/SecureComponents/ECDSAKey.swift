import Foundation
import URKit
import WolfBase
import BCCrypto

public protocol ECKeyBase: Hashable {
    static var keyLen: Int { get }

    var data: Data { get }
    
    init?(_ data: DataProvider)
    
    var hex: String { get }
    init?(hex: String)
}

extension ECKeyBase {
    public var hex: String {
        data.hex
    }

    public var description: String {
        hex
    }
}

public protocol ECDSAKey: ECKeyBase, UREncodable {
    var ecdsaPublicKey: ECDSAPublicKey { get }
}

public protocol Ed25519Key: ECKeyBase {
    var ed25519PublicKey: Ed25519PublicKey { get }
}

public protocol ECDSAPublicKeyProtocol: ECDSAKey {
    var uncompressedPublicKey: ECUncompressedPublicKey { get }
}

public struct ECPrivateKey: ECDSAKey, Ed25519Key {
    public static let cborTags = [Tag.ecKey, Tag.ecKeyV1]
    public static let keyLen = ecdsaPrivateKeySize
    public let data: Data

    public init?(_ data: DataProvider) {
        let data = data.providedData
        guard data.count == Self.keyLen else {
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

    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }

    public var ecdsaPublicKey: ECDSAPublicKey {
        ECDSAPublicKey(ecdsaPublicKeyFromPrivateKey(privateKey: data))!
    }
    
    public var schnorrPublicKey: SchnorrPublicKey {
        SchnorrPublicKey(schnorrPublicKeyFromPrivateKey(privateKey: data))!
    }
    
    public var ed25519PublicKey: Ed25519PublicKey {
        Ed25519PublicKey(ed25519PublicKeyFromPrivateKey(privateKey: data))!
    }
    
    public func ecdsaSign(_ message: DataProvider) -> Data {
        BCCrypto.ecdsaSign(privateKeyECDSA: data, message: message.providedData)
    }
    
    public func schnorrSign<T>(_ message: DataProvider, tag: DataProvider, using rng: inout T) -> Data
        where T: RandomNumberGenerator
    {
        BCCrypto.schnorrSign(ecdsaPrivateKey: self.data, message: message.providedData, tag: tag.providedData, rng: &rng)
    }
    
    public func schnorrSign(_ message: DataProvider, tag: DataProvider) -> Data {
        var rng = SecureRandomNumberGenerator()
        return schnorrSign(message, tag: tag, using: &rng)
    }
    
    public var wif: String {
        Wally.encodeWIF(key: data, network: .mainnet, isPublicKeyCompressed: true)
    }
    
    public var untaggedCBOR: CBOR {
        ([2: true, 3: data] as Map).cbor
    }
}

extension ECPrivateKey: CustomStringConvertible {
}

public struct SchnorrPublicKey: ECKeyBase {
    public static let keyLen = 32
    public let data: Data

    public init?(_ data: DataProvider) {
        let data = data.providedData
        guard data.count == Self.keyLen else {
            return nil
        }
        self.data = data
    }
    
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }
    
    public func schnorrVerify(signature: Data, message: DataProvider, tag: DataProvider) -> Bool {
        BCCrypto.schnorrVerify(schnorrPublicKey: data, signature: signature, message: message.providedData, tag: tag.providedData)
    }
}

public struct Ed25519PublicKey: ECKeyBase, Ed25519Key {
    public static let keyLen = 32
    public let data: Data

    public init?(_ data: DataProvider) {
        let data = data.providedData
        guard data.count == Self.keyLen else {
            return nil
        }
        self.data = data
    }
    
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }

    public var ed25519PublicKey: Ed25519PublicKey { self }

    public func ed25519Verify(signature: Data, message: DataProvider) -> Bool {
        BCCrypto.ed25519Verify(publicKey: data, signature: signature, message: message.providedData)
    }
}

public struct ECDSAPublicKey: ECDSAPublicKeyProtocol, Hashable {
    public static let cborTags = [Tag.ecKey, Tag.ecKeyV1]
    public static var keyLen = ecdsaPublicKeySize
    public let data: Data

    public init?(_ data: DataProvider) {
        let data = data.providedData
        guard data.count == Self.keyLen else {
            return nil
        }
        self.data = data
    }
    
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }

    public var ecdsaPublicKey: ECDSAPublicKey {
        self
    }
    
    public var uncompressedPublicKey: ECUncompressedPublicKey {
        ECUncompressedPublicKey(ecdsaDecompressPublicKey(compressedPublicKey: data))!
    }
    
    public func verify(signature: Data, message: DataProvider) -> Bool {
        precondition(signature.count == 64)
        return ecdsaVerify(publicKeyECDSA: data, signature: signature, message: message.providedData)
    }
    
    public var hash160: Data {
        data.hash160
    }

    public var untaggedCBOR: CBOR {
        // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-008-eckey.md#cddl
        ([3: data] as Map).cbor
    }
}

extension ECDSAPublicKey: CustomStringConvertible {
}

public struct ECUncompressedPublicKey: ECDSAPublicKeyProtocol {
    public static let cborTags = [Tag.ecKey, Tag.ecKeyV1]
    public static var keyLen = ecdsaPublicKeyUncompressedSize
    public let data: Data

    public init?(_ data: DataProvider) {
        let data = data.providedData
        guard data.count == Self.keyLen else {
            return nil
        }
        self.data = data
    }
    
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }

    public var ecdsaPublicKey: ECDSAPublicKey {
        ECDSAPublicKey(ecdsaCompressPublicKey(uncompressedPublicKey: data))!
    }
    
    public var uncompressedPublicKey: ECUncompressedPublicKey {
        self
    }

    public var untaggedCBOR: CBOR {
        // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-008-eckey.md#cddl
        ([3: data] as Map).cbor
    }
}

extension ECUncompressedPublicKey: CustomStringConvertible {
}
