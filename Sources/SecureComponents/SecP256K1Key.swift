import Foundation
import URKit
import WolfBase
import BCCrypto
import BCRandom

public protocol KeyProtocol: Hashable {
    static var keyLen: Int { get }

    var data: Data { get }
    
    init?(_ data: DataProvider)
    
    var hex: String { get }
    init?(hex: String)
}

extension KeyProtocol {
    public var hex: String {
        data.hex
    }

    public var description: String {
        hex
    }
}

public protocol SecP256K1Key: KeyProtocol, UREncodable {
    var secp256k1PublicKey: SecP256K1PublicKey { get }
}

public protocol Ed25519Key: KeyProtocol {
    var ed25519PublicKey: Ed25519PublicKey { get }
}

public protocol SecP256K1PublicKeyProtocol: SecP256K1Key {
    var uncompressedPublicKey: SecP256K1UncompressedPublicKey { get }
}

public struct ECPrivateKey: SecP256K1Key, Ed25519Key {
    public static let cborTags = [Tag.ecKey, Tag.ecKeyV1]
    public static let keyLen = Secp256k1.privateKeySize
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

    public var secp256k1PublicKey: SecP256K1PublicKey {
        SecP256K1PublicKey(Secp256k1.ECDSA.derivePublicKey(privateKey: data))!
    }
    
    public var secp256k1SchnorrPublicKey: SecP256K1SchnorrPublicKey {
        SecP256K1SchnorrPublicKey(Secp256k1.Schnorr.derivePublicKey(privateKey: data))!
    }
    
    public var ed25519PublicKey: Ed25519PublicKey {
        Ed25519PublicKey(Ed25519.derivePublicKey(privateKey: data))!
    }
    
    public func secp256k1ecdsaSign(_ message: DataProvider) -> Data {
        Secp256k1.ECDSA.sign(privateKey: data, message: message.providedData)
    }
    
    public func secp256k1schnorrSign<T>(_ message: DataProvider, tag: DataProvider, using rng: inout T) -> Data
        where T: RandomNumberGenerator
    {
        Secp256k1.Schnorr.sign(privateKey: self.data, message: message.providedData, tag: tag.providedData, rng: &rng)
    }
    
    public func secp256k1schnorrSign(_ message: DataProvider, tag: DataProvider) -> Data {
        var rng = SecureRandomNumberGenerator()
        return secp256k1schnorrSign(message, tag: tag, using: &rng)
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

public struct SecP256K1SchnorrPublicKey: KeyProtocol {
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
        Secp256k1.Schnorr.verify(schnorrPublicKey: data, signature: signature, message: message.providedData, tag: tag.providedData)
    }
}

public struct Ed25519PublicKey: KeyProtocol, Ed25519Key {
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
        Ed25519.verify(publicKey: data, signature: signature, message: message.providedData)
    }
}

public struct SecP256K1PublicKey: SecP256K1PublicKeyProtocol, Hashable {
    public static let cborTags = [Tag.ecKey, Tag.ecKeyV1]
    public static var keyLen = Secp256k1.publicKeySize
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

    public var secp256k1PublicKey: SecP256K1PublicKey {
        self
    }
    
    public var uncompressedPublicKey: SecP256K1UncompressedPublicKey {
        SecP256K1UncompressedPublicKey(Secp256k1.ECDSA.uncompressPublicKey(compressedPublicKey: data))!
    }
    
    public func verify(signature: Data, message: DataProvider) -> Bool {
        precondition(signature.count == 64)
        return Secp256k1.ECDSA.verify(publicKey: data, signature: signature, message: message.providedData)
    }
    
    public var hash160: Data {
        data.hash160
    }

    public var untaggedCBOR: CBOR {
        // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-008-eckey.md#cddl
        ([3: data] as Map).cbor
    }
}

extension SecP256K1PublicKey: CustomStringConvertible {
}

public struct SecP256K1UncompressedPublicKey: SecP256K1PublicKeyProtocol {
    public static let cborTags = [Tag.ecKey, Tag.ecKeyV1]
    public static var keyLen = Secp256k1.uncompressedPublicKeySize
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

    public var secp256k1PublicKey: SecP256K1PublicKey {
        SecP256K1PublicKey(Secp256k1.ECDSA.compressPublicKey(uncompressedPublicKey: data))!
    }
    
    public var uncompressedPublicKey: SecP256K1UncompressedPublicKey {
        self
    }

    public var untaggedCBOR: CBOR {
        // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-008-eckey.md#cddl
        ([3: data] as Map).cbor
    }
}

extension SecP256K1UncompressedPublicKey: CustomStringConvertible {
}
