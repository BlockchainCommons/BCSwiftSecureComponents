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

public protocol ECKey: ECKeyBase, UREncodable {
    var publicKey: ECPublicKey { get }
}

extension ECKeyBase {
    public var hex: String {
        data.hex
    }

    public var description: String {
        hex
    }
}

public protocol ECPublicKeyProtocol: ECKey {
    var uncompressedPublicKey: ECUncompressedPublicKey { get }
}

public struct ECPrivateKey: ECKey {
    public static let cborTag = Tag.ecKey
    public static let keyLen = Crypto.ecdsaPrivateKeySize
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

    public var publicKey: ECPublicKey {
        ECPublicKey(Crypto.ecdsaPublicKeyFromPrivateKey(privateKey: data))!
    }
    
    public var schnorrPublicKey: SchnorrPublicKey {
        SchnorrPublicKey(Crypto.schnorrPublicKeyFromPrivateKey(privateKey: data))!
    }
    
    public func ecdsaSign(_ message: DataProvider) -> Data {
        Crypto.ecdsaSign(privateKeyECDSA: data, message: message.providedData)
    }
    
    public func schnorrSignUsing<T>(_ message: DataProvider, tag: DataProvider, rng: inout T) -> Data
        where T: RandomNumberGenerator
    {
        Crypto.schnorrSign(ecdsaPrivateKey: self.data, message: message.providedData, tag: tag.providedData, rng: &rng)
    }
    
    public func schnorrSign(_ message: DataProvider, tag: DataProvider) -> Data {
        var rng = SecureRandomNumberGenerator()
        return schnorrSignUsing(message, tag: tag, rng: &rng)
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
        Crypto.schnorrVerify(schnorrPublicKey: data, signature: signature, message: message.providedData, tag: tag.providedData)
    }
}

public struct ECPublicKey: ECPublicKeyProtocol, Hashable {
    public static let cborTag = Tag.ecKey
    public static var keyLen = Crypto.ecdsaPublicKeySize
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

    public var publicKey: ECPublicKey {
        self
    }
    
    public var uncompressedPublicKey: ECUncompressedPublicKey {
        ECUncompressedPublicKey(Crypto.ecdsaDecompressPublicKey(compressedPublicKey: data))!
    }
    
    public func verify(signature: Data, message: DataProvider) -> Bool {
        precondition(signature.count == 64)
        return Crypto.ecdsaVerify(publicKeyECDSA: data, signature: signature, message: message.providedData)
    }
    
    public var hash160: Data {
        data.hash160
    }

    public var untaggedCBOR: CBOR {
        // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-008-eckey.md#cddl
        ([3: data] as Map).cbor
    }
}

extension ECPublicKey: CustomStringConvertible {
}

public struct ECUncompressedPublicKey: ECPublicKeyProtocol {
    public static let cborTag = Tag.ecKey
    public static var keyLen = Crypto.ecdsaPublicKeyUncompressedSize
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

    public var publicKey: ECPublicKey {
        ECPublicKey(Crypto.ecdsaCompressPublicKey(uncompressedPublicKey: data))!
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
