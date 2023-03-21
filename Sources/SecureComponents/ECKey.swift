import Foundation
import URKit
import WolfBase
import BCCrypto

public protocol ECKey: UREncodable {
    static var keyLen: Int { get }

    var data: Data { get }
    
    init?(_ data: DataProvider)
    
    var hex: String { get }
    
    var `public`: ECPublicKey { get }
}

extension ECKey {
    public var hex: String {
        data.hex
    }

    public var description: String {
        hex
    }
}

public protocol ECPublicKeyProtocol: ECKey {
    var compressed: ECPublicKey { get }
    var uncompressed: ECUncompressedPublicKey { get }
}

public struct ECPrivateKey: ECKey {
    public static let cborTag = Tag.ecKey
    public static let keyLen = Crypto.privateKeyLenECDSA
    public let data: Data

    public init?(_ data: DataProvider) {
        let data = data.providedData
        guard data.count == Self.keyLen else {
            return nil
        }
        self.data = data
    }
    
    public init() {
        self.data = Crypto.randomData(count: 32)
    }

    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }

    public var `public`: ECPublicKey {
        ECPublicKey(Crypto.publicKeyFromPrivateKeyECDSA(privateKey: data))!
    }
    
    public var xOnlyPublic: ECXOnlyPublicKey {
        ECXOnlyPublicKey(Crypto.xOnlyPublicKeyFromPrivateKeyECDSA(data: data))!
    }
    
    public func ecdsaSign(message: DataProvider) -> Data {
        Crypto.signECDSA(message: message.providedData, privateKeyECDSA: data)
    }
    
    public func schnorrSign(message: DataProvider, tag: DataProvider, randomGenerator: Crypto.RandomGenerator = Crypto.randomData) -> Data {
        Crypto.signSchnorr(message: message.providedData, tag: tag.providedData, privateKeyECDSA: self.data, randomGenerator: randomGenerator)
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

public struct ECXOnlyPublicKey: Hashable {
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
    
    public func schnorrVerify(signature: Data, tag: DataProvider, message: DataProvider) -> Bool {
        Crypto.verifySchnorr(message: message.providedData, tag: tag.providedData, signature: signature, xOnlyPublicKeyECDSA: data)
    }
}

public struct ECPublicKey: ECPublicKeyProtocol, Hashable {
    public static let cborTag = Tag.ecKey
    public static var keyLen = Crypto.publicKeyLenECDSA
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

    public var compressed: ECPublicKey {
        self
    }
    
    public var uncompressed: ECUncompressedPublicKey {
        ECUncompressedPublicKey(Crypto.decompressPublicKeyECDSA(compressedPublicKey: data))!
    }

    public var `public`: ECPublicKey {
        self
    }
    
    public func verify(message: DataProvider, signature: Data) -> Bool {
        precondition(signature.count == 64)
        return Crypto.verifyECDSA(message: message.providedData, signature: signature, publicKeyECDSA: data)
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
    public static var keyLen = Crypto.publicKeyUncompressedLenECDSA
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

    public var compressed: ECPublicKey {
        ECPublicKey(Crypto.compressPublicKeyECDSA(decompressedPublicKey: data))!
    }
    
    public var uncompressed: ECUncompressedPublicKey {
        self
    }

    public var `public`: ECPublicKey {
        self.compressed
    }

    public var untaggedCBOR: CBOR {
        // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-008-eckey.md#cddl
        ([3: data] as Map).cbor
    }
}

extension ECUncompressedPublicKey: CustomStringConvertible {
}
