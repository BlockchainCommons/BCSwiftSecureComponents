import Foundation
import BLAKE3
import URKit
import WolfBase

/// A cryptographically secure digest.
///
/// Implemented with BLAKE3 hashing.
///
/// https://datatracker.ietf.org/doc/rfc7693
public struct Digest: CustomStringConvertible, Hashable {
    public let data: Data
    public static let defaultDigestLength = 32
    
    public init(_ data: DataProvider, digestLength: Int = defaultDigestLength) {
        self.data = BLAKE3.hash(contentsOf: data.providedData, outputByteCount: digestLength).data
    }
    
    public init?(_ data: DataProvider, includeDigest: Bool, digestLength: Int = defaultDigestLength) {
        guard includeDigest else {
            return nil
        }
        self.init(data, digestLength: digestLength)
    }
    
    public init?(rawValue: Data, digestLength: Int = defaultDigestLength) {
        guard rawValue.count == digestLength else {
            return nil
        }
        self.data = rawValue
    }
}

public extension Digest {
    var description: String {
        "Digest(\(data.hex))"
    }
    
    func validate(_ data: DataProvider) -> Bool {
        self == Digest(data, digestLength: self.data.count)
    }
    
    static func validate(_ data: DataProvider, digest: Digest?) -> Bool {
        guard let digest else {
            return true
        }
        return digest.validate(data)
    }
}

public extension Digest {
    init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }
    
    var hex: String {
        data.hex
    }
}

extension Digest: Comparable {
    public static func < (lhs: Digest, rhs: Digest) -> Bool {
        lhs.data.lexicographicallyPrecedes(rhs.data)
    }
}

extension Digest: DataProvider {
    public var providedData: Data {
        data
    }
}

extension Digest: DigestProvider {
    public var digest: Digest {
        self
    }
}

public func +(lhs: Digest, rhs: Digest) -> Data {
    lhs.data + rhs.data
}

public func +(lhs: Data, rhs: Digest) -> Data {
    lhs + rhs.data
}

public extension Digest {
    var shortDescription: String {
        String(self.data.hex.prefix(count: 8))
    }
}

extension Digest: URCodable {
    public static let urType = "crypto-digest"
    public static let cborTag: UInt64 = 203

    public var untaggedCBOR: CBOR {
        CBOR(bytes: data)
    }

    public static func decodeUntaggedCBOR(_ cbor: CBOR) throws -> Digest {
        guard
            case let CBOR.bytes(data) = cbor,
            let value = Digest(rawValue: data)
        else {
            throw DecodeError.invalidFormat
        }
        return value
    }
}
