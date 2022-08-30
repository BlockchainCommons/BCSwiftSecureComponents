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
    
    public var description: String {
        "Digest(\(data.hex))"
    }
    
    public func validate(_ data: DataProvider) -> Bool {
        self == Digest(data, digestLength: self.data.count)
    }
    
    public static func validate(_ data: DataProvider, digest: Digest?) -> Bool {
        guard let digest else {
            return true
        }
        return digest.validate(data)
    }
}

extension Digest: Comparable {
    public static func < (lhs: Digest, rhs: Digest) -> Bool {
        lhs.data.lexicographicallyPrecedes(rhs.data)
    }
}

extension Digest {
    public var untaggedCBOR: CBOR {
        CBOR.data(self.data)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.digest, untaggedCBOR)
    }
    
    public static func optionalTaggedCBOR(_ digest: Digest?) -> CBOR {
        guard let digest else {
            return CBOR.null
        }
        return digest.taggedCBOR
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.data(data) = untaggedCBOR,
            let digest = Digest(rawValue: data)
        else {
            throw CBORError.invalidFormat
        }
        self = digest
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.digest, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
    
    public init?(optionalTaggedCBOR cbor: CBOR) throws {
        guard cbor != .null else {
            return nil
        }
        try self.init(taggedCBOR: cbor)
    }
}

extension Digest {
    public var ur: UR {
        return try! UR(type: .digest, cbor: untaggedCBOR)
    }
    
    public init(ur: UR) throws {
        try ur.checkType(.digest)
        let cbor = try CBOR(ur.cbor)
        try self.init(untaggedCBOR: cbor)
    }
}

extension Digest: CBORCodable {
    public static func cborDecode(_ cbor: URKit.CBOR) throws -> Digest {
        try Digest(taggedCBOR: cbor)
    }
    
    public var cbor: CBOR {
        taggedCBOR
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
