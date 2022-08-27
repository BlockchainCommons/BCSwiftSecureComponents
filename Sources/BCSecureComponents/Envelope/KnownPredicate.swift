import Foundation
import URKit

public struct KnownPredicate {
    public let rawValue: UInt64
    public let name: String
    
    public init(_ rawValue: UInt64, _ name: String) {
        self.rawValue = rawValue
        self.name = name
    }
    
    public init(rawValue: UInt64) {
        guard let p = knownPredicatesByRawValue[rawValue] else {
            self = KnownPredicate(rawValue, "UNKNOWN")
            return
        }
        self = p
    }
}

public extension KnownPredicate {
    static let id = KnownPredicate(1, "id")
    static let isA = KnownPredicate(2, "isA")
    static let verifiedBy = KnownPredicate(3, "verifiedBy")
    static let note = KnownPredicate(4, "note")
    static let hasRecipient = KnownPredicate(5, "hasRecipient")
    static let sskrShare = KnownPredicate(6, "sskrShare")
    static let controller = KnownPredicate(7, "controller")
    static let publicKeys = KnownPredicate(8, "publicKeys")
    static let dereferenceVia = KnownPredicate(9, "dereferenceVia")
    static let entity = KnownPredicate(10, "entity")
    static let hasName = KnownPredicate(11, "hasName")
    static let language = KnownPredicate(12, "language")
    static let issuer = KnownPredicate(13, "issuer")
    static let holder = KnownPredicate(14, "holder")
    static let body = KnownPredicate(15, "body")
    static let result = KnownPredicate(16, "result")
    static let salt = KnownPredicate(17, "salt")
}

fileprivate var knownPredicates: [KnownPredicate] = [
    .id,
    .isA,
    .verifiedBy,
    .note,
    .hasRecipient,
    .sskrShare,
    .controller,
    .publicKeys,
    .dereferenceVia,
    .entity,
    .hasName,
    .language,
    .issuer,
    .holder,
    .body,
    .result,
    .salt,
]

fileprivate var knownPredicatesByRawValue: [UInt64: KnownPredicate] = {
    var result: [UInt64: KnownPredicate] = [:]
    knownPredicates.forEach {
        result[$0.rawValue] = $0
    }
    return result
}()

extension KnownPredicate: Equatable {
    public static func ==(lhs: KnownPredicate, rhs: KnownPredicate) -> Bool {
        lhs.rawValue == rhs.rawValue
    }
}

extension KnownPredicate: CustomStringConvertible {
    public var description: String {
        name
    }
}

public extension KnownPredicate {
    var untaggedCBOR: CBOR {
        CBOR.unsignedInt(rawValue)
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.knownPredicate, untaggedCBOR)
    }
    
    init(untaggedCBOR: CBOR) throws {
        guard
            case CBOR.unsignedInt(let rawValue) = untaggedCBOR
        else {
            throw EnvelopeError.invalidFormat
        }
        self = KnownPredicate(rawValue: rawValue)
    }
    
    init(taggedCBOR: CBOR) throws {
        guard
            case CBOR.tagged(.knownPredicate, let untaggedCBOR) = taggedCBOR
        else {
            throw EnvelopeError.invalidFormat
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

extension KnownPredicate: DigestProvider {
    public var digest: Digest {
        Digest(taggedCBOR)
    }
}

extension KnownPredicate: CBORCodable {
    public var cbor: CBOR {
        taggedCBOR
    }
    
    public static func cborDecode(_ cbor: CBOR) throws -> KnownPredicate {
        return try KnownPredicate(taggedCBOR: cbor)
    }
}

extension KnownPredicate {
    var formatItem: EnvelopeFormatItem {
        .item(name)
    }
}
