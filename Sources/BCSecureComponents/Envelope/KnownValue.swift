import Foundation
import URKit

public struct KnownValue {
    public let rawValue: UInt64
    public let assignedName: String?
    
    public init(_ rawValue: UInt64, _ name: String?) {
        self.rawValue = rawValue
        self.assignedName = name
    }
    
    public init(rawValue: UInt64) {
        guard let p = knownValuesByRawValue[rawValue] else {
            self = KnownValue(rawValue, nil)
            return
        }
        self = p
    }
    
    public init?(name: String) {
        guard let p = knownValuesByName[name] else {
            return nil
        }
        self = p
    }
    
    public var name: String {
        return assignedName ?? String(rawValue)
    }
}

public extension KnownValue {
    static let id = KnownValue(1, "id")
    static let isA = KnownValue(2, "isA")
    static let verifiedBy = KnownValue(3, "verifiedBy")
    static let note = KnownValue(4, "note")
    static let hasRecipient = KnownValue(5, "hasRecipient")
    static let sskrShare = KnownValue(6, "sskrShare")
    static let controller = KnownValue(7, "controller")
    static let publicKeys = KnownValue(8, "publicKeys")
    static let dereferenceVia = KnownValue(9, "dereferenceVia")
    static let entity = KnownValue(10, "entity")
    static let hasName = KnownValue(11, "hasName")
    static let language = KnownValue(12, "language")
    static let issuer = KnownValue(13, "issuer")
    static let holder = KnownValue(14, "holder")
    static let salt = KnownValue(15, "salt")
    static let date = KnownValue(16, "date")
    
    static let noChange = KnownValue(50, "noChange")
    static let add = KnownValue(51, "add")
    static let delete = KnownValue(52, "delete")
    static let edit = KnownValue(53, "edit")
    static let predicate = KnownValue(54, "predicate")
    static let object = KnownValue(55, "object")

    static let body = KnownValue(100, "body")
    static let result = KnownValue(101, "result")
    static let error = KnownValue(102, "error")
    static let ok = KnownValue(103, "ok")
    static let processing = KnownValue(104, "processing")
}

fileprivate var knownValues: [KnownValue] = [
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
    .salt,
    .date,

    .noChange,
    .add,
    .delete,
    .edit,
    .predicate,
    .object,

    .body,
    .result,
    .error,
    .ok,
    .processing,
]

public extension Envelope {
    static let noChange = Envelope(KnownValue.noChange)
    static let add = Envelope(KnownValue.noChange)
    static let delete = Envelope(KnownValue.noChange)
    static let edit = Envelope(KnownValue.noChange)
    static let predicate = Envelope(KnownValue.noChange)
    static let object = Envelope(KnownValue.noChange)
}

fileprivate var knownValuesByRawValue: [UInt64: KnownValue] = {
    var result: [UInt64: KnownValue] = [:]
    knownValues.forEach {
        result[$0.rawValue] = $0
    }
    return result
}()

fileprivate var knownValuesByName: [String: KnownValue] = {
    var result: [String: KnownValue] = [:]
    knownValues.forEach {
        if let name = $0.assignedName {
            result[name] = $0
        }
    }
    return result
}()

extension KnownValue: Equatable {
    public static func ==(lhs: KnownValue, rhs: KnownValue) -> Bool {
        lhs.rawValue == rhs.rawValue
    }
}

extension KnownValue: CustomStringConvertible {
    public var description: String {
        assignedName ?? String(rawValue)
    }
}

public extension KnownValue {
    var untaggedCBOR: CBOR {
        CBOR.unsignedInt(rawValue)
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.knownValue, untaggedCBOR)
    }
    
    init(untaggedCBOR: CBOR) throws {
        guard
            case CBOR.unsignedInt(let rawValue) = untaggedCBOR
        else {
            throw EnvelopeError.invalidFormat
        }
        self = KnownValue(rawValue: rawValue)
    }
    
    init(taggedCBOR: CBOR) throws {
        guard
            case CBOR.tagged(.knownValue, let untaggedCBOR) = taggedCBOR
        else {
            throw EnvelopeError.invalidFormat
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

extension KnownValue: DigestProvider {
    public var digest: Digest {
        Digest(taggedCBOR)
    }
}

extension KnownValue: CBORCodable {
    public var cbor: CBOR {
        taggedCBOR
    }
    
    public static func cborDecode(_ cbor: CBOR) throws -> KnownValue {
        return try KnownValue(taggedCBOR: cbor)
    }
}

extension KnownValue {
    var formatItem: EnvelopeFormatItem {
        .item(name)
    }
}
