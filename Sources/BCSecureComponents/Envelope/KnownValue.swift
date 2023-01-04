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

fileprivate var knownValuesByRawValue: [UInt64: KnownValue] = {
    var result: [UInt64: KnownValue] = [:]
    knownValueRegistry.forEach {
        result[$0.rawValue] = $0
    }
    return result
}()

fileprivate var knownValuesByName: [String: KnownValue] = {
    var result: [String: KnownValue] = [:]
    knownValueRegistry.forEach {
        if let name = $0.assignedName {
            result[name] = $0
        }
    }
    return result
}()
