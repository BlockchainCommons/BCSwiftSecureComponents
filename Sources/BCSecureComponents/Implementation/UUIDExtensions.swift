import Foundation
import URKit

extension UUID {
    public var untaggedCBOR: CBOR {
        CBOR.data(serialized)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.uuid, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.data(bytes) = untaggedCBOR,
            bytes.count == MemoryLayout<uuid_t>.size
        else {
            throw CBORError.invalidFormat
        }
        self = bytes.withUnsafeBytes {
            UUID(uuid: $0.bindMemory(to: uuid_t.self).baseAddress!.pointee)
        }
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.uuid, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

extension UUID: CBORCodable {
    public static func cborDecode(_ cbor: CBOR) throws -> UUID {
        try UUID(taggedCBOR: cbor)
    }
    
    public var cbor: CBOR {
        taggedCBOR
    }
}
