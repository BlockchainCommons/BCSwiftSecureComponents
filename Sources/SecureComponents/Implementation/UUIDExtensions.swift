import Foundation
import URKit

extension UUID: TaggedCBORCodable {
    public static let cborTag: UInt64 = 37

    public var untaggedCBOR: CBOR {
        serialized.cbor
    }
    
    public static func decodeUntaggedCBOR(_ cbor: CBOR) throws -> UUID {
        guard
            case let CBOR.bytes(bytes) = cbor,
            bytes.count == MemoryLayout<uuid_t>.size
        else {
            throw DecodeError.invalidFormat
        }
        return bytes.withUnsafeBytes {
            UUID(uuid: $0.bindMemory(to: uuid_t.self).baseAddress!.pointee)
        }
    }
}
