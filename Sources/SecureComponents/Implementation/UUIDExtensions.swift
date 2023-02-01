import Foundation
import URKit

extension UUID: CBORTaggedCodable {
    public static let cborTag: Tag = 37

    public var untaggedCBOR: CBOR {
        serialized.cbor
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.bytes(bytes) = untaggedCBOR,
            bytes.count == MemoryLayout<uuid_t>.size
        else {
            throw CBORDecodingError.invalidFormat
        }
        self = bytes.withUnsafeBytes {
            UUID(uuid: $0.bindMemory(to: uuid_t.self).baseAddress!.pointee)
        }
    }
}
