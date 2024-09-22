import Foundation
import URKit

extension UUID: @retroactive CBORTaggedDecodable {}
extension UUID: @retroactive CBORDecodable {}
extension UUID: @retroactive CBORTaggedEncodable {}
extension UUID: @retroactive CBOREncodable {}
extension UUID: @retroactive CBORCodable {}
extension UUID: @retroactive CBORTaggedCodable {
    public static let cborTags: [Tag] = [37]

    public var untaggedCBOR: CBOR {
        serialized.cbor
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.bytes(bytes) = untaggedCBOR,
            bytes.count == MemoryLayout<uuid_t>.size
        else {
            throw CBORError.invalidFormat
        }
        self = bytes.withUnsafeBytes {
            UUID(uuid: $0.bindMemory(to: uuid_t.self).baseAddress!.pointee)
        }
    }
}
