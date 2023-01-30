import Foundation
import URKit

extension URL: TaggedCBORCodable {
    public static var cborTag: UInt64 = 32
    
    public var untaggedCBOR: CBOR {
        absoluteString.cbor
    }
    
    public static func decodeUntaggedCBOR(_ cbor: CBOR) throws -> URL {
        guard
            case let CBOR.text(string) = cbor,
            let result = URL(string: string)
        else {
            throw DecodeError.invalidFormat
        }
        return result
    }
}
