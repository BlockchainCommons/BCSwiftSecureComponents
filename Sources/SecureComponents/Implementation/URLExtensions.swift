import Foundation
import URKit

extension URL: CBORTaggedCodable {
    public static var cborTag: Tag = 32
    
    public var untaggedCBOR: CBOR {
        absoluteString.cbor
    }
    
    public static func decodeUntaggedCBOR(_ cbor: CBOR) throws -> URL {
        guard
            case let CBOR.text(string) = cbor,
            let result = URL(string: string)
        else {
            throw CBORDecodingError.invalidFormat
        }
        return result
    }
}
