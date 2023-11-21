import Foundation
import URKit

extension URL: CBORTaggedCodable {
    public static var cborTags: [Tag] = [32]
    
    public var untaggedCBOR: CBOR {
        absoluteString.cbor
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.text(string) = untaggedCBOR,
            let result = URL(string: string)
        else {
            throw CBORError.invalidFormat
        }
        self = result
    }
}
