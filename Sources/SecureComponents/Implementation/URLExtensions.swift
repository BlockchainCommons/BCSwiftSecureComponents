import Foundation
import URKit

extension URL: @retroactive CBORTaggedDecodable {}
extension URL: @retroactive CBORDecodable {}
extension URL: @retroactive CBORTaggedEncodable {}
extension URL: @retroactive CBOREncodable {}
extension URL: @retroactive CBORCodable {}
extension URL: @retroactive CBORTaggedCodable {
    public static let cborTags: [Tag] = [32]
    
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
