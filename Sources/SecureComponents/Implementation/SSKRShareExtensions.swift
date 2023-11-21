import Foundation
import WolfBase
import BCCrypto
import URKit

extension SSKRShare {
    public func bytewords(style: Bytewords.Style) -> String {
        return Bytewords.encode(taggedCBOR.cborData, style: style)
    }

    public init?(bytewords: String) throws {
        guard let share = try? Bytewords.decode(bytewords) else {
            return nil
        }
        self = try SSKRShare(taggedCBORData: share)
    }
}

extension SSKRShare: CustomStringConvertible {
    public var description: String {
        "SSKRShare(\(identifierHex) \(groupIndex + 1)-\(memberIndex + 1))"
    }
}

extension SSKRShare: URCodable {
    public static let cborTags = [Tag.sskrShare, Tag.sskrShareV1]

    public var untaggedCBOR: CBOR {
        Data(data).cbor
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard case let CBOR.bytes(data) = untaggedCBOR else {
            throw CBORError.invalidFormat
        }
        self = SSKRShare(data: data.bytes)
    }
}
