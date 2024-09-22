import Foundation
import URKit
import WolfBase

public enum Signature: Sendable {
    case schnorr(data: Data)
    case ecdsa(data: Data)
    
    public init?(schnorrData data: DataProvider) {
        let data = data.providedData
        guard data.count == 64 else {
            return nil
        }
        self = .schnorr(data: data)
    }
    
    public init?(ecdsaData data: DataProvider) {
        let data = data.providedData
        guard data.count == 64 else {
            return nil
        }
        self = .ecdsa(data: data)
    }
}

extension Signature: Equatable {
    public static func ==(lhs: Signature, rhs: Signature) -> Bool {
        switch lhs {
        case .schnorr(let lhsData):
            switch rhs {
            case .schnorr(let rhsData):
                return lhsData == rhsData
            default:
                return false
            }
        case .ecdsa(let lhsData):
            switch rhs {
            case .ecdsa(let rhsData):
                return lhsData == rhsData
            default:
                return false
            }
        }
    }
}

extension Signature: URCodable {
    public static let cborTags = [Tag.signature]

    public var untaggedCBOR: CBOR {
        switch self {
        case .schnorr(let data):
            return data.cbor
        case .ecdsa(let data):
            return [1.cbor, data.cbor]
        }
    }
    
    public init(untaggedCBOR: CBOR) throws {
        if
            case let CBOR.bytes(data) = untaggedCBOR
        {
            self = .schnorr(data: data)
        } else if
            case let CBOR.array(elements) = untaggedCBOR,
            elements.count == 2,
            case CBOR.unsigned(1) = elements[0],
            case let CBOR.bytes(data) = elements[1]
        {
            self = .ecdsa(data: data)
        } else {
            throw CBORError.invalidFormat
        }
    }
}
