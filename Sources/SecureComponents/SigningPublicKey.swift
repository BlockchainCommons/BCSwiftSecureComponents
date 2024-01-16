import Foundation
import WolfBase
import URKit

public enum SigningPublicKey {
    case schnorr(SchnorrPublicKey)
    case ecdsa(ECDSAPublicKey)
    
    public init(_ key: SchnorrPublicKey) {
        self = .schnorr(key)
    }
    
    public init(_ key: ECDSAPublicKey) {
        self = .ecdsa(key)
    }
    
    public func verify(signature: Signature, for message: DataProvider) -> Bool {
        switch self {
        case .schnorr(let key):
            switch signature {
            case .schnorr(let sigData, let tag):
                return key.schnorrVerify(signature: sigData, message: message, tag: tag)
            default:
                return false
            }
        case .ecdsa(let key):
            switch signature {
            case .ecdsa(let sigData):
                return key.verify(signature: sigData, message: message)
            default:
                return false
            }
        }
    }
    
    public var data: Data {
        switch self {
        case .schnorr(let key):
            return key.data
        case .ecdsa(let key):
            return key.data
        }
    }
}

extension SigningPublicKey: Hashable {
    public static func ==(lhs: SigningPublicKey, rhs: SigningPublicKey) -> Bool {
        switch lhs {
        case .schnorr(let lhsData):
            switch rhs {
            case .schnorr(let rhsData):
                return lhsData == rhsData
            default:
                return false
            }
        case .ecdsa(let lhsKey):
            switch rhs {
            case .ecdsa(let rhsKey):
                return lhsKey == rhsKey
            default:
                return false
            }
        }
    }
    
    public func hash(into hasher: inout Hasher) {
        switch self {
        case .schnorr(let data):
            hasher.combine(data)
        case .ecdsa(let key):
            hasher.combine(key)
        }
    }
}

extension SigningPublicKey: URCodable {
    public static let cborTags = [Tag.signingPublicKey]

    public var untaggedCBOR: CBOR {
        switch self {
        case .schnorr(let key):
            return key.data.cbor
        case .ecdsa(let key):
            return [1.cbor, key.data.cbor]
        }
    }
    
    public init(untaggedCBOR: CBOR) throws {
        if case let CBOR.bytes(data) = untaggedCBOR,
           let key = SchnorrPublicKey(data)
        {
            self = .schnorr(key)
            return
        } else if case let CBOR.array(elements) = untaggedCBOR,
                  elements.count == 2,
                  case CBOR.unsigned(1) = elements[0],
                  case let CBOR.bytes(data) = elements[1],
                  let key = ECDSAPublicKey(data)
        {
            self = .ecdsa(key)
            return
        }
        throw CBORError.invalidFormat
    }
}

extension SigningPublicKey: CustomStringConvertible {
    public var description: String {
        "SigningPublicKey(\(data.hex))"
    }
}
