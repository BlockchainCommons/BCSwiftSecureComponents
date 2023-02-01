import Foundation
import WolfBase
import URKit

public struct Nonce: CustomStringConvertible, Equatable, Hashable, DataProvider {
    public let data: Data
    
    public init?(_ data: Data) {
        guard data.count == 12 else {
            return nil
        }
        self.data = data
    }
    
    public init() {
        self.init(SecureRandomNumberGenerator.shared.data(count: 12))!
    }
}

public extension Nonce {
    var bytes: [UInt8] {
        data.bytes
    }
    
    var description: String {
        data.hex.flanked("Nonce(", ")")
    }
    
    var providedData: Data {
        data
    }
}

extension Nonce: URCodable {
    public static let cborTag = Tag(707, "nonce")

    public var untaggedCBOR: CBOR {
        CBOR(bytes: data)
    }

    public static func decodeUntaggedCBOR(_ cbor: CBOR) throws -> Nonce {
        guard
            case let CBOR.bytes(data) = cbor,
            let value = Nonce(data)
        else {
            throw CBORDecodingError.invalidFormat
        }
        return value
    }
}
