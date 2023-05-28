import Foundation
import WolfBase
import URKit
import BCCrypto

public struct Nonce: CustomStringConvertible, Equatable, Hashable, DataProvider {
    public let data: Data
    
    public init?(_ data: Data) {
        guard data.count == 12 else {
            return nil
        }
        self.data = data
    }
    
    public init() {
        self.init(secureRandomData(12))!
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
    public static let cborTag = Tag.nonce

    public var untaggedCBOR: CBOR {
        CBOR.bytes(data)
    }

    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.bytes(data) = untaggedCBOR,
            let value = Nonce(data)
        else {
            throw CBORError.invalidFormat
        }
        self = value
    }
}
