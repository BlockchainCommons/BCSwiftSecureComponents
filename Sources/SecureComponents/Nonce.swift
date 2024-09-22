import Foundation
import WolfBase
import URKit
import BCCrypto
import BCRandom

public struct Nonce: CustomStringConvertible, Equatable, Hashable, Sendable, DataProvider {
    public let data: Data
    
    public init?(_ data: Data) {
        guard data.count == 12 else {
            return nil
        }
        self.data = data
    }
    
    public init<T: RandomNumberGenerator>(using rng: inout T) {
        self.init(rng.randomData(12))!
    }

    public init() {
        var rng = SecureRandomNumberGenerator()
        self.init(using: &rng)
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
    public static let cborTags = [Tag.nonce]

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
