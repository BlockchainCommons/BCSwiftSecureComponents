import Foundation
import URKit
import BCCrypto

public struct ARID: Equatable, Hashable {
    public let data: Data
    
    public init?(_ data: Data) {
        guard data.count == 32 else {
            return nil
        }
        self.data = data
    }
    
    public init<T: RandomNumberGenerator>(using rng: inout T) {
        self.init(rng.randomData(32))!
    }
    
    public init() {
        var rng = SecureRandomNumberGenerator()
        self.init(using: &rng)
    }
}

extension ARID: CustomStringConvertible {
    public var description: String {
        data.hex.flanked("ARID(", ")")
    }
}

public extension ARID {
    init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }
    
    var hex: String {
        data.hex
    }
}

extension ARID: Comparable {
    public static func < (lhs: ARID, rhs: ARID) -> Bool {
        lhs.data.lexicographicallyPrecedes(rhs.data)
    }
}

extension ARID: URCodable {
    public static let cborTags = [Tag.arid]

    public var untaggedCBOR: CBOR {
        CBOR.bytes(data)
    }

    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.bytes(data) = untaggedCBOR,
            let value = ARID(data)
        else {
            throw CBORError.invalidFormat
        }
        self = value
    }
}

public extension ARID {
    var shortDescription: String {
        String(self.data.hex.prefix(count: 8))
    }
}

