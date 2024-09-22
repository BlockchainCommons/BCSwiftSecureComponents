import Foundation
import WolfBase
import URKit
import BCRandom

public struct Salt: CustomStringConvertible, Equatable, Hashable, Sendable, DataProvider {
    public let data: Data
    
    public init?(_ data: Data) {
        guard data.count >= 8 else {
            return nil
        }
        self.data = data
    }

    /// Create a specific number of bytes of salt.
    public init?(count: Int) {
        var rng = SecureRandomNumberGenerator.shared
        self.init(count: count, using: &rng)
    }
    
    /// Create a specific number of bytes of salt.
    public init?<R: RandomNumberGenerator>(count: Int, using rng: inout R) {
        self.init(rng.data(count: count))
    }
    
    /// Create a number of bytes of salt chosen randomly from the given range.
    public init?(range: ClosedRange<Int>) {
        var rng = SecureRandomNumberGenerator.shared
        self.init(range: range, using: &rng)
    }
    
    /// Create a number of bytes of salt chosen randomly from the given range.
    public init?<R: RandomNumberGenerator>(range: ClosedRange<Int>, using rng: inout R) {
        let count = range.randomElement(using: &rng)!
        self.init(count: count, using: &rng)
    }

    /// Create a number of bytes of salt generally proportionate to the size of the object being salted.
    ///
    /// For small objects, the number of bytes added will generally be from 8...16.
    ///
    /// For larger objects the number of bytes added will generally be from 5%...25% of the size of the object.
    public init(forSize size: Int) {
        var rng = SecureRandomNumberGenerator.shared
        self.init(forSize: size, using: &rng)
    }

    /// Create a number of bytes of salt generally proportionate to the size of the object being salted.
    ///
    /// For small objects, the number of bytes added will generally be from 8...16.
    ///
    /// For larger objects the number of bytes added will generally be from 5%...25% of the size of the object.
    public init<R: RandomNumberGenerator>(forSize size: Int, using rng: inout R) {
        let count = Double(size)
        let minSize = max(8, Int((count * 0.05).rounded(.up)))
        let maxSize = max(minSize + 8, Int((count * 0.25).rounded(.up)))
        self.init(range: minSize...maxSize, using: &rng)!
    }
}

public extension Salt {
    var bytes: [UInt8] {
        data.bytes
    }
    
    var description: String {
        data.hex.flanked("Salt(", ")")
    }
    
    var providedData: Data {
        data
    }
}

extension Salt: URCodable {
    public static let cborTags = [Tag.salt]

    public var untaggedCBOR: CBOR {
        CBOR.bytes(data)
    }

    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.bytes(data) = untaggedCBOR,
            let value = Salt(data)
        else {
            throw CBORError.invalidFormat
        }
        self = value
    }
}
