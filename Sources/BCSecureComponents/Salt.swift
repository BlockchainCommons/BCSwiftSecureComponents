import Foundation
import WolfBase
import URKit

public struct Salt: CustomStringConvertible, Equatable, Hashable, DataProvider {
    public let data: Data
    
    public init(_ data: Data) {
        self.data = data
    }
    
    /// Create a specific number of bytes of salt.
    public init(count: Int) {
        self.init(SecureRandomNumberGenerator.shared.data(count: count))
    }
    
    /// Create a number of bytes of salt chosen randomly from the given range.
    public init(range: ClosedRange<Int>) {
        var s = SecureRandomNumberGenerator.shared
        let count = range.randomElement(using: &s)!
        self.init(count: count)
    }
    
    /// Create a number of bytes of salt generally proportionate to the size of the object being salted.
    ///
    /// For small objects, the number of bytes added will generally be from 8...16.
    ///
    /// For larger objects the number of bytes added will generally be from 5%...25% of the size of the object.
    public init(forSize size: Int) {
        let count = Double(size)
        let minSize = max(8, Int((count * 0.05).rounded(.up)))
        let maxSize = max(minSize + 8, Int((count * 0.25).rounded(.up)))
        self.init(range: minSize...maxSize)
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

public extension Salt {
    var untaggedCBOR: CBOR {
        CBOR.data(self.data)
    }
    
    init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.data(data) = untaggedCBOR
        else {
            throw CBORError.invalidFormat
        }
        self = Salt(data)
    }

    var taggedCBOR: CBOR {
        CBOR.tagged(.salt, untaggedCBOR)
    }

    init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.salt, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

extension Salt: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}

extension Salt: CBORDecodable {
    public static func cborDecode(_ cbor: CBOR) throws -> Salt {
        try Salt(taggedCBOR: cbor)
    }
}

public extension Salt {
    var ur: UR {
        return try! UR(type: .salt, cbor: untaggedCBOR)
    }
    
    init(ur: UR) throws {
        try ur.checkType(.salt)
        let cbor = try CBOR(ur.cbor)
        try self.init(untaggedCBOR: cbor)
    }
    
    init(urString: String) throws {
        try self.init(ur: UR(urString: urString))
    }
}
