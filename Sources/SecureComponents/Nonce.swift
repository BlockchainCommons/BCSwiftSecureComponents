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

public extension Nonce {
    var untaggedCBOR: CBOR {
        CBOR.data(self.data)
    }
    
    init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.data(data) = untaggedCBOR,
            let result = Nonce(data)
        else {
            throw CBORError.invalidFormat
        }
        self = result
    }

    var taggedCBOR: CBOR {
        CBOR.tagged(.nonce, untaggedCBOR)
    }

    init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.nonce, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

extension Nonce: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}

extension Nonce: CBORDecodable {
    public static func cborDecode(_ cbor: CBOR) throws -> Nonce {
        try Nonce(taggedCBOR: cbor)
    }
}

public extension Nonce {
    var ur: UR {
        return try! UR(type: .nonce, cbor: untaggedCBOR)
    }
    
    init(ur: UR) throws {
        try ur.checkType(.nonce)
        let cbor = try CBOR(ur.cbor)
        try self.init(untaggedCBOR: cbor)
    }
    
    init(urString: String) throws {
        try self.init(ur: UR(urString: urString))
    }
}
