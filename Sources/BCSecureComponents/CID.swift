import Foundation
import URKit

public struct CID: Equatable, Hashable {
    public let data: Data
    
    public init?(_ data: Data) {
        guard data.count == 32 else {
            return nil
        }
        self.data = data
    }
    
    public init() {
        self.init(SecureRandomNumberGenerator.shared.data(count: 32))!
    }
}

extension CID: CustomStringConvertible {
    public var description: String {
        data.hex.flanked("CID(", ")")
    }
}

public extension CID {
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

public extension CID {
    var untaggedCBOR: CBOR {
        CBOR.data(data)
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.cid, untaggedCBOR)
    }
    
    init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.data(data) = untaggedCBOR,
            let value = CID(data)
        else {
            throw CBORError.invalidFormat
        }
        self = value
    }
    
    init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.cid, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
    
    init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

public extension CID {
    var ur: UR {
        return try! UR(type: .cid, cbor: untaggedCBOR)
    }
    
    init(ur: UR) throws {
        try ur.checkType(.cid)
        let cbor = try CBOR(ur.cbor)
        try self.init(untaggedCBOR: cbor)
    }
    
    init(urString: String) throws {
        try self.init(ur: UR(urString: urString))
    }
}

extension CID: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}

extension CID: CBORDecodable {
    public static func cborDecode(_ cbor: CBOR) throws -> CID {
        try CID(taggedCBOR: cbor)
    }
}
