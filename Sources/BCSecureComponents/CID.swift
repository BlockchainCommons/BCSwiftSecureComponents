import Foundation
import URKit

public struct CID: CustomStringConvertible, Equatable, Hashable {
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
    
    public var description: String {
        data.hex.flanked("CID(", ")")
    }
}

extension CID {
    public var untaggedCBOR: CBOR {
        CBOR.data(data)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.cid, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.data(data) = untaggedCBOR,
            let value = CID(data)
        else {
            throw CBORError.invalidFormat
        }
        self = value
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.cid, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension CID {
    public var ur: UR {
        return try! UR(type: .cid, cbor: untaggedCBOR)
    }
    
    public init(ur: UR) throws {
        try ur.checkType(.cid)
        let cbor = try CBOR(ur.cbor)
        try self.init(untaggedCBOR: cbor)
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
