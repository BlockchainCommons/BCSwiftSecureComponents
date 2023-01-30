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

extension CID: Comparable {
    public static func < (lhs: CID, rhs: CID) -> Bool {
        lhs.data.lexicographicallyPrecedes(rhs.data)
    }
}

extension CID: URCodable {
    public static let urType = "crypto-cid"
    public static let cborTag: UInt64 = 202

    public var untaggedCBOR: CBOR {
        CBOR(bytes: data)
    }

    public static func decodeUntaggedCBOR(_ cbor: CBOR) throws -> CID {
        guard
            case let CBOR.bytes(data) = cbor,
            let value = CID(data)
        else {
            throw DecodeError.invalidFormat
        }
        return value
    }
}

public extension CID {
    var shortDescription: String {
        String(self.data.hex.prefix(count: 8))
    }
}

