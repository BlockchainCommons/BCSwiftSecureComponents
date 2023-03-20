import Foundation
import URKit
import BCCrypto

public struct CID: Equatable, Hashable {
    public let data: Data
    
    public init?(_ data: Data) {
        guard data.count == 32 else {
            return nil
        }
        self.data = data
    }
    
    public init() {
        self.init(Crypto.randomData(count: 32))!
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
    public static let cborTag = Tag.commonIdentifier

    public var untaggedCBOR: CBOR {
        CBOR.bytes(data)
    }

    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.bytes(data) = untaggedCBOR,
            let value = CID(data)
        else {
            throw CBORError.invalidFormat
        }
        self = value
    }
}

public extension CID {
    var shortDescription: String {
        String(self.data.hex.prefix(count: 8))
    }
}

