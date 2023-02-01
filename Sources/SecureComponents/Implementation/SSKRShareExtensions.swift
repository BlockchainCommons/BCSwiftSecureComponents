import Foundation
import WolfBase
import SSKR
import URKit

public func SSKRGenerate(groupThreshold: Int, groups: [SSKRGroupDescriptor], secret: DataProvider, testRandomGenerator: ((Int) -> Data)? = nil) throws -> [[SSKRShare]] {
    let randomGenerator = testRandomGenerator ?? {
        SecureRandomNumberGenerator.shared.data(count: $0)
    }
    return try SSKRGenerate(groupThreshold: groupThreshold, groups: groups, secret: secret.providedData, randomGenerator: randomGenerator)
}

public func SSKRGenerate(groupThreshold: Int, groups: [(Int, Int)], secret: DataProvider, testRandomGenerator: ((Int) -> Data)? = nil) throws -> [[SSKRShare]] {
    let groups = groups.map { SSKRGroupDescriptor(threshold: UInt8($0.0), count: UInt8($0.1)) }
    return try SSKRGenerate(groupThreshold: groupThreshold, groups: groups, secret: secret.providedData, testRandomGenerator: testRandomGenerator)
}

extension SSKRShare {
    public var identifier: UInt16 {
        (UInt16(data[0]) << 8) | UInt16(data[1])
    }
    
    public var identifierHex: String {
        Data(data[0...1]).hex
    }

    public var groupThreshold: Int {
        Int(data[2] >> 4) + 1
    }
    
    public var groupCount: Int {
        Int(data[2] & 0xf) + 1
    }
    
    public var groupIndex: Int {
        Int(data[3]) >> 4
    }
    
    public var memberThreshold: Int {
        Int(data[3] & 0xf) + 1
    }
    
    public var memberIndex: Int {
        Int(data[4] & 0xf)
    }
    
    public static func ==(lhs: SSKRShare, rhs: SSKRShare) -> Bool {
        lhs.data == rhs.data
    }
}

extension SSKRShare: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(data)
    }
}

extension SSKRShare {
    public func bytewords(style: Bytewords.Style) -> String {
        return Bytewords.encode(taggedCBOR.cborData, style: style)
    }

    public init?(bytewords: String) throws {
        guard let share = try? Bytewords.decode(bytewords) else {
            return nil
        }
        self = try SSKRShare(untaggedCBOR: share.cbor)
    }
}

extension SSKRShare: CustomStringConvertible {
    public var description: String {
        "SSKRShare(\(identifierHex) \(groupIndex + 1)-\(memberIndex + 1))"
    }
}

extension SSKRShare: URCodable {
    public static let cborTag = Tag(309, "crypto-sskr")

    public var untaggedCBOR: CBOR {
        Data(data).cbor
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard case let CBOR.bytes(data) = untaggedCBOR else {
            throw CBORDecodingError.invalidFormat
        }
        self = SSKRShare(data: data.bytes)
    }
}
