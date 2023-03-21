import Foundation
import Compression
import WolfBase

/// A compressed binary object.
///
/// Implemented using the raw DEFLATE format as described in
/// [IETF RFC 1951](https://www.ietf.org/rfc/rfc1951.txt).
///
/// The following obtains the equivalent configuration of the encoder:
///
/// ```
/// deflateInit2(zstream,5,Z_DEFLATED,-15,8,Z_DEFAULT_STRATEGY)
/// ```
///
/// If the payload is too small to compress, the uncompressed payload is placed in
/// the `compressedData` field and the size of that field will be the same as the
/// `uncompressedSize` field.
public struct Compressed {
    public let checksum: UInt32
    public let uncompressedSize: Int
    public let compressedData: Data
    
    public var compressedSize: Int {
        compressedData.count
    }
    
    public var compressionRatio: Double {
        Double(compressedSize) / Double(uncompressedSize)
    }
    
    public init?(checksum: UInt32, uncompressedSize: Int, compressedData: Data) {
        guard compressedData.count <= uncompressedSize else {
            return nil
        }
        self.checksum = checksum
        self.uncompressedSize = uncompressedSize
        self.compressedData = compressedData
    }
    
    public init(uncompressedData: Data) {
        var compressedData = Data(repeating: 0, count: uncompressedData.count)
        let maxOutputSize = compressedData.count
        let inputSize = uncompressedData.count
        
        let compressedSize =
        compressedData.withUnsafeMutableByteBuffer { compressedPtr in
            uncompressedData.withUnsafeByteBuffer { uncompressedPtr in
                compression_encode_buffer(
                    compressedPtr.baseAddress!,
                    maxOutputSize,
                    uncompressedPtr.baseAddress!,
                    inputSize,
                    nil,
                    COMPRESSION_ZLIB
                )
            }
        }
        
        self.checksum = Crypto.crc32(uncompressedData)
        self.uncompressedSize = uncompressedData.count
        if compressedSize != 0 && compressedSize < uncompressedData.count {
            compressedData.count = compressedSize
            self.compressedData = compressedData
        } else {
            self.compressedData = uncompressedData
        }
    }
    
    public func uncompress(checkDigest: Bool = true) throws -> Data {
        let compressedSize = compressedData.count
        guard compressedSize < uncompressedSize else {
            return compressedData
        }
        var uncompressedData = Data(repeating: 0, count: uncompressedSize)
        let bytesWritten =
        uncompressedData.withUnsafeMutableByteBuffer { uncompressedPtr in
            compressedData.withUnsafeByteBuffer { compressedPtr in
                compression_decode_buffer(
                    uncompressedPtr.baseAddress!,
                    uncompressedSize,
                    compressedPtr.baseAddress!,
                    compressedSize,
                    nil,
                    COMPRESSION_ZLIB)
            }
        }
        guard bytesWritten == uncompressedSize else {
            throw Error.corrupt
        }
        guard Crypto.crc32(uncompressedData) == checksum else {
            throw Error.invalidChecksum
        }
        return uncompressedData
    }
    
    public enum Error: Swift.Error {
        case corrupt
        case invalidChecksum
    }
}

extension Compressed: Equatable {
}

extension Compressed: CustomStringConvertible {
    public var description: String {
        "Compressed(checksum: \(checksum.hex), size: \(compressedSize)/\(uncompressedSize), ratio: \(compressionRatio %% 2))"
    }
}

extension Compressed: URCodable {
    public static var cborTag = Tag.compressed
    
    public var untaggedCBOR: CBOR {
        [checksum, uncompressedSize, compressedData]
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.array(elements) = untaggedCBOR,
            elements.count == 3
        else {
            throw CBORError.invalidFormat
        }
        
        let checksum = try UInt32(cbor: elements[0])
        let uncompressedSize = try Int(cbor: elements[1])
        let compressedData = try Data(cbor: elements[2])
        guard let a = Self.init(checksum: checksum, uncompressedSize: uncompressedSize, compressedData: compressedData) else {
            throw CBORError.invalidFormat
        }
        self = a
    }
}