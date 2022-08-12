import Foundation
import Security
import WolfBase

public final class SecureRandomNumberGenerator: RandomNumberGenerator {
    public init() { }

    public static var shared = SecureRandomNumberGenerator()

    public func next() -> UInt64 {
        var result: UInt64 = 0
        precondition(SecRandomCopyBytes(kSecRandomDefault, MemoryLayout<UInt64>.size, &result) == errSecSuccess)
        return result
    }

    public func data(count: Int) -> Data {
        var s = self
        return Data((0..<count).map { _ in UInt8.random(in: 0...255, using: &s) })
    }
        
    public func data(range: ClosedRange<Int>) -> Data {
        precondition(range == range.clamped(to: 1...32))
        var s = self
        let count = range.randomElement(using: &s)!
        return data(count: count)
    }
}
