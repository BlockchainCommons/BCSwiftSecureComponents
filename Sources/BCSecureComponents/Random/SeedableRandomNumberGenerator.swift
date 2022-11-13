import Foundation
import WolfBase

public protocol SeedableRandomNumberGenerator: RandomNumberGenerator {
    associatedtype State
    init(seed: State)
    init<Source: RandomNumberGenerator>(from source: inout Source)
}

public extension SeedableRandomNumberGenerator {
    init() {
        var source = SystemRandomNumberGenerator()
        self.init(from: &source)
    }
}

public extension RandomNumberGenerator {
    mutating func data(count: Int) -> Data {
        (0..<count).reduce(into: Data()) { data, _ in
            data.append(UInt8.random(in: 0...255, using: &self))
        }
    }
}

public struct Xoroshiro256StarStar: SeedableRandomNumberGenerator {
    public typealias State = (UInt64, UInt64, UInt64, UInt64)
    public var state: State

    public init(seed: State) {
        precondition(seed != (0, 0, 0, 0))
        state = seed
    }

    private static func rotl(_ x: UInt64, _ k: UInt64) -> UInt64 {
        return (x << k) | (x >> (64 &- k))
    }

    public init<Source: RandomNumberGenerator>(from source: inout Source) {
        repeat {
            state = (source.next(), source.next(), source.next(), source.next())
        } while state == (0, 0, 0, 0)
    }

    public mutating func next() -> UInt64 {
        let result = Self.rotl(state.1 &* 5, 7) &* 9

        let t = state.1 << 17
        state.2 ^= state.0
        state.3 ^= state.1
        state.1 ^= state.2
        state.0 ^= state.3
    
        state.2 ^= t
    
        state.3 = Self.rotl(state.3, 45)
    
        return result
    }
}
