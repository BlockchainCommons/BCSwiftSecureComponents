import Foundation

public extension Envelope {
    /// Add the given Salt as an assertion
    func addSalt(_ salt: Salt) -> Envelope {
        addAssertion(.salt, salt)
    }
    
    /// Add a specified number of bytes of salt.
    func addSalt(_ count: Int) throws -> Envelope {
        guard let salt = Salt(count: count) else {
            throw EnvelopeError.invalidFormat
        }
        return addSalt(salt)
    }

    /// Add a number of bytes of salt chosen randomly from the given range.
    func addSalt(_ range: ClosedRange<Int>) throws -> Envelope {
        guard let salt = Salt(range: range) else {
            throw EnvelopeError.invalidFormat
        }
        return addSalt(salt)
    }

    /// Add a number of bytes of salt generally proportionate to the size of the object being salted.
    func addSalt() -> Envelope {
        var rng = SecureRandomNumberGenerator.shared
        return addSalt(using: &rng)
    }
    
    func addSalt<R: RandomNumberGenerator>(using rng: inout R) -> Envelope {
        addSalt(Salt(forSize: taggedCBOR.cborEncode.count, using: &rng))
    }
}
