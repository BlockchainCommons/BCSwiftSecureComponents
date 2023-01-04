import Foundation

public extension Envelope {
    func wrap() -> Envelope {
        Envelope(self)
    }

    func unwrap() throws -> Envelope {
        guard case .wrapped(let envelope, _) = subject else {
            throw EnvelopeError.notWrapped
        }
        return envelope
    }
}
