import Foundation

extension EnvelopeError {
    static let notWrapped = EnvelopeError("notWrapped")
}

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
