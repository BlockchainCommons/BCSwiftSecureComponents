import Foundation

public extension Envelope {
    func elide() -> Envelope {
        switch self {
        case .elided:
            return self
        default:
            return Envelope(elided: self.digest)
        }
    }

    func unelide(_ envelope: Envelope) throws -> Envelope {
        guard digest == envelope.digest else {
            throw EnvelopeError.invalidDigest
        }
        return envelope
    }
}

// Target Matches   isRevealing     elide
// ----------------------------------------
//     false           false        false
//     false           true         true
//     true            false        true
//     true            true         false

public extension Envelope {
    func elide(_ target: Set<Digest>, isRevealing: Bool, encryptingWith key: SymmetricKey? = nil) throws -> Envelope {
        let result: Envelope
        if target.contains(digest) != isRevealing {
            if let key {
                let message = key.encrypt(plaintext: self.taggedCBOR, digest: self.digest)
                result = try Envelope(encryptedMessage: message)
            } else {
                result = elide()
            }
        } else if case .assertion(let assertion) = self {
            let predicate = try assertion.predicate.elide(target, isRevealing: isRevealing, encryptingWith: key)
            let object = try assertion.object.elide(target, isRevealing: isRevealing, encryptingWith: key)
            let elidedAssertion = Assertion(predicate: predicate, object: object)
            assert(elidedAssertion == assertion)
            result = Envelope(assertion: elidedAssertion)
        } else if case .node(let subject, let assertions, _) = self {
            let elidedSubject = try subject.elide(target, isRevealing: isRevealing, encryptingWith: key)
            assert(elidedSubject.digest == subject.digest)
            let elidedAssertions = try assertions.map { assertion in
                let elidedAssertion = try assertion.elide(target, isRevealing: isRevealing, encryptingWith: key)
                assert(elidedAssertion.digest == assertion.digest)
                return elidedAssertion
            }
            result = Envelope(subject: elidedSubject, uncheckedAssertions: elidedAssertions)
        } else if case .wrapped(let envelope, _) = self {
            let elidedEnvelope = try envelope.elide(target, isRevealing: isRevealing, encryptingWith: key)
            assert(elidedEnvelope.digest == envelope.digest)
            result = Envelope(wrapped: elidedEnvelope)
        } else {
            result = self
        }
        assert(result.digest == digest)
        return result
    }

    func elideRemoving(_ target: Set<Digest>, encryptingWith key: SymmetricKey? = nil) throws -> Envelope {
        try elide(target, isRevealing: false, encryptingWith: key)
    }

    func elideRevealing(_ target: Set<Digest>, encryptingWith key: SymmetricKey? = nil) throws -> Envelope {
        try elide(target, isRevealing: true, encryptingWith: key)
    }
}

public extension Envelope {
    func elide(_ target: [DigestProvider], isRevealing: Bool, encryptingWith key: SymmetricKey? = nil) throws -> Envelope {
        try elide(Set(target.map { $0.digest }), isRevealing: isRevealing, encryptingWith: key)
    }
    
    func elideRemoving(_ target: [DigestProvider], encryptingWith key: SymmetricKey? = nil) throws -> Envelope {
        try elide(target, isRevealing: false, encryptingWith: key)
    }

    func elideRevealing(_ target: [DigestProvider], encryptingWith key: SymmetricKey? = nil) throws -> Envelope {
        try elide(target, isRevealing: true, encryptingWith: key)
    }
}

public extension Envelope {
    func elide(_ target: DigestProvider, isRevealing: Bool, encryptingWith key: SymmetricKey? = nil) throws -> Envelope {
        try elide([target], isRevealing: isRevealing, encryptingWith: key)
    }

    func elideRemoving(_ target: DigestProvider, encryptingWith key: SymmetricKey? = nil) throws -> Envelope {
        try elide(target, isRevealing: false, encryptingWith: key)
    }

    func elideRevealing(_ target: DigestProvider, encryptingWith key: SymmetricKey? = nil) throws -> Envelope {
        try elide(target, isRevealing: true, encryptingWith: key)
    }
}
