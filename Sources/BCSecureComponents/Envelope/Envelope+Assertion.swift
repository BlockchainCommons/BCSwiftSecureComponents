import Foundation

public extension Envelope {
    func addAssertion(_ envelope: Envelope?, salted: Bool = false) throws -> Envelope {
        guard let envelope else {
            return self
        }
        guard envelope.isSubjectAssertion || envelope.isSubjectObscured else {
            throw EnvelopeError.invalidFormat
        }
        let envelope2 = salted ? envelope.addSalt() : envelope
        switch self {
        case .node(subject: let subject, assertions: let assertions, digest: _):
            if !assertions.contains(where: { $0.digest == envelope2.digest}) {
                return Envelope(subject: subject, uncheckedAssertions: assertions.appending(envelope2))
            } else {
                return self
            }
        default:
            return Envelope(subject: subject, uncheckedAssertions: [envelope2])
        }
    }
    
    func addAssertions(_ envelopes: [Envelope], salted: Bool = false) throws -> Envelope {
        try envelopes.reduce(into: self) {
            $0 = try $0.addAssertion($1, salted: salted)
        }
    }

    func addAssertion(_ assertion: Assertion?, salted: Bool = false) -> Envelope {
        guard let assertion else {
            return self
        }
        return try! addAssertion(Envelope(assertion: assertion), salted: salted)
    }

    func addAssertion(_ predicate: Any, _ object: Any?, salted: Bool = false) -> Envelope {
        guard let object else {
            return self
        }
        return addAssertion(Assertion(predicate: predicate, object: object), salted: salted)
    }

    func addAssertion(_ predicate: KnownValue, _ object: Any?, salted: Bool = false) -> Envelope {
        guard let object else {
            return self
        }
        return addAssertion(Assertion(predicate: predicate, object: object), salted: salted)
    }
}

public extension Envelope {
    func addAssertion(if condition: Bool, _ envelope: @autoclosure () -> Envelope?, salted: Bool = false) throws -> Envelope {
        guard condition else {
            return self
        }
        return try addAssertion(envelope(), salted: salted)
    }

    func addAssertion(if condition: Bool, _ assertion: @autoclosure () -> Assertion?, salted: Bool = false) -> Envelope {
        guard condition else {
            return self
        }
        return addAssertion(assertion(), salted: salted)
    }

    func addAssertion(if condition: Bool, _ predicate: @autoclosure () -> Any, _ object: @autoclosure () -> Any?, salted: Bool = false) -> Envelope {
        guard condition else {
            return self
        }
        return addAssertion(predicate(), object(), salted: salted)
    }

    func addAssertion(if condition: Bool, _ predicate: @autoclosure () -> KnownValue, _ object: @autoclosure () -> Any?, salted: Bool = false) -> Envelope {
        guard condition else {
            return self
        }
        return addAssertion(predicate(), object(), salted: salted)
    }
}

public extension Envelope {
    func removeAssertion(_ target: DigestProvider) -> Envelope {
        var assertions = self.assertions
        let target = target.digest
        if let index = assertions.firstIndex(where: { $0.digest == target }) {
            assertions.remove(at: index)
        }
        if assertions.isEmpty {
            return subject
        } else {
            return Envelope(subject: subject, uncheckedAssertions: assertions)
        }
    }
    
    func replaceAssertion(_ assertion: DigestProvider, with newAssertion: Envelope) throws -> Envelope {
        var e = self
        e = e.removeAssertion(assertion)
        e = try e.addAssertion(newAssertion)
        return e
    }
}

public extension Envelope {
    func replaceSubject(with subject: Envelope) -> Envelope {
        assertions.reduce(into: subject) {
            try! $0 = $0.addAssertion($1)
        }
    }
}
