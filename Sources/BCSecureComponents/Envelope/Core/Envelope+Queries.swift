import Foundation

public extension Envelope {
    /// The envelope's subject.
    var subject: Envelope {
        if case .node(let subject, _, _) = self {
            return subject
        }
        return self
    }

    /// The envelope's assertions.
    var assertions: [Envelope] {
        guard case .node(_, let assertions, _) = self else {
            return []
        }
        return assertions
    }

    /// `true` if the envelope has at least one assertion, `false` otherwise.
    var hasAssertions: Bool {
        !assertions.isEmpty
    }

    /// The envelope's `Assertion`, or `nil` if the envelope is not an assertion.
    var assertion: Assertion? {
        guard case .assertion(let assertion) = self else {
            return nil
        }
        return assertion
    }

    /// The envelope's predicate, or `nil` if the envelope is not an assertion.
    var predicate: Envelope! {
        assertion?.predicate
    }

    /// The envelope's object, or `nil` if the envelope is not an assertion.
    var object: Envelope! {
        assertion?.object
    }

    /// The envelope's leaf CBOR object, or `nil` if the envelope is not a leaf.
    var leaf: CBOR? {
        guard case .leaf(let cbor, _) = subject else {
            return nil
        }
        return cbor
    }

    /// The envelope's `KnownValue`, or `nil` if the envelope is not case `.knownValue`.
    var knownValue: KnownValue? {
        guard case .knownValue(let knownValue, _) = self else {
            return nil
        }
        return knownValue
    }
}

public extension Envelope {
    /// `true` if the envelope is case `.leaf`, `false` otherwise.
    var isLeaf: Bool {
        guard case .leaf = self else {
            return false
        }
        return true
    }
    
    /// `true` if the envelope is case `.node`, `false` otherwise.
    var isNode: Bool {
        guard case .node = self else {
            return false
        }
        return true
    }
    
    /// `true` if the envelope is case `.encrypted`, `false` otherwise.
    var isEncrypted: Bool {
        guard case .encrypted = self else {
            return false
        }
        return true
    }
    
    /// `true` if the envelope is case `.elided`, `false` otherwise.
    var isElided: Bool {
        guard case .elided = self else {
            return false
        }
        return true
    }
    
    /// `true` if the envelope is case `.wrapped`, `false` otherwise.
    var isWrapped: Bool {
        guard case .wrapped = self else {
            return false
        }
        return true
    }
    
    /// `true` if the envelope is case `.knownValue`, `false` otherwise.
    var isKnownValue: Bool {
        guard case .knownValue = self else {
            return false
        }
        return true
    }
}

public extension Envelope {
    /// `true` if the subject of the envelope is an assertion, `false` otherwise.
    var isSubjectAssertion: Bool {
        switch self {
        case .assertion:
            return true
        case .node(subject: let subject, assertions: _, digest: _):
            if case .assertion = subject {
                return true
            }
            return false
        default:
            return false
        }
    }
    
    /// `true` if the subject of the envelope has been encrypted, `false` otherwise.
    var isSubjectEncrypted: Bool {
        switch self {
        case .encrypted:
            return true
        case .node(subject: let subject, assertions: _, digest: _):
            if case .encrypted = subject {
                return true
            }
            return false
        default:
            return false
        }
    }
    
    /// `true` if the subject of the envelope has been elided, `false` otherwise.
    var isSubjectElided: Bool {
        switch self {
        case .elided:
            return true
        case .node(subject: let subject, assertions: _, digest: _):
            if case .elided = subject {
                return true
            }
            return false
        default:
            return false
        }
    }
    
    /// `true` if the subject of the envelope has been encrypted or elided, `false` otherwise
    var isSubjectObscured: Bool {
        isSubjectEncrypted || isSubjectElided
    }
}

public extension Envelope {
    /// `true` if the envelope is *internal*, that is, it has child elements, or `false` if it is a leaf node.
    ///
    /// Internal elements include `.node`, `.wrapped`, and `.assertion`.
    var isInternal: Bool {
        isNode || isWrapped || isSubjectAssertion
    }
    
    /// `true` if the envelope is either encrypted or elided, `false` otherwise.
    var isObscured: Bool {
        isEncrypted || isElided
    }
}

public extension Envelope {
    func extractSubject<T>(_ type: T.Type) throws -> T {
        switch self {
        case .wrapped(let envelope, _):
            guard let result = envelope as? T else {
                throw EnvelopeError.invalidFormat
            }
            return result
        case .node(let subject, _, _):
            return try subject.extractSubject(type)
        case .leaf(let cbor, _):
            let t = (type.self as! CBORDecodable.Type)
            return try t.cborDecode(cbor) as! T
        case .knownValue(let knownValue, _):
            guard let result = knownValue as? T else {
                throw EnvelopeError.invalidFormat
            }
            return result
        case .assertion(let assertion):
            guard let result = assertion as? T else {
                throw EnvelopeError.invalidFormat
            }
            return result
        case .encrypted(let encryptedMessage):
            guard let result = encryptedMessage as? T else {
                throw EnvelopeError.invalidFormat
            }
            return result
        case .elided(let digest):
            guard let result = digest as? T else {
                throw EnvelopeError.invalidFormat
            }
            return result
        }
    }
}

public extension Envelope {
    func assertions(withPredicate predicate: Envelope) -> [Envelope] {
        return assertions.filter { $0.predicate.digest == predicate.digest }
    }

    func assertion(withPredicate predicate: Envelope) throws -> Envelope {
        let a = assertions(withPredicate: predicate)
        guard !a.isEmpty else {
            throw EnvelopeError.nonexistentPredicate
        }
        guard
            a.count == 1,
            let result = a.first
        else {
            throw EnvelopeError.ambiguousPredicate
        }
        return result
    }
    
    func assertion(withDigest digest: DigestProvider) throws -> Envelope {
        let digest = digest.digest
        guard let result = assertions.first(where: { $0.digest == digest }) else {
            throw EnvelopeError.nonexistentAssertion
        }
        return result
    }

    func extractObject(forPredicate predicate: Envelope) throws -> Envelope {
        guard let result = try assertion(withPredicate: predicate).object else {
            throw EnvelopeError.invalidFormat
        }
        return result
    }
    
    func extractObjects(forPredicate predicate: Envelope) -> [Envelope] {
        assertions(withPredicate: predicate).map { $0.object! }
    }
    
    func extractObjects(forPredicate predicate: KnownValue) -> [Envelope] {
        let predicate = Envelope(predicate)
        return extractObjects(forPredicate: predicate)
    }

    func extractObject<T>(_ type: T.Type, forPredicate predicate: Envelope) throws -> T where T: CBORDecodable {
        try extractObject(forPredicate: predicate).extractSubject(type)
    }
    
    func extractObjects<T>(_ type: T.Type, forPredicate predicate: CBOREncodable) throws -> [T] where T: CBORDecodable {
        let predicate = Envelope(predicate)
        return try extractObjects(forPredicate: predicate).map { try $0.extractSubject(type) }
    }
    
    func extractObjects<T>(_ type: T.Type, forPredicate predicate: KnownValue) throws -> [T] where T: CBORDecodable {
        let predicate = Envelope(predicate)
        return try extractObjects(forPredicate: predicate).map { try $0.extractSubject(type) }
    }
}

public extension Envelope {
    func assertions(withPredicate predicate: CBOREncodable) -> [Envelope] {
        assertions(withPredicate: Envelope(predicate))
    }

    func assertion(withPredicate predicate: CBOREncodable) throws -> Envelope {
        try assertion(withPredicate: Envelope(predicate))
    }

    func extractObject(forPredicate predicate: CBOREncodable) throws -> Envelope {
        try extractObject(forPredicate: Envelope(predicate))
    }

    func extractObject<T>(_ type: T.Type, forPredicate predicate: CBOREncodable) throws -> T where T: CBORDecodable {
        try extractObject(type, forPredicate: Envelope(predicate))
    }

    func extractObject<T>(_ type: T.Type, forParameter parameter: ParameterIdentifier) throws -> T where T: CBORDecodable {
        try extractObject(type, forPredicate: parameter)
    }
    
    func extractObjects<T>(_ type: T.Type, forParameter parameter: ParameterIdentifier) throws -> [T] where T: CBORDecodable {
        try extractObjects(type, forPredicate: parameter)
    }
}

public extension Envelope {
    func assertions(withPredicate predicate: KnownValue) -> [Envelope] {
        assertions(withPredicate: Envelope(knownValue: predicate))
    }

    func assertion(withPredicate predicate: KnownValue) throws -> Envelope {
        try assertion(withPredicate: Envelope(knownValue: predicate))
    }

    func extractObject(forPredicate predicate: KnownValue) throws -> Envelope {
        try extractObject(forPredicate: Envelope(knownValue: predicate))
    }

    func extractObject<T>(_ type: T.Type, forPredicate predicate: KnownValue) throws -> T where T: CBORDecodable {
        try extractObject(type, forPredicate: Envelope(knownValue: predicate))
    }
}

public extension Envelope {
    var elementsCount: Int {
        var result = 0
        
        func _count(_ envelope: Envelope) {
            result += 1
            switch envelope {
            case .node(let subject, let assertions, _):
                result += subject.elementsCount
                for assertion in assertions {
                    result += assertion.elementsCount
                }
            case .assertion(let assertion):
                result += assertion.predicate.elementsCount
                result += assertion.object.elementsCount
            case .wrapped(let envelope, _):
                result += envelope.elementsCount
            default:
                break
            }
        }
        
        _count(self)
        
        return result
    }
}
