import Foundation

public extension Envelope {
    /// Create an envelope with the given subject.
    init(_ item: Any) {
        if let envelope = item as? Envelope {
            self.init(wrapped: envelope)
        } else if let knownValue = item as? KnownValue {
            self.init(knownValue: knownValue)
        } else if let assertion = item as? Assertion {
            self.init(assertion: assertion)
        } else if
            let encryptedMessage = item as? EncryptedMessage,
            encryptedMessage.digest != nil
        {
            try! self.init(encryptedMessage: encryptedMessage)
        } else if let cborItem = item as? CBOREncodable {
            self.init(cborEncodable: cborItem)
        } else {
            preconditionFailure()
        }
    }

    /// Create an assertion envelope with the given predicate and object.
    init(_ predicate: Any, _ object: Any) {
        self.init(assertion: Assertion(predicate: predicate, object: object))
    }

    /// Create an assertion envelope with the given `KnownValue` predicate and object.
    init(_ predicate: KnownValue, _ object: Any) {
        self.init(assertion: Assertion(predicate: predicate, object: object))
    }
}

extension Envelope: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int) {
        self.init(value)
    }
}

extension Envelope: ExpressibleByStringLiteral {
    public init(stringLiteral value: StringLiteralType) {
        self.init(value)
    }
}

public extension Envelope {
    static func isA(_ object: Envelope) -> Envelope {
        Envelope(.isA, object)
    }

    static func id(_ id: CID) -> Envelope {
        Envelope(.id, id)
    }
}
