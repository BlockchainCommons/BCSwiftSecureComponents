import Foundation
import WolfBase
import SSKR
import URKit

public struct Assertion: DigestProvider {
    let envelope: Envelope
}

public extension Assertion {
    init(_ predicate: Envelope, _ object: Envelope) {
        self.envelope = Envelope(predicate: predicate, object: object)
    }

    init(_ digest: Digest) {
        self.envelope = Envelope(digest)
    }
    
    init(_ envelope: Envelope) {
        self.envelope = envelope
    }
}

public extension Assertion {
    func hasPredicate(_ predicate: Envelope) -> Bool {
        guard
            let myPredicate = try? self.predicate,
            myPredicate == predicate
        else {
            return false
        }
        return true
    }

    func hasPredicate(_ predicate: Predicate) -> Bool {
        hasPredicate(Envelope(predicate: predicate))
    }

    func hasPredicate(_ predicate: CBOREncodable) -> Bool {
        hasPredicate(Envelope(predicate))
    }
}

public extension Assertion {
    var digest: Digest {
        envelope.digest
    }

    var predicate: Envelope {
        get throws {
            switch envelope.subject {
            case .assertion(predicate: let predicate, object: _, digest: _):
                return predicate
            default:
                throw EnvelopeError.invalidFormat
            }
        }
    }

    var object: Envelope {
        get throws {
            switch envelope.subject {
            case .assertion(predicate: _, object: let object, digest: _):
                return object
            default:
                throw EnvelopeError.invalidFormat
            }
        }
    }
}

public extension Assertion {
    var deepDigests: Set<Digest> {
        envelope.deepDigests
    }

    var shallowDigests: Set<Digest> {
        switch envelope.subject {
        case .assertion(predicate: let predicate, object: let object, digest: let digest):
            return [
                envelope.digest,
                digest,
                predicate.digest, predicate.subject.digest,
                object.digest, object.subject.digest
            ]
        default:
            return envelope.shallowDigests
        }
    }
}

public extension Assertion {
    func assertions(predicate: CBOREncodable) -> [Assertion] {
        envelope.assertions(predicate: predicate)
    }

    func assertion(predicate: CBOREncodable) throws -> Assertion {
        try envelope.assertion(predicate: predicate)
    }
}

extension Assertion: Equatable {
    public static func ==(lhs: Assertion, rhs: Assertion) -> Bool {
        lhs.digest == rhs.digest
    }
}

extension Assertion: Comparable {
    public static func <(lhs: Assertion, rhs: Assertion) -> Bool {
        lhs.digest < rhs.digest
    }
}

public extension Assertion {
    static func verifiedBy(signature: Signature, note: String? = nil) -> Assertion {
        var object = Envelope(signature)
        if let note = note {
            object = object.add(.note, note)
        }
        return Assertion(Envelope(predicate: .verifiedBy), object)
    }

    static func hasRecipient(_ recipient: PublicKeyBase, contentKey: SymmetricKey, testKeyMaterial: DataProvider? = nil, testNonce: Nonce? = nil) -> Assertion {
        let sealedMessage = SealedMessage(plaintext: contentKey.taggedCBOR, recipient: recipient, testKeyMaterial: testKeyMaterial, testNonce: testNonce)
        return Assertion(Envelope(predicate: .hasRecipient), Envelope(sealedMessage))
    }

    static func sskrShare(_ share: SSKRShare) -> Assertion {
        Assertion(Envelope(predicate: .sskrShare), Envelope(share))
    }

    static func isA(_ object: Envelope) -> Assertion {
        Assertion(Envelope(predicate: .isA), object)
    }

    static func id(_ id: SCID) -> Assertion {
        Assertion(Envelope(predicate: .id), Envelope(id))
    }
}

public extension Assertion {
    func redact() -> Assertion {
        Assertion(envelope.redact())
    }

    func redact(items: Set<Digest>) -> Assertion {
        Assertion(envelope.redact(items: items))
    }

    func redact(revealing items: Set<Digest>) -> Assertion {
        Assertion(envelope.redact(revealing: items))
    }
}

public extension Assertion {
    static func parameter(_ param: FunctionParameter, value: CBOREncodable) -> Assertion {
        Assertion(Envelope(param.cbor), Envelope(value))
    }

    static func parameter(_ name: String, value: CBOREncodable) -> Assertion {
        Assertion(Envelope(FunctionParameter.tagged(name: name)), Envelope(value))
    }
}

public extension Assertion {
    var taggedCBOR: CBOR {
        envelope.taggedCBOR
    }
    
    init(taggedCBOR: CBOR) throws {
        let envelope = try Envelope(taggedCBOR: taggedCBOR)
        guard case .assertion = envelope.subject else {
            throw EnvelopeError.invalidFormat
        }
        self.envelope = envelope
    }
}
