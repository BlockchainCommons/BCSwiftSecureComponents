import Foundation
import WolfBase
import SSKR
import URKit

public enum Assertion: DigestProvider {
    case present(predicate: Envelope, object: Envelope, digest: Digest)
    case redacted(Digest)
}

//public struct Assertion: DigestProvider {
//    public let predicate: Envelope
//    public let object: Envelope
//    public let digest: Digest
//}

public extension Assertion {
    init(_ predicate: Envelope, _ object: Envelope) {
        let digest = Digest(predicate.digest + object.digest)
        self = .present(predicate: predicate, object: object, digest: digest)
    }
    
    init(_ digest: Digest) {
        self = .redacted(digest)
    }
}

public extension Assertion {
    func hasPredicate(_ predicate: Envelope) -> Bool {
        switch self {
        case .present(predicate: let myPredicate, object: _, digest: _):
            return myPredicate == predicate
        case .redacted(_):
            return false
        }
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
        switch self {
        case .present(predicate: _, object: _, digest: let digest):
            return digest
        case .redacted(let digest):
            return digest
        }
    }
    
    var predicate: Envelope {
        get throws {
            switch self {
            case .present(predicate: let predicate, object: _, digest: _):
                return predicate
            case .redacted(_):
                throw EnvelopeError.redacted
            }
        }
    }
    
    var object: Envelope {
        get throws {
            switch self {
            case .present(predicate: _, object: let object, digest: _):
                return object
            case .redacted(_):
                throw EnvelopeError.redacted
            }
        }
    }
}

public extension Assertion {
    var deepDigests: Set<Digest> {
        switch self {
        case .present(predicate: let predicate, object: let object, digest: let digest):
            return predicate.deepDigests.union(object.deepDigests).union([digest])
        case .redacted(let digest):
            return [digest]
        }
        
    }
    
    var shallowDigests: Set<Digest> {
        switch self {
        case .present(predicate: let predicate, object: let object, digest: let digest):
            return         [
                digest,
                predicate.digest, predicate.subject.digest,
                object.digest, object.subject.digest
            ]
        case .redacted(let digest):
            return [digest]
        }
    }
}

public extension Assertion {
    func assertions(predicate: CBOREncodable) -> [Assertion] {
        switch self {
        case .present(predicate: _, object: let object, digest: _):
            return object.assertions(predicate: predicate)
        case .redacted(_):
            return []
        }
    }
    
    func assertion(predicate: CBOREncodable) throws -> Assertion {
        switch self {
        case .present(predicate: _, object: let object, digest: _):
            return try object.assertion(predicate: predicate)
        case .redacted(_):
            throw EnvelopeError.redacted
        }
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
        switch self {
        case .present(predicate: _, object: _, digest: let digest):
            return .redacted(digest)
        case .redacted(_):
            return self
        }
    }
    
    func redact(items: Set<Digest>) -> Assertion {
        switch self {
        case .present(predicate: let predicate, object: let object, digest: let digest):
            if items.contains(digest) {
                return redact()
            }
            let result = Assertion(predicate.redact(items: items), object.redact(items: items))
            assert(result.digest == digest)
            return result
        case .redacted(_):
            return self
        }
    }
    
    func redact(revealing items: Set<Digest>) -> Assertion {
        switch self {
        case .present(predicate: let predicate, object: let object, digest: let digest):
            if !items.contains(digest) {
                return redact()
            }
            let result = Assertion(predicate.redact(revealing: items), object.redact(revealing: items))
            assert(result.digest == digest)
            return result
        case .redacted(_):
            return self
        }
    }
}

public extension Assertion {
    var untaggedCBOR: CBOR {
        switch self {
        case .present(predicate: let predicate, object: let object, digest: _):
            return [predicate.taggedCBOR, object.taggedCBOR]
        case .redacted(let digest):
            return digest.taggedCBOR
        }
    }
    
    init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.array(elements) = untaggedCBOR,
            elements.count == 2
        else {
            throw CBORError.invalidFormat
        }

        let predicate = try Envelope(taggedCBOR: elements[0])
        let object = try Envelope(taggedCBOR: elements[1])

        self.init(predicate, object)
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
