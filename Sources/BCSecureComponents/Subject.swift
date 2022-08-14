import Foundation
import URKit

public indirect enum Subject {
    case leaf(CBOR, Digest)
    case envelope(Envelope)
    case assertion(predicate: Envelope, object: Envelope, digest: Digest)
    case encrypted(EncryptedMessage, Digest)
    case redacted(Digest)
}

public extension Subject {
    init(predicate: Envelope, object: Envelope) {
        let digest = Digest(predicate.digest + object.digest)
        self = .assertion(predicate: predicate, object: object, digest: digest)
    }
    
    init(predicate: CBOR, object: CBOR) throws {
        let predicate = try Envelope(taggedCBOR: predicate)
        let object = try Envelope(taggedCBOR: object)
        self.init(predicate: predicate, object: object)
    }
}

extension Subject: DigestProvider {
    public var digest: Digest {
        switch self {
        case .leaf(_, let digest):
            return digest
        case .envelope(let envelope):
            return envelope.digest
        case .assertion(predicate: _, object: _, digest: let digest):
            return digest
        case .encrypted(_, let digest):
            return digest
        case .redacted(let digest):
            return digest
        }
    }
}

public extension Subject {
    var shallowDigests: Set<Digest> {
        switch self {
        case .leaf(_, let digest):
            return [digest]
        case .envelope(let envelope):
            return envelope.shallowDigests
        case .assertion(predicate: let predicate, object: let object, digest: let digest):
            return [digest, predicate.digest, predicate.subject.digest, object.digest, object.subject.digest]
        case .encrypted(_, let digest):
            return [digest]
        case .redacted(let digest):
            return [digest]
        }
    }

    var deepDigests: Set<Digest> {
        switch self {
        case .leaf(_, let digest):
            return [digest]
        case .envelope(let envelope):
            return envelope.deepDigests
        case .assertion(predicate: let predicate, object: let object, digest: let digest):
            return predicate.deepDigests.union(object.deepDigests).union([digest])
        case .encrypted(_, let digest):
            return [digest]
        case .redacted(let digest):
            return [digest]
        }
    }
}

extension Subject: Equatable {
    public static func ==(lhs: Subject, rhs: Subject) -> Bool {
        lhs.digest == rhs.digest
    }
}

public extension Subject {
    var isAssertion: Bool {
        if case .assertion = self {
            return true
        }
        return false
    }
}

public extension Subject {
    func redact() -> Subject {
        switch self {
        case .leaf(_, let digest):
            return .redacted(digest)
        case .envelope(let envelope):
            return .redacted(envelope.digest)
        case .assertion(predicate: _, object: _, digest: let digest):
            return .redacted(digest)
        case .encrypted(_, let digest):
            return .redacted(digest)
        case .redacted(_):
            return self
        }
    }
    
    func redact(items: Set<Digest>) -> Subject {
        if items.contains(digest) {
            return .redacted(digest)
        }
        
        switch self {
        case .leaf(_, _):
            return self
        case .envelope(let envelope):
            return .envelope(envelope.redact(items: items))
        case .assertion(predicate: let predicate, object: let object, digest: let digest):
            if items.contains(digest) {
                return .redacted(digest)
            } else {
                return .assertion(predicate: predicate.redact(items: items), object: object.redact(items: items), digest: digest)
            }
        case .encrypted(_, _):
            return self
        case .redacted(_):
            return self
        }
    }
    
    func redact(revealing items: Set<Digest>) -> Subject {
        if !items.contains(digest) {
            return .redacted(digest)
        }
        
        switch self {
        case .leaf(_, _):
            return self
        case .envelope(let envelope):
            return .envelope(envelope.redact(revealing: items))
        case .assertion(predicate: let predicate, object: let object, digest: let digest):
            if !items.contains(digest) {
                return .redacted(digest)
            } else {
                return .assertion(predicate: predicate.redact(revealing: items), object: object.redact(revealing: items), digest: digest)
            }
        case .encrypted(_, _):
            return self
        case .redacted(_):
            return self
        }
    }
}

public extension Subject {
    init(plaintext: CBOREncodable) {
        if let envelope = plaintext as? Envelope {
            self = .envelope(envelope)
        } else {
            let cbor = plaintext.cbor
            let encodedCBOR = cbor.cborEncode
            self = .leaf(cbor, Digest(encodedCBOR))
        }
    }
    
    init(predicate: KnownPredicate) {
        self.init(plaintext: CBOR.tagged(.predicate, CBOR.unsignedInt(predicate.rawValue)))
    }
}

public extension Subject {
    var plaintext: CBOR? {
        guard case let .leaf(plaintext, _) = self else {
            return nil
        }
        return plaintext
    }

    var envelope: Envelope? {
        guard case let .envelope(envelope) = self else {
            return nil
        }
        return envelope
    }

    var predicate: Envelope? {
        guard case let .assertion(predicate, _, _) = self else {
            return nil
        }
        return predicate
    }
    
    var object: Envelope? {
        guard case let .assertion(_, object, _) = self else {
            return nil
        }
        return object
    }
    
    var knownPredicate: KnownPredicate? {
        guard
            let predicate = predicate,
            let plaintext = predicate.plaintext,
            case CBOR.tagged(.predicate, let value) = plaintext,
            case CBOR.unsignedInt(let rawValue) = value,
            let result = KnownPredicate(rawValue: rawValue)
        else {
            return nil
        }
        
        return result
    }
}

public extension Subject {
    var cbor: CBOR {
        switch self {
        case .envelope(let envelope):
            return envelope.taggedCBOR
        case .leaf(let plaintext, _):
            return CBOR.tagged(.plaintext, plaintext)
        case .assertion(predicate: let predicate, object: let object, digest: _):
            return CBOR.tagged(.assertion, [predicate.taggedCBOR, object.taggedCBOR])
        case .encrypted(let message, _):
            return message.taggedCBOR
        case .redacted(let digest):
            return digest.taggedCBOR
        }
    }
    
    init(cbor: CBOR) throws {
        if case CBOR.tagged(URType.envelope.tag, _) = cbor {
            self = try .envelope(Envelope(taggedCBOR: cbor))
        } else if case let CBOR.tagged(.plaintext, plaintext) = cbor {
            self = .leaf(plaintext, Digest(plaintext.cborEncode))
        } else if case let CBOR.tagged(.assertion, assertion) = cbor {
            guard
                case let CBOR.array(array) = assertion,
                array.count == 2
            else {
                throw EnvelopeError.invalidFormat
            }
            try self.init(predicate: array[0], object: array[1])
        } else if case CBOR.tagged(URType.message.tag, _) = cbor {
            let message = try EncryptedMessage(taggedCBOR: cbor)
            self = try .encrypted(message, message.digest)
        } else if case CBOR.tagged(URType.digest.tag, _) = cbor {
            self = try .redacted(Digest(taggedCBOR: cbor))
        } else {
            throw EnvelopeError.invalidFormat
        }
    }
}

public extension Subject {
    func encrypt(with key: SymmetricKey, nonce: Nonce? = nil) throws -> Subject {
        let encodedCBOR: Data
        let digest: Digest
        switch self {
        case .leaf(let c, _):
            encodedCBOR = c.cborEncode
            digest = Digest(encodedCBOR)
        case .envelope(let s):
            encodedCBOR = s.taggedCBOR.cborEncode
            digest = s.digest
        case .assertion(predicate: let predicate, object: let object, digest: let _digest):
            encodedCBOR = CBOR.array([predicate.taggedCBOR, object.taggedCBOR]).cborEncode
            digest = _digest
        case .encrypted(_, _):
            throw EnvelopeError.invalidOperation
        case .redacted(_):
            throw EnvelopeError.invalidOperation
        }
        
        let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: digest, nonce: nonce)
        return Subject.encrypted(encryptedMessage, digest)
    }
    
    func decrypt(with key: SymmetricKey) throws -> Subject {
        guard
            case let .encrypted(encryptedMessage, _) = self
        else {
            throw EnvelopeError.invalidOperation
        }
        
        guard
            let encodedCBOR = key.decrypt(message: encryptedMessage)
        else {
            throw EnvelopeError.invalidKey
        }
        
        let cbor = try CBOR(encodedCBOR)
        if case CBOR.tagged(URType.envelope.tag, _) = cbor {
            let envelope = try Envelope(taggedCBOR: cbor)
            guard envelope.digest == digest else {
                throw EnvelopeError.invalidDigest
            }
            return .envelope(envelope)
        } else if case CBOR.array(let array) = cbor {
            guard array.count == 2 else {
                throw EnvelopeError.invalidFormat
            }
            let assertion = try Subject(predicate: array[0], object: array[1])
            guard assertion.digest == digest else {
                throw EnvelopeError.invalidDigest
            }
            return assertion
        } else {
            guard try Digest.validate(encodedCBOR, digest: encryptedMessage.digest) else {
                throw EnvelopeError.invalidDigest
            }
            return .leaf(cbor, digest)
        }
    }
}
