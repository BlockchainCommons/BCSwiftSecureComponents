import Foundation
import URKit
import WolfBase
import CryptoKit
import SSKR
import URKit

public indirect enum Envelope: DigestProvider {
    case node(subject: Envelope, assertions: [Envelope], digest: Digest)
    case leaf(CBOR, Digest)
    case wrapped(Envelope, Digest)
    case knownValue(KnownValue, Digest)
    case assertion(Assertion)
    case encrypted(EncryptedMessage)
    case elided(Digest)
}

extension Envelope: CustomStringConvertible {
    public var description: String {
        switch self {
        case .node(subject: let subject, assertions: let assertions, digest: _):
            return ".node(\(subject), \(assertions))"
        case .leaf(let cbor, _):
            return ".cbor(\(cbor.formatItem.description))"
        case .wrapped(let envelope, _):
            return ".wrapped(\(envelope))"
        case .knownValue(let knownValue, _):
            return ".knownValue(\(knownValue))"
        case .assertion(let assertion):
            return ".assertion(\(assertion.predicate), \(assertion.object))"
        case .encrypted(_):
            return ".encrypted"
        case .elided(_):
            return ".elided"
        }
    }
}
