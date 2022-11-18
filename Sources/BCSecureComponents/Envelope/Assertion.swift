import Foundation
import URKit

public struct Assertion: DigestProvider {
    public let predicate: Envelope
    public let object: Envelope
    public let digest: Digest
    
    public init(predicate: Any, object: Any) {
        let p: Envelope
        if let predicate = predicate as? Envelope {
            p = predicate
        } else {
            p = Envelope(predicate)
        }
        let o: Envelope
        if let object = object as? Envelope {
            o = object
        } else {
            o = Envelope(object)
        }
        self.predicate = p
        self.object = o
        self.digest = Digest(p.digest + o.digest)
    }
}

extension Assertion {
    var untaggedCBOR: CBOR {
        [predicate.cbor, object.cbor]
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.assertion, untaggedCBOR)
    }
    
    init(untaggedCBOR: CBOR) throws {
        guard
            case CBOR.array(let array) = untaggedCBOR,
            array.count == 2
        else {
            throw CBORError.invalidFormat
        }
        let predicate = try Envelope.cborDecode(array[0])
        let object = try Envelope.cborDecode(array[1])
        self.init(predicate: predicate, object: object)
    }
}

extension Assertion: Equatable {
    public static func ==(lhs: Assertion, rhs: Assertion) -> Bool {
        lhs.digest == rhs.digest
    }
}

extension Assertion {
    var hasAssertions: Bool {
        predicate.hasAssertions || object.hasAssertions
    }
}

extension Assertion {
    var formatItem: EnvelopeFormatItem {
        .list([predicate.formatItem, ": ", object.formatItem])
    }
}
