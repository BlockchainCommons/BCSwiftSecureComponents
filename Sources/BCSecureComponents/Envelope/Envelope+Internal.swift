import Foundation

extension Envelope {
    init(subject: Envelope, uncheckedAssertions: [Envelope]) {
        assert(!uncheckedAssertions.isEmpty)
        let sortedAssertions = uncheckedAssertions.sorted() { $0.digest < $1.digest }
        var digests = [subject.digest]
        digests.append(contentsOf: sortedAssertions.map { $0.digest })
        let digest = Digest(Data(digests.map { $0.data }.joined()))

        self = .node(subject: subject, assertions: sortedAssertions, digest: digest)
    }

    init(subject: Envelope, assertions: [Envelope]) throws {
        guard assertions.allSatisfy({ $0.isSubjectAssertion || $0.isSubjectElided || $0.isSubjectEncrypted }) else {
            throw EnvelopeError.invalidFormat
        }
        self.init(subject: subject, uncheckedAssertions: assertions)
    }

    init(knownValue: KnownValue) {
        self = .knownValue(knownValue, knownValue.digest)
    }

    init(assertion: Assertion) {
        self = .assertion(assertion)
    }

    init(encryptedMessage: EncryptedMessage) throws {
        guard encryptedMessage.digest != nil else {
            throw EnvelopeError.missingDigest
        }
        self = .encrypted(encryptedMessage)
    }

    init(elided digest: Digest) {
        self = .elided(digest)
    }

    init(cbor: CBOR) {
        let digest = Digest(cbor.cborEncode)
        self = .leaf(cbor, digest)
    }

    init(cborEncodable item: CBOREncodable) {
        self.init(cbor: item.cbor)
    }

    init(wrapped envelope: Envelope) {
        let digest = Digest(envelope.digest)
        self = .wrapped(envelope, digest)
    }
}
