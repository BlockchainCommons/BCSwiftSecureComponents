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
    case knownPredicate(KnownPredicate, Digest)
    case assertion(Assertion)
    case encrypted(EncryptedMessage)
    case elided(Digest)
}

public extension Envelope {
    var digest: Digest {
        switch self {
        case .node(subject: _, assertions: _, digest: let digest):
            return digest
        case .leaf(_, let digest):
            return digest
        case .wrapped(_, let digest):
            return digest
        case .knownPredicate(_, let digest):
            return digest
        case .assertion(let assertion):
            return assertion.digest
        case .encrypted(let encryptedMessage):
            return encryptedMessage.digest!
        case .elided(digest: let digest):
            return digest
        }
    }

    var subject: Envelope {
        if case .node(let subject, _, _) = self {
            return subject
        }
        return self
    }

    var assertions: [Envelope] {
        guard case .node(_, let assertions, _) = self else {
            return []
        }
        return assertions
    }

    var hasAssertions: Bool {
        !assertions.isEmpty
    }

    var assertion: Assertion? {
        guard case .assertion(let assertion) = self else {
            return nil
        }
        return assertion
    }

    var predicate: Envelope? {
        assertion?.predicate
    }

    var object: Envelope? {
        assertion?.object
    }

    var leaf: CBOR? {
        guard case .leaf(let cbor, _) = subject else {
            return nil
        }
        return cbor
    }

    var knownPredicate: KnownPredicate? {
        guard case .knownPredicate(let knownPredicate, _) = self else {
            return nil
        }
        return knownPredicate
    }
}

public extension Envelope {
    var isNode: Bool {
        guard case .node = self else {
            return false
        }
        return true
    }

    var isAssertion: Bool {
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

    var isEncrypted: Bool {
        guard case .encrypted = self else {
            return false
        }
        return true
    }
    
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

    var isElided: Bool {
        guard case .elided = self else {
            return false
        }
        return true
    }
    
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

    var isWrapped: Bool {
        guard case .wrapped = self else {
            return false
        }
        return true
    }

    var isKnownPredicate: Bool {
        guard case .knownPredicate = self else {
            return false
        }
        return true
    }
}

private extension Envelope {
    init(subject: Envelope, uncheckedAssertions: [Envelope]) {
        assert(!uncheckedAssertions.isEmpty)
        let sortedAssertions = uncheckedAssertions.sorted()
        var digests = [subject.digest]
        digests.append(contentsOf: sortedAssertions.map { $0.digest })
        let digest = Digest(Data(digests.map { $0.data }.joined()))

        self = .node(subject: subject, assertions: sortedAssertions, digest: digest)
    }

    init(subject: Envelope, assertions: [Envelope]) throws {
        guard assertions.allSatisfy({ $0.isAssertion || $0.isSubjectElided || $0.isSubjectEncrypted }) else {
            throw EnvelopeError.invalidFormat
        }
        self.init(subject: subject, uncheckedAssertions: assertions)
    }

    init(knownPredicate: KnownPredicate) {
        self = .knownPredicate(knownPredicate, knownPredicate.digest)
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

public extension Envelope {
    init(_ item: Any) {
        if let envelope = item as? Envelope {
            self.init(wrapped: envelope)
        } else if let knownPredicate = item as? KnownPredicate {
            self.init(knownPredicate: knownPredicate)
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

    init(predicate: Any, object: Any) {
        self.init(assertion: Assertion(predicate: predicate, object: object))
    }

    init(predicate: KnownPredicate, object: Any) {
        self.init(assertion: Assertion(predicate: predicate, object: object))
    }
}

public extension Envelope {
    func digests(levels level: Int) -> Set<Digest> {
        guard level > 0 else {
            return []
        }

        var result: Set<Digest> = [digest]

        let nextLevel = level - 1

        switch self {
        case .node(let subject, let assertions, _):
            result.insert(subject.digests(levels: nextLevel))
            for assertion in assertions {
                result.insert(assertion.digests(levels: nextLevel))
            }
        case .assertion(let assertion):
            result.insert(assertion.predicate.digests(levels: nextLevel))
            result.insert(assertion.predicate.subject.digests(levels: nextLevel))
            result.insert(assertion.object.digests(levels: nextLevel))
            result.insert(assertion.object.subject.digests(levels: nextLevel))
        case .wrapped(let envelope, _):
            result.insert(envelope.digests(levels: nextLevel))
        default:
            break
        }

        return result
    }

    var deepDigests: Set<Digest> {
        digests(levels: .max)
    }

    var shallowDigests: Set<Digest> {
        digests(levels: 2)
    }
}

extension Envelope: CBORCodable {
    public var cbor: CBOR {
        taggedCBOR
    }

    public static func cborDecode(_ cbor: CBOR) throws -> Envelope {
        try Envelope(taggedCBOR: cbor)
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
        case .knownPredicate(let knownPredicate, _):
            guard let result = knownPredicate as? T else {
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
    func wrap() -> Envelope {
        Envelope(self)
    }

    func unwrap() throws -> Envelope {
        guard case .wrapped(let envelope, _) = subject else {
            throw EnvelopeError.notWrapped
        }
        return envelope
    }
}

extension Envelope: Equatable {
    public static func ==(lhs: Envelope, rhs: Envelope) -> Bool {
        lhs.digest == rhs.digest
    }
}

extension Envelope: Comparable {
    public static func <(lhs: Envelope, rhs: Envelope) -> Bool {
        lhs.digest < rhs.digest
    }
}

extension Envelope: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int) {
        self.init(value)
    }
}

public extension Envelope {
    func assertions(withPredicate predicate: Envelope) -> [Envelope] {
        return assertions.filter { $0.predicate == predicate }
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

    func extractObject(forPredicate predicate: Envelope) throws -> Envelope {
        guard let result = try assertion(withPredicate: predicate).object else {
            throw EnvelopeError.invalidFormat
        }
        return result
    }

    func extractObject<T>(_ type: T.Type, forPredicate predicate: Envelope) throws -> T where T: CBORDecodable {
        try extractObject(forPredicate: predicate).extractSubject(type)
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
}

public extension Envelope {
    func assertions(withPredicate predicate: KnownPredicate) -> [Envelope] {
        assertions(withPredicate: Envelope(knownPredicate: predicate))
    }

    func assertion(withPredicate predicate: KnownPredicate) throws -> Envelope {
        try assertion(withPredicate: Envelope(knownPredicate: predicate))
    }

    func extractObject(forPredicate predicate: KnownPredicate) throws -> Envelope {
        try extractObject(forPredicate: Envelope(knownPredicate: predicate))
    }

    func extractObject<T>(_ type: T.Type, forPredicate predicate: KnownPredicate) throws -> T where T: CBORDecodable {
        try extractObject(type, forPredicate: Envelope(knownPredicate: predicate))
    }
}

public extension Envelope {
    func addAssertion(_ envelope: Envelope, salted: Bool = false) throws -> Envelope {
        guard envelope.isAssertion else {
            throw EnvelopeError.invalidFormat
        }
        let envelope = salted ? envelope.addSalt() : envelope
        switch self {
        case .node(subject: let subject, assertions: let assertions, digest: _):
            if !assertions.contains(envelope) {
                return Envelope(subject: subject, uncheckedAssertions: assertions.appending(envelope))
            } else {
                return self
            }
        default:
            return Envelope(subject: subject, uncheckedAssertions: [envelope])
        }
    }

    func addAssertion(_ assertion: Assertion, salted: Bool = false) -> Envelope {
        try! addAssertion(Envelope(assertion: assertion), salted: salted)
    }

    func addAssertion(_ predicate: Any, _ object: Any, salted: Bool = false) -> Envelope {
        addAssertion(Assertion(predicate: predicate, object: object), salted: salted)
    }

    func addAssertion(_ predicate: KnownPredicate, _ object: Any, salted: Bool = false) -> Envelope {
        addAssertion(Assertion(predicate: predicate, object: object), salted: salted)
    }
}

public extension Envelope {
    func addAssertion(if condition: Bool, _ envelope: @autoclosure () -> Envelope, salted: Bool = false) throws -> Envelope {
        guard condition else {
            return self
        }
        return try addAssertion(envelope(), salted: salted)
    }

    func addAssertion(if condition: Bool, _ assertion: @autoclosure () -> Assertion, salted: Bool = false) -> Envelope {
        guard condition else {
            return self
        }
        return addAssertion(assertion(), salted: salted)
    }

    func addAssertion(if condition: Bool, _ predicate: @autoclosure () -> Any, _ object: @autoclosure () -> Any, salted: Bool = false) -> Envelope {
        guard condition else {
            return self
        }
        return addAssertion(predicate(), object(), salted: salted)
    }

    func addAssertion(if condition: Bool, _ predicate: @autoclosure () -> KnownPredicate, _ object: @autoclosure () -> Any, salted: Bool = false) -> Envelope {
        guard condition else {
            return self
        }
        return addAssertion(predicate(), object(), salted: salted)
    }
}

public extension Envelope {
    /// Add the given Salt as an assertion
    func addSalt(_ salt: Salt) -> Envelope {
        addAssertion(.salt, salt)
    }
    
    /// Add a specified number of bytes of salt.
    func addSalt(_ count: Int) throws -> Envelope {
        guard let salt = Salt(count: count) else {
            throw EnvelopeError.invalidFormat
        }
        return addSalt(salt)
    }

    /// Add a number of bytes of salt chosen randomly from the given range.
    func addSalt(_ range: ClosedRange<Int>) throws -> Envelope {
        guard let salt = Salt(range: range) else {
            throw EnvelopeError.invalidFormat
        }
        return addSalt(salt)
    }

    /// Add a number of bytes of salt generally proportionate to the size of the object being salted.
    func addSalt() -> Envelope {
        addSalt(Salt(forSize: taggedCBOR.cborEncode.count))
    }
}

public extension Envelope {
    static func verifiedBy(signature: Signature, note: String? = nil) -> Envelope {
        Envelope(
            predicate: .verifiedBy,
            object: Envelope(signature)
                .addAssertion(if: note != nil, .note, note!)
        )
    }

    static func hasRecipient(_ recipient: PublicKeyBase, contentKey: SymmetricKey, testKeyMaterial: DataProvider? = nil, testNonce: Nonce? = nil) -> Envelope {
        let sealedMessage = SealedMessage(plaintext: contentKey.taggedCBOR, recipient: recipient, testKeyMaterial: testKeyMaterial, testNonce: testNonce)
        return Envelope(predicate: .hasRecipient, object: sealedMessage)
    }

    static func sskrShare(_ share: SSKRShare) -> Envelope {
        Envelope(predicate: .sskrShare, object: share)
    }

    static func isA(_ object: Envelope) -> Envelope {
        Envelope(predicate: .isA, object: object)
    }

    static func id(_ id: CID) -> Envelope {
        Envelope(predicate: .id, object: id)
    }
}

public extension Envelope {
    static func parameter(_ param: ParameterIdentifier, value: CBOREncodable) -> Envelope {
        Envelope(predicate: param.cbor, object: Envelope(value))
    }

    static func parameter(_ name: String, value: CBOREncodable) -> Envelope {
        parameter(ParameterIdentifier(name), value: value)
    }

    func addParameter(_ param: ParameterIdentifier, value: CBOREncodable) -> Envelope {
        try! addAssertion(.parameter(param, value: value))
    }

    func addParameter(_ name: String, value: CBOREncodable) -> Envelope {
        try! addAssertion(.parameter(name, value: value))
    }
}

public extension Envelope {
    func sign(with privateKeys: PrivateKeyBase, note: String? = nil, tag: Data? = nil, randomGenerator: ((Int) -> Data)? = nil) -> Envelope {
        let signature = privateKeys.signingPrivateKey.schnorrSign(subject.digest, tag: tag, randomGenerator: randomGenerator)
        return try! addAssertion(.verifiedBy(signature: signature, note: note))
    }

    func sign(with privateKeys: [PrivateKeyBase], tag: Data? = nil, randomGenerator: ((Int) -> Data)? = nil) -> Envelope {
        var result = self
        for keys in privateKeys {
            result = result.sign(with: keys, randomGenerator: randomGenerator)
        }
        return result
    }

    func addRecipient(_ recipient: PublicKeyBase, contentKey: SymmetricKey, testKeyMaterial: DataProvider? = nil, testNonce: Nonce? = nil) -> Envelope {
        try! addAssertion(.hasRecipient(recipient, contentKey: contentKey, testKeyMaterial: testKeyMaterial, testNonce: testNonce))
    }

    func addSSKRShare(_ share: SSKRShare) -> Envelope {
        try! addAssertion(.sskrShare(share))
    }

    func split(groupThreshold: Int, groups: [(Int, Int)], contentKey: SymmetricKey, testRandomGenerator: ((Int) -> Data)? = nil) -> [[Envelope]] {
        let shares = try! SSKRGenerate(groupThreshold: groupThreshold, groups: groups, secret: contentKey, testRandomGenerator: testRandomGenerator)
        return shares.map { groupShares in
            groupShares.map { share in
                self.addSSKRShare(share)
            }
        }
    }

    static func shares(in envelopes: [Envelope]) throws -> [UInt16: [SSKRShare]] {
        var result: [UInt16: [SSKRShare]] = [:]
        for envelope in envelopes {
            try envelope.assertions(withPredicate: .sskrShare)
                .forEach {
                    let share = try $0.object!.extractSubject(SSKRShare.self)
                    let identifier = share.identifier
                    if result[identifier] == nil {
                        result[identifier] = []
                    }
                    result[identifier]!.append(share)
                }
        }
        return result
    }

    init(shares envelopes: [Envelope]) throws {
        guard !envelopes.isEmpty else {
            throw EnvelopeError.invalidShares
        }
        for shares in try Self.shares(in: envelopes).values {
            guard let contentKey = try? SymmetricKey(SSKRCombine(shares: shares)) else {
                continue
            }
            self = try envelopes.first!.decryptSubject(with: contentKey).subject
            return
        }
        throw EnvelopeError.invalidShares
    }
}

public extension Envelope {
    var signatures: [Signature] {
        get throws {
            try assertions(withPredicate: .verifiedBy)
                .map { try $0.object!.extractSubject(Signature.self) }
        }
    }

    func isVerifiedSignature(_ signature: Signature, key: SigningPublicKey) -> Bool {
        return key.isValidSignature(signature, for: subject.digest)
    }

    @discardableResult
    func verifySignature(_ signature: Signature, key: SigningPublicKey) throws -> Envelope {
        guard isVerifiedSignature(signature, key: key) else {
            throw EnvelopeError.unverifiedSignature
        }
        return self
    }

    func isVerifiedSignature(_ signature: Signature, publicKeys: PublicKeyBase) -> Bool {
        isVerifiedSignature(signature, key: publicKeys.signingPublicKey)
    }

    @discardableResult
    func verifySignature(_ signature: Signature, publicKeys: PublicKeyBase) throws -> Envelope {
        try verifySignature(signature, key: publicKeys.signingPublicKey)
    }

    func hasVerifiedSignature(key: SigningPublicKey) throws -> Bool {
        let sigs = try signatures
        return sigs.contains { isVerifiedSignature($0, key: key) }
    }

    @discardableResult
    func verifySignature(key: SigningPublicKey) throws -> Envelope {
        guard try hasVerifiedSignature(key: key) else {
            throw EnvelopeError.unverifiedSignature
        }
        return self
    }

    func hasVerifiedSignature(from publicKeys: PublicKeyBase) throws -> Bool {
        try hasVerifiedSignature(key: publicKeys.signingPublicKey)
    }

    @discardableResult
    func verifySignature(from publicKeys: PublicKeyBase) throws -> Envelope {
        try verifySignature(key: publicKeys.signingPublicKey)
    }

    func hasVerifiedSignatures(with keys: [SigningPublicKey], threshold: Int? = nil) throws -> Bool {
        let threshold = threshold ?? keys.count
        var count = 0
        for key in keys {
            if try hasVerifiedSignature(key: key) {
                count += 1
                if count >= threshold {
                    return true
                }
            }
        }
        return false
    }

    @discardableResult
    func verifySignatures(with keys: [SigningPublicKey], threshold: Int? = nil) throws -> Envelope {
        guard try hasVerifiedSignatures(with: keys, threshold: threshold) else {
            throw EnvelopeError.unverifiedSignature
        }
        return self
    }

    func hasVerifiedSignatures(from publicKeysArray: [PublicKeyBase], threshold: Int? = nil) throws -> Bool {
        try hasVerifiedSignatures(with: publicKeysArray.map { $0.signingPublicKey }, threshold: threshold)
    }

    @discardableResult
    func verifySignatures(from publicKeysArray: [PublicKeyBase], threshold: Int? = nil) throws -> Envelope {
        try verifySignatures(with: publicKeysArray.map { $0.signingPublicKey }, threshold: threshold)
    }
}

public extension Envelope {
    func encryptSubject(with key: SymmetricKey, testNonce: Nonce? = nil) throws -> Envelope {
        let result: Envelope
        let originalDigest: Digest

        switch self {
        case .node(let subject, let assertions, let envelopeDigest):
            guard !subject.isEncrypted else {
                throw EnvelopeError.alreadyEncrypted
            }
            let encodedCBOR = subject.cborEncode
            let subjectDigest = subject.digest
            let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: subjectDigest, nonce: testNonce)
            let encryptedSubject = try Envelope(encryptedMessage: encryptedMessage)
            result = Envelope(subject: encryptedSubject, uncheckedAssertions: assertions)
            originalDigest = envelopeDigest
        case .leaf(let cbor, let envelopeDigest):
            let encodedCBOR = CBOR.tagged(.leaf, cbor).cborEncode
            let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: envelopeDigest, nonce: testNonce)
            result = try Envelope(encryptedMessage: encryptedMessage)
            originalDigest = envelopeDigest
        case .wrapped(_, let wrappedDigest):
            let encodedCBOR = self.untaggedCBOR.cborEncode
            let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: wrappedDigest, nonce: testNonce)
            result = try Envelope(encryptedMessage: encryptedMessage)
            originalDigest = wrappedDigest
        case .knownPredicate(let knownPredicate, let envelopeDigest):
            let encodedCBOR = knownPredicate.taggedCBOR.cborEncode
            let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: envelopeDigest, nonce: testNonce)
            result = try Envelope(encryptedMessage: encryptedMessage)
            originalDigest = envelopeDigest
        case .assertion(let assertion):
            let assertionDigest = assertion.digest
            let encodedCBOR = assertion.taggedCBOR.cborEncode
            let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: assertionDigest, nonce: testNonce)
            result = try Envelope(encryptedMessage: encryptedMessage)
            originalDigest = assertionDigest
        case .encrypted(_):
            throw EnvelopeError.alreadyEncrypted
        case .elided(_):
            throw EnvelopeError.elided
        }

        assert(result.digest == originalDigest)
        return result
    }

    func decryptSubject(with key: SymmetricKey) throws -> Envelope {
        guard case .encrypted(let message) = subject else {
            throw EnvelopeError.notEncrypted
        }

        guard
            let encodedCBOR = key.decrypt(message: message)
        else {
            throw EnvelopeError.invalidKey
        }

        guard let subjectDigest = message.digest else {
            throw EnvelopeError.missingDigest
        }

        let cbor = try CBOR(encodedCBOR)
        let resultSubject = try Envelope(untaggedCBOR: cbor).subject

        guard resultSubject.digest == subjectDigest else {
            throw EnvelopeError.invalidDigest
        }

        switch self {
        case .node(subject: _, assertions: let assertions, digest: let originalDigest):
            let result = Envelope(subject: resultSubject, uncheckedAssertions: assertions)
            guard result.digest == originalDigest else {
                throw EnvelopeError.invalidDigest
            }
            return result
        default:
            return resultSubject
        }
    }
}

public extension Envelope {
    var recipients: [SealedMessage] {
        get throws {
            try assertions(withPredicate: .hasRecipient)
                .map { try $0.object!.extractSubject(SealedMessage.self) }
        }
    }

    func decrypt(to recipient: PrivateKeyBase) throws -> Envelope {
        guard
            let contentKeyData = try SealedMessage.firstPlaintext(in: recipients, for: recipient)
        else {
            throw EnvelopeError.invalidRecipient
        }

        let cbor = try CBOR(contentKeyData)
        let contentKey = try SymmetricKey(taggedCBOR: cbor)
        return try decryptSubject(with: contentKey).subject
    }
}

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

extension Envelope {
    public func proof(contains target: DigestProvider, allPositions: Bool = false) -> Envelope? {
        let targetSet = targetSet(of: target, allPositions: allPositions)
        guard !targetSet.isEmpty else { return nil }
        return try! elideRevealing(targetSet).elideRemoving(target)
    }
    
    public func targetSet(of target: DigestProvider, allPositions: Bool = false) -> Set<Digest> {
        var result: [Set<Digest>] = []
        targetSets(of: target.digest, current: [], result: &result)
        if allPositions {
            return result.reduce(into: []) {
                $0.formUnion($1)
            }
        } else {
            return result.first!
        }
    }
    
    func targetSets(of target: Digest, current: Set<Digest>, result: inout [Set<Digest>]) {
        var current = current
        current.insert(digest)

        if digest == target {
            result.append(current)
            return
        }

        switch self {
        case .node(let subject, let assertions, _):
            subject.targetSets(of: target, current: current, result: &result)
            for assertion in assertions {
                assertion.targetSets(of: target, current: current, result: &result)
            }
        case .wrapped(let envelope, _):
            envelope.targetSets(of: target, current: current, result: &result)
        case .assertion(let assertion):
            assertion.predicate.targetSets(of: target, current: current, result: &result)
            assertion.object.targetSets(of: target, current: current, result: &result)
        default:
            break
        }
    }
    
    public func contains(_ target: DigestProvider) -> Bool {
        _contains(target.digest)
    }
    
    func _contains(_ target: Digest) -> Bool {
        if digest == target {
            return true
        }

        switch self {
        case .node(let subject, let assertions, _):
            if subject.contains(target) { return true }
            for assertion in assertions {
                if assertion.contains(target) { return true }
            }
        case .wrapped(let envelope, _):
            if envelope.contains(target) { return true }
        case .assertion(let assertion):
            if assertion.predicate.contains(target) { return true }
            if assertion.object.contains(target) { return true }
        default:
            break
        }
        
        return false
    }
    
    public func confirm(contains digest: DigestProvider, proof: Envelope) -> Bool {
        return self.digest == proof.digest && proof.contains(digest)
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
            assert(elidedSubject == subject)
            let elidedAssertions = try assertions.map { assertion in
                let elidedAssertion = try assertion.elide(target, isRevealing: isRevealing, encryptingWith: key)
                assert(elidedAssertion == assertion)
                return elidedAssertion
            }
            result = Envelope(subject: elidedSubject, uncheckedAssertions: elidedAssertions)
        } else if case .wrapped(let envelope, _) = self {
            let elidedEnvelope = try envelope.elide(target, isRevealing: isRevealing, encryptingWith: key)
            assert(elidedEnvelope == envelope)
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

public extension Envelope {
    func revoke(_ digest: Digest) -> Envelope {
        var assertions = self.assertions
        if let index = assertions.firstIndex(where: { $0.digest == digest }) {
            assertions.remove(at: index)
        }
        return Envelope(subject: subject, uncheckedAssertions: assertions)
    }
}

public extension Envelope {
    var untaggedCBOR: CBOR {
        switch self {
        case .node(let subject, let assertions, _):
            if assertions.isEmpty {
                return subject.taggedCBOR
            } else {
                var result = [subject.taggedCBOR]
                for assertion in assertions {
                    result.append(assertion.taggedCBOR)
                }
                return CBOR.array(result)
            }
        case .leaf(let cbor, _):
            return CBOR.tagged(.leaf, cbor)
        case .wrapped(let envelope, _):
            return CBOR.tagged(.wrappedEnvelope, envelope.untaggedCBOR)
        case .knownPredicate(let knownPredicate, _):
            return knownPredicate.taggedCBOR
        case .assertion(let assertion):
            return assertion.taggedCBOR
        case .encrypted(let encryptedMessage):
            return encryptedMessage.taggedCBOR
        case .elided(let digest):
            return digest.taggedCBOR
        }
    }

    var taggedCBOR: CBOR {
        CBOR.tagged(.envelope, untaggedCBOR)
    }

    init(untaggedCBOR cbor: CBOR) throws {
        switch cbor {
        case CBOR.tagged(.leaf, let item):
            self.init(cbor: item)
        case CBOR.tagged(.knownPredicate, let item):
            self.init(knownPredicate: try KnownPredicate(untaggedCBOR: item))
        case CBOR.tagged(.wrappedEnvelope, let item):
            self.init(wrapped: try Envelope(untaggedCBOR: item))
        case CBOR.tagged(.assertion, let item):
            self.init(assertion: try Assertion(untaggedCBOR: item))
        case CBOR.tagged(.envelope, let item):
            self = try Envelope(untaggedCBOR: item)
        case CBOR.tagged(.message, let item):
            let message = try EncryptedMessage(untaggedCBOR: item)
            try self.init(encryptedMessage: message)
        case CBOR.tagged(.digest, let item):
            let digest = try Digest(untaggedCBOR: item)
            self.init(elided: digest)
        case CBOR.array(let elements):
            guard elements.count >= 2 else {
                throw CBORError.invalidFormat
            }
            let subject = try Envelope(taggedCBOR: elements[0])
            let assertions = try elements.dropFirst().map { try Envelope(taggedCBOR: $0 ) }
            try self.init(subject: subject, assertions: assertions)
        default:
            preconditionFailure()
        }
    }

    init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.envelope, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

public extension Envelope {
    var ur: UR {
        return try! UR(type: .envelope, cbor: untaggedCBOR)
    }

    init(ur: UR) throws {
        try ur.checkType(.envelope)
        let cbor = try CBOR(ur.cbor)
        try self.init(untaggedCBOR: cbor)
    }

    init(urString: String) throws {
        try self.init(ur: UR(urString: urString))
    }

    init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

public extension Envelope {
    init(function: FunctionIdentifier) {
        self.init(function)
    }

    init(function name: String) {
        self.init(function: FunctionIdentifier(name))
    }

    init(function value: Int, name: String? = nil) {
        self.init(function: FunctionIdentifier(value, name))
    }

    init(request id: CID, body: CBOREncodable) {
        self = Envelope(CBOR.tagged(.request, id.taggedCBOR))
            .addAssertion(.body, body)
    }

    init(response id: CID, result: CBOREncodable) {
        self = Envelope(CBOR.tagged(.response, id.taggedCBOR))
            .addAssertion(.result, result)
    }
}

public extension Envelope {
    @discardableResult
    func checkEncoding() throws -> Envelope {
        do {
            let cbor = taggedCBOR
            let restored = try Envelope(taggedCBOR: cbor)
            guard self == restored else {
                print("=== EXPECTED")
                print(self.format)
                print("=== GOT")
                print(restored.format)
                print("===")
                throw EnvelopeError.invalidFormat
            }
            return self
        } catch {
            print("===")
            print(format)
            print("===")
            print(cbor.diagAnnotated)
            print("===")
            throw error
        }
    }
}

public extension Envelope {
    var diag: String {
        taggedCBOR.diag
    }

    var diagAnnotated: String {
        taggedCBOR.diagAnnotated
    }

    var dump: String {
        taggedCBOR.dump
    }
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
        case .knownPredicate(let knownPredicate, _):
            return ".knownPredicate(\(knownPredicate))"
        case .assertion(let assertion):
            return ".assertion(\(assertion.predicate), \(assertion.object))"
        case .encrypted(_):
            return ".encryptedMessage"
        case .elided(_):
            return ".elided"
        }
    }
}
