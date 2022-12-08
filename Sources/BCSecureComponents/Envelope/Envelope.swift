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

public extension Envelope {
    /// The envelope's digest.
    var digest: Digest {
        switch self {
        case .node(subject: _, assertions: _, digest: let digest):
            return digest
        case .leaf(_, let digest):
            return digest
        case .wrapped(_, let digest):
            return digest
        case .knownValue(_, let digest):
            return digest
        case .assertion(let assertion):
            return assertion.digest
        case .encrypted(let encryptedMessage):
            return encryptedMessage.digest!
        case .elided(digest: let digest):
            return digest
        }
    }

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

public extension Envelope {
    /// Returns the set of digests contained in the envelope's elements, down to the
    /// specified level.
    ///
    /// - Parameter levelLimit: Return digests at levels below this value.
    /// - Returns: The set of digests down to `levelLimit`.
    ///
    /// The digest of the envelope is included as well as the digest of the envelope's
    /// subject (if it is different).
    ///
    /// If no `levelLimit` is provided, all digests in the envelope will be returned.
    ///
    /// A `levelLimit` of zero will return no digests.
    func digests(levelLimit: Int = .max) -> Set<Digest> {
        var result: Set<Digest> = []
        walkStructure { (envelope, level, incomingEdge, _) -> Int? in
            guard level < levelLimit else {
                return nil
            }
            result.insert(envelope)
            result.insert(envelope.subject)
            return nil
        }
        return result
    }
    
    /// The set of all digests in the envelope.
    var deepDigests: Set<Digest> {
        digests()
    }

    /// The set of all digests in the envelope, down to its second level.
    var shallowDigests: Set<Digest> {
        digests(levelLimit: 2)
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

public extension Envelope {
    /// Produce a value that will necessarily be different if two envelopes differ
    /// structurally, even if they are semantically equivalent.
    ///
    /// Comparing the `digest` field of two envelopes (or calling `isEquivalent(to:)`) tests
    /// whether two envelopes are *semantically equivalent*. This is accomplished by
    /// simply comparing the top level digests of the envelopes for equality, and has a
    /// complexity of `O(1)`.
    ///
    /// This means that two envelopes are considered equivalent if they contain
    /// identical information in their completely unencrypted and unelided form.
    ///
    /// Some applications need to determine whether two envelopes are not only
    /// semantically equivalent, but also structurally identical. Two envelopes that are
    /// not semantically equivalent cannot be structurally identical, but two envelopes
    /// that *are* semantically equivalent *may or may not* be structurally identical.
    ///
    /// The `structuralDigest` attribute is used to produce a value that will
    /// necessarily be different if two envelopes differ structurally, even if they are
    /// semantically equivalent. It has a complexity of `O(m + n)` where `m` and `n` are
    /// the number of elements in each of the two envelopes when they *are* semantically
    /// equivalent. It is recommended that envelopes be compared for structural equality
    /// by calling `isIdentical(to:)` as this short-circuits to `false` in cases where
    /// the compared envelopes are not semantically equivalent.
    var structuralDigest: Digest {
        var image = Data()
        walkStructure { (envelope, _, _, _) -> Int? in
            // Add a discriminator to the image for the encrypted and elided cases.
            switch envelope {
            case .encrypted:
                image.append(contentsOf: [0])
            case .elided:
                image.append(contentsOf: [1])
            default:
                break
            }
            image.append(envelope.digest.data)
            return nil
        }
        return Digest(image)
    }
    
    /// Tests two envelopes for semantic equivalence.
    ///
    /// Calling `e1.isEquivalent(to: e2)` has a complexity of `O(1)` and simply compares
    /// the two envelope's digests. The means that two envelopes with certain structural
    /// differences (e.g., one envelope is partially elided and the other is not) will
    /// still test as equivalent.
    func isEquivalent(to other: Envelope) -> Bool {
        return digest == other.digest
    }

    /// Tests two envelopes for structural equality.
    ///
    /// Calling `e1.isIdentical(to: d2)` has a complexity of `O(1)` if the envelopes are
    /// not semantically equivalent (that is, their top-level digests are different, and
    /// thus they *must* have different structures) and a complexity of `O(m + n)` where
    /// `m` and `n` are the number of elements in each of the two envelopes when they
    /// *are* semantically equivalent.
    func isIdentical(to other: Envelope) -> Bool {
        guard isEquivalent(to: other) else {
            return false
        }
        return structuralDigest == other.structuralDigest
    }
}

extension Envelope: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int) {
        self.init(value)
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
        var rng = SecureRandomNumberGenerator.shared
        return addSalt(using: &rng)
    }
    
    func addSalt<R: RandomNumberGenerator>(using rng: inout R) -> Envelope {
        addSalt(Salt(forSize: taggedCBOR.cborEncode.count, using: &rng))
    }
}

public extension Envelope {
    static func verifiedBy(signature: Signature, note: String? = nil) -> Envelope {
        Envelope(
            .verifiedBy,
            Envelope(signature)
                .addAssertion(if: note != nil, .note, note!)
        )
    }

    static func hasRecipient(_ recipient: PublicKeyBase, contentKey: SymmetricKey, testKeyMaterial: DataProvider? = nil, testNonce: Nonce? = nil) -> Envelope {
        let sealedMessage = SealedMessage(plaintext: contentKey.taggedCBOR, recipient: recipient, testKeyMaterial: testKeyMaterial, testNonce: testNonce)
        return Envelope(.hasRecipient, sealedMessage)
    }

    static func sskrShare(_ share: SSKRShare) -> Envelope {
        Envelope(.sskrShare, share)
    }

    static func isA(_ object: Envelope) -> Envelope {
        Envelope(.isA, object)
    }

    static func id(_ id: CID) -> Envelope {
        Envelope(.id, id)
    }
}

public extension Envelope {
    static func parameter(_ param: ParameterIdentifier, value: CBOREncodable?) -> Envelope? {
        guard let value else {
            return nil
        }
        return Envelope(param.cbor, Envelope(value))
    }

    static func parameter(_ name: String, value: CBOREncodable?) -> Envelope? {
        guard let value else {
            return nil
        }
        return parameter(ParameterIdentifier(name), value: value)
    }

    func addParameter(_ param: ParameterIdentifier, value: CBOREncodable?) -> Envelope {
        try! addAssertion(.parameter(param, value: value))
    }

    func addParameter(_ name: String, value: CBOREncodable?) -> Envelope {
        try! addAssertion(.parameter(name, value: value))
    }
    
    func result() throws -> Envelope {
        try extractObject(forPredicate: .result)
    }
    
    func results() throws -> [Envelope] {
        extractObjects(forPredicate: .result)
    }
    
    func result<T: CBORDecodable>(_ type: T.Type) throws -> T {
        try extractObject(T.self, forPredicate: .result)
    }
    
    func results<T: CBORDecodable>(_ type: T.Type) throws -> [T] {
        try extractObjects(T.self, forPredicate: .result)
    }
    
    func isResultOK() throws -> Bool {
        try result(KnownValue.self) == .ok
    }
    
    func error<T: CBORDecodable>(_ type: T.Type) throws -> T {
        try extractObject(T.self, forPredicate: .error)
    }
}

public extension Envelope {
    func sign(with privateKeys: PrivateKeyBase, uncoveredAssertions: [Envelope], tag: Data? = nil, randomGenerator: ((Int) -> Data)? = nil) throws -> Envelope {
        let signature = try Envelope(privateKeys.signingPrivateKey.schnorrSign(subject.digest, tag: tag, randomGenerator: randomGenerator))
            .addAssertions(uncoveredAssertions)
        return try addAssertion(Envelope(.verifiedBy, signature))
    }
    
    func sign(with privateKeys: PrivateKeyBase, note: String? = nil, tag: Data? = nil, randomGenerator: ((Int) -> Data)? = nil) -> Envelope {
        var assertions: [Envelope] = []
        if let note {
            assertions.append(Envelope(.note, note))
        }
        return try! sign(with: privateKeys, uncoveredAssertions: assertions, tag: tag, randomGenerator: randomGenerator)
    }

    func sign(with privateKeys: [PrivateKeyBase], tag: Data? = nil, randomGenerator: ((Int) -> Data)? = nil) -> Envelope {
        privateKeys.reduce(into: self) {
            $0 = $0.sign(with: $1, tag: tag, randomGenerator: randomGenerator)
        }
    }
    
    func sign(with privateKeys: PrivateKeyBase, coveredAssertions: [Envelope], tag: Data? = nil, randomGenerator: ((Int) -> Data)? = nil) throws -> Envelope {
        guard !coveredAssertions.isEmpty else {
            return sign(with: privateKeys, tag: tag, randomGenerator: randomGenerator)
        }
        return try self.elide()
            .addAssertions(coveredAssertions)
            .wrap()
            .sign(with: privateKeys, tag: tag, randomGenerator: randomGenerator)
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
        case .knownValue(let knownValue, let envelopeDigest):
            let encodedCBOR = knownValue.taggedCBOR.cborEncode
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
    
    func encryptSubject(to recipients: [PublicKeyBase]) throws -> Envelope {
        let contentKey = SymmetricKey()
        var e = try encryptSubject(with: contentKey)
        for recipient in recipients {
            e = e.addRecipient(recipient, contentKey: contentKey)
        }
        return e
    }
    
    func encryptSubject(to recipient: PublicKeyBase) throws -> Envelope {
        try encryptSubject(to: [recipient])
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
    public func proof(contains target: DigestProvider) -> Envelope? {
        proof(contains: [target.digest])
    }
    
    public func proof(contains target: Set<Digest>) -> Envelope? {
        let revealSet = revealSet(of: target)
        guard target.isSubset(of: revealSet) else { return nil }
        return try! elideRevealing(revealSet).elideRemoving(target)
    }
    
    public func revealSet(of target: DigestProvider) -> Set<Digest> {
        revealSet(of: [target.digest])
    }
    
    public func revealSet(of target: Set<Digest>) -> Set<Digest> {
        var result: Set<Digest> = []
        revealSets(of: target, current: [], result: &result)
        return result
    }
    
    func revealSets(of target: Set<Digest>, current: Set<Digest>, result: inout Set<Digest>) {
        var current = current
        current.insert(digest)

        if target.contains(digest) {
            result.formUnion(current)
        }

        switch self {
        case .node(let subject, let assertions, _):
            subject.revealSets(of: target, current: current, result: &result)
            for assertion in assertions {
                assertion.revealSets(of: target, current: current, result: &result)
            }
        case .wrapped(let envelope, _):
            envelope.revealSets(of: target, current: current, result: &result)
        case .assertion(let assertion):
            assertion.predicate.revealSets(of: target, current: current, result: &result)
            assertion.object.revealSets(of: target, current: current, result: &result)
        default:
            break
        }
    }
    
    public func contains(_ target: DigestProvider) -> Bool {
        containsAll(in: [target.digest])
    }
    
    public func containsAll(in target: Set<Digest>) -> Bool {
        var target = target
        removeAllFound(in: &target)
        return target.isEmpty
    }
    
    func removeAllFound(in target: inout Set<Digest>) {
        if target.contains(digest) {
            target.remove(digest)
        }
        guard !target.isEmpty else { return }

        switch self {
        case .node(let subject, let assertions, _):
            subject.removeAllFound(in: &target)
            for assertion in assertions {
                assertion.removeAllFound(in: &target)
            }
        case .wrapped(let envelope, _):
            envelope.removeAllFound(in: &target)
        case .assertion(let assertion):
            assertion.predicate.removeAllFound(in: &target)
            assertion.object.removeAllFound(in: &target)
        default:
            break
        }
    }
    
    public func confirm(contains target: DigestProvider, using proof: Envelope) -> Bool {
        confirm(contains: [target.digest], using: proof)
    }
    
    public func confirm(contains target: Set<Digest>, using proof: Envelope) -> Bool {
        self.digest == proof.digest && proof.containsAll(in: target)
    }
}

public extension Envelope {
    /// Perform a depth-first walk of the envelope's element tree.
    func mutatingWalk(visit: (Envelope, [Envelope], EnvelopeEdgeType) -> Void) {
        mutatingWalk(path: [], incomingEdge: .none, visit: visit)
    }
    
    private func mutatingWalk(path: [Envelope], incomingEdge: EnvelopeEdgeType, visit: (Envelope, [Envelope], EnvelopeEdgeType) -> Void) {
        let nextPath = path.appending(self)
        switch self {
        case .node(let subject, let assertions, _):
            for assertion in assertions {
                assertion.mutatingWalk(path: nextPath, incomingEdge: .assertion, visit: visit)
            }
            subject.mutatingWalk(path: nextPath, incomingEdge: .subject, visit: visit)
        case .wrapped(let envelope, _):
            envelope.mutatingWalk(path: nextPath, incomingEdge: .wrapped, visit: visit)
        case .assertion(let assertion):
            assertion.object.mutatingWalk(path: nextPath, incomingEdge: .object, visit: visit)
            assertion.predicate.mutatingWalk(path: nextPath, incomingEdge: .predicate, visit: visit)
        default:
            break
        }
        visit(self, path, incomingEdge)
    }
    
    /// Perform a depth-first walk of the envelope's structure.
    func walk<Parent>(hideNodes: Bool, visit: (Envelope, Int, EnvelopeEdgeType, Parent?) -> Parent?) {
        if hideNodes {
            walkTree { envelope, level, parent in
                visit(envelope, level, .none, parent)
            }
        } else {
            walkStructure(visit: visit)
        }
    }

    private func walkStructure<Parent>(visit: (Envelope, Int, EnvelopeEdgeType, Parent?) -> Parent?) {
        walkStructure(level: 0, incomingEdge: .none, parent: nil, visit: visit)
    }
    
    private func walkStructure<Parent>(level: Int, incomingEdge: EnvelopeEdgeType, parent: Parent?, visit: (Envelope, Int, EnvelopeEdgeType, Parent?) -> Parent?) {
        let parent = visit(self, level, incomingEdge, parent)
        let nextLevel = level + 1
        switch self {
        case .node(let subject, let assertions, _):
            subject.walkStructure(level: nextLevel, incomingEdge: .subject, parent: parent, visit: visit)
            for assertion in assertions {
                assertion.walkStructure(level: nextLevel, incomingEdge: .assertion, parent: parent, visit: visit)
            }
        case .wrapped(let envelope, _):
            envelope.walkStructure(level: nextLevel, incomingEdge: .wrapped, parent: parent, visit: visit)
        case .assertion(let assertion):
            assertion.predicate.walkStructure(level: nextLevel, incomingEdge: .predicate, parent: parent, visit: visit)
            assertion.object.walkStructure(level: nextLevel, incomingEdge: .object, parent: parent, visit: visit)
        default:
            break
        }
    }

    /// Perform a depth-first walk of the envelope's tree.
    private func walkTree<Parent>(visit: (Envelope, Int, Parent?) -> Parent?) {
        walkTree(level: 0, parent: nil, visit: visit)
    }
    
    @discardableResult
    private func walkTree<Parent>(level: Int, parent: Parent?, visit: (Envelope, Int, Parent?) -> Parent?) -> Parent? {
        var parent = parent
        var subjectLevel = level
        if !isNode {
            parent = visit(self, level, parent)
            subjectLevel = level + 1
        }
        switch self {
        case .node(let subject, let assertions, _):
            let assertionParent = subject.walkTree(level: subjectLevel, parent: parent, visit: visit)
            let assertionLevel = subjectLevel + 1
            for assertion in assertions {
                assertion.walkTree(level: assertionLevel, parent: assertionParent, visit: visit)
            }
        case .wrapped(let envelope, _):
            envelope.walkTree(level: subjectLevel, parent: parent, visit: visit)
        case .assertion(let assertion):
            assertion.predicate.walkTree(level: subjectLevel, parent: parent, visit: visit)
            assertion.object.walkTree(level: subjectLevel, parent: parent, visit: visit)
        default:
            break
        }
        return parent
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
            assert(elidedSubject.digest == subject.digest)
            let elidedAssertions = try assertions.map { assertion in
                let elidedAssertion = try assertion.elide(target, isRevealing: isRevealing, encryptingWith: key)
                assert(elidedAssertion.digest == assertion.digest)
                return elidedAssertion
            }
            result = Envelope(subject: elidedSubject, uncheckedAssertions: elidedAssertions)
        } else if case .wrapped(let envelope, _) = self {
            let elidedEnvelope = try envelope.elide(target, isRevealing: isRevealing, encryptingWith: key)
            assert(elidedEnvelope.digest == envelope.digest)
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
}

public extension Envelope {
    var untaggedCBOR: CBOR {
        switch self {
        case .node(let subject, let assertions, _):
            precondition(!assertions.isEmpty)
            var result = [subject.taggedCBOR]
            for assertion in assertions {
                result.append(assertion.taggedCBOR)
            }
            return CBOR.array(result)
        case .leaf(let cbor, _):
            return CBOR.tagged(.leaf, cbor)
        case .wrapped(let envelope, _):
            return CBOR.tagged(.wrappedEnvelope, envelope.untaggedCBOR)
        case .knownValue(let knownValue, _):
            return knownValue.taggedCBOR
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
        case CBOR.tagged(.knownValue, let item):
            self.init(knownValue: try KnownValue(untaggedCBOR: item))
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
            throw EnvelopeError.invalidFormat
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

    init(response id: CID, result: CBOREncodable? = KnownValue.ok) {
        self = Envelope(CBOR.tagged(.response, id.taggedCBOR))
            .addAssertion(.result, result)
    }
    
    init(response id: CID, results: [CBOREncodable]) {
        var e = Envelope(CBOR.tagged(.response, id.taggedCBOR))
        for result in results {
            e = e.addAssertion(.result, result)
        }
        self = e
    }
    
    init(response id: CID, error: CBOREncodable) {
        self = Envelope(CBOR.tagged(.response, id.taggedCBOR))
            .addAssertion(.error, error)
    }
    
    init(error: CBOREncodable?) {
        self = Envelope(CBOR.tagged(.response, "unknown"))
            .addAssertion(.error, error)
    }
}

public extension Envelope {
    @discardableResult
    func checkEncoding() throws -> Envelope {
        do {
            let cbor = taggedCBOR
            let restored = try Envelope(taggedCBOR: cbor)
            guard self.digest == restored.digest else {
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
        case .knownValue(let knownValue, _):
            return ".knownValue(\(knownValue))"
        case .assertion(let assertion):
            return ".assertion(\(assertion.predicate), \(assertion.object))"
        case .encrypted(_):
            return ".encryptedMessage"
        case .elided(_):
            return ".elided"
        }
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

public extension Envelope {
    func replaceSubject(with subject: Envelope) -> Envelope {
        assertions.reduce(into: subject) {
            try! $0 = $0.addAssertion($1)
        }
    }
    
    func replaceAssertion(_ assertion: DigestProvider, with newAssertion: Envelope) throws -> Envelope {
        var e = self
        e = e.removeAssertion(assertion)
        e = try e.addAssertion(newAssertion)
        return e
    }
}

extension Envelope: ExpressibleByStringLiteral {
    public init(stringLiteral value: StringLiteralType) {
        self = Envelope(value)
    }
}
