import Foundation
import URKit
import WolfBase
import CryptoKit
import SSKR

public struct Envelope: DigestProvider {
    public let subject: Subject
    public let assertions: [Envelope]
    public let digest: Digest
}

public extension Envelope {
    private init(subject: Subject, uncheckedAssertions: [Envelope]) {
        self.subject = subject
        let sortedAssertions = uncheckedAssertions.sorted()
        self.assertions = sortedAssertions
        var digests = [subject.digest]
        digests.append(contentsOf: sortedAssertions.map { $0.digest })
        self.digest = Digest(Data(digests.map { $0.data }.joined()))
    }

    init(subject: Subject, assertions: [Envelope]) throws {
        guard assertions.allSatisfy({ $0.isAssertion }) else {
            throw EnvelopeError.invalidFormat
        }
        self.init(subject: subject, uncheckedAssertions: assertions)
    }

    init(subject: Subject) {
        try! self.init(subject: subject, assertions: [])
    }

    init(predicate: CBOREncodable, object: CBOREncodable) {
        let p = predicate as? Envelope ?? Envelope(predicate)
        let o = object as? Envelope ?? Envelope(object)
        self.init(subject: Subject(predicate: p, object: o))
    }

    init(predicate: KnownPredicate, object: CBOREncodable) {
        let p = Envelope(predicate: predicate)
        let o = object as? Envelope ?? Envelope(object)
        self.init(subject: Subject(predicate: p, object: o))
    }

    init(digest: Digest) {
        self.subject = .redacted(digest)
        self.assertions = []
        self.digest = digest
    }
}

public extension Envelope {
    var isAssertion: Bool {
        subject.isAssertion
    }
}

public extension Envelope {
    var deepDigests: Set<Digest> {
        var result = subject.deepDigests.union([digest])
        for assertion in assertions {
            result.formUnion(assertion.deepDigests)
        }
        return result
    }
    
    var shallowDigests: Set<Digest> {
        Set([digest, subject.digest]).union(subject.shallowDigests)
    }
}

extension Envelope: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}

extension Envelope: CBORDecodable {
    public static func cborDecode(_ cbor: CBOR) throws -> Envelope {
        try Envelope(taggedCBOR: cbor)
    }
}

public extension Envelope {
    init(_ plaintext: CBOREncodable) {
        self.init(subject: Subject(plaintext: plaintext))
    }
    
    init(predicate: KnownPredicate) {
        self.init(subject: Subject(predicate: predicate))
    }
    
    func extract<T>(_ type: T.Type) throws -> T where T: CBORDecodable {
        guard let cbor = self.plaintext else {
            throw CBORError.invalidFormat
        }
        return try T.cborDecode(cbor)
    }
}

public extension Envelope {
    var plaintext: CBOR? {
        subject.plaintext
    }
    
    var envelope: Envelope? {
        subject.envelope
    }
    
    var predicate: Envelope? {
        subject.predicate
    }
    
    var object: Envelope? {
        subject.object
    }
    
    var knownPredicate: KnownPredicate? {
        subject.knownPredicate
    }
}

public extension Envelope {
    func enclose() -> Envelope {
        Envelope(subject: Subject(plaintext: self))
    }
    
    func extract() throws -> Envelope {
        guard
            let envelope = envelope
        else {
            throw EnvelopeError.invalidFormat
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
    func hasPredicate(_ predicate: Envelope) -> Bool {
        guard
            let myPredicate = self.predicate,
            myPredicate == predicate
        else {
            return false
        }
        return true
    }

    func hasPredicate(_ predicate: KnownPredicate) -> Bool {
        hasPredicate(Envelope(predicate: predicate))
    }

    func hasPredicate(_ predicate: CBOREncodable) -> Bool {
        hasPredicate(Envelope(predicate))
    }
}

public extension Envelope {
    func assertions(predicate: Envelope) -> [Envelope] {
        return assertions.filter { $0.hasPredicate(predicate) }
    }

    func assertion(predicate: Envelope) throws -> Envelope {
        let a = assertions(predicate: predicate)
        guard
            a.count == 1,
            let result = a.first
        else {
            throw EnvelopeError.invalidFormat
        }
        return result
    }

    func extract(predicate: Envelope) throws -> Envelope {
        guard let result = try assertion(predicate: predicate).object else {
            throw EnvelopeError.invalidFormat
        }
        return result
    }
    
    func extract<T>(_ type: T.Type, predicate: Envelope) throws -> T where T: CBORDecodable {
        try extract(predicate: predicate).extract(type)
    }
}

public extension Envelope {
    func assertions(predicate: CBOREncodable) -> [Envelope] {
        assertions(predicate: Envelope(predicate))
    }

    func assertion(predicate: CBOREncodable) throws -> Envelope {
        try assertion(predicate: Envelope(predicate))
    }

    func extract(predicate: CBOREncodable) throws -> Envelope {
        try extract(predicate: Envelope(predicate))
    }
    
    func extract<T>(_ type: T.Type, predicate: CBOREncodable) throws -> T where T: CBORDecodable {
        try extract(type, predicate: Envelope(predicate))
    }
}

public extension Envelope {
    func assertions(predicate: KnownPredicate) -> [Envelope] {
        assertions(predicate: Envelope(predicate: predicate))
    }

    func assertion(predicate: KnownPredicate) throws -> Envelope {
        try assertion(predicate: Envelope(predicate: predicate))
    }

    func extract(predicate: KnownPredicate) throws -> Envelope {
        try extract(predicate: Envelope(predicate: predicate))
    }
    
    func extract<T>(_ type: T.Type, predicate: KnownPredicate) throws -> T where T: CBORDecodable {
        try extract(type, predicate: Envelope(predicate: predicate))
    }
}

public extension Envelope {
    func add(_ assertion: Envelope) throws -> Envelope {
        guard assertion.isAssertion else {
            throw EnvelopeError.invalidFormat
        }
        if !assertions.contains(assertion) {
            return Envelope(subject: self.subject, uncheckedAssertions: assertions.appending(assertion))
        } else {
            return self
        }
    }
    
    func add(_ predicate: CBOREncodable, _ object: CBOREncodable) -> Envelope {
        try! add(Envelope(predicate: predicate, object: object))
    }

    func add(_ predicate: KnownPredicate, _ object: CBOREncodable) -> Envelope {
        add(Envelope(predicate: predicate), object)
    }
}

public extension Envelope {
    func addIf(_ condition: Bool, _ assertion: @autoclosure () -> Envelope) throws -> Envelope {
        guard condition else {
            return self
        }
        return try add(assertion())
    }
    
    func addIf(_ condition: Bool, _ predicate: @autoclosure () -> CBOREncodable, _ object: @autoclosure () -> CBOREncodable) -> Envelope {
        guard condition else {
            return self
        }
        return add(predicate(), object())
    }
    
    func addIf(_ condition: Bool, _ predicate: @autoclosure () -> KnownPredicate, _ object: @autoclosure () -> CBOREncodable) -> Envelope {
        guard condition else {
            return self
        }
        return add(predicate(), object())
    }
}

public extension Envelope {
    /// Add a specified number of bytes of salt.
    func addSalt(_ count: Int) -> Envelope {
        return add(.salt, SecureRandomNumberGenerator.shared.data(count: count))
    }
    
    /// Add a number of bytes of salt chosen randomly from the given range.
    func addSalt(_ range: ClosedRange<Int>) -> Envelope {
        var s = SecureRandomNumberGenerator.shared
        let count = range.randomElement(using: &s)!
        return addSalt(count)
    }

    /// Add a number of bytes of salt generally proportional to the size of the object being salted.
    ///
    /// For small objects, the number of bytes added will generally be from 8...16.
    ///
    /// For larger objects the number of bytes added will generally be from 5%...25% of the size of the object.
    func addSalt() -> Envelope {
        let size = Double(self.taggedCBOR.cborEncode.count)
        let minSize = max(8, Int((size * 0.05).rounded(.up)))
        let maxSize = max(minSize + 8, Int((size * 0.25).rounded(.up)))
        return addSalt(minSize...maxSize)
    }
}

public extension Envelope {
    static func verifiedBy(signature: Signature, note: String? = nil) -> Envelope {
        Envelope(
            predicate: .verifiedBy,
            object: Envelope(signature)
                .addIf(note != nil, .note, note!)
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

    static func id(_ id: SCID) -> Envelope {
        Envelope(predicate: .id, object: id)
    }
}

public extension Envelope {
    static func parameter(_ param: FunctionParameter, value: CBOREncodable) -> Envelope {
        Envelope(predicate: param.cbor, object: Envelope(value))
    }

    static func parameter(_ name: String, value: CBOREncodable) -> Envelope {
        Envelope(predicate: FunctionParameter.tagged(name: name), object: value)
    }
    
    func addParameter(_ param: FunctionParameter, value: CBOREncodable) -> Envelope {
        try! add(.parameter(param, value: value))
    }
    
    func addParameter(_ name: String, value: CBOREncodable) -> Envelope {
        try! add(.parameter(name, value: value))
    }
}

public extension Envelope {
    func sign(with privateKeys: PrivateKeyBase, note: String? = nil, tag: Data? = nil, randomGenerator: ((Int) -> Data)? = nil) -> Envelope {
        let signature = privateKeys.signingPrivateKey.schnorrSign(subject.digest, tag: tag, randomGenerator: randomGenerator)
        return try! add(.verifiedBy(signature: signature, note: note))
    }
    
    func sign(with privateKeys: [PrivateKeyBase], tag: Data? = nil, randomGenerator: ((Int) -> Data)? = nil) -> Envelope {
        var result = self
        for keys in privateKeys {
            result = result.sign(with: keys, randomGenerator: randomGenerator)
        }
        return result
    }
    
    func addRecipient(_ recipient: PublicKeyBase, contentKey: SymmetricKey, testKeyMaterial: DataProvider? = nil, testNonce: Nonce? = nil) -> Envelope {
        try! add(.hasRecipient(recipient, contentKey: contentKey, testKeyMaterial: testKeyMaterial, testNonce: testNonce))
    }
    
    func addSSKRShare(_ share: SSKRShare) -> Envelope {
        try! add(.sskrShare(share))
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
            try envelope.assertions(predicate: .sskrShare)
                .forEach {
                    let share = try $0.object!.extract(SSKRShare.self)
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
            self = try envelopes.first!.decrypt(with: contentKey)
            return
        }
        throw EnvelopeError.invalidShares
    }
}

public extension Envelope {
    var signatures: [Signature] {
        get throws {
            try assertions(predicate: .verifiedBy)
                .map { try $0.object!.extract(Signature.self) }
        }
    }
    
    func isValidSignature(_ signature: Signature, key: SigningPublicKey) -> Bool {
        return key.isValidSignature(signature, for: subject.digest)
    }
    
    @discardableResult
    func validateSignature(_ signature: Signature, key: SigningPublicKey) throws -> Envelope {
        guard isValidSignature(signature, key: key) else {
            throw EnvelopeError.invalidSignature
        }
        return self
    }
    
    func isValidSignature(_ signature: Signature, publicKeys: PublicKeyBase) -> Bool {
        isValidSignature(signature, key: publicKeys.signingPublicKey)
    }
    
    @discardableResult
    func validateSignature(_ signature: Signature, publicKeys: PublicKeyBase) throws -> Envelope {
        try validateSignature(signature, key: publicKeys.signingPublicKey)
    }
    
    func hasValidSignature(key: SigningPublicKey) throws -> Bool {
        let sigs = try signatures
        return sigs.contains { isValidSignature($0, key: key) }
    }
    
    @discardableResult
    func validateSignature(key: SigningPublicKey) throws -> Envelope {
        guard try hasValidSignature(key: key) else {
            throw EnvelopeError.invalidSignature
        }
        return self
    }
    
    func hasValidSignature(from publicKeys: PublicKeyBase) throws -> Bool {
        try hasValidSignature(key: publicKeys.signingPublicKey)
    }
    
    @discardableResult
    func validateSignature(from publicKeys: PublicKeyBase) throws -> Envelope {
        try validateSignature(key: publicKeys.signingPublicKey)
    }
    
    func hasValidSignatures(with keys: [SigningPublicKey], threshold: Int? = nil) throws -> Bool {
        let threshold = threshold ?? keys.count
        var count = 0
        for key in keys {
            if try hasValidSignature(key: key) {
                count += 1
                if count >= threshold {
                    return true
                }
            }
        }
        return false
    }

    @discardableResult
    func validateSignatures(with keys: [SigningPublicKey], threshold: Int? = nil) throws -> Envelope {
        guard try hasValidSignatures(with: keys, threshold: threshold) else {
            throw EnvelopeError.invalidSignature
        }
        return self
    }

    func hasValidSignatures(from publicKeysArray: [PublicKeyBase], threshold: Int? = nil) throws -> Bool {
        try hasValidSignatures(with: publicKeysArray.map { $0.signingPublicKey }, threshold: threshold)
    }

    @discardableResult
    func validateSignatures(from publicKeysArray: [PublicKeyBase], threshold: Int? = nil) throws -> Envelope {
        try validateSignatures(with: publicKeysArray.map { $0.signingPublicKey }, threshold: threshold)
    }
}

public extension Envelope {
    func encrypt(with key: SymmetricKey, testNonce: Nonce? = nil) throws -> Envelope {
        let subject = try self.subject.encrypt(with: key, nonce: testNonce)
        let result = Envelope(subject: subject, uncheckedAssertions: assertions)
        assert(digest == result.digest)
        return result
    }
    
    func decrypt(with key: SymmetricKey) throws -> Envelope {
        let subject = try self.subject.decrypt(with: key)
        let result = Envelope(subject: subject, uncheckedAssertions: assertions)
        assert(digest == result.digest)
        return result
    }
}

public extension Envelope {
    var recipients: [SealedMessage] {
        get throws {
            try assertions(predicate: .hasRecipient)
                .map { try $0.object!.extract(SealedMessage.self) }
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
        return try decrypt(with: contentKey)
    }
}

public extension Envelope {
    func redact() -> Envelope {
        let result = Envelope(digest: digest)
        assert(result.digest == digest)
        return result
    }
    
    func redact(items: Set<Digest>) -> Envelope {
        if items.contains(digest) {
            return redact()
        }
        let subject = self.subject.redact(items: items)
        let assertions = self.assertions.map {
            $0.redact(items: items)
        }
        let result = Envelope(subject: subject, uncheckedAssertions: assertions)
        assert(result.digest == digest)
        return result
    }
    
    func redact(revealing items: Set<Digest>) -> Envelope {
        if !items.contains(digest) {
            return redact()
        }
        let subject = self.subject.redact(revealing: items)
        let assertions = self.assertions.map {
            $0.redact(revealing: items)
        }
        let result = Envelope(subject: subject, uncheckedAssertions: assertions)
        assert(result.digest == digest)
        return result
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
        if assertions.isEmpty {
            return subject.cbor
        } else {
            var array = [subject.cbor]
            array.append(contentsOf: assertions.map { $0.taggedCBOR })
            return CBOR.array(array)
        }
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(URType.envelope.tag, untaggedCBOR)
    }
    
    init(untaggedCBOR: CBOR) throws {
        if case let CBOR.array(elements) = untaggedCBOR {
            guard elements.count >= 2 else {
                throw CBORError.invalidFormat
            }
            let subject = try Subject(cbor: elements[0])
            let assertions = try elements.dropFirst().map { try Envelope(taggedCBOR: $0 ) }
            try self.init(subject: subject, assertions: assertions)
        } else {
            try self.init(subject: Subject(cbor: untaggedCBOR), assertions: [])
        }
    }
    
    init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.envelope.tag, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

public extension Envelope {
    var ur: UR {
        return try! UR(type: URType.envelope.type, cbor: untaggedCBOR)
    }
    
    init(ur: UR) throws {
        guard ur.type == URType.envelope.type else {
            throw URError.unexpectedType
        }
        let cbor = try CBOR(ur.cbor)
        try self.init(untaggedCBOR: cbor)
    }
    
    init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

public extension Envelope {
    init(function: FunctionIdentifier) {
        self.init(function.cbor)
    }
    
    init(function name: String) {
        self.init(FunctionIdentifier.tagged(name: name))
    }
    
    init(request id: UUID, body: CBOREncodable) {
        self = Envelope(CBOR.tagged(.request, id.taggedCBOR))
            .add(.body, body)
    }
    
    init(response id: UUID, result: CBOREncodable) {
        self = Envelope(CBOR.tagged(.response, id.taggedCBOR))
            .add(.result, result)
    }
}
