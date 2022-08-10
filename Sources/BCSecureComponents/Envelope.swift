import Foundation
import URKit
import WolfBase
import CryptoKit
import SSKR

public struct Envelope: DigestProvider {
    public let subject: Subject
    public let assertions: [Assertion]
    public let digest: Digest
}

public extension Envelope {
    init(subject: Subject, assertions: [Assertion] = []) {
        self.subject = subject
        let sortedAssertions = assertions.sorted()
        self.assertions = sortedAssertions
        var digests = [subject.digest]
        digests.append(contentsOf: sortedAssertions.map { $0.digest })
        self.digest = Digest(Data(digests.map { $0.data }.joined()))
    }
    
    init(digest: Digest) {
        self.subject = .redacted(digest)
        self.assertions = []
        self.digest = digest
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
        [digest, subject.digest]
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
    
    init(predicate: Predicate) {
        self.init(subject: Subject(predicate: predicate))
    }
    
    func extract<T>(_ type: T.Type) throws -> T where T: CBORDecodable {
        guard let cbor = self.plaintext else {
            throw CBORError.invalidFormat
        }
        return try T.cborDecode(cbor)
    }
    
    var plaintext: CBOR? {
        subject.plaintext
    }
    
    var envelope: Envelope? {
        subject.envelope
    }
    
    var predicate: Predicate? {
        guard
            let plaintext = plaintext,
            case let CBOR.tagged(.predicate, value) = plaintext,
            case let CBOR.unsignedInt(rawValue) = value,
            let predicate = Predicate(rawValue: rawValue)
        else {
            return nil
        }
        
        return predicate
    }
    
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

extension Envelope: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int) {
        self.init(value)
    }
}

public extension Envelope {
    func assertions(predicate: CBOREncodable) -> [Assertion] {
        let predicate = Envelope(predicate)
        return assertions.filter { $0.predicate == predicate }
    }

    func assertion(predicate: CBOREncodable) throws -> Assertion {
        let a = assertions(predicate: predicate)
        guard a.count == 1 else {
            throw EnvelopeError.invalidFormat
        }
        return a.first!
    }

    func extract(predicate: CBOREncodable) throws -> Envelope {
        try assertion(predicate: predicate).object
    }
    
    func extract<T>(predicate: CBOREncodable, _ type: T.Type) throws -> T where T: CBORDecodable {
        try extract(predicate: predicate).extract(type)
    }
}

public extension Envelope {
    func assertions(predicate: Predicate) -> [Assertion] {
        let p = Envelope(predicate: predicate)
        return assertions.filter { $0.predicate == p }
    }
    
    func assertion(predicate: Predicate) throws -> Assertion {
        let a = assertions(predicate: predicate)
        guard a.count == 1 else {
            throw EnvelopeError.invalidFormat
        }
        return a.first!
    }
    
    func extract(predicate: Predicate) throws -> Envelope {
        try assertion(predicate: predicate).object
    }
    
    func extract<T>(predicate: Predicate, _ type: T.Type) throws -> T where T: CBORDecodable {
        try extract(predicate: predicate).extract(type)
    }
}

public extension Envelope {
    func add(_ assertion: Assertion) -> Envelope {
        if !assertions.contains(assertion) {
            return Envelope(subject: self.subject, assertions: assertions.appending(assertion))
        } else {
            return self
        }
    }
    
    func add(_ predicate: CBOREncodable, _ object: CBOREncodable) -> Envelope {
        let p = predicate as? Envelope ?? Envelope(predicate)
        let o = object as? Envelope ?? Envelope(object)
        return add(Assertion(p, o))
    }

    func add(_ predicate: Predicate, _ object: CBOREncodable) -> Envelope {
        return add(Envelope(predicate: predicate), object)
    }
}

public extension Envelope {
    func addIf(_ condition: Bool, _ assertion: Assertion) -> Envelope {
        guard condition else {
            return self
        }
        return add(assertion)
    }
    
    func addIf(_ condition: Bool, _ predicate: CBOREncodable, _ object: CBOREncodable) -> Envelope {
        guard condition else {
            return self
        }
        return add(predicate, object)
    }
    
    func addIf(_ condition: Bool, _ predicate: Predicate, _ object: CBOREncodable) -> Envelope {
        guard condition else {
            return self
        }
        return add(predicate, object)
    }
}

public extension Envelope {
    func sign(with privateKeys: PrivateKeyBase, note: String? = nil, tag: Data? = nil, randomGenerator: ((Int) -> Data)? = nil) -> Envelope {
        let signature = privateKeys.signingPrivateKey.schnorrSign(subject.digest, tag: tag, randomGenerator: randomGenerator)
        return add(.verifiedBy(signature: signature, note: note))
    }
    
    func sign(with privateKeys: [PrivateKeyBase], tag: Data? = nil, randomGenerator: ((Int) -> Data)? = nil) -> Envelope {
        var result = self
        for keys in privateKeys {
            result = result.sign(with: keys, randomGenerator: randomGenerator)
        }
        return result
    }
    
    func addRecipient(_ recipient: PublicKeyBase, contentKey: SymmetricKey, testKeyMaterial: DataProvider? = nil, testNonce: Nonce? = nil) -> Envelope {
        add(.hasRecipient(recipient, contentKey: contentKey, testKeyMaterial: testKeyMaterial, testNonce: testNonce))
    }
    
    func addSSKRShare(_ share: SSKRShare) -> Envelope {
        add(.sskrShare(share))
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
                    let share = try $0.object.extract(SSKRShare.self)
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
                .map { try $0.object.extract(Signature.self) }
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
        let result = Envelope(subject: subject, assertions: assertions)
        assert(digest == result.digest)
        return result
    }
    
    func decrypt(with key: SymmetricKey) throws -> Envelope {
        let subject = try self.subject.decrypt(with: key)
        let result = Envelope(subject: subject, assertions: assertions)
        assert(digest == result.digest)
        return result
    }
}

public extension Envelope {
    var recipients: [SealedMessage] {
        get throws {
            try assertions(predicate: .hasRecipient)
                .map { try $0.object.extract(SealedMessage.self) }
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
        let result = Envelope(subject: subject, assertions: assertions)
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
        let result = Envelope(subject: subject, assertions: assertions)
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
        return Envelope(subject: subject, assertions: assertions)
    }
}

public extension Envelope {
    var untaggedCBOR: CBOR {
        if assertions.isEmpty {
            return subject.cbor
        } else {
            var array = [subject.cbor]
            array.append(contentsOf: assertions.map { $0.untaggedCBOR })
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
            let assertions = try elements.dropFirst().map { try Assertion(untaggedCBOR: $0 ) }
            self.init(subject: subject, assertions: assertions)
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
