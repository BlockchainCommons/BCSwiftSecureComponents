import Foundation

extension EnvelopeError {
    static let unverifiedSignature = EnvelopeError("unverifiedSignature")
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
}

public extension Envelope {
    static func verifiedBy(signature: Signature, note: String? = nil) -> Envelope {
        Envelope(
            .verifiedBy,
            Envelope(signature)
                .addAssertion(if: note != nil, .note, note!)
        )
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
