import Foundation

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
