import Foundation

public enum EnvelopeError: Error {
    case invalidKey
    case missingDigest
    case invalidDigest
    case unverifiedSignature
    case invalidFormat
    case invalidRecipient
    case invalidShares
    case invalidDiff
    case nonexistentPredicate
    case nonexistentAssertion
    case ambiguousPredicate
    case alreadyEncrypted
    case notEncrypted
    case notWrapped
    case elided
}
