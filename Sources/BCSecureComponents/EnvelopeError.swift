import Foundation

public enum EnvelopeError: Error {
    case invalidKey
    case missingDigest
    case invalidDigest
    case invalidSignature
    case invalidFormat
    case invalidRecipient
    case invalidShares
    case nonexistentPredicate
    case ambiguousPredicate
    case alreadyEncrypted
    case notEncrypted
    case notWrapped
    case elided
}
