import Foundation

public enum EnvelopeError: Error {
    case invalidOperation
    case invalidKey
    case invalidDigest
    case invalidSignature
    case invalidFormat
    case invalidRecipient
    case invalidShares
    case nonexistentPredicate
    case ambiguousPredicate
    case elided
}
