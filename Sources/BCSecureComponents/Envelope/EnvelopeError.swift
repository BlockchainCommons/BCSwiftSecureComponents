import Foundation

public struct EnvelopeError: LocalizedError {
    public let type: String
    
    init(_ type: String) {
        self.type = type
    }
    
    var localizedString: String {
        type
    }
}

extension EnvelopeError {
    static let invalidDigest = EnvelopeError("invalidDigest")
    static let invalidFormat = EnvelopeError("invalidFormat")
}
