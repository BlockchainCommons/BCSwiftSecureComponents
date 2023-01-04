import Foundation

extension EnvelopeError {
    static let invalidShares = EnvelopeError("invalidShares")
}

public extension Envelope {
    static func sskrShare(_ share: SSKRShare) -> Envelope {
        Envelope(.sskrShare, share)
    }
}

public extension Envelope {
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
