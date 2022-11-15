import Foundation
import BCSecureComponents
import WolfLorem
import WolfBase

public class EnvelopeGenerator {
    var rng: Xoroshiro256StarStar
    
    var state: Xoroshiro256StarStar.State {
        rng.state
    }
    
    init(state: Xoroshiro256StarStar.State) {
        self.rng = Xoroshiro256StarStar(state: state)
    }
    
    init() {
        self.rng = Xoroshiro256StarStar()
    }
    
    func envelope(count: Int = 20) -> Envelope {
        var count = count
        return envelope(level: 0, count: &count)
    }
    
//    func mutate(_ envelope: Envelope) -> Envelope {
//        try! envelope.mutatingWalk { envelope, level in
//            guard Double.random(in: 0..<1, using: &rng) < 0.1 else {
//                return envelope
//            }
//            var count = 5
//            var result = envelope
//            permute(level: level, count: &count, envelope: &result)
//            return result
//        }
//    }
    
    private enum LeafType: CaseIterable {
        case string
        case knownValue
    }
    
    private func makeLeaf() -> Envelope {
        let weightsDict: [LeafType: Int] = [
            .string: 5,
            .knownValue: 1
        ]
        let leafTypes = LeafType.allCases
        let weights = leafTypes.map { weightsDict[$0]! }
        let leafType = leafTypes[WeightedRandomGenerator(weights).pick(using: &rng)]
        switch leafType {
        case .string:
            return Envelope(Lorem.shortTitle(using: &rng))
        case .knownValue:
            return Envelope(KnownValue(rawValue: UInt64.random(in: UInt64.min ... UInt64.max, using: &rng)))
        }
    }
    
    private func envelope(level: Int, count: inout Int) -> Envelope {
        var envelope = makeLeaf()
        let availableCount = count / 4
        var localCount = availableCount
        while localCount > 0 {
            permute(level: level, count: &localCount, envelope: &envelope)
        }
        let usedCount = availableCount - localCount
        count -= usedCount
        return envelope
    }
    
    private enum Operation: CaseIterable {
        case addAssertion
        case removeAssertion
        case encryptSubject
        case elideSubject
        case encryptAssertion
        case elideAssertion
        case wrap
        case salt
    }
    
    private func weights(level: Int) -> [Operation: Int] {
        var result: [Operation: Int] = [:]
        result[.addAssertion] = Int(400.0 / pow(2, Double(level)))
        result[.removeAssertion] = 10
        result[.encryptSubject] = 10
        result[.elideSubject] = 10
        result[.encryptAssertion] = 10
        result[.elideAssertion] = 10
        result[.wrap] = 5
        result[.salt] = 5
        return result
    }

    private func permute(level: Int, count: inout Int, envelope: inout Envelope) {
        let originalCount = count
        guard count > 0 else {
            return
        }
        var localCount = count
        
        let weightsDict = weights(level: level)
        let operations = Operation.allCases
        let weights = operations.map { weightsDict[$0]! }
        let operation = operations[WeightedRandomGenerator(weights).pick(using: &rng)]
        permute(level: level + 1, count: &localCount, envelope: &envelope, operation: operation)
        count -= originalCount - localCount
    }

    private func permute(level: Int, count: inout Int, envelope: inout Envelope, operation: Operation) {
        count -= 1
        switch operation {
        case .addAssertion:
            let object = self.envelope(level: level, count: &count)
            let predicate = self.envelope(level: level, count: &count)
            envelope = envelope.addAssertion(predicate, object)
        case .removeAssertion:
            guard let assertion = envelope.assertions.randomElement(using: &rng) else {
                return
            }
            envelope = envelope.removeAssertion(assertion)
        case .encryptSubject:
            guard !envelope.subject.isObscured else {
                return
            }
            envelope = try! envelope.encryptSubject(with: fakeContentKey, testNonce: fakeNonce)
        case .elideSubject:
            guard !envelope.subject.isObscured else {
                return
            }
            envelope = envelope.elide()
        case .encryptAssertion:
            guard
                let assertion = envelope.assertions.randomElement(using: &rng),
                !assertion.subject.isObscured
            else {
                return
            }
            envelope = try! envelope.elideRemoving(Set([assertion.digest]), encryptingWith: SymmetricKey())
        case .elideAssertion:
            guard
                let assertion = envelope.assertions.randomElement(using: &rng),
                !assertion.subject.isObscured
            else {
                return
            }
            envelope = try! envelope.elideRemoving(Set([assertion.digest]))
        case .wrap:
            envelope = envelope.wrap()
        case .salt:
            envelope = envelope.addSalt(using: &rng)
        }
    }
}
