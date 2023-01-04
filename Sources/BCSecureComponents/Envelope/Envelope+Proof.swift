import Foundation

extension Envelope {
    public func proof(contains target: DigestProvider) -> Envelope? {
        proof(contains: [target.digest])
    }
    
    public func proof(contains target: Set<Digest>) -> Envelope? {
        let revealSet = revealSet(of: target)
        guard target.isSubset(of: revealSet) else { return nil }
        return try! elideRevealing(revealSet).elideRemoving(target)
    }
    
    public func revealSet(of target: DigestProvider) -> Set<Digest> {
        revealSet(of: [target.digest])
    }
    
    public func revealSet(of target: Set<Digest>) -> Set<Digest> {
        var result: Set<Digest> = []
        revealSets(of: target, current: [], result: &result)
        return result
    }
    
    func revealSets(of target: Set<Digest>, current: Set<Digest>, result: inout Set<Digest>) {
        var current = current
        current.insert(digest)

        if target.contains(digest) {
            result.formUnion(current)
        }

        switch self {
        case .node(let subject, let assertions, _):
            subject.revealSets(of: target, current: current, result: &result)
            for assertion in assertions {
                assertion.revealSets(of: target, current: current, result: &result)
            }
        case .wrapped(let envelope, _):
            envelope.revealSets(of: target, current: current, result: &result)
        case .assertion(let assertion):
            assertion.predicate.revealSets(of: target, current: current, result: &result)
            assertion.object.revealSets(of: target, current: current, result: &result)
        default:
            break
        }
    }
    
    public func contains(_ target: DigestProvider) -> Bool {
        containsAll(in: [target.digest])
    }
    
    public func containsAll(in target: Set<Digest>) -> Bool {
        var target = target
        removeAllFound(in: &target)
        return target.isEmpty
    }
    
    func removeAllFound(in target: inout Set<Digest>) {
        if target.contains(digest) {
            target.remove(digest)
        }
        guard !target.isEmpty else { return }

        switch self {
        case .node(let subject, let assertions, _):
            subject.removeAllFound(in: &target)
            for assertion in assertions {
                assertion.removeAllFound(in: &target)
            }
        case .wrapped(let envelope, _):
            envelope.removeAllFound(in: &target)
        case .assertion(let assertion):
            assertion.predicate.removeAllFound(in: &target)
            assertion.object.removeAllFound(in: &target)
        default:
            break
        }
    }
    
    public func confirm(contains target: DigestProvider, using proof: Envelope) -> Bool {
        confirm(contains: [target.digest], using: proof)
    }
    
    public func confirm(contains target: Set<Digest>, using proof: Envelope) -> Bool {
        self.digest == proof.digest && proof.containsAll(in: target)
    }
}
