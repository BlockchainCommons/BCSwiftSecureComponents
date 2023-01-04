import Foundation

public extension Envelope {
    enum EdgeType {
        case none
        case subject
        case assertion
        case predicate
        case object
        case wrapped
        
        var label: String? {
            switch self {
            case .subject, .wrapped:
                return "subj"
            case .predicate:
                return "pred"
            case .object:
                return "obj"
            default:
                return nil
            }
        }
    }

    /// Perform a depth-first walk of the envelope's structure.
    func walk<Parent>(hideNodes: Bool, visit: (Envelope, Int, EdgeType, Parent?) -> Parent?) {
        if hideNodes {
            walkTree { envelope, level, parent in
                visit(envelope, level, .none, parent)
            }
        } else {
            walkStructure(visit: visit)
        }
    }

    func walkStructure<Parent>(visit: (Envelope, Int, EdgeType, Parent?) -> Parent?) {
        walkStructure(level: 0, incomingEdge: .none, parent: nil, visit: visit)
    }
    
    private func walkStructure<Parent>(level: Int, incomingEdge: EdgeType, parent: Parent?, visit: (Envelope, Int, EdgeType, Parent?) -> Parent?) {
        let parent = visit(self, level, incomingEdge, parent)
        let nextLevel = level + 1
        switch self {
        case .node(let subject, let assertions, _):
            subject.walkStructure(level: nextLevel, incomingEdge: .subject, parent: parent, visit: visit)
            for assertion in assertions {
                assertion.walkStructure(level: nextLevel, incomingEdge: .assertion, parent: parent, visit: visit)
            }
        case .wrapped(let envelope, _):
            envelope.walkStructure(level: nextLevel, incomingEdge: .wrapped, parent: parent, visit: visit)
        case .assertion(let assertion):
            assertion.predicate.walkStructure(level: nextLevel, incomingEdge: .predicate, parent: parent, visit: visit)
            assertion.object.walkStructure(level: nextLevel, incomingEdge: .object, parent: parent, visit: visit)
        default:
            break
        }
    }

    /// Perform a depth-first walk of the envelope's tree.
    private func walkTree<Parent>(visit: (Envelope, Int, Parent?) -> Parent?) {
        walkTree(level: 0, parent: nil, visit: visit)
    }
    
    @discardableResult
    private func walkTree<Parent>(level: Int, parent: Parent?, visit: (Envelope, Int, Parent?) -> Parent?) -> Parent? {
        var parent = parent
        var subjectLevel = level
        if !isNode {
            parent = visit(self, level, parent)
            subjectLevel = level + 1
        }
        switch self {
        case .node(let subject, let assertions, _):
            let assertionParent = subject.walkTree(level: subjectLevel, parent: parent, visit: visit)
            let assertionLevel = subjectLevel + 1
            for assertion in assertions {
                assertion.walkTree(level: assertionLevel, parent: assertionParent, visit: visit)
            }
        case .wrapped(let envelope, _):
            envelope.walkTree(level: subjectLevel, parent: parent, visit: visit)
        case .assertion(let assertion):
            assertion.predicate.walkTree(level: subjectLevel, parent: parent, visit: visit)
            assertion.object.walkTree(level: subjectLevel, parent: parent, visit: visit)
        default:
            break
        }
        return parent
    }
}
