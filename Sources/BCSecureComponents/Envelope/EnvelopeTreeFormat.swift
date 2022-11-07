import Foundation
import Graph

extension Envelope {
    public var treeFormat: String {
        var elements: [TreeElement] = []
        addEnvelope(self, level: 0, incomingEdge: .none, result: &elements)
        return elements.map { $0.string }.joined(separator: "\n")
    }

    fileprivate func addEnvelope(_ envelope: Envelope, level: Int, incomingEdge: EdgeType, result: inout [TreeElement]) {
        result.append(TreeElement(level: level, envelope: envelope, incomingEdge: incomingEdge))
        let level = level + 1
        switch envelope {
        case .node(let subject, let assertions, _):
            addEnvelope(subject, level: level, incomingEdge: .subject, result: &result)
            for assertion in assertions {
                addEnvelope(assertion, level: level, incomingEdge: .assertion, result: &result)
            }
        case .assertion(let assertion):
            addEnvelope(assertion.predicate, level: level, incomingEdge: .predicate, result: &result)
            addEnvelope(assertion.object, level: level, incomingEdge: .object, result: &result)
        case .wrapped(let envelope, _):
            addEnvelope(envelope, level: level, incomingEdge: .wrapped, result: &result)
        default:
            break
        }
    }
}

fileprivate struct TreeElement {
    let level: Int
    let envelope: Envelope
    let incomingEdge: EdgeType

    init(level: Int, envelope: Envelope, incomingEdge: EdgeType) {
        self.level = level
        self.envelope = envelope
        self.incomingEdge = incomingEdge
    }
    
    var string: String {
        let line = [
            envelope.shortID,
            incomingEdge.label,
            envelope.summary
        ]
            .compactMap { $0 }
            .joined(separator: " ")
        let indent = String(repeating: " ", count: level * 4)
        return indent + line
    }
}
