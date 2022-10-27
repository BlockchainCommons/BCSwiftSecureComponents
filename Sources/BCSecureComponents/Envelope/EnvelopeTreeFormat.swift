import Foundation

struct TreeElement {
    let level: Int
    let envelope: Envelope
    let edgeType: EdgeType?

    init(level: Int, envelope: Envelope, edgeType: EdgeType? = nil) {
        self.level = level
        self.envelope = envelope
        self.edgeType = edgeType
    }
    
    var string: String {
        let line = [
            envelope.shortID,
            edgeType?.label,
            envelope.summary
        ]
            .compactMap { $0 }
            .joined(separator: " ")
        let indent = String(repeating: " ", count: level * 4)
        return indent + line
    }
}

extension TreeEnvelopeGraph {
    var treeFormat: String {
        let envelope = try! nodeData(nodes.first!)
        var elements: [TreeElement] = []
        addEnvelope(envelope, level: 0, edgeType: nil, result: &elements)
        return elements.map { $0.string }.joined(separator: "\n")
    }
    
    func addEnvelope(_ envelope: Envelope, level: Int, edgeType: EdgeType?, result: inout [TreeElement]) {
        result.append(TreeElement(level: level, envelope: envelope, edgeType: edgeType))
        let level = level + 1
        switch envelope {
        case .node(let subject, let assertions, _):
            addEnvelope(subject, level: level, edgeType: .subject, result: &result)
            for assertion in assertions {
                addEnvelope(assertion, level: level, edgeType: .assertion, result: &result)
            }
        case .assertion(let assertion):
            addEnvelope(assertion.predicate, level: level, edgeType: .predicate, result: &result)
            addEnvelope(assertion.object, level: level, edgeType: .object, result: &result)
        case .wrapped(let envelope, _):
            addEnvelope(envelope, level: level, edgeType: .wrapped, result: &result)
        default:
            break
        }
    }
}

extension Envelope {
    public var treeFormat: String {
        graph(data: ()).treeFormat
    }
}
