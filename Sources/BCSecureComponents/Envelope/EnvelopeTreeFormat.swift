import Foundation
import Graph

extension Envelope {
    public var treeFormat: String {
        treeFormat()
    }
    
    public func treeFormat(highlighting target: Set<Digest> = []) -> String {
        var elements: [TreeElement] = []
        walk { level, incomingEdge, parent, envelope in
            elements.append(TreeElement(level: level, envelope: envelope, incomingEdge: incomingEdge, isHighlighted: target.contains(envelope.digest)))
            return nil
        }
        return elements.map { $0.string }.joined(separator: "\n")
    }
}

fileprivate struct TreeElement {
    let level: Int
    let envelope: Envelope
    let incomingEdge: EnvelopeEdgeType
    let isHighlighted: Bool

    init(level: Int, envelope: Envelope, incomingEdge: EnvelopeEdgeType, isHighlighted: Bool) {
        self.level = level
        self.envelope = envelope
        self.incomingEdge = incomingEdge
        self.isHighlighted = isHighlighted
    }
    
    var string: String {
        let line = [
            isHighlighted ? "*" : nil,
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
