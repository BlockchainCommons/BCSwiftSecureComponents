import Foundation
import Graph

extension Envelope {
    public func treeFormat(hideNodes: Bool = false, highlighting target: Set<Digest> = []) -> String {
        var elements: [TreeElement] = []
        walk(hideNodes: hideNodes) { envelope, level, incomingEdge, parent in
            elements.append(TreeElement(level: level, envelope: envelope, incomingEdge: incomingEdge, showID: !hideNodes, isHighlighted: target.contains(envelope.digest)))
            return nil
        }
        return elements.map { $0.string }.joined(separator: "\n")
    }
}

fileprivate struct TreeElement {
    let level: Int
    let envelope: Envelope
    let incomingEdge: EnvelopeEdgeType
    let showID: Bool
    let isHighlighted: Bool

    init(level: Int, envelope: Envelope, incomingEdge: EnvelopeEdgeType = .none, showID: Bool = true, isHighlighted: Bool = false) {
        self.level = level
        self.envelope = envelope
        self.incomingEdge = incomingEdge
        self.showID = showID
        self.isHighlighted = isHighlighted
    }
    
    var string: String {
        let line = [
            isHighlighted ? "*" : nil,
            showID ? envelope.shortID : nil,
            incomingEdge.label,
            envelope.summary(maxLength: 40)
        ]
            .compactMap { $0 }
            .joined(separator: " ")
        let indent = String(repeating: " ", count: level * 4)
        return indent + line
    }
}
