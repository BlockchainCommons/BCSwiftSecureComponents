import Foundation
import Graph
import WolfBase

struct EnvelopeEdgeData {
    let type: Envelope.EdgeType
}

extension Envelope {
    var shortID: String {
        self.digest.shortDescription
    }
    
    func summary(maxLength: Int = .max) -> String {
        switch self {
        case .node(_, _, _):
            return "NODE"
        case .leaf(let cbor, _):
            return cbor.envelopeSummary(maxLength: maxLength)
        case .wrapped(_, _):
            return "WRAPPED"
        case .knownValue(let knownValue, _):
            return knownValue.name
        case .assertion(_):
            return "ASSERTION"
        case .encrypted(_):
            return "ENCRYPTED"
        case .elided(_):
            return "ELIDED"
        }
    }
}

struct EnvelopeGraphBuilder<GraphData> {
    typealias GraphType = Graph<Int, Int, Envelope, EnvelopeEdgeData, GraphData>
    var graph: GraphType
    var _nextNodeID = 1
    var _nextEdgeID = 1

    init(data: GraphData) {
        self.graph = Graph(data: data)
    }

    var nextNodeID: Int {
        mutating get {
            defer {
                _nextNodeID += 1
            }
            return _nextNodeID
        }
    }
    
    var nextEdgeID: Int {
        mutating get {
            defer {
                _nextEdgeID += 1
            }
            return _nextEdgeID
        }
    }
    
    init(_ envelope: Envelope, hideNodes: Bool, data: GraphData) {
        self.init(data: data)
        envelope.walk(hideNodes: hideNodes) { (envelope, level, incomingEdge, parent) -> Int? in
            let node = nextNodeID
            try! graph.newNode(node, data: envelope)
            if let parent {
                try! graph.newEdge(nextEdgeID, tail: parent, head: node, data: .init(type: incomingEdge))
            }
            return node
        }
    }
}

extension Envelope {
    func graph<GraphData>(hideNodes: Bool, data: GraphData) -> Graph<Int, Int, Envelope, EnvelopeEdgeData, GraphData> {
        EnvelopeGraphBuilder(self, hideNodes: hideNodes, data: data).graph
    }
    
    func graph(hideNodes: Bool) -> Graph<Int, Int, Envelope, EnvelopeEdgeData, Void> {
        graph(hideNodes: hideNodes, data: ())
    }
}
