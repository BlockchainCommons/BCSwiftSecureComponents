import Foundation
import Graph
import WolfBase

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

struct EnvelopeEdgeData {
    let type: EdgeType
}

extension Digest: ElementID { }
extension CID: ElementID { }

extension Envelope {
    var shortID: String {
        self.digest.shortDescription
    }
    
    var summary: String {
        switch self {
        case .node(_, _, _):
            return "NODE"
        case .leaf(let cbor, _):
            return cbor.envelopeSummary
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
    
    init(_ envelope: Envelope, data: GraphData) {
        self.init(data: data)
        addNode(envelope, incomingEdge: .none)
    }

    @discardableResult
    mutating func addNode(_ envelope: Envelope, parent: Int? = nil, incomingEdge: EdgeType) -> Int {
        let node = nextNodeID
        try! graph.newNode(node, data: envelope)
        if let parent {
            try! graph.newEdge(nextEdgeID, tail: parent, head: node, data: .init(type: incomingEdge))
        }
        switch envelope {
        case .node(let subject, let assertions, _):
            addNode(subject, parent: node, incomingEdge: .subject)
            for assertion in assertions {
                addNode(assertion, parent: node, incomingEdge: .assertion)
            }
        case .assertion(let assertion):
            addNode(assertion.predicate, parent: node, incomingEdge: .predicate)
            addNode(assertion.object, parent: node, incomingEdge: .object)
        case .wrapped(let envelope, _):
            addNode(envelope, parent: node, incomingEdge: .wrapped)
        default:
            break
        }
        return node
    }
}

extension Envelope {
    func graph<GraphData>(data: GraphData) -> Graph<Int, Int, Envelope, EnvelopeEdgeData, GraphData> {
        EnvelopeGraphBuilder(self, data: data).graph
    }
}
