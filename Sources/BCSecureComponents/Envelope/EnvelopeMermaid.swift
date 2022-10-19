import Foundation
import Graph
import GraphMermaid
import WolfBase

public enum EnvelopeMermaidLayoutDirection {
    case leftToRight
    case topToBottom
}

struct MermaidEnvelopeEdgeData {
    let type: EdgeType
    
    enum EdgeType {
        case unknown
        case subject
        case assertion
        case predicate
        case object
        case wrapped
    }
}

extension Digest: ElementID { }
extension CID: ElementID { }
typealias EnvelopeGraph = Graph<Int, Int, Envelope, MermaidEnvelopeEdgeData, EnvelopeMermaidLayoutDirection>

extension Envelope {
    var shortID: String {
        self.digest.shortDescription
    }
    
    var summary: String {
        switch self {
        case .node(_, _, _):
            return "NODE"
        case .leaf(let cBOR, _):
            return cBOR.envelopeSummary
        case .wrapped(_, _):
            return "WRAPPED"
        case .knownPredicate(let knownPredicate, _):
            return knownPredicate.name
        case .assertion(_):
            return "ASSERTION"
        case .encrypted(_):
            return "ENCRYPTED"
        case .elided(_):
            return "ELIDED"
        }
    }
}

struct EnvelopeGraphBuilder {
    var graph: EnvelopeGraph
    var _nextNodeID = 1
    var _nextEdgeID = 1

    init(layoutDirection: EnvelopeMermaidLayoutDirection) {
        self.graph = EnvelopeGraph(data: layoutDirection)
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
    
    init(_ envelope: Envelope, layoutDirection: EnvelopeMermaidLayoutDirection) {
        self.init(layoutDirection: layoutDirection)
        addNode(envelope)
    }

    @discardableResult
    mutating func addNode(_ envelope: Envelope, parent: Int? = nil, edgeType: MermaidEnvelopeEdgeData.EdgeType? = nil) -> Int {
        let node = nextNodeID
        try! graph.newNode(node, data: envelope)
        if let parent {
            try! graph.newEdge(nextEdgeID, tail: parent, head: node, data: .init(type: edgeType ?? .unknown))
        }
        switch envelope {
        case .node(let subject, let assertions, _):
            addNode(subject, parent: node, edgeType: .subject)
            for assertion in assertions {
                addNode(assertion, parent: node, edgeType: .assertion)
            }
        case .assertion(let assertion):
            addNode(assertion.predicate, parent: node, edgeType: .predicate)
            addNode(assertion.object, parent: node, edgeType: .object)
        case .wrapped(let envelope, _):
            addNode(envelope, parent: node, edgeType: .wrapped)
        default:
            break
        }
        return node
    }
}

extension Envelope {
    func graph(layoutDirection: EnvelopeMermaidLayoutDirection) -> EnvelopeGraph {
        EnvelopeGraphBuilder(self, layoutDirection: layoutDirection).graph
    }
    
    public func mermaidFormat(layoutDirection: EnvelopeMermaidLayoutDirection = .leftToRight) -> String {
        graph(layoutDirection: layoutDirection).mermaidFormat
    }
}

extension EnvelopeGraph: MermaidEncodable {
    public var mermaidGraphAttributes: GraphAttributes {
        let layoutDirection: LayoutDirection
        switch self.data {
        case .leftToRight:
            layoutDirection = .leftToRight
        case .topToBottom:
            layoutDirection = .topToBottom
        }
        return GraphAttributes(layoutDirection: layoutDirection)
    }
    
    public func mermaidNodeAttributes(_ node: Int) -> NodeAttributes {
        let envelope = try! nodeData(node)
        let label = (envelope.shortID + "<br/>" +
                     envelope.summary.replacingOccurrences(of: "\"", with: "#quot;"))
            .flanked("\"")

        var attributes = NodeAttributes(label: label)
        attributes.strokeWidth = 3
        switch envelope {
        case .node(_, _, _):
            attributes.shape = .circle
            attributes.strokeColor = "red"
        case .leaf(_, _):
            attributes.shape = .rectangle
            attributes.strokeColor = "blue"
        case .wrapped(_, _):
            attributes.shape = .trapezoid
            attributes.strokeColor = "red"
        case .knownPredicate(_, _):
            attributes.shape = .parallelogram
            attributes.strokeColor = "blue"
        case .assertion(_):
            attributes.shape = .stadium
            attributes.strokeColor = "red"
        case .encrypted(_):
            attributes.shape = .asymmetric
            attributes.dashArray = [5, 5]
            attributes.strokeColor = "blue"
        case .elided(_):
            attributes.shape = .hexagon
            attributes.dashArray = [5, 5]
            attributes.strokeColor = "blue"
        }
        return attributes
    }
    
    public func mermaidEdgeAttributes(_ edge: Int) -> EdgeAttributes {
        let data = try! edgeData(edge)
        var attributes = EdgeAttributes()
        attributes.strokeWidth = 2
        switch data.type {
        case .unknown:
            break
        case .subject:
            attributes.label = "subj"
            attributes.strokeColor = "red"
        case .assertion:
            break
        case .predicate:
            attributes.label = "pred"
            attributes.strokeColor = "green"
        case .object:
            attributes.label = "obj"
            attributes.strokeColor = "blue"
        case .wrapped:
            attributes.label = "subj"
            attributes.strokeColor = "red"
        }
        return attributes
    }
}
