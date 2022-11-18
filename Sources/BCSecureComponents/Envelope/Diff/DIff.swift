import Foundation
import Graph
import WolfBase

struct EnvelopeTreeBuilder {
    typealias TreeGraph = Graph<Int, Int, Envelope, Void, Void>
    typealias TreeType = Tree<TreeGraph>
    
    static func build(_ envelope: Envelope) -> TreeType {
        var _nextNodeID = 1
        var _nextEdgeID = 1

        var nextNodeID: Int {
            get {
                defer { _nextNodeID += 1 }
                return _nextNodeID
            }
        }
        
        var nextEdgeID: Int {
            get {
                defer { _nextEdgeID += 1 }
                return _nextEdgeID
            }
        }
        
        var graph = TreeGraph()
        let root = nextNodeID
        try! graph.newNode(root, data: envelope.subject)
        let tree = try! TreeType(graph: graph, root: root)
        var isRoot = true
//        envelope.walk { envelope, level, incomingEdge, parent in
//            guard !isRoot else {
//                isRoot = false
//                return
//            }
//
//            let node =
//            return nil
//        }
        
        todo()
    }
}
