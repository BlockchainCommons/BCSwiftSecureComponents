import Foundation
import Graph
import GraphMermaid
import WolfBase

public extension Envelope {
    func mermaidFormat(hideNodes: Bool = false, layoutDirection: MermaidOptions.LayoutDirection? = nil, theme: MermaidOptions.Theme? = nil) -> String {
        graph(hideNodes: hideNodes, data: MermaidOptions(layoutDirection: layoutDirection, theme: theme, includeDigests: !hideNodes)).mermaidFormat
    }
}

public struct MermaidOptions {
    public let layoutDirection: LayoutDirection
    public let theme: Theme
    public let includeDigests: Bool

    public init(layoutDirection: LayoutDirection? = nil, theme: Theme? = nil, includeDigests: Bool = true) {
        self.layoutDirection = layoutDirection ?? .leftToRight
        self.theme = theme ?? .color
        self.includeDigests = includeDigests
    }

    public enum LayoutDirection {
        case leftToRight
        case topToBottom
    }
    
    public enum Theme {
        case color
        case monochrome
    }
}

typealias MermaidEnvelopeGraph = Graph<Int, Int, Envelope, EnvelopeEdgeData, MermaidOptions>

extension MermaidEnvelopeGraph: MermaidEncodable {
    public var mermaidGraphAttributes: GraphAttributes {
        let layoutDirection: LayoutDirection
        switch self.data.layoutDirection {
        case .leftToRight:
            layoutDirection = .leftToRight
        case .topToBottom:
            layoutDirection = .topToBottom
        }
        return GraphAttributes(layoutDirection: layoutDirection)
    }
    
    public func mermaidNodeAttributes(_ node: Int) -> NodeAttributes {
        let envelope = try! nodeData(node)
        var labelComponents: [String] = []
        if data.includeDigests {
            labelComponents.append(envelope.shortID)
        }
        labelComponents.append(envelope.summary(maxLength: 40).replacingOccurrences(of: "\"", with: "#quot;"))
        let label = labelComponents.joined(separator: "<br/>").flanked("\"")

        var attributes = NodeAttributes(label: label)
        attributes.strokeWidth = 3
        switch envelope {
        case .node(_, _, _):
            attributes.shape = .circle
            attributes.strokeColor = "red"
        case .leaf(_, _):
            attributes.shape = .rectangle
            attributes.strokeColor = "#55f"
        case .wrapped(_, _):
            attributes.shape = .trapezoid
            attributes.strokeColor = "red"
        case .knownValue(_, _):
            attributes.shape = .parallelogram
            attributes.strokeColor = "#55f"
        case .assertion(_):
            attributes.shape = .stadium
            attributes.strokeColor = "red"
        case .encrypted(_):
            attributes.shape = .asymmetric
            attributes.dashArray = [5, 5]
            attributes.strokeColor = "#55f"
        case .elided(_):
            attributes.shape = .hexagon
            attributes.dashArray = [5, 5]
            attributes.strokeColor = "#55f"
        }
        
        if data.theme == .monochrome {
            attributes.strokeColor = nil
            attributes.fillColor = nil
        }
        
        return attributes
    }
    
    public func mermaidEdgeAttributes(_ edge: Int) -> EdgeAttributes {
        let edgeAttributes = try! edgeData(edge)
        var attributes = EdgeAttributes()
        attributes.strokeWidth = 2
        attributes.label = edgeAttributes.type.label
        switch edgeAttributes.type {
        case .subject:
            attributes.strokeColor = "red"
        case .predicate:
            attributes.strokeColor = "green"
        case .object:
            attributes.strokeColor = "#55f"
        case .wrapped:
            attributes.strokeColor = "red"
        default:
            break
        }
        
        if data.theme == .monochrome {
            attributes.strokeColor = nil
        }
        
        return attributes
    }
}
