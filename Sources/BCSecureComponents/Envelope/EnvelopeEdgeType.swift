import Foundation

public enum EnvelopeEdgeType {
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
