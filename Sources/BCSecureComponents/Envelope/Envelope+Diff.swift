import Foundation
import WolfBase
import TreeDistance
import OrderedCollections

typealias EnvelopeTreeNode = TreeNode<EnvelopeTreeLabel>
typealias EnvelopeEdit = TreeDistance<EnvelopeTreeNode>.Edit

public extension Envelope {
    func diff(target: Envelope) -> Envelope {
        let root1 = envelopeToTree(self)
        let root2 = envelopeToTree(target)
        let edits = TreeDistance.treeDistance(root1, root2).edits
        return Envelope(.diffEdits, editsToCBOR(edits))
    }
    
    func transform(edits envelope: Envelope) throws -> Envelope {
        let edits = try envelopeToEdits(envelope)
        let root = envelopeToTree(self)
        let resultRoot = TreeDistance.transformTree(root, edits: edits)
        let result = try treeToEnvelope(resultRoot)
        return result
    }
}

enum EnvelopeTreeLabel: CBORCodable {
    case leaf(CBOR, Digest)
    case wrapped
    case knownValue(KnownValue)
    case assertion
    case encrypted(EncryptedMessage)
    case elided(Digest)
    
    init(_ envelope: Envelope) {
        switch envelope {
        case .node:
            preconditionFailure()
        case .leaf(let cbor, let digest):
            self = .leaf(cbor, digest)
        case .wrapped:
            self = .wrapped
        case .knownValue(let knownValue, _):
            self = .knownValue(knownValue)
        case .assertion:
            self = .assertion
        case .encrypted(let encryptedMessage):
            self = .encrypted(encryptedMessage)
        case .elided(let digest):
            self = .elided(digest)
        }
    }
    
    var identifier: Int {
        switch self {
        case .leaf(_, _):
            return 0
        case .wrapped:
            return 1
        case .knownValue(_):
            return 2
        case .assertion:
            return 3
        case .encrypted(_):
            return 4
        case .elided(_):
            return 5
        }
    }
    
    var cbor: CBOR {
        var components: [CBOREncodable] = []
        components.append(identifier)
        switch self {
        case .leaf(let cbor, _):
            components.append(cbor)
        case .wrapped:
            break
        case .knownValue(let knownValue):
            components.append(knownValue)
        case .assertion:
            break
        case .encrypted(let encryptedMessage):
            components.append(encryptedMessage)
        case .elided(let digest):
            components.append(digest)
        }
        return CBOR.array(components.map { $0.cbor })
    }

    static func cborDecode(_ cbor: CBOR) throws -> EnvelopeTreeLabel {
        guard
            case CBOR.array(var elements) = cbor,
            case CBOR.unsignedInt(let identifier) = elements.removeFirst()
        else {
            throw EnvelopeError.invalidDiff
        }
        
        switch identifier {
        case 0:
            let element = elements.removeFirst()
            let digest = Digest(element.cborEncode)
            return .leaf(element, digest)
        case 1:
            return .wrapped
        case 2:
            return .knownValue(try KnownValue(taggedCBOR: elements.removeFirst()))
        case 3:
            return .assertion
        case 4:
            return .encrypted(try EncryptedMessage(taggedCBOR: elements.removeFirst()))
        case 5:
            return .elided(try Digest(taggedCBOR: elements.removeFirst()))
        default:
            throw EnvelopeError.invalidDiff
        }
    }
}

extension EnvelopeTreeLabel: Equatable {
    static func == (lhs: EnvelopeTreeLabel, rhs: EnvelopeTreeLabel) -> Bool {
        switch lhs {
        case .leaf(_, let lhsDigest):
            guard case .leaf(_, let rhsDigest) = rhs, lhsDigest == rhsDigest else {
                return false
            }
            return true
            
        case .wrapped:
            guard case .wrapped = rhs else {
                return false
            }
            return true
            
        case .knownValue(let lhsKnownValue):
            guard case .knownValue(let rhsKnownValue) = rhs else {
                return false
            }
            return lhsKnownValue == rhsKnownValue
            
        case .assertion:
            guard case .assertion = rhs else {
                return false
            }
            return true
            
        case .encrypted(let lhsEncryptedMessage):
            guard case .encrypted(let rhsEncryptedMessage) = rhs else {
                return false
            }
            return lhsEncryptedMessage.digest == rhsEncryptedMessage.digest
            
        case .elided(let lhsDigest):
            guard case .elided(let rhsDigest) = rhs else {
                return false
            }
            return lhsDigest == rhsDigest
        }
    }
}

extension EnvelopeTreeLabel: TransformableLabel {
    func transformationCost(operation: TreeOperation, other: EnvelopeTreeLabel?) -> Double {
        let cost: Double
        switch operation {
        case .rename:
            cost = self == other! ? 0 : 1
        case .insert:
            cost = 1
        case .delete:
            cost = 1
        }
        //print("\(self) -> \(other†): \(cost)")
        return cost
    }
}

extension EnvelopeTreeLabel: CustomStringConvertible {
    var description: String {
        switch self {
        case .leaf(let cbor, _):
            return Envelope(cbor).summary()
        case .wrapped:
            return "WRAPPED"
        case .knownValue(let knownValue):
            return Envelope(knownValue).summary()
        case .assertion:
            return "ASSERTION"
        case .encrypted:
            return "ENCRYPTED"
        case .elided:
            return "ELIDED"
        }
    }
}

func envelopeToTree(_ envelope: Envelope) -> EnvelopeTreeNode {
    var result: EnvelopeTreeNode!

    envelope.walk(hideNodes: true) { (envelope, level, incomingEdge, parent: EnvelopeTreeNode?) -> EnvelopeTreeNode? in
        let node = EnvelopeTreeNode(EnvelopeTreeLabel(envelope))
        if result == nil {
            result = node
        }
        if let parent {
            parent.addChild(node)
            node.parent = parent
        }
        return node
    }
    
    return result
}

func treeToEnvelope(_ root: EnvelopeTreeNode) throws -> Envelope {
    var children = root.children
    
    var result: Envelope
    
    switch root.label {
    case .leaf(let cbor, _):
        result = Envelope(cbor)
    case .wrapped:
        guard children.count >= 1 else {
            throw EnvelopeError.invalidDiff
        }
        let subject = try treeToEnvelope(children.removeFirst())
        result = Envelope(subject)
    case .knownValue(let knownValue):
        result = Envelope(knownValue)
    case .assertion:
        guard children.count == 2 else {
            throw EnvelopeError.invalidDiff
        }
        let predicate = try treeToEnvelope(children.removeFirst())
        let object = try treeToEnvelope(children.removeFirst())
        result = Envelope(predicate, object)
    case .encrypted(let encryptedMessage):
        result = try Envelope(encryptedMessage: encryptedMessage)
    case .elided(let digest):
        result = Envelope(elided: digest)
    }
    
    for child in children {
        result = try result.addAssertion(treeToEnvelope(child))
    }
    
    return result
}

extension EnvelopeEdit.Operation {
    var identifier: Int {
        switch self {
        case .delete:
            return 0
        case .rename:
            return 1
        case .insertRoot:
            return 2
        case .insert:
            return 3
        }
    }
}

extension EnvelopeEdit {
    static func cborDecode(_ cbor: CBOR) throws -> EnvelopeEdit {
        let operation: EnvelopeEdit.Operation
        let id: UInt64
        
        switch cbor {
        case .unsignedInt(let _id):
            id = _id
            operation = .delete
        case .array(var components):
            guard components.count >= 2 else {
                throw EnvelopeError.invalidDiff
            }
            id = try UInt64.cborDecode(components.removeFirst())
            let label = try EnvelopeTreeLabel.cborDecode(components.removeFirst())
            if components.isEmpty {
                operation = .rename(label: label)
            } else {
                switch components.removeFirst() {
                case .negativeInt(let n):
                    guard n == 0 else { // -1
                        throw EnvelopeError.invalidDiff
                    }
                    operation = .insertRoot(label: label)
                case .unsignedInt(let parent):
                    guard
                        components.count >= 2,
                        case CBOR.unsignedInt(let position) = components.removeFirst(),
                        case CBOR.unsignedInt(let childrenCount) = components.removeFirst()
                    else {
                        throw EnvelopeError.invalidDiff
                    }
                    let descendants: [Int]
                    if
                        !components.isEmpty,
                        case CBOR.array(let descendantsItems) = components.removeFirst()
                    {
                        descendants = try descendantsItems.map { item in
                            switch item {
                            case .unsignedInt(let descendant):
                                return Int(descendant)
                            default:
                                throw EnvelopeError.invalidDiff
                            }
                        }
                    } else {
                        descendants = []
                    }
                    guard components.isEmpty else {
                        throw EnvelopeError.invalidDiff
                    }
                    operation = .insert(label: label, parent: Int(parent), position: Int(position), childrenCount: Int(childrenCount), descendants: descendants)
                default:
                    throw EnvelopeError.invalidDiff
                }
            }
        default:
            throw EnvelopeError.invalidDiff
        }
        
        return EnvelopeEdit(id: Int(id), operation: operation)
    }
    
    var cbor: CBOR {
        let components: [CBOREncodable]
        switch operation {
        case .delete:
            return CBOR.unsignedInt(UInt64(id))
        case .rename(let label):
            components = [id, label]
        case .insertRoot(let label):
            components = [id, label, -1]
        case .insert(let label, let parent, let position, let childrenCount, let descendants):
            var _components: [CBOREncodable] = [id, label, parent, position, childrenCount]
            if !descendants.isEmpty {
                _components.append(descendants)
            }
            components = _components
        }
        return CBOR.array(components.map { $0.cbor })
    }
}

func editsToCBOR(_ edits: [EnvelopeEdit]) -> CBOR {
    var components: [CBOREncodable] = []
    components.append(1) // version number
    for edit in edits {
        components.append(edit.cbor)
    }
    return CBOR.array(components.map { $0.cbor })
}

func cborToEdits(_ cbor: CBOR) throws -> [EnvelopeEdit] {
    guard
        case var CBOR.array(components) = cbor,
        components.count >= 1,
        case let CBOR.unsignedInt(version) = components.removeFirst(),
        version == 1
    else {
        throw EnvelopeError.invalidDiff
    }

    return try components.map { try EnvelopeEdit.cborDecode($0) }
}

func envelopeToEdits(_ envelope: Envelope) throws -> [EnvelopeEdit] {
    guard let cbor = envelope.object?.leaf else {
        throw EnvelopeError.invalidDiff
    }
    return try cborToEdits(cbor)
}
