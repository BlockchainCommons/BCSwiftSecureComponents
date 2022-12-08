import Foundation
import WolfBase
import TreeDistance
import OrderedCollections

typealias EnvelopeTreeNode = TreeNode<EnvelopeTreeLabel>
typealias EnvelopeEdit = TreeDistance<EnvelopeTreeNode>.Edit

public extension Envelope {
    func diff(target: Envelope) -> Envelope {
        let sourceDigest = self.digest
        let targetDigest = target.digest
        let subject = Digest(sourceDigest.data + targetDigest.data)
        var result = Envelope(subject)
            .addAssertion(.diffSource, sourceDigest)
            .addAssertion(.diffTarget, targetDigest)

        let root1 = envelopeToTree(self)
        let root2 = envelopeToTree(target)
        let edits = TreeDistance.treeDistance(root1, root2).edits.enumerated().map { (index, edit) in
            editToEnvelope(edit, index: index)
        }
        for edit in edits {
            result = result.addAssertion(.diffEdit, edit)
        }

        return result
    }
    
    func transform(edits envelope: Envelope) throws -> Envelope {
        let sourceDigest = try envelope.extractObject(Digest.self, forPredicate: .diffSource)
        let targetDigest = try envelope.extractObject(Digest.self, forPredicate: .diffTarget)
        
        guard digest == sourceDigest else {
            throw EnvelopeError.invalidDiff
        }

        let edits = try envelopeToEdits(envelope)
        let root = envelopeToTree(self)
        let resultRoot = TreeDistance.transformTree(root, edits: edits)
        let result = try treeToEnvelope(resultRoot)

        guard result.digest == targetDigest else {
            throw EnvelopeError.invalidDiff
        }
        
        return result
    }
}

enum EnvelopeTreeLabel {
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

func editToEnvelope(_ edit: EnvelopeEdit, index: Int) -> Envelope {
    var result = Envelope(index)
        .addAssertion(.diffID, edit.id)
    let operation: KnownValue
    var label: EnvelopeTreeLabel? = nil
    switch edit.operation {
    case .delete:
        operation = .diffDelete
    case .rename(let _label):
        operation = .diffRename
        label = _label
    case .insertRoot(let _label):
        operation = .diffInsert
        label = _label
    case .insert(let _label, let parent, let position, let childrenCount, let descendants):
        operation = .diffInsert
        result = result
            .addAssertion(.diffParent, parent)
            .addAssertion(.diffPosition, position)
            .addAssertion(.diffChildrenCount, childrenCount)
            .addAssertion(.diffDescendants, descendants)
        label = _label
    }
    
    result = result
        .addAssertion(.diffOperation, operation)
    
    if let label {
        let value: Envelope
        switch label {
        case .leaf(let cbor, _):
            value = Envelope(cbor: cbor)
        case .wrapped:
            value = Envelope(KnownValue.diffWrapped).wrap()
        case .knownValue(let knownValue):
            value = Envelope(knownValue: knownValue)
        case .assertion:
            value = Envelope(KnownValue.diffAssertion).wrap()
        case .encrypted(let encryptedMessage):
            value = try! Envelope(encryptedMessage: encryptedMessage)
        case .elided(let digest):
            value = Envelope(elided: digest)
        }
        result = result.addAssertion(.diffLabel, value)
    }
    return result
}

func envelopeToEdit(_ envelope: Envelope) throws -> (Int, EnvelopeEdit) {
    let seq = try envelope.extractSubject(Int.self)
    let id = try envelope.extractObject(Int.self, forPredicate: .diffID)
    let operation = try envelope.extractObject(KnownValue.self, forPredicate: .diffOperation)
    let edit: EnvelopeEdit
    
    func label() throws -> EnvelopeTreeLabel {
        let value = try envelope.extractObject(forPredicate: .diffLabel)
        guard value.assertions.isEmpty else {
            throw EnvelopeError.invalidDiff
        }
        switch value {
        case .leaf(let cbor, let digest):
            return .leaf(cbor, digest)
        case .wrapped(let envelope, _):
            guard envelope.assertions.isEmpty else {
                throw EnvelopeError.invalidDiff
            }
            switch try envelope.extractSubject(KnownValue.self) {
            case .diffWrapped:
                return .wrapped
            case .diffAssertion:
                return .assertion
            default:
                throw EnvelopeError.invalidDiff
            }
        case .knownValue(let knownValue, _):
            return .knownValue(knownValue)
        case .encrypted(let encryptedMessage):
            return .encrypted(encryptedMessage)
        case .elided(let digest):
            return .elided(digest)
        default:
            throw EnvelopeError.invalidDiff
        }
    }
    
    switch operation {
    case .diffDelete:
        guard envelope.assertions.count == 2 else {
            throw EnvelopeError.invalidDiff
        }
        edit = EnvelopeEdit(id: id, operation: .delete)
    case .diffRename:
        edit = try EnvelopeEdit(id: id, operation: .rename(label: label()))
    case .diffInsert:
        if let parent = try envelope.assertions(withPredicate: .diffParent).first?.object?.extractSubject(Int.self)
        {
            guard envelope.assertions.count == 7 else {
                throw EnvelopeError.invalidDiff
            }
            let position = try envelope.extractObject(Int.self, forPredicate: .diffPosition)
            let childrenCount = try envelope.extractObject(Int.self, forPredicate: .diffChildrenCount)
            guard case .array(let items) = try envelope.extractObject(forPredicate: .diffDescendants).leaf else {
                throw EnvelopeError.invalidDiff
            }
            let descendants = try items.map { try Int.cborDecode($0) }
            edit = try EnvelopeEdit(id: id, operation: .insert(label: label(), parent: parent, position: position, childrenCount: childrenCount, descendants: descendants))
        } else {
            guard envelope.assertions.count == 3 else {
                throw EnvelopeError.invalidDiff
            }
            edit = try EnvelopeEdit(id: id, operation: .insertRoot(label: label()))
        }
    default:
        throw EnvelopeError.invalidDiff
    }
    
    return (seq, edit)
}

func envelopeToEdits(_ envelope: Envelope) throws -> [EnvelopeEdit] {
    try envelope
        .extractObjects(forPredicate: .diffEdit)
        .map { try envelopeToEdit($0) }
        .sorted { $0.0 < $1.0 }
        .map { $0.1 }
}
