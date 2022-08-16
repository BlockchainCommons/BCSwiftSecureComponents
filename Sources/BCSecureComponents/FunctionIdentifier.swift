import Foundation

public enum FunctionIdentifier: Hashable {
    case known(value: Int, name: String?)
    case named(name: String)
}

public extension FunctionIdentifier {
    init(_ value: Int, _ name: String? = nil) {
        self = .known(value: value, name: name)
    }
    
    init(_ name: String) {
        self = .named(name: name)
    }
}

public extension FunctionIdentifier {
    var isKnown: Bool {
        guard case .known = self else {
            return false
        }
        return true
    }
    
    var isNamed: Bool {
        guard case .named = self else {
            return false
        }
        return true
    }
    
    var name: String? {
        switch self {
        case .known(value: _, name: let name):
            return name
        case .named(name: let name):
            return name
        }
    }
    
    var value: Int? {
        switch self {
        case .known(value: let value, name: _):
            return value
        case .named(name: _):
            return nil
        }
    }
}

public extension FunctionIdentifier {
    static func knownIdentifier(for value: Int) -> FunctionIdentifier {
        knownFunctionIdentifiersByValue[value] ?? FunctionIdentifier(value)
    }

    static func setKnownIdentifier(_ identifier: FunctionIdentifier) {
        guard case .known(value: let value, name: _) = identifier else {
            preconditionFailure()
        }
        knownFunctionIdentifiersByValue[value] = identifier
    }
}

extension FunctionIdentifier: CBORCodable {
    public static func cborDecode(_ cbor: CBOR) throws -> FunctionIdentifier {
        try FunctionIdentifier(taggedCBOR: cbor)
    }

    public var cbor: CBOR {
        switch self {
        case .known(value: let value, name: _):
            return CBOR.tagged(.function, CBOR.unsignedInt(UInt64(value)))
        case .named(name: let name):
            return CBOR.tagged(.function, CBOR.utf8String(name))
        }
    }
}

public extension FunctionIdentifier {
    init(taggedCBOR cbor: CBOR) throws {
        guard case CBOR.tagged(.function, let item) = cbor else {
            throw CBORError.invalidTag
        }
        switch item {
        case CBOR.unsignedInt(let value):
            if let knownIdentifier = knownFunctionIdentifiersByValue[Int(value)] {
                self = knownIdentifier
            } else {
                self.init(Int(value))
            }
        case CBOR.utf8String(let name):
            self.init(name)
        default:
            throw CBORError.invalidFormat
        }
    }
}

extension FunctionIdentifier: CustomStringConvertible {
    public var description: String {
        switch self {
        case .known(value: let value, name: let name):
            return name ?? String(value)
        case .named(name: let name):
            return name.flanked("\"")
        }
    }
}

var knownFunctionIdentifiersByValue: [Int: FunctionIdentifier] = {
    knownFunctionIdentifiers.reduce(into: [Int: FunctionIdentifier]()) {
        guard case .known(value: let value, name: _) = $1 else {
            preconditionFailure()
        }
        $0[value] = $1
    }
}()

public extension FunctionIdentifier {
    static let add = FunctionIdentifier(1, "add")
    static let sub = FunctionIdentifier(2, "sub")
    static let mul = FunctionIdentifier(3, "mul")
    static let div = FunctionIdentifier(4, "div")
}

var knownFunctionIdentifiers: [FunctionIdentifier] = [
    .add,
    .sub,
    .mul,
    .div
]
