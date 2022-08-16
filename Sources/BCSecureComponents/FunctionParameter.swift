import Foundation

public enum FunctionParameter: Hashable {
    case known(value: Int, name: String?)
    case named(name: String)
}

public extension FunctionParameter {
    init(_ value: Int, _ name: String? = nil) {
        self = .known(value: value, name: name)
    }
    
    init(_ name: String) {
        self = .named(name: name)
    }
}

public extension FunctionParameter {
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

public extension FunctionParameter {
    static func knownParameter(for value: Int) -> FunctionParameter {
        knownFunctionParametersByValue[value] ?? FunctionParameter(value)
    }

    static func setKnownParameter(_ parameter: FunctionParameter) {
        guard case .known(value: let value, name: _) = parameter else {
            preconditionFailure()
        }
        knownFunctionParametersByValue[value] = parameter
    }
}

extension FunctionParameter: CBORCodable {
    public static func cborDecode(_ cbor: CBOR) throws -> FunctionParameter {
        try FunctionParameter(taggedCBOR: cbor)
    }

    public var cbor: CBOR {
        switch self {
        case .known(value: let value, name: _):
            return CBOR.tagged(.parameter, CBOR.unsignedInt(UInt64(value)))
        case .named(name: let name):
            return CBOR.tagged(.parameter, CBOR.utf8String(name))
        }
    }
}

public extension FunctionParameter {
    init(taggedCBOR cbor: CBOR) throws {
        guard case CBOR.tagged(.parameter, let item) = cbor else {
            throw CBORError.invalidTag
        }
        switch item {
        case CBOR.unsignedInt(let value):
            if let knownParameter = knownFunctionParametersByValue[Int(value)] {
                self = knownParameter
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

extension FunctionParameter: CustomStringConvertible {
    public var description: String {
        switch self {
        case .known(value: let value, name: let name):
            return name ?? String(value)
        case .named(name: let name):
            return name.flanked("\"")
        }
    }
}

var knownFunctionParametersByValue: [Int: FunctionParameter] = {
    knownFunctionParameters.reduce(into: [Int: FunctionParameter]()) {
        guard case .known(value: let value, name: _) = $1 else {
            preconditionFailure()
        }
        $0[value] = $1
    }
}()

extension FunctionParameter {
    public static let blank = FunctionParameter(1, "_")
    public static let lhs = FunctionParameter(2, "lhs")
    public static let rhs = FunctionParameter(3, "rhs")
}

var knownFunctionParameters: [FunctionParameter] = [
    .blank,
    .lhs,
    .rhs
]
