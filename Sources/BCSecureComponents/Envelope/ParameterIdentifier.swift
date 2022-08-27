import Foundation
import URKit

public enum ParameterIdentifier: Hashable {
    case known(value: Int, name: String?)
    case named(name: String)
}

public extension ParameterIdentifier {
    init(_ value: Int, _ name: String? = nil) {
        self = .known(value: value, name: name)
    }
    
    init(_ name: String) {
        self = .named(name: name)
    }
}

public extension ParameterIdentifier {
    static func ==(lhs: ParameterIdentifier, rhs: ParameterIdentifier) -> Bool {
        if
            case .known(let lValue, _) = lhs,
            case .known(let rValue, _) = rhs
        {
            return lValue == rValue
        } else if
            case .named(let lName) = lhs,
            case .named(let rName) = rhs
        {
            return lName == rName
        } else {
            return false
        }
    }
}

public extension ParameterIdentifier {
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

public extension ParameterIdentifier {
    static func knownParameter(for value: Int) -> ParameterIdentifier {
        knownFunctionParametersByValue[value] ?? ParameterIdentifier(value)
    }

    static func setKnownParameter(_ parameter: ParameterIdentifier) {
        guard case .known(value: let value, name: _) = parameter else {
            preconditionFailure()
        }
        knownFunctionParametersByValue[value] = parameter
    }
}

extension ParameterIdentifier: CBORCodable {
    public static func cborDecode(_ cbor: CBOR) throws -> ParameterIdentifier {
        try ParameterIdentifier(taggedCBOR: cbor)
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

public extension ParameterIdentifier {
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

extension ParameterIdentifier: CustomStringConvertible {
    public var description: String {
        switch self {
        case .known(value: let value, name: let name):
            return name ?? String(value)
        case .named(name: let name):
            return name.flanked("\"")
        }
    }
}

var knownFunctionParametersByValue: [Int: ParameterIdentifier] = {
    knownFunctionParameters.reduce(into: [Int: ParameterIdentifier]()) {
        guard case .known(value: let value, name: _) = $1 else {
            preconditionFailure()
        }
        $0[value] = $1
    }
}()

extension ParameterIdentifier {
    public static let blank = ParameterIdentifier(1, "_")
    public static let lhs = ParameterIdentifier(2, "lhs")
    public static let rhs = ParameterIdentifier(3, "rhs")
}

var knownFunctionParameters: [ParameterIdentifier] = [
    .blank,
    .lhs,
    .rhs
]
