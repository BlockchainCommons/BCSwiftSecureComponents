import Foundation

public struct FunctionParameter: RawRepresentable, Equatable, Hashable {
    public let rawValue: Int
    public let name: String?
    
    public init(rawValue: Int) {
        self.rawValue = rawValue
        self.name = nil
    }
    
    public init(_ rawValue: Int, _ name: String) {
        self.rawValue = rawValue
        self.name = name
    }

    public var hashValue : Int {
        return rawValue.hashValue
    }
    
    public static func ==(lhs: FunctionParameter, rhs: FunctionParameter) -> Bool {
        lhs.rawValue == rhs.rawValue
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawValue)
    }

    public static func knownParameter(for rawValue: Int) -> FunctionParameter {
        knownFunctionParametersByRawValue[rawValue] ?? FunctionParameter(rawValue: rawValue)
    }
    
    public static func setKnownParameter(_ parameter: FunctionParameter) {
        knownFunctionParametersByRawValue[parameter.rawValue] = parameter
    }
    
    public var cbor: CBOR {
        CBOR.tagged(.parameter, CBOR.unsignedInt(UInt64(self.rawValue)))
    }
    
    public static func nameString(for cbor: CBOR) -> String {
        switch cbor {
        case CBOR.unsignedInt(let rawValue):
            if let identifier = knownFunctionParametersByRawValue[Int(rawValue)] {
                return identifier.name ?? String(rawValue)
            } else {
                return String(rawValue)
            }
        case CBOR.utf8String(let string):
            return string.flanked("\"")
        default:
            return "CBOR"
        }
    }
    
    public static func tagged(name: String) -> CBOR {
        CBOR.tagged(.parameter, CBOR.utf8String(name))
    }
}

extension FunctionParameter {
    public static let blank = FunctionParameter(1, "_")
    public static let lhs = FunctionParameter(2, "lhs")
    public static let rhs = FunctionParameter(3, "rhs")
}

var knownFunctionParametersByRawValue: [Int: FunctionParameter] = {
    knownFunctionParameters.reduce(into: [Int: FunctionParameter]()) {
        $0[$1.rawValue] = $1
    }
}()

var knownFunctionParameters: [FunctionParameter] = [
    .blank,
    .lhs,
    .rhs
]
