import Foundation

public struct FunctionIdentifier: RawRepresentable, Equatable, Hashable {
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
    
    public static func ==(lhs: FunctionIdentifier, rhs: FunctionIdentifier) -> Bool {
        lhs.rawValue == rhs.rawValue
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawValue)
    }

    public static func knownIdentifier(for rawValue: Int) -> FunctionIdentifier {
        knownFunctionIdentifiersByRawValue[rawValue] ?? FunctionIdentifier(rawValue: rawValue)
    }
    
    public static func setKnownIdentifier(_ identifier: FunctionIdentifier) {
        knownFunctionIdentifiersByRawValue[identifier.rawValue] = identifier
    }
    
    public var cbor: CBOR {
        CBOR.tagged(.function, CBOR.unsignedInt(UInt64(self.rawValue)))
    }
    
    public static func nameString(for cbor: CBOR) -> String {
        switch cbor {
        case CBOR.unsignedInt(let rawValue):
            if let identifier = knownFunctionIdentifiersByRawValue[Int(rawValue)] {
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
        CBOR.tagged(.function, CBOR.utf8String(name))
    }
}

public extension FunctionIdentifier {
    static let add = FunctionIdentifier(1, "add")
    static let sub = FunctionIdentifier(2, "sub")
    static let mul = FunctionIdentifier(3, "mul")
    static let div = FunctionIdentifier(4, "div")
}

var knownFunctionIdentifiersByRawValue: [Int: FunctionIdentifier] = {
    knownFunctionIdentifiers.reduce(into: [Int: FunctionIdentifier]()) {
        $0[$1.rawValue] = $1
    }
}()

var knownFunctionIdentifiers: [FunctionIdentifier] = [
    .add,
    .sub,
    .mul,
    .div
]
