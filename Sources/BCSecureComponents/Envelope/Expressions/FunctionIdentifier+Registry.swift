import Foundation
import URKit

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
