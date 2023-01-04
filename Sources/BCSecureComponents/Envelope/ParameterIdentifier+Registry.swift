import Foundation

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
