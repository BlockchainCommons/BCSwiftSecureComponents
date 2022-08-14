import Foundation

public extension Set where Element == Digest {
    mutating func insert<E>(_ element: E) where E: DigestProvider {
        insert(element.digest)
    }

    mutating func insert<S>(_ other: S) where S: Sequence, S.Element: DigestProvider {
        formUnion(other.map { $0.digest })
    }
}
