import Foundation
import XCTest

final class TableOfContents: XCTestCase {
    func testGenerateTableOfContents() {
        (1...tocItems.count).forEach {
            print(formatTableOfContents(itemIndex: $0))
        }
    }
}

let tocItems: [(title: String, filename: String)] = [
    ("Overview", "OVERVIEW.md"),
    ("Envelope Overview", "ENVELOPE.md"),
    ("Envelope Notation", "ENVELOPE-NOTATION.md"),
    ("Envelope Expressions", "ENVELOPE-EXPRESSIONS.md"),
    ("Definitions", "DEFINITIONS.md"),
    ("Examples", "EXAMPLES.md"),
    ("Envelope Test Vectors", "ENVELOPE-TEST-VECTORS.md"),
    ("Envelope SSKR Test Vectors", "ENVELOPE-SSKR-TEST-VECTORS.md"),
    ("Noncorrelation", "NONCORRELATION.md"),
]

func tocFilename(at index: Int) -> String {
    "\(index)-\(tocItems[index - 1].filename)"
}

@StringBuilder
func formatTableOfContents(itemIndex: Int) -> String {
    header2("Contents")

    list(
        (1...tocItems.count).map {
            item(itemIndex: itemIndex, index: $0)
        }
    )
    
    divider()
}

fileprivate func item(itemIndex: Int, index: Int) -> String {
    let title = tocItems[index - 1].title
    let target = tocFilename(at: index)
    if index == itemIndex {
        return "\(title): This document"
    } else {
        return link(title, target)
    }
}

@StringBuilder
func documentHeader(_ name: String) -> String {
    header1("Secure Components - \(name)")

    "**Authors:** Wolf McNally, Christopher Allen, Blockchain Commons</br>"
    "**Revised:** \(Date())</br>"
    "**Status:** DRAFT"
    ""
}

fileprivate extension String.StringInterpolation {
    mutating func appendInterpolation(_ value: Date) {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        
        let dateString = formatter.string(from: value)
        appendLiteral(dateString)
    }
}
