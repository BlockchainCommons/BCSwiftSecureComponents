import Foundation
import XCTest

final class TableOfContents: XCTestCase {
    func testGenerateTableOfContents() {
        (0..<tocItems.count).forEach {
            print(formatTableOfContents(itemIndex: $0))
        }
    }
}

let tocItems: [(title: String, filename: String)] = [
    ("Envelope Introduction", "INTRODUCTION.md"),
    ("Types", "TYPES.md"),
    ("Envelope Overview", "ENVELOPE.md"),
    ("Envelope Notation", "ENVELOPE-NOTATION.md"),
    ("Envelope Expressions", "ENVELOPE-EXPRESSIONS.md"),
    ("Definitions", "DEFINITIONS.md"),
    ("Examples", "EXAMPLES.md"),
    ("Noncorrelation", "NONCORRELATION.md"),
    ("Elision and Redaction", "ELISION-REDACTION.md"),
    ("Appendix A: MVA Algorithm Suite", "A-ALGORITHMS.md"),
    ("Appendix B: Envelope Test Vectors", "B-ENVELOPE-TEST-VECTORS.md"),
    ("Appendix C: Envelope SSKR Test Vectors", "C-ENVELOPE-SSKR-TEST-VECTORS.md"),
]

func tocFilename(at index: Int) -> String {
    "\(pad: index, toWidth: 2)-\(tocItems[index].filename)"
}

@StringBuilder
func formatTableOfContents(itemIndex: Int) -> String {
    header2("Contents")

    list(
        (0..<tocItems.count).map {
            item(itemIndex: itemIndex, index: $0)
        }
    )
    
    divider()
}

fileprivate func item(itemIndex: Int, index: Int) -> String {
    let title = tocItems[index].title
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
