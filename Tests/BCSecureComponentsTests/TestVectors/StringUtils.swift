import Foundation

@resultBuilder
struct StringBuilder {
    static func buildBlock(_ components: String...) -> String {
        components.joined(separator: "\n")
    }
}

func monospaced(_ string: String) -> String {
    [
        "```\n",
        string,
        "\n```\n",
    ].joined()
}

func header(_ level: Int, _ string: String) -> String {
    [
        String(Array(repeating: "#", count: level)),
        " ",
        string,
        "\n"
    ].joined()
}

func header1(_ string: String) -> String {
    header(1, string)
}

func header2(_ string: String) -> String {
    header(2, string)
}

func header3(_ string: String) -> String {
    header(3, string)
}

func header4(_ string: String) -> String {
    header(4, string)
}

func paragraph(_ string: String) -> String {
    [
        string,
        "\n",
    ].joined()
}

func paragraph(_ strings: [String]) -> String {
    paragraph(strings.joined())
}

func bold(_ string: String) -> String {
    string.flanked("**")
}

func italic(_ string: String) -> String {
    string.flanked("_")
}

func spaced(_ strings: [String]) -> String {
    strings.joined(separator: " ")
}

func note(_ string: String) -> String {
    paragraph(spaced(["👉", italic(string)]))
}

func divider() -> String {
    "---\n"
}

func link(_ text: String, _ dest: String) -> String {
    [
        text.flanked("[", "]"),
        dest.flanked("(", ")")
    ].joined()
}

func listItem(_ text: String) -> String {
    text.flanked("* ", "\n")
}

func numberedListItem(_ index: Int, _ text: String) -> String {
    text.flanked("\(index). ", "\n")
}

func numberedList(_ items: [String]) -> String {
    items.enumerated().map {
        numberedListItem($0.0 + 1, $0.1)
    }.joined()
}

func list(_ items: [String]) -> String {
    items.map {
        listItem($0)
    }.joined()
}

func localLink(for title: String) -> String {
    let a: [Character] = title.compactMap { c in
        if c.isWhitespace {
            return "-"
        }
        if c.isLetter || c.isNumber {
            return c
        }
        return nil
    }
    return "#" + String(a)
}

func link(title: String, target: String) -> String {
    [
        title.flanked("[", "]"),
        target.flanked("(", ")")
    ].joined()
}

extension DefaultStringInterpolation {
    mutating func appendInterpolation(pad value: Int, toWidth width: Int, using paddingCharacter: Character = "0") {
        appendInterpolation(String(format: "%\(paddingCharacter)\(width)d", value))
    }
}
