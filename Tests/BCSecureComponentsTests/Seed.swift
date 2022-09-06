import Foundation
import BCSecureComponents
import WolfBase

/// This is a mostly-duplicate of the `Seed` struct from BCSwiftFoundation, used here for demonstration and testing purposes only.
struct Seed {
    let data: Data
    var name: String
    var note: String
    var creationDate: Date?
    
    init?(data: Data, name: String = "", note: String = "", creationDate: Date? = nil) {
        self.data = data
        self.name = name
        self.note = note
        self.creationDate = creationDate
    }
}

extension Seed: PrivateKeysDataProvider {
    public var privateKeysData: Data {
        data
    }
}

extension Seed {
    public var untaggedCBOR: CBOR {
        var a: OrderedMap = [1: .data(data)]

        if let creationDate {
            a.append(2, .date(creationDate))
        }

        if !name.isEmpty {
            a.append(3, .utf8String(name))
        }

        if !note.isEmpty {
            a.append(4, .utf8String(note))
        }

        return CBOR.orderedMap(a)
    }

    public var taggedCBOR: CBOR {
        return CBOR.tagged(.seed, untaggedCBOR)
    }

    public var ur: UR {
        return try! UR(type: .seed, cbor: untaggedCBOR)
    }
}

extension Seed: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}

extension Seed: CBORDecodable {
    public static func cborDecode(_ cbor: CBOR) throws -> Seed {
        try Seed(taggedCBOR: cbor)
    }
}

extension Seed {
    public init(ur: UR) throws {
        try ur.checkType(.seed)
        try self.init(cborData: ur.cbor)
    }

    public init(urString: String) throws {
        try self.init(ur: UR(urString: urString))
    }

    public init(cborData: Data) throws {
        let cbor = try CBOR(cborData)
        try self.init(untaggedCBOR: cbor)
    }

    public init(untaggedCBOR: CBOR) throws {
        guard case CBOR.orderedMap(let orderedMap) = untaggedCBOR else {
            // CBOR doesn't contain a map.
            throw CBORError.invalidFormat
        }
        let pairs = try orderedMap.valuesByIntKey()
        guard
            let dataItem = pairs[1],
            case let CBOR.data(bytes) = dataItem,
            !bytes.isEmpty
        else {
            // CBOR doesn't contain data field.
            throw CBORError.invalidFormat
        }
        let data = bytes.data

        let creationDate: Date?
        if let dateItem = pairs[2] {
            guard case let CBOR.date(d) = dateItem else {
                // CreationDate field doesn't contain a date.
                throw CBORError.invalidFormat
            }
            creationDate = d
        } else {
            creationDate = nil
        }

        let name: String
        if let nameItem = pairs[3] {
            guard case let CBOR.utf8String(s) = nameItem else {
                // Name field doesn't contain string.
                throw CBORError.invalidFormat
            }
            name = s
        } else {
            name = ""
        }

        let note: String
        if let noteItem = pairs[4] {
            guard case let CBOR.utf8String(s) = noteItem else {
                // Note field doesn't contain string.
                throw CBORError.invalidFormat
            }
            note = s
        } else {
            note = ""
        }
        self.init(data: data, name: name, note: note, creationDate: creationDate)!
    }

    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(tag, content) = taggedCBOR, tag == .seed else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: content)
    }

    public init(taggedCBOR: Data) throws {
        try self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}
