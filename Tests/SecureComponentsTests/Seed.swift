import Foundation
import SecureComponents
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

extension Seed: URCodable {
    static var cborTag = Tag.seed
    
    var untaggedCBOR: CBOR {
        var map: Map = [1: data]
        if let creationDate {
            map[2] = creationDate.cbor
        }
        if !name.isEmpty {
            map[3] = name.cbor
        }
        if !note.isEmpty {
            map[4] = note.cbor
        }
        return map.cbor
    }
    
    init(untaggedCBOR: CBOR) throws {
        guard case CBOR.map(let map) = untaggedCBOR else {
            // CBOR doesn't contain a map.
            throw CBORError.invalidFormat
        }
        guard
            let dataItem = map[1],
            case let CBOR.bytes(bytes) = dataItem,
            !bytes.isEmpty
        else {
            // CBOR doesn't contain data field.
            throw CBORError.invalidFormat
        }
        let data = bytes.data

        let creationDate: Date?
        if let dateItem = map[2] {
            guard let d = try? Date(cbor: dateItem) else {
                // CreationDate field doesn't contain a date.
                throw CBORError.invalidFormat
            }
            creationDate = d
        } else {
            creationDate = nil
        }

        let name: String
        if let nameItem = map[3] {
            guard case let CBOR.text(s) = nameItem else {
                // Name field doesn't contain string.
                throw CBORError.invalidFormat
            }
            name = s
        } else {
            name = ""
        }

        let note: String
        if let noteItem = map[4] {
            guard case let CBOR.text(s) = noteItem else {
                // Note field doesn't contain string.
                throw CBORError.invalidFormat
            }
            note = s
        } else {
            note = ""
        }
        self = Seed(data: data, name: name, note: note, creationDate: creationDate)!
    }
}
