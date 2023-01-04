import Foundation

public extension Envelope {
    var ur: UR {
        return try! UR(type: .envelope, cbor: untaggedCBOR)
    }

    init(ur: UR) throws {
        try ur.checkType(.envelope)
        let cbor = try CBOR(ur.cbor)
        try self.init(untaggedCBOR: cbor)
    }

    init(urString: String) throws {
        try self.init(ur: UR(urString: urString))
    }

    init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}
