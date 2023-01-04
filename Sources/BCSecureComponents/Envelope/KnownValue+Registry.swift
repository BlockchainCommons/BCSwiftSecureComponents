import Foundation

public extension KnownValue {
    static let id = KnownValue(1, "id")
    static let isA = KnownValue(2, "isA")
    static let verifiedBy = KnownValue(3, "verifiedBy")
    static let note = KnownValue(4, "note")
    static let hasRecipient = KnownValue(5, "hasRecipient")
    static let sskrShare = KnownValue(6, "sskrShare")
    static let controller = KnownValue(7, "controller")
    static let publicKeys = KnownValue(8, "publicKeys")
    static let dereferenceVia = KnownValue(9, "dereferenceVia")
    static let entity = KnownValue(10, "entity")
    static let hasName = KnownValue(11, "hasName")
    static let language = KnownValue(12, "language")
    static let issuer = KnownValue(13, "issuer")
    static let holder = KnownValue(14, "holder")
    static let salt = KnownValue(15, "salt")
    static let date = KnownValue(16, "date")
    
    static let diffEdits = KnownValue(20, "edits")

    static let body = KnownValue(100, "body")
    static let result = KnownValue(101, "result")
    static let error = KnownValue(102, "error")
    static let ok = KnownValue(103, "ok")
    static let processing = KnownValue(104, "processing")
}

var knownValueRegistry: [KnownValue] = [
    .id,
    .isA,
    .verifiedBy,
    .note,
    .hasRecipient,
    .sskrShare,
    .controller,
    .publicKeys,
    .dereferenceVia,
    .entity,
    .hasName,
    .language,
    .issuer,
    .holder,
    .salt,
    .date,

    .diffEdits,

    .body,
    .result,
    .error,
    .ok,
    .processing,
]
