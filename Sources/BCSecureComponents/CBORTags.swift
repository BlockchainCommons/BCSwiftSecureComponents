import Foundation
import URKit

/// https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md

/// As of August 13 2022, the [IANA registry of CBOR tags](https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml)
/// has the following low-numbered values available:
///
/// One byte encoding: 6-15, 19-20
/// Two byte encoding: 48-51, 53, 55-60, 62, 88-95, 99, 102, 105-109, 113-119, 128-255
///
/// Tags in the range 0-23 require "standards action" for the IANA to recognize.
/// Tags in the range 24-32767 require a specification to reserve.
/// Tags in the range 24-255 only require two bytes to encode.
/// Higher numbered tags are first-come, first-served.
///
/// Currently Secure Components would benefit from having 17 of these tags.
/// As we expect to file a specification at some point, we are choosing tags from 200 up for our highest-frequency tags.

public struct URType {
    public let type: String
    public let tag: CBOR.Tag
    
    public init(type: String, tag: UInt64) {
        self.type = type
        self.tag = CBOR.Tag(tag, type)
    }
}

/// UR types and CBOR tags for objects that can be top-level.
/// These tags use two-byte encoding.
public extension URType {
    static let envelope = URType(type: "envelope", tag: 200)
    static let message = URType(type: "crypto-msg", tag: 201)
    static let cid = URType(type: "crypto-cid", tag: 202)
    static let digest = URType(type: "crypto-digest", tag: 203)
    static let symmetricKey = URType(type: "crypto-key", tag: 204)
    static let privateKeyBase = URType(type: "crypto-prvkeys", tag: 205)
    static let publicKeyBase = URType(type: "crypto-pubkeys", tag: 206)
    static let sealedMessage = URType(type: "crypto-sealed", tag: 207)
}

/// Tags for subtypes specific to Secure Components.
/// These tags use two-byte encoding.
public extension CBOR.Tag {
    static let leaf = CBOR.Tag(220, "leaf")
    static let assertion = CBOR.Tag(221, "assertion")
    static let signature = CBOR.Tag(222, "signature")
    static let knownPredicate = CBOR.Tag(223, "known-predicate")
    static let enclosedEnvelope = CBOR.Tag(224, "enclosed-envelope")
    static let elided = CBOR.Tag(225, "elided")
    
    static let agreementPublicKey = CBOR.Tag(230, "agreement-public-key")
}

/// UR types and CBOR tags for objects that can be top-level.
/// These tags use three-byte encoding.
public extension URType {
    static let seed = URType(type: "crypto-seed", tag: 300)
    static let hdKey = URType(type: "crypto-hdkey", tag: 303)
    static let derivationPath = URType(type: "crypto-keypath", tag: 304)
    static let useInfo = URType(type: "crypto-coin-info", tag: 305)
    static let ecKey = URType(type: "crypto-eckey", tag: 306)
    static let address = URType(type: "crypto-address", tag: 307)
    static let output = URType(type: "crypto-output", tag: 308)
    static let sskrShare = URType(type: "crypto-sskr", tag: 309)
    static let psbt = URType(type: "crypto-psbt", tag: 310)
    static let account = URType(type: "crypto-account", tag: 311)
}

/// Tags for subtypes specific to AccountBundle (crypto-output).
/// These tags use three-byte encoding.
public extension CBOR.Tag {
    static let outputScriptHash = CBOR.Tag(400, "output-script-hash")
    static let outputWitnessScriptHash = CBOR.Tag(401, "output-witness-script-hash")
    static let outputPublicKey = CBOR.Tag(402, "output-public-key")
    static let outputPublicKeyHash = CBOR.Tag(403, "output-public-key-hash")
    static let outputWitnessPublicKeyHash = CBOR.Tag(404, "output-witness-public-key-hash")
    static let outputCombo = CBOR.Tag(405, "output-combo")
    static let outputMultisig = CBOR.Tag(406, "output-multisig")
    static let outputSortedMultisig = CBOR.Tag(407, "output-sorted-multisig")
    static let outputRawScript = CBOR.Tag(408, "output-raw-script")
    static let outputTaproot = CBOR.Tag(409, "output-taproot")
    static let outputCosigner = CBOR.Tag(410, "output-cosigner")
}

/// Tags for subtypes specific to requests and responses.
/// These tags use three-byte encoding.
public extension CBOR.Tag {
    static let outputDescriptorResponse = CBOR.Tag(500, "output-descriptor-response")
}

/// These tags use three-byte encoding.
public extension CBOR.Tag {
    static let seedDigest = CBOR.Tag(600, "seed-digest")
}

/// Tags for subtypes specific to Distributed Function Calls.
/// These tags use two-byte encoding.
public extension CBOR.Tag {
    static let function = CBOR.Tag(213, "function")
    static let parameter = CBOR.Tag(214, "parameter")
    static let request = CBOR.Tag(215, "request")
    static let response = CBOR.Tag(216, "response")
}

/// Tags for subtypes specific to Secure Components.
/// These tags use three-byte encoding.
public extension CBOR.Tag {
    static let password = CBOR.Tag(700, "password")
    static let agreementPrivateKey = CBOR.Tag(702, "agreement-private-key")
    static let signingPrivateKey = CBOR.Tag(704, "signing-private-key")
    static let signingPublicKey = CBOR.Tag(705, "signing-public-key")
    static let nonce = CBOR.Tag(707, "nonce")
}
