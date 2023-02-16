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

/// UR types and CBOR tags for objects that can be top-level.
/// These tags use two-byte encoding.

public extension Tag {
    static let envelope = Tag(200, "envelope")
    static let message = Tag(201, "crypto-msg")
    static let cid = Tag(202, "crypto-cid")
    static let digest = Tag(203, "crypto-digest")
    static let symmetricKey = Tag(204, "crypto-key")
    static let privateKeyBase = Tag(205, "crypto-prvkeys")
    static let publicKeyBase = Tag(206, "crypto-pubkeys")
    static let sealedMessage = Tag(207, "crypto-sealed")
}

/// Tags for subtypes specific to Secure Components.
/// Except for `.leaf`, these tags use two-byte encoding.
public extension Tag {
    /// See https://www.rfc-editor.org/rfc/rfc8949.html#name-encoded-cbor-data-item
    static let leaf = Tag(24, "leaf")
    
    static let assertion = Tag(221, "assertion")
    static let signature = Tag(222, "signature")
    static let knownValue = Tag(223, "known-value")
    static let wrappedEnvelope = Tag(224, "wrapped-envelope")
    
    static let agreementPublicKey = Tag(230, "agreement-public-key")
}

/// UR types and CBOR tags for objects that can be top-level.
/// These tags use three-byte encoding.
public extension Tag {
    static let seed = Tag(300, "crypto-seed")
    static let hdKey = Tag(303, "crypto-hdkey")
    static let derivationPath = Tag(304, "crypto-keypath")
    static let useInfo = Tag(305, "crypto-coin-info")
    static let ecKey = Tag(306, "crypto-eckey")
    static let address = Tag(307, "crypto-address")
    static let output = Tag(308, "crypto-output")
    static let sskrShare = Tag(309, "crypto-sskr")
    static let psbt = Tag(310, "crypto-psbt")
    static let account = Tag(311, "crypto-account")
}

/// Tags for subtypes specific to AccountBundle (crypto-output).
/// These tags use three-byte encoding.
public extension Tag {
    static let outputScriptHash = Tag(400, "output-script-hash")
    static let outputWitnessScriptHash = Tag(401, "output-witness-script-hash")
    static let outputPublicKey = Tag(402, "output-public-key")
    static let outputPublicKeyHash = Tag(403, "output-public-key-hash")
    static let outputWitnessPublicKeyHash = Tag(404, "output-witness-public-key-hash")
    static let outputCombo = Tag(405, "output-combo")
    static let outputMultisig = Tag(406, "output-multisig")
    static let outputSortedMultisig = Tag(407, "output-sorted-multisig")
    static let outputRawScript = Tag(408, "output-raw-script")
    static let outputTaproot = Tag(409, "output-taproot")
    static let outputCosigner = Tag(410, "output-cosigner")
}

/// Tags for subtypes specific to requests and responses.
/// These tags use three-byte encoding.
public extension Tag {
    static let outputDescriptorResponse = Tag(500, "output-descriptor-response")
}

/// These tags use three-byte encoding.
public extension Tag {
    static let seedDigest = Tag(600, "seed-digest")
}

/// Tags for subtypes specific to Distributed Function Calls.
/// These tags use two-byte encoding.
public extension Tag {
    static let function = Tag(213, "function")
    static let parameter = Tag(214, "parameter")
    static let request = Tag(215, "request")
    static let response = Tag(216, "response")
    static let placeholder = Tag(217, "placeholder")
    static let replacement = Tag(218, "replacement")
}

/// Tags for subtypes specific to Secure Components.
/// These tags use three-byte encoding.
public extension Tag {
    static let password = Tag(700, "password")
    static let agreementPrivateKey = Tag(702, "agreement-private-key")
    static let signingPrivateKey = Tag(704, "signing-private-key")
    static let signingPublicKey = Tag(705, "signing-public-key")
    static let nonce = Tag(707, "nonce")
    static let salt = Tag(708, "salt")
    static let receipt = Tag(709, "receipt")
}

public var knownTags: KnownTagsDict = [
    .envelope,
    .message,
    .cid,
    .digest,
    .symmetricKey,
    .privateKeyBase,
    .publicKeyBase,
    .sealedMessage,
    .leaf,
    .assertion,
    .signature,
    .knownValue,
    .wrappedEnvelope,
    .agreementPublicKey,
    .seed,
    .hdKey,
    .derivationPath,
    .useInfo,
    .ecKey,
    .address,
    .output,
    .sskrShare,
    .psbt,
    .account,
    .outputScriptHash,
    .outputWitnessScriptHash,
    .outputPublicKey,
    .outputPublicKeyHash,
    .outputWitnessPublicKeyHash,
    .outputCombo,
    .outputMultisig,
    .outputSortedMultisig,
    .outputRawScript,
    .outputTaproot,
    .outputCosigner,
    .outputDescriptorResponse,
    .seedDigest,
    .function,
    .parameter,
    .request,
    .response,
    .password,
    .agreementPrivateKey,
    .signingPrivateKey,
    .signingPublicKey,
    .nonce,
    .salt,
    .receipt
]
