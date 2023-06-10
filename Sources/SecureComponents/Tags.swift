import Foundation
import URKit

/// Assignments marked "Fixed" are likely to be in active use by external developers.

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

/// Core Envelope tags.
public extension Tag {
    /// See https://www.rfc-editor.org/rfc/rfc8949.html#name-encoded-cbor-data-item
    static let leaf = Tag(24, "leaf")

    static let envelope = Tag(200, "envelope")
    static let assertion = Tag(201, "assertion")
    static let knownValue = Tag(202, "known-value")
    static let wrappedEnvelope = Tag(203, "wrapped-envelope")
    static let digest = Tag(204, "digest")
    static let encrypted = Tag(205, "encrypted")
    static let compressed = Tag(206, "compressed")
}

/// Tags for subtypes specific to Distributed Function Calls. These tags use
/// two-byte encoding.
public extension Tag {
    static let request = Tag(207, "request")
    static let response = Tag(208, "response")
    static let function = Tag(209, "function")
    static let parameter = Tag(210, "parameter")
    static let placeholder = Tag(211, "placeholder")
    static let replacement = Tag(212, "replacement")
}

/// These are the utility structures we've identified and speced related to other
/// various applications that aren't specifically Bitcoin-related.
public extension Tag {
    static let seed = Tag(300, "crypto-seed") // Fixed
    static let agreementPrivateKey = Tag(301, "agreement-private-key")
    static let agreementPublicKey = Tag(302, "agreement-public-key")
    static let ecKey = Tag(306, "crypto-eckey") // Fixed
    static let sskrShare = Tag(309, "crypto-sskr") // Fixed
    static let commonIdentifier = Tag(312, "cid")
    static let seedDigest = Tag(313, "seed-digest")
    static let nonce = Tag(314, "nonce")
    static let password = Tag(315, "password")
    static let privateKeyBase = Tag(316, "crypto-prvkeys")
    static let publicKeyBase = Tag(317, "crypto-pubkeys")
    static let salt = Tag(318, "salt")
    static let sealedMessage = Tag(319, "crypto-sealed")
    static let signature = Tag(320, "signature")
    static let signingPrivateKey = Tag(321, "signing-private-key")
    static let signingPublicKey = Tag(322, "signing-public-key")
    static let symmetricKey = Tag(323, "crypto-key")
}

/// Bitcoin-related
public extension Tag {
    static let hdKey = Tag(303, "crypto-hdkey") // Fixed
    static let derivationPath = Tag(304, "crypto-keypath") // Fixed
    static let useInfo = Tag(305, "crypto-coin-info") // Fixed
    static let address = Tag(307, "crypto-address") // Fixed
    static let psbt = Tag(310, "crypto-psbt") // Fixed
    static let account = Tag(311, "crypto-account") // Fixed
}

/// Tags for subtypes specific to AccountBundle (crypto-output).
public extension Tag {
    static let output = Tag(308, "crypto-output") // Fixed

    static let outputScriptHash = Tag(400, "output-script-hash") // Fixed
    static let outputWitnessScriptHash = Tag(401, "output-witness-script-hash") // Fixed
    static let outputPublicKey = Tag(402, "output-public-key") // Fixed
    static let outputPublicKeyHash = Tag(403, "output-public-key-hash") // Fixed
    static let outputWitnessPublicKeyHash = Tag(404, "output-witness-public-key-hash") // Fixed
    static let outputCombo = Tag(405, "output-combo") // Fixed
    static let outputMultisig = Tag(406, "output-multisig") // Fixed
    static let outputSortedMultisig = Tag(407, "output-sorted-multisig") // Fixed
    static let outputRawScript = Tag(408, "output-raw-script") // Fixed
    static let outputTaproot = Tag(409, "output-taproot") // Fixed
    static let outputCosigner = Tag(410, "output-cosigner") // Fixed

    static let outputDescriptorResponse = Tag(500, "output-descriptor-response") // Fixed
}

public var globalTags: TagsStore = [
    .account,
    .address,
    .agreementPrivateKey,
    .agreementPublicKey,
    .assertion,
    .commonIdentifier,
    .compressed,
    .derivationPath,
    .digest,
    .ecKey,
    .encrypted,
    .envelope,
    .function,
    .hdKey,
    .knownValue,
    .leaf,
    .nonce,
    .output,
    .outputCombo,
    .outputCosigner,
    .outputDescriptorResponse,
    .outputMultisig,
    .outputPublicKey,
    .outputPublicKeyHash,
    .outputRawScript,
    .outputScriptHash,
    .outputSortedMultisig,
    .outputTaproot,
    .outputWitnessPublicKeyHash,
    .outputWitnessScriptHash,
    .parameter,
    .password,
    .privateKeyBase,
    .psbt,
    .publicKeyBase,
    .request,
    .response,
    .salt,
    .sealedMessage,
    .seed,
    .seedDigest,
    .signature,
    .signingPrivateKey,
    .signingPublicKey,
    .sskrShare,
    .symmetricKey,
    .useInfo,
    .wrappedEnvelope,
]
