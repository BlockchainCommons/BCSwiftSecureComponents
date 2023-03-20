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
    static let agreementPrivateKey = Tag(300, "agreement-private-key")
    static let agreementPublicKey = Tag(301, "agreement-public-key")
    static let commonIdentifier = Tag(302, "cid")
    static let ecKey = Tag(303, "crypto-eckey")
    static let seed = Tag(304, "crypto-seed")
    static let seedDigest = Tag(305, "seed-digest")
    static let sskrShare = Tag(306, "crypto-sskr")
    static let nonce = Tag(307, "nonce")
    static let password = Tag(308, "password")
    static let privateKeyBase = Tag(309, "crypto-prvkeys")
    static let publicKeyBase = Tag(310, "crypto-pubkeys")
    static let salt = Tag(311, "salt")
    static let sealedMessage = Tag(312, "crypto-sealed")
    static let signature = Tag(313, "signature")
    static let signingPrivateKey = Tag(314, "signing-private-key")
    static let signingPublicKey = Tag(315, "signing-public-key")
    static let symmetricKey = Tag(316, "crypto-key")
}

/// Bitcoin-related
public extension Tag {
    static let account = Tag(350, "crypto-account")
    static let address = Tag(351, "crypto-address")
    static let useInfo = Tag(352, "crypto-coin-info")
    static let hdKey = Tag(353, "crypto-hdkey")
    static let derivationPath = Tag(354, "crypto-keypath")
    static let psbt = Tag(355, "crypto-psbt")
}

/// Tags for subtypes specific to AccountBundle (crypto-output).
public extension Tag {
    static let output = Tag(370, "crypto-output")

    static let outputCombo = Tag(371, "output-combo")
    static let outputCosigner = Tag(372, "output-cosigner")
    static let outputMultisig = Tag(373, "output-multisig")
    static let outputPublicKey = Tag(374, "output-public-key")
    static let outputPublicKeyHash = Tag(375, "output-public-key-hash")
    static let outputRawScript = Tag(376, "output-raw-script")
    static let outputScriptHash = Tag(377, "output-script-hash")
    static let outputSortedMultisig = Tag(378, "output-sorted-multisig")
    static let outputTaproot = Tag(379, "output-taproot")
    static let outputWitnessPublicKeyHash = Tag(380, "output-witness-public-key-hash")
    static let outputWitnessScriptHash = Tag(381, "output-witness-script-hash")
    
    static let outputDescriptorResponse = Tag(390, "output-descriptor-response")
}

public var knownTags: KnownTagsDict = [
    .account,
    .address,
    .agreementPrivateKey,
    .agreementPublicKey,
    .assertion,
    .commonIdentifier,
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
