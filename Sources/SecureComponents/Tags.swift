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
}

/// Envelope extension tags
public extension Tag {
    static let knownValue = Tag(40000, "known-value")
    static let digest     = Tag(40001, "digest")
    static let encrypted  = Tag(40002, "encrypted")
    static let compressed = Tag(40003, "compressed")
}

/// Tags for subtypes specific to Distributed Function Calls.
public extension Tag {
    static let request     = Tag(40004, "request")
    static let response    = Tag(40005, "response")
    static let function    = Tag(40006, "function")
    static let parameter   = Tag(40007, "parameter")
    static let placeholder = Tag(40008, "placeholder")
    static let replacement = Tag(40009, "replacement")
}

/// These are the utility structures we've identified and speced related to other
/// various applications that aren't specifically Bitcoin-related.
public extension Tag {
    static let seed      = Tag(300, "crypto-seed") // Fixed
    static let ecKey     = Tag(306, "crypto-eckey") // Fixed
    static let sskrShare = Tag(309, "crypto-sskr") // Fixed
}

public extension Tag {
    static let agreementPrivateKey = Tag(40010, "agreement-private-key")
    static let agreementPublicKey  = Tag(40011, "agreement-public-key")
    static let arid                = Tag(40012, "arid")
    static let seedDigest          = Tag(40013, "seed-digest")
    static let nonce               = Tag(40014, "nonce")
    static let password            = Tag(40015, "password")
    static let privateKeyBase      = Tag(40016, "crypto-prvkeys")
    static let publicKeyBase       = Tag(40017, "crypto-pubkeys")
    static let salt                = Tag(40018, "salt")
    static let sealedMessage       = Tag(40019, "crypto-sealed")
    static let signature           = Tag(40020, "signature")
    static let signingPrivateKey   = Tag(40021, "signing-private-key")
    static let signingPublicKey    = Tag(40022, "signing-public-key")
    static let symmetricKey        = Tag(40023, "crypto-key")
}

/// Bitcoin-related
public extension Tag {
    static let hdKey            = Tag(303, "crypto-hdkey") // Fixed
    static let derivationPath   = Tag(304, "crypto-keypath") // Fixed
    static let useInfo          = Tag(305, "crypto-coin-info") // Fixed
    static let address          = Tag(307, "crypto-address") // Fixed
    static let psbt             = Tag(310, "crypto-psbt") // Fixed
    static let account          = Tag(311, "crypto-account") // Fixed
}

/// Tags for subtypes specific to AccountBundle (crypto-output).
public extension Tag {
    static let output = Tag(308, "crypto-output") // Fixed

    static let outputScriptHash             = Tag(400, "output-script-hash") // Fixed
    static let outputWitnessScriptHash      = Tag(401, "output-witness-script-hash") // Fixed
    static let outputPublicKey              = Tag(402, "output-public-key") // Fixed
    static let outputPublicKeyHash          = Tag(403, "output-public-key-hash") // Fixed
    static let outputWitnessPublicKeyHash   = Tag(404, "output-witness-public-key-hash") // Fixed
    static let outputCombo                  = Tag(405, "output-combo") // Fixed
    static let outputMultisig               = Tag(406, "output-multisig") // Fixed
    static let outputSortedMultisig         = Tag(407, "output-sorted-multisig") // Fixed
    static let outputRawScript              = Tag(408, "output-raw-script") // Fixed
    static let outputTaproot                = Tag(409, "output-taproot") // Fixed
    static let outputCosigner               = Tag(410, "output-cosigner") // Fixed

    static let outputDescriptorResponse = Tag(500, "output-descriptor-response") // Fixed
}

public var globalTags: TagsStore = [
    .account,
    .address,
    .agreementPrivateKey,
    .agreementPublicKey,
    .arid,
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
]
