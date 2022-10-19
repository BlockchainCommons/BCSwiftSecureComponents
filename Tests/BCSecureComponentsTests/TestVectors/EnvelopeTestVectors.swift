import XCTest
import BCSecureComponents
import WolfBase

final class EnvelopeTestVectors: XCTestCase {
    func testGenerateEnvelopeTestVectors() throws {
        let helloWorld = TestCase(
            name: "Hello, World!",
            explanation: "The simplest case: encoding a plaintext string as the envelope's `subject`. The `subject` can be any CBOR-encodable structure.",
            envelope: Envelope(plaintextHello)
        )

        let signedPlaintext = TestCase(
            name: "Signed Plaintext",
            explanation: "A string has been signed by Alice.",
            envelope: Envelope(plaintextHello)
                .sign(with: alicePrivateKeys, randomGenerator: generateFakeRandomNumbers)
        )

        let multisignedPlaintext = TestCase(
            name: "Multisigned Plaintext",
            explanation: "Alice and Carol jointly send a signed plaintext message to Bob.",
            envelope: Envelope(plaintextHello)
                .sign(with: [alicePrivateKeys, carolPrivateKeys], randomGenerator: generateFakeRandomNumbers)
        )

        let symmetricEncryption = TestCase(
            name: "Symmetric Encryption",
            explanation: "Alice and Bob have agreed to use a symmetric key.",
            envelope: try Envelope(plaintextHello)
                .encryptSubject(with: fakeContentKey, testNonce: fakeNonce)
        )

        let signThenEncrypt = TestCase(
            name: "Sign Then Encrypt",
            explanation: "A message is first signed, then encrypted. Its signature can only be checked once the envelope is decrypted.",
            envelope: try Envelope(plaintextHello)
                .sign(with: alicePrivateKeys, randomGenerator: generateFakeRandomNumbers)
                .wrap()
                .encryptSubject(with: fakeContentKey, testNonce: fakeNonce)
        )

        let encryptThenSign = TestCase(
            name: "Encrypt Then Sign",
            explanation: "A message is first encrypted, then signed. Its signature may be checked before the envelope is decrypted.",
            envelope: try Envelope(plaintextHello)
                .encryptSubject(with: fakeContentKey, testNonce: fakeNonce)
                .sign(with: alicePrivateKeys, randomGenerator: generateFakeRandomNumbers)
        )

        let multiRecipient = TestCase(
            name: "Multi-Recipient",
            explanation: "Alice encrypts a message using the public keys of Bob and Carol so that it can only be decrypted by the private key of either Bob or Carol. Each of the `SealedMessage` encrypts just the symmetric key used to encrypt the payload.",
            envelope: try Envelope(plaintextHello)
                .encryptSubject(with: fakeContentKey, testNonce: fakeNonce)
                .addRecipient(bobPublicKeys, contentKey: fakeContentKey, testKeyMaterial: fakeContentKey, testNonce: fakeNonce)
                .addRecipient(carolPublicKeys, contentKey: fakeContentKey, testKeyMaterial: fakeContentKey, testNonce: fakeNonce)
        )

        let visibleSignatureMultiRecipient = TestCase(
            name: "Visible Signature Multi-Recipient",
            explanation: "Alice encrypts a message using the public keys of Bob and Carol so that it can only be decrypted by the private key of either Bob or Carol. Each of the `SealedMessage` encrypts just the symmetric key used to encrypt the payload. Alice then signs the envelope so her signature may be verified by anyone with her public key.",
            envelope: try Envelope(plaintextHello)
                .sign(with: alicePrivateKeys, randomGenerator: generateFakeRandomNumbers)
                .encryptSubject(with: fakeContentKey, testNonce: fakeNonce)
                .addRecipient(bobPublicKeys, contentKey: fakeContentKey, testKeyMaterial: fakeContentKey, testNonce: fakeNonce)
                .addRecipient(carolPublicKeys, contentKey: fakeContentKey, testKeyMaterial: fakeContentKey, testNonce: fakeNonce)
        )

        let verifiableCredential = TestCase(
            name: "Verifiable Credential",
            explanation: "John Smith is issued a Permanent Resident Card signed by the State of Example",
            envelope: Self.johnSmithResidentCard
        )

        let elidedCredential = TestCase(
            name: "Redacted Verifiable Credential",
            explanation: "John wishes to identify himself to a third party using his government-issued credential, but does not wish to reveal more than his name, his photo, and the fact that the state has verified his identity. Despite redacting numerous fields, the overall digest of the elided structure is the same, and the signature still validates.",
            envelope: Self.johnSmithRedactedCredential
        )

        let testCases = [
            helloWorld,
            signedPlaintext,
            multisignedPlaintext,
            symmetricEncryption,
            signThenEncrypt,
            encryptThenSign,
            multiRecipient,
            visibleSignatureMultiRecipient,
            verifiableCredential,
            elidedCredential
        ]
            .enumerated().map {
                var testCase = $0.1
                testCase.index = $0.0 + 1
                return testCase
            }

        let text = formatDocument(chapterNumber: envelopeTestVectorsChapterNumber, testCases: testCases)
        writeDocFile(tocFilename(at: envelopeTestVectorsChapterNumber), text)
    }

    @StringBuilder
    private func formatDocument(chapterNumber: Int, testCases: [TestCase]) -> String {
        documentHeader("Envelope Test Vectors")

        formatTableOfContents(itemIndex: chapterNumber)

        header2("Introduction")

        paragraph("This document provides test vectors for `envelope`. It is generated by `EnvelopeTestVectors.testGenerateEnvelopeTestVectors()` in the `BCSwiftSecureComponents` test suite.")

        header2("Status")

        paragraph("This document is a draft with a reference implementation in [BCSwiftSecureComponents](https://github.com/blockchaincommons/BCSwiftSecureComponents).")

        divider()

        paragraph("These test vectors use these fixed seed values, from which other key pairs are derived:")
        list([
            "Alice's Seed: `\(aliceSeed.data.hex)`",
            "Bob's Seed: `\(bobSeed.data.hex)`",
            "Carol's Seed: `\(carolSeed.data.hex)`",
        ])

        paragraph("These objects are normally random, but they are fixed for these test vectors:")
        list([
            "Symmetric key used for encryption: `\(fakeContentKey.data.hex)`",
            "Nonce for encryption: `\(fakeNonce.data.hex)`",
            "Random generator for signing returns repeating sequence: `\(fakeRandomGeneratorSeed.hex)`"
        ])

        formatIndex(testCases)

        testCases.map {
            $0.format()
        }.joined(separator: "\n")
    }

    struct TestCase {
        var index: Int
        var name: String
        var explanation: String
        var envelope: Envelope

        init(index: Int = 0, name: String, explanation: String, envelope: Envelope) {
            self.index = index
            self.name = name
            self.explanation = explanation
            self.envelope = envelope
        }

        var title: String {
            "TEST VECTOR \(index): \(name)"
        }

        @StringBuilder
        func format() -> String {
            header2(title)

            paragraph(explanation)

            header3("Payload in Envelope Notation")
            monospaced(envelope.format)

            header3("UR")
            note("The CBOR in a UR is never tagged, because the UR `type` field serves this purpose.")
            monospaced(envelope.ur†)

            header3("Tagged CBOR Binary")
            monospaced(envelope.taggedCBOR.hex)

            header3("Tagged CBOR Diagnostic Notation")
            monospaced(envelope.diagAnnotated)

            header3("Tagged CBOR Annotated Binary")
            monospaced(envelope.dump)

            divider()
        }
    }

    func formatIndex(_ testCases: [TestCase]) -> String {
        var result = [
            header2("INDEX"),
        ]
        let items = testCases.map { link($0.name, localLink(for: $0.title)) }
        result.append(numberedList(items))
        result.append(divider())
        return result.joined(separator: "\n")
    }

    // John Smith's identifier
    static let johnSmithIdentifier = CID(‡"78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc")!

    // A photo of John Smith
    static let johnSmithImage = Envelope(Digest("John Smith smiling"))
        .addAssertion(.note, "This is an image of John Smith.")
        .addAssertion(.dereferenceVia, "https://exampleledger.com/digest/36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999")

    static let johnSmithResidentCard = try! Envelope(CID(‡"174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8")!)
        .addAssertion(.isA, "credential")
        .addAssertion("dateIssued", Date(iso8601: "2022-04-27"))
        .addAssertion(.issuer, Envelope(stateIdentifier)
            .addAssertion(.note, "Issued by the State of Example")
            .addAssertion(.dereferenceVia, URL(string: "https://exampleledger.com/cid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8")!)
        )
        .addAssertion(.holder, Envelope(johnSmithIdentifier)
            .addAssertion(.isA, "Person")
            .addAssertion(.isA, "Permanent Resident")
            .addAssertion("givenName", "JOHN")
            .addAssertion("familyName", "SMITH")
            .addAssertion("sex", "MALE")
            .addAssertion("birthDate", Date(iso8601: "1974-02-18"))
            .addAssertion("image", johnSmithImage)
            .addAssertion("lprCategory", "C09")
            .addAssertion("lprNumber", "999-999-999")
            .addAssertion("birthCountry", Envelope("bs").addAssertion(.note, "The Bahamas"))
            .addAssertion("residentSince", Date(iso8601: "2018-01-07"))
        )
        .addAssertion(.note, "The State of Example recognizes JOHN SMITH as a Permanent Resident.")
        .wrap()
        .sign(with: statePrivateKeys, note: "Made by the State of Example.", randomGenerator: generateFakeRandomNumbers)

    static let johnSmithRedactedCredential: Envelope = try! {
        var target: Set<Digest> = []

        // Reveal the card. Without this, everything about the card would be elided.
        let top = johnSmithResidentCard
        target.insert(top)

        // Reveal everything about the state's signature on the card
        try target.insert(top.assertion(withPredicate: .verifiedBy).deepDigests)

        // Reveal the top level of the card.
        target.insert(top.shallowDigests)

        let card = try top.unwrap()
        target.insert(card)
        target.insert(card.subject)

        // Reveal everything about the `isA` and `issuer` assertions at the top level of the card.
        try target.insert(card.assertion(withPredicate: .isA).deepDigests)
        try target.insert(card.assertion(withPredicate: .issuer).deepDigests)

        // Reveal the `holder` assertion on the card, but not any of its sub-assertions.
        let holder = try card.assertion(withPredicate: .holder)
        target.insert(holder.shallowDigests)

        // Within the `holder` assertion, reveal everything about just the `givenName`, `familyName`, and `image` assertions.
        let holderObject = holder.object!
        try target.insert(holderObject.assertion(withPredicate: "givenName").deepDigests)
        try target.insert(holderObject.assertion(withPredicate: "familyName").deepDigests)
        try target.insert(holderObject.assertion(withPredicate: "image").deepDigests)

        // Perform the elision
        let elidedCredential = try top.elideRevealing(target).checkEncoding()

        // Verify that the elided credential compares equal to the original credential.
        XCTAssertEqual(elidedCredential, johnSmithResidentCard)

        // Verify that the state's signature on the elided card is still valid.
        return try! elidedCredential.verifySignature(from: statePublicKeys)
    }()
}
