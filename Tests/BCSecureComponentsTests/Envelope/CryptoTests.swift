import XCTest
import BCSecureComponents
import WolfBase

class CryptoTests: XCTestCase {
    override func setUp() {
        addKnownTags()
    }
    
    func testPlaintext() throws {
        // Alice sends a plaintext message to Bob.
        let envelope = try Envelope(plaintextHello).checkEncoding()
        let ur = envelope.ur

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
//        print(ur)

        let expectedFormat =
        """
        "Hello."
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        // Alice ➡️ ☁️ ➡️ Bob

        // Bob receives the envelope and reads the message.
        let receivedPlaintext = try Envelope(ur: ur)
            .checkEncoding()
            .extractSubject(String.self)
        XCTAssertEqual(receivedPlaintext, plaintextHello)
    }

    func testSignedPlaintext() throws {
        // Alice sends a signed plaintext message to Bob.
        let envelope = try Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)
            .checkEncoding()
        let ur = envelope.ur

//        print(envelope.diagAnnotated)
//        print(envelope.dump)
//        print(envelope.ur)

        let expectedFormat =
        """
        "Hello." [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        // Alice ➡️ ☁️ ➡️ Bob

        // Bob receives the envelope.
        let receivedEnvelope = try Envelope(ur: ur).checkEncoding()

        // Bob receives the message, validates Alice's signature, and reads the message.
        let receivedPlaintext = try receivedEnvelope.validateSignature(from: alicePublicKeys)
            .extractSubject(String.self)
        XCTAssertEqual(receivedPlaintext, plaintextHello)

        // Confirm that it wasn't signed by Carol.
        XCTAssertThrowsError(try receivedEnvelope.validateSignature(from: carolPublicKeys))

        // Confirm that it was signed by Alice OR Carol.
        try receivedEnvelope.validateSignatures(from: [alicePublicKeys, carolPublicKeys], threshold: 1)

        // Confirm that it was not signed by Alice AND Carol.
        XCTAssertThrowsError(try receivedEnvelope.validateSignatures(from: [alicePublicKeys, carolPublicKeys], threshold: 2))
    }

    func testMultisignedPlaintext() throws {
        // Alice and Carol jointly send a signed plaintext message to Bob.
        let envelope = try Envelope(plaintextHello)
            .sign(with: [alicePrivateKeys, carolPrivateKeys])
            .checkEncoding()
        let ur = envelope.ur

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
//        print(envelope.ur)

        let expectedFormat =
        """
        "Hello." [
            verifiedBy: Signature
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        // Alice & Carol ➡️ ☁️ ➡️ Bob

        // Bob receives the envelope and verifies the message was signed by both Alice and Carol.
        let receivedPlaintext = try Envelope(ur: ur)
            .checkEncoding()
            .validateSignatures(from: [alicePublicKeys, carolPublicKeys])
            .extractSubject(String.self)

        // Bob reads the message.
        XCTAssertEqual(receivedPlaintext, plaintextHello)
    }

    func testSymmetricEncryption() throws {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice sends a message encrypted with the key to Bob.
        let envelope = try Envelope(plaintextHello).checkEncoding()
            .encryptSubject(with: key).checkEncoding()
        let ur = envelope.ur

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
//        print(envelope.ur)

        let expectedFormat =
        """
        EncryptedMessage
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        // Alice ➡️ ☁️ ➡️ Bob

        // Bob receives the envelope.
        let receivedEnvelope = try Envelope(ur: ur).checkEncoding()

        // Bob decrypts and reads the message.
        let receivedPlaintext = try receivedEnvelope
            .decryptSubject(with: key)
            .extractSubject(String.self)
        XCTAssertEqual(receivedPlaintext, plaintextHello)

        // Can't read with no key.
        try XCTAssertThrowsError(receivedEnvelope.extractSubject(String.self))

        // Can't read with incorrect key.
        try XCTAssertThrowsError(receivedEnvelope.decryptSubject(with: SymmetricKey()))
    }

    func testEncryptDecrypt() throws {
        let key = SymmetricKey()
        let plaintextEnvelope = try Envelope(plaintextHello).checkEncoding()
//        print(plaintextEnvelope.format)
        let encryptedEnvelope = try plaintextEnvelope.encryptSubject(with: key).checkEncoding()
//        print(encryptedEnvelope.format)
        XCTAssertEqual(plaintextEnvelope, encryptedEnvelope)
        let plaintextEnvelope2 = try encryptedEnvelope.decryptSubject(with: key).checkEncoding()
//        print(plaintextEnvelope2.format)
        XCTAssertEqual(encryptedEnvelope, plaintextEnvelope2)
    }

    func testSignThenEncrypt() throws {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice signs a plaintext message, then encrypts it.
        let envelope = try Envelope(plaintextHello)
            .sign(with: alicePrivateKeys).checkEncoding()
            .wrap().checkEncoding()
            .encryptSubject(with: key).checkEncoding()
        let ur = envelope.ur

        let expectedFormat =
        """
        EncryptedMessage
        """
        XCTAssertEqual(envelope.format, expectedFormat)

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
//        print(envelope.ur)

        // Alice ➡️ ☁️ ➡️ Bob

        // Bob receives the envelope, decrypts it using the shared key, and then validates Alice's signature.
        let receivedPlaintext = try Envelope(ur: ur).checkEncoding()
            .decryptSubject(with: key).checkEncoding()
            .unwrap().checkEncoding()
            .validateSignature(from: alicePublicKeys)
            .extractSubject(String.self)
        // Bob reads the message.
        XCTAssertEqual(receivedPlaintext, plaintextHello)
    }

    func testEncryptThenSign() throws {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice encryptes a plaintext message, then signs it.
        //
        // It doesn't actually matter whether the `encrypt` or `sign` method comes first,
        // as the `encrypt` method transforms the `subject` into its `.encrypted` form,
        // which carries a `Digest` of the plaintext `subject`, while the `sign` method
        // only adds an `Assertion` with the signature of the hash as the `object` of the
        // `Assertion`.
        //
        // Similarly, the `decrypt` method used below can come before or after the
        // `validateSignature` method, as `validateSignature` checks the signature against
        // the `subject`'s hash, which is explicitly present when the subject is in
        // `.encrypted` form and can be calculated when the subject is in `.plaintext`
        // form. The `decrypt` method transforms the subject from its `.encrypted` case to
        // its `.plaintext` case, and also checks that the decrypted plaintext has the same
        // hash as the one associated with the `.encrypted` subject.
        //
        // The end result is the same: the `subject` is encrypted and the signature can be
        // checked before or after decryption.
        //
        // The main difference between this order of operations and the sign-then-encrypt
        // order of operations is that with sign-then-encrypt, the decryption *must*
        // be performed first before the presence of signatures can be known or checked.
        // With this order of operations, the presence of signatures is known before
        // decryption, and may be checked before or after decryption.
        let envelope = try Envelope(plaintextHello)
            .encryptSubject(with: key).checkEncoding()
            .sign(with: alicePrivateKeys).checkEncoding()
        let ur = envelope.ur

        let expectedFormat =
        """
        EncryptedMessage [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
//        print(envelope.ur)

        // Alice ➡️ ☁️ ➡️ Bob

        // Bob receives the envelope, validates Alice's signature, then decrypts the message.
        let receivedPlaintext = try Envelope(ur: ur).checkEncoding()
            .validateSignature(from: alicePublicKeys)
            .decryptSubject(with: key).checkEncoding()
            .extractSubject(String.self)
        // Bob reads the message.
        XCTAssertEqual(receivedPlaintext, plaintextHello)
    }

    func testMultiRecipient() throws {
        // Alice encrypts a message so that it can only be decrypted by Bob or Carol.
        let contentKey = SymmetricKey()
        let envelope = try Envelope(plaintextHello)
            .encryptSubject(with: contentKey).checkEncoding()
            .addRecipient(bobPublicKeys, contentKey: contentKey).checkEncoding()
            .addRecipient(carolPublicKeys, contentKey: contentKey).checkEncoding()
        let ur = envelope.ur

        let expectedFormat =
        """
        EncryptedMessage [
            hasRecipient: SealedMessage
            hasRecipient: SealedMessage
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
//        print(envelope.ur)

        // Alice ➡️ ☁️ ➡️ Bob
        // Alice ➡️ ☁️ ➡️ Carol

        // The envelope is received
        let receivedEnvelope = try Envelope(ur: ur)

        // Bob decrypts and reads the message
        let bobReceivedPlaintext = try receivedEnvelope
            .decrypt(to: bobPrivateKeys).checkEncoding()
            .extractSubject(String.self)
        XCTAssertEqual(bobReceivedPlaintext, plaintextHello)

        // Alice decrypts and reads the message
        let carolReceivedPlaintext = try receivedEnvelope
            .decrypt(to: carolPrivateKeys).checkEncoding()
            .extractSubject(String.self)
        XCTAssertEqual(carolReceivedPlaintext, plaintextHello)

        // Alice didn't encrypt it to herself, so she can't read it.
        XCTAssertThrowsError(try receivedEnvelope.decrypt(to: alicePrivateKeys))
    }

    func testVisibleSignatureMultiRecipient() throws {
        // Alice signs a message, and then encrypts it so that it can only be decrypted by Bob or Carol.
        let contentKey = SymmetricKey()
        let envelope = try Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)
            .encryptSubject(with: contentKey)
            .addRecipient(bobPublicKeys, contentKey: contentKey)
            .addRecipient(carolPublicKeys, contentKey: contentKey)
        let ur = envelope.ur

        let expectedFormat =
        """
        EncryptedMessage [
            hasRecipient: SealedMessage
            hasRecipient: SealedMessage
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
//        print(envelope.ur)

        // Alice ➡️ ☁️ ➡️ Bob
        // Alice ➡️ ☁️ ➡️ Carol

        // The envelope is received
        let receivedEnvelope = try Envelope(ur: ur)

        // Bob validates Alice's signature, then decrypts and reads the message
        let bobReceivedPlaintext = try receivedEnvelope
            .validateSignature(from: alicePublicKeys)
            .decrypt(to: bobPrivateKeys)
            .extractSubject(String.self)
        XCTAssertEqual(bobReceivedPlaintext, plaintextHello)

        // Carol validates Alice's signature, then decrypts and reads the message
        let carolReceivedPlaintext = try receivedEnvelope
            .validateSignature(from: alicePublicKeys)
            .decrypt(to: carolPrivateKeys)
            .extractSubject(String.self)
        XCTAssertEqual(carolReceivedPlaintext, plaintextHello)

        // Alice didn't encrypt it to herself, so she can't read it.
        XCTAssertThrowsError(try receivedEnvelope.decrypt(to: alicePrivateKeys))
    }

    func testHiddenSignatureMultiRecipient() throws {
        // Alice signs a message, and then encloses it in another envelope before
        // encrypting it so that it can only be decrypted by Bob or Carol. This hides
        // Alice's signature, and requires recipients to decrypt the subject before they
        // are able to validate the signature.
        let contentKey = SymmetricKey()
        let envelope = try Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)
            .wrap()
            .encryptSubject(with: contentKey)
            .addRecipient(bobPublicKeys, contentKey: contentKey)
            .addRecipient(carolPublicKeys, contentKey: contentKey).checkEncoding()
        let ur = envelope.ur

        let expectedFormat =
        """
        EncryptedMessage [
            hasRecipient: SealedMessage
            hasRecipient: SealedMessage
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
//        print(envelope.ur)

        // Alice ➡️ ☁️ ➡️ Bob
        // Alice ➡️ ☁️ ➡️ Carol

        // The envelope is received
        let receivedEnvelope = try Envelope(ur: ur)

        // Bob decrypts the envelope, then extracts the inner envelope and validates
        // Alice's signature, then reads the message
        let bobReceivedPlaintext = try receivedEnvelope
            .decrypt(to: bobPrivateKeys)
            .unwrap().checkEncoding()
            .validateSignature(from: alicePublicKeys)
            .extractSubject(String.self)
        XCTAssertEqual(bobReceivedPlaintext, plaintextHello)

        // Carol decrypts the envelope, then extracts the inner envelope and validates
        // Alice's signature, then reads the message
        let carolReceivedPlaintext = try receivedEnvelope
            .decrypt(to: carolPrivateKeys)
            .unwrap().checkEncoding()
            .validateSignature(from: alicePublicKeys)
            .extractSubject(String.self)
        XCTAssertEqual(carolReceivedPlaintext, plaintextHello)

        // Alice didn't encrypt it to herself, so she can't read it.
        XCTAssertThrowsError(try receivedEnvelope.decrypt(to: alicePrivateKeys))
    }

    func testSSKR() throws {
        // Dan has a cryptographic seed he wants to backup using a social recovery scheme.
        // The seed includes metadata he wants to back up also, making it too large to fit
        // into a basic SSKR share.
        var danSeed = Seed(data: ‡"59f2293a5bce7d4de59e71b4207ac5d2")!
        danSeed.name = "Dark Purple Aqua Love"
        danSeed.creationDate = try! Date(iso8601: "2021-02-24")
        danSeed.note = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

        // Dan encrypts the seed and then splits the content key into a single group
        // 2-of-3. This returns an array of arrays of Envelope, the outer arrays
        // representing SSKR groups and the inner array elements each holding the encrypted
        // seed and a single share.
        let contentKey = SymmetricKey()
        let seedEnvelope = Envelope(danSeed)
        let encryptedSeedEnvelope = try seedEnvelope
            .encryptSubject(with: contentKey)
        
        let envelopes = encryptedSeedEnvelope
            .split(groupThreshold: 1, groups: [(2, 3)], contentKey: contentKey)

        // Flattening the array of arrays gives just a single array of all the envelopes
        // to be distributed.
        let sentEnvelopes = envelopes.flatMap { $0 }
        let sentURs = sentEnvelopes.map { $0.ur }

        let expectedFormat =
        """
        EncryptedMessage [
            sskrShare: SSKRShare
        ]
        """
        XCTAssertEqual(sentEnvelopes[0].format, expectedFormat)

        // Dan sends one envelope to each of Alice, Bob, and Carol.

//        print(sentEnvelopes[0].format)
//        print(sentEnvelopes[0].taggedCBOR.diag)
//        print(sentEnvelopes[0].taggedCBOR.dump)
//        print(sentEnvelopes[0].ur)

        // Dan ➡️ ☁️ ➡️ Alice
        // Dan ➡️ ☁️ ➡️ Bob
        // Dan ➡️ ☁️ ➡️ Carol

        // let aliceEnvelope = try Envelope(ur: sentURs[0]) // UNRECOVERED
        let bobEnvelope = try Envelope(ur: sentURs[1])
        let carolEnvelope = try Envelope(ur: sentURs[2])

        // At some future point, Dan retrieves two of the three envelopes so he can recover his seed.
        let recoveredEnvelopes = [bobEnvelope, carolEnvelope]
        let a = try Envelope(shares: recoveredEnvelopes)
        let recoveredSeed = try a
            .extractSubject(Seed.self)

        // The recovered seed is correct.
        XCTAssertEqual(danSeed.data, recoveredSeed.data)
        XCTAssertEqual(danSeed.creationDate, recoveredSeed.creationDate)
        XCTAssertEqual(danSeed.name, recoveredSeed.name)
        XCTAssertEqual(danSeed.note, recoveredSeed.note)

        // Attempting to recover with only one of the envelopes won't work.
        XCTAssertThrowsError(try Envelope(shares: [bobEnvelope]))
    }
}
