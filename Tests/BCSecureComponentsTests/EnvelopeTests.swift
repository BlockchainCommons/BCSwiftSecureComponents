import XCTest
import BCSecureComponents
import WolfBase

class EnvelopeTests: XCTestCase {
    func testPredicate() {
        let envelope = Envelope(predicate: .verifiedBy)
        XCTAssertEqual(envelope.format, "verifiedBy")
    }
    
    func testDate() throws {
        let envelope = try Envelope(Date(iso8601: "2018-01-07"))
        XCTAssertEqual(envelope.format, "2018-01-07")
    }

    func testNestingPlaintext() {
        let envelope = Envelope(plaintextHello)

        let expectedFormat =
        """
        "Hello."
        """
        XCTAssertEqual(envelope.format, expectedFormat)
        
        let redactedEnvelope = envelope.redact()
        XCTAssertEqual(redactedEnvelope, envelope)

        let expectedRedactedFormat =
        """
        REDACTED
        """
        XCTAssertEqual(redactedEnvelope.format, expectedRedactedFormat)
    }
    
    func testNestingOnce() {
        let envelope = Envelope(plaintextHello)
            .enclose()

        let expectedFormat =
        """
        {
            "Hello."
        }
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        let redactedEnvelope = Envelope(plaintextHello)
            .redact()
            .enclose()

        XCTAssertEqual(redactedEnvelope, envelope)

        let expectedRedactedFormat =
        """
        {
            REDACTED
        }
        """
        XCTAssertEqual(redactedEnvelope.format, expectedRedactedFormat)
    }
    
    func testNestingTwice() throws {
        let envelope = Envelope(plaintextHello)
            .enclose()
            .enclose()

        let expectedFormat =
        """
        {
            {
                "Hello."
            }
        }
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        let redaction = try envelope
            .extract()
            .extract()
            .digest
        let redactedEnvelope = envelope.redact(items: [redaction])
        
        let expectedRedactedFormat =
        """
        {
            REDACTED
        }
        """
        XCTAssertEqual(redactedEnvelope.format, expectedRedactedFormat)
        XCTAssertEqual(envelope.digest, redactedEnvelope.digest)
        try XCTAssertEqual(envelope.extract().digest, redactedEnvelope.extract().digest)
    }
    
    func testNestingSigned() throws {
        let envelope = Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)

        let expectedFormat =
        """
        "Hello." [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        let redaction = envelope
            .subject
            .digest
        let redactedEnvelope = envelope.redact(items: Set([redaction]))
        try redactedEnvelope.validateSignature(from: alicePublicKeys)
        let expectedRedactedFormat =
        """
        REDACTED [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(redactedEnvelope.format, expectedRedactedFormat)
    }
    
    func testNestingEncloseThenSign() throws {
        let envelope = Envelope(plaintextHello)
            .enclose()
            .sign(with: alicePrivateKeys)

        let expectedFormat =
        """
        {
            "Hello."
        } [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)

        let redaction = try envelope
            .extract()
            .subject
            .digest
        let redactedEnvelope = envelope.redact(items: Set([redaction]))
        XCTAssertEqual(redactedEnvelope, envelope)
        try redactedEnvelope.validateSignature(from: alicePublicKeys)
        let expectedRedactedFormat =
        """
        {
            REDACTED
        } [
            verifiedBy: Signature
        ]
        """
        XCTAssertEqual(redactedEnvelope.format, expectedRedactedFormat)
        
        let p1 = envelope
        let p2 = try p1.extract()
        let p3 = p2.subject
        let revealSet: Set<Digest> = [p1.digest, p2.digest, p3.digest]
        let revealedEnvelope = envelope.redact(revealing: revealSet)
        XCTAssertEqual(revealedEnvelope, envelope)
        let expectedRevealedFormat =
        """
        {
            "Hello."
        } [
            REDACTED
        ]
        """
        XCTAssertEqual(revealedEnvelope.format, expectedRevealedFormat)
    }
    
    func testNestingSignThenEnclose() {
        let envelope = Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)
            .enclose()

        let expectedFormat =
        """
        {
            "Hello." [
                verifiedBy: Signature
            ]
        }
        """
        XCTAssertEqual(envelope.format, expectedFormat)
    }

    func testAssertionsOnAllPartsOfEnvelope() throws {
        let predicate = Envelope("predicate")
            .add("predicate-predicate", "predicate-object")
        let object = Envelope("object")
            .add("object-predicate", "object-object")
        let envelope = Envelope("subject")
            .add(predicate, object)

        let expectedFormat =
        """
        "subject" [
            "predicate" [
                "predicate-predicate": "predicate-object"
            ]
            : "object" [
                "object-predicate": "object-object"
            ]
        ]
        """
        XCTAssertEqual(envelope.format, expectedFormat)
    }

    func testPlaintext() throws {
        // Alice sends a plaintext message to Bob.
        let envelope = Envelope(plaintextHello)
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
            .extract(String.self)
        XCTAssertEqual(receivedPlaintext, plaintextHello)
    }

    func testSignedPlaintext() throws {
        // Alice sends a signed plaintext message to Bob.
        let envelope = Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)
        let ur = envelope.ur

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
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
        let receivedEnvelope = try Envelope(ur: ur)
        
        // Bob receives the message, validates Alice's signature, and reads the message.
        let receivedPlaintext = try receivedEnvelope.validateSignature(from: alicePublicKeys)
            .extract(String.self)
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
        let envelope = Envelope(plaintextHello)
            .sign(with: [alicePrivateKeys, carolPrivateKeys])
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
            .validateSignatures(from: [alicePublicKeys, carolPublicKeys])
            .extract(String.self)

        // Bob reads the message.
        XCTAssertEqual(receivedPlaintext, plaintextHello)
    }
    
    func testSymmetricEncryption() throws {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice sends a message encrypted with the key to Bob.
        let envelope = try Envelope(plaintextHello)
            .encrypt(with: key)
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
        let receivedEnvelope = try Envelope(ur: ur)
        
        // Bob decrypts and reads the message.
        let receivedPlaintext = try receivedEnvelope
            .decrypt(with: key)
            .extract(String.self)
        XCTAssertEqual(receivedPlaintext, plaintextHello)

        // Can't read with no key.
        try XCTAssertThrowsError(receivedEnvelope.extract(String.self))
        
        // Can't read with incorrect key.
        try XCTAssertThrowsError(receivedEnvelope.decrypt(with: SymmetricKey()))
    }
    
    func testEncryptDecrypt() throws {
        let key = SymmetricKey()
        let plaintextEnvelope = Envelope(plaintextHello)
//        print(plaintextEnvelope.format)
        let encryptedEnvelope = try plaintextEnvelope.encrypt(with: key)
//        print(encryptedEnvelope.format)
        XCTAssertEqual(plaintextEnvelope, encryptedEnvelope)
        let plaintextEnvelope2 = try encryptedEnvelope.decrypt(with: key)
//        print(plaintextEnvelope2.format)
        XCTAssertEqual(encryptedEnvelope, plaintextEnvelope2)
    }
    
    func testSignThenEncrypt() throws {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice signs a plaintext message, then encrypts it.
        let envelope = try Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)
            .enclose()
            .encrypt(with: key)
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
        let receivedPlaintext = try Envelope(ur: ur)
            .decrypt(with: key)
            .extract()
            .validateSignature(from: alicePublicKeys)
            .extract(String.self)
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
            .encrypt(with: key)
            .sign(with: alicePrivateKeys)
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
        let receivedPlaintext = try Envelope(ur: ur)
            .validateSignature(from: alicePublicKeys)
            .decrypt(with: key)
            .extract(String.self)
        // Bob reads the message.
        XCTAssertEqual(receivedPlaintext, plaintextHello)
    }
    
    func testMultiRecipient() throws {
        // Alice encrypts a message so that it can only be decrypted by Bob or Carol.
        let contentKey = SymmetricKey()
        let envelope = try Envelope(plaintextHello)
            .encrypt(with: contentKey)
            .addRecipient(bobPublicKeys, contentKey: contentKey)
            .addRecipient(carolPublicKeys, contentKey: contentKey)
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
            .decrypt(to: bobPrivateKeys)
            .extract(String.self)
        XCTAssertEqual(bobReceivedPlaintext, plaintextHello)

        // Alice decrypts and reads the message
        let carolReceivedPlaintext = try receivedEnvelope
            .decrypt(to: carolPrivateKeys)
            .extract(String.self)
        XCTAssertEqual(carolReceivedPlaintext, plaintextHello)
        
        // Alice didn't encrypt it to herself, so she can't read it.
        XCTAssertThrowsError(try receivedEnvelope.decrypt(to: alicePrivateKeys))
    }
    
    func testVisibleSignatureMultiRecipient() throws {
        // Alice signs a message, and then encrypts it so that it can only be decrypted by Bob or Carol.
        let contentKey = SymmetricKey()
        let envelope = try Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)
            .encrypt(with: contentKey)
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
            .extract(String.self)
        XCTAssertEqual(bobReceivedPlaintext, plaintextHello)

        // Carol validates Alice's signature, then decrypts and reads the message
        let carolReceivedPlaintext = try receivedEnvelope
            .validateSignature(from: alicePublicKeys)
            .decrypt(to: carolPrivateKeys)
            .extract(String.self)
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
            .enclose()
            .encrypt(with: contentKey)
            .addRecipient(bobPublicKeys, contentKey: contentKey)
            .addRecipient(carolPublicKeys, contentKey: contentKey)
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
            .extract()
            .validateSignature(from: alicePublicKeys)
            .extract(String.self)
        XCTAssertEqual(bobReceivedPlaintext, plaintextHello)

        // Carol decrypts the envelope, then extracts the inner envelope and validates
        // Alice's signature, then reads the message
        let carolReceivedPlaintext = try receivedEnvelope
            .decrypt(to: carolPrivateKeys)
            .extract()
            .validateSignature(from: alicePublicKeys)
            .extract(String.self)
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
        let envelopes = try Envelope(danSeed)
            .encrypt(with: contentKey)
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

        print(sentEnvelopes[0].format)
        print(sentEnvelopes[0].taggedCBOR.diag)
        print(sentEnvelopes[0].taggedCBOR.dump)
        print(sentEnvelopes[0].ur)

        // Dan ➡️ ☁️ ➡️ Alice
        // Dan ➡️ ☁️ ➡️ Bob
        // Dan ➡️ ☁️ ➡️ Carol

        // let aliceEnvelope = try Envelope(ur: sentURs[0]) // UNRECOVERED
        let bobEnvelope = try Envelope(ur: sentURs[1])
        let carolEnvelope = try Envelope(ur: sentURs[2])

        // At some future point, Dan retrieves two of the three envelopes so he can recover his seed.
        let recoveredEnvelopes = [bobEnvelope, carolEnvelope]
        let recoveredSeed = try Envelope(shares: recoveredEnvelopes)
            .extract(Seed.self)

        // The recovered seed is correct.
        XCTAssertEqual(danSeed.data, recoveredSeed.data)
        XCTAssertEqual(danSeed.creationDate, recoveredSeed.creationDate)
        XCTAssertEqual(danSeed.name, recoveredSeed.name)
        XCTAssertEqual(danSeed.note, recoveredSeed.note)

        // Attempting to recover with only one of the envelopes won't work.
        XCTAssertThrowsError(try Envelope(shares: [bobEnvelope]))
    }

    func testComplexMetadata() throws {
        // Assertions made about an SCID are considered part of a distributed set. Which
        // assertions are returned depends on who resolves the SCID and when it is
        // resolved. In other words, the referent of an SCID is mutable.
        let author = Envelope(SCID(‡"9c747ace78a4c826392510dd6285551e7df4e5164729a1b36198e56e017666c8")!)
            .add(.dereferenceVia, "LibraryOfCongress")
            .add(.hasName, "Ayn Rand")
        
        // Assertions made on a literal value are considered part of the same set of
        // assertions made on the digest of that value.
        let name_en = Envelope("Atlas Shrugged")
            .add(.language, "en")

        let name_es = Envelope("La rebelión de Atlas")
            .add(.language, "es")
        
        let work = Envelope(SCID(‡"7fb90a9d96c07f39f75ea6acf392d79f241fac4ec0be2120f7c82489711e3e80")!)
            .add(.isA, "novel")
            .add("isbn", "9780451191144")
            .add("author", author)
            .add(.dereferenceVia, "LibraryOfCongress")
            .add(.hasName, name_en)
            .add(.hasName, name_es)

        let bookData = "This is the entire book “Atlas Shrugged” in EPUB format."
        // Assertions made on a digest are considered associated with that specific binary
        // object and no other. In other words, the referent of a Digest is immutable.
        let bookMetadata = Envelope(Digest(bookData))
            .add("work", work)
            .add("format", "EPUB")
            .add(.dereferenceVia, "IPFS")
        
        let expectedFormat =
        """
        Digest(e8aa201db4044168d05b77d7b36648fb7a97db2d3e72f5babba9817911a52809) [
            "format": "EPUB"
            "work": SCID(7fb90a9d96c07f39f75ea6acf392d79f241fac4ec0be2120f7c82489711e3e80) [
                "author": SCID(9c747ace78a4c826392510dd6285551e7df4e5164729a1b36198e56e017666c8) [
                    dereferenceVia: "LibraryOfCongress"
                    hasName: "Ayn Rand"
                ]
                "isbn": "9780451191144"
                dereferenceVia: "LibraryOfCongress"
                hasName: "Atlas Shrugged" [
                    language: "en"
                ]
                hasName: "La rebelión de Atlas" [
                    language: "es"
                ]
                isA: "novel"
            ]
            dereferenceVia: "IPFS"
        ]
        """
        XCTAssertEqual(bookMetadata.format, expectedFormat)
    }
    
    func testIdentifier() throws {
        // An analogue of a DID document, which identifies a self-sovereign entity. The
        // document itself can be referred to by its SCID, while the signed document
        // can be referred to by its digest.
        
        let aliceUnsignedDocument = Envelope(aliceIdentifier)
            .add(.controller, aliceIdentifier)
            .add(.publicKeys, alicePublicKeys)
        
        let aliceSignedDocument = aliceUnsignedDocument
            .enclose()
            .sign(with: alicePrivateKeys, note: "Made by Alice.")
        
        let expectedFormat =
        """
        {
            SCID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f) [
                controller: SCID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
                publicKeys: PublicKeyBase
            ]
        } [
            verifiedBy: Signature [
                note: "Made by Alice."
            ]
        ]
        """
        XCTAssertEqual(aliceSignedDocument.format, expectedFormat)
        
        // Signatures have a random component, so anything with a signature will have a
        // non-deterministic digest. Therefore, the two results of signing the same object
        // twice with the same private key will not compare as equal. This means that each
        // signing is a particular event that can never be repeated.

        let aliceSignedDocument2 = aliceUnsignedDocument
            .enclose()
            .sign(with: alicePrivateKeys, note: "Made by Alice.")

        XCTAssertNotEqual(aliceSignedDocument, aliceSignedDocument2)
        
        // ➡️ ☁️ ➡️

        // A registrar checks the signature on Alice's submitted identifier document,
        // performs any other necessary validity checks, and then extracts her SCID from
        // it.
        let aliceSCID = try aliceSignedDocument.validateSignature(from: alicePublicKeys)
            .extract()
            // other validity checks here
            .extract(SCID.self)
        
        // The registrar creates its own registration document using Alice's SCID as the
        // subject, incorporating Alice's signed document, and adding its own signature.
        let aliceURL = URL(string: "https://exampleledger.com/scid/\(aliceSCID.data.hex)")!
        let aliceRegistration = Envelope(aliceSCID)
            .add(.entity, aliceSignedDocument)
            .add(.dereferenceVia, aliceURL)
            .enclose()
            .sign(with: exampleLedgerPrivateKeys, note: "Made by ExampleLedger.")
        
        let expectedRegistrationFormat =
        """
        {
            SCID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f) [
                dereferenceVia: URI(https://exampleledger.com/scid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
                entity: {
                    SCID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f) [
                        controller: SCID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
                        publicKeys: PublicKeyBase
                    ]
                } [
                    verifiedBy: Signature [
                        note: "Made by Alice."
                    ]
                ]
            ]
        } [
            verifiedBy: Signature [
                note: "Made by ExampleLedger."
            ]
        ]
        """
        XCTAssertEqual(aliceRegistration.format, expectedRegistrationFormat)
        
        // Alice receives the registration document back, validates its signature, and
        // extracts the URI that now points to her record.
        let aliceURI = try aliceRegistration
            .validateSignature(from: exampleLedgerPublicKeys)
            .extract()
            .extract(predicate: .dereferenceVia, URL.self)
        XCTAssertEqual(aliceURI†, "https://exampleledger.com/scid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f")
        
        // Alice wants to introduce herself to Bob, so Bob needs to know she controls her
        // identifier. Bob sends a challenge:
        let aliceChallenge = Envelope(Nonce())
            .add(.note, "Challenge to Alice from Bob.")
        
        let aliceChallengeExpectedFormat =
        """
        Nonce [
            note: "Challenge to Alice from Bob."
        ]
        """
        XCTAssertEqual(aliceChallenge.format, aliceChallengeExpectedFormat)

        // Alice responds by adding her registered URI to the nonce, and signing it.
        let aliceChallengeResponse = aliceChallenge
            .enclose()
            .add(.dereferenceVia, aliceURI)
            .enclose()
            .sign(with: alicePrivateKeys, note: "Made by Alice.")
        
        let aliceChallengeResponseExpectedFormat =
        """
        {
            {
                Nonce [
                    note: "Challenge to Alice from Bob."
                ]
            } [
                dereferenceVia: URI(https://exampleledger.com/scid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
            ]
        } [
            verifiedBy: Signature [
                note: "Made by Alice."
            ]
        ]
        """
        XCTAssertEqual(aliceChallengeResponse.format, aliceChallengeResponseExpectedFormat)

        // Bob receives Alice's response, and first checks that the nonce is the once he sent.
        let responseNonce = try aliceChallengeResponse
            .extract()
            .extract()
        XCTAssertEqual(aliceChallenge, responseNonce)
        
        // Bob then extracts Alice's registered URI
        let responseURI = try aliceChallengeResponse
            .extract()
            .extract(predicate: .dereferenceVia, URL.self)
        XCTAssertEqual(responseURI.absoluteString, "https://exampleledger.com/scid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f")
        
        // Bob uses the URI to ask ExampleLedger for Alice's identifier document, then
        // checks ExampleLedgers's signature. Bob trusts ExampleLedger's validation of
        // Alice's original document, so doesn't bother to check it for internal
        // consistency, and instead goes ahead and extracts Alice's public keys from it.
        let aliceDocumentPublicKeys = try aliceRegistration
            .validateSignature(from: exampleLedgerPublicKeys)
            .extract()
            .extract(predicate: .entity)
            .extract()
            .extract(predicate: .publicKeys, PublicKeyBase.self)
        
        // Finally, Bob uses Alice's public keys to validate the challenge he sent her.
        try aliceChallengeResponse.validateSignature(from: aliceDocumentPublicKeys)
    }
    
    func testCredential() throws {
        // John Smith's identifier
        let johnSmithIdentifier = SCID(‡"78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc")!

        // A photo of John Smith
        let johnSmithImage = Envelope(Digest("John Smith smiling"))
            .add(.note, "This is an image of John Smith.")
            .add(.dereferenceVia, "https://exampleledger.com/digest/36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999")
        
        // John Smith's Permanent Resident Card issued by the State of Example
        let johnSmithResidentCard = try Envelope(SCID(‡"174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8")!)
            .add(.isA, "credential")
            .add("dateIssued", Date(iso8601: "2022-04-27"))
            .add(.issuer, Envelope(stateIdentifier)
                .add(.note, "Issued by the State of Example")
                .add(.dereferenceVia, URL(string: "https://exampleledger.com/scid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8")!)
            )
            .add(.holder, Envelope(johnSmithIdentifier)
                .add(.isA, "Person")
                .add(.isA, "Permanent Resident")
                .add("givenName", "JOHN")
                .add("familyName", "SMITH")
                .add("sex", "MALE")
                .add("birthDate", Date(iso8601: "1974-02-18"))
                .add("image", johnSmithImage)
                .add("lprCategory", "C09")
                .add("lprNumber", "999-999-999")
                .add("birthCountry", Envelope("bs").add(.note, "The Bahamas"))
                .add("residentSince", Date(iso8601: "2018-01-07"))
            )
            .add(.note, "The State of Example recognizes JOHN SMITH as a Permanent Resident.")
            .enclose()
            .sign(with: statePrivateKeys, note: "Made by the State of Example.")

        // Validate the state's signature
        try johnSmithResidentCard.validateSignature(from: statePublicKeys)
        
        let expectedFormat =
        """
        {
            SCID(174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8) [
                "dateIssued": 2022-04-27
                holder: SCID(78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc) [
                    "birthCountry": "bs" [
                        note: "The Bahamas"
                    ]
                    "birthDate": 1974-02-18
                    "familyName": "SMITH"
                    "givenName": "JOHN"
                    "image": Digest(36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999) [
                        dereferenceVia: "https://exampleledger.com/digest/36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999"
                        note: "This is an image of John Smith."
                    ]
                    "lprCategory": "C09"
                    "lprNumber": "999-999-999"
                    "residentSince": 2018-01-07
                    "sex": "MALE"
                    isA: "Permanent Resident"
                    isA: "Person"
                ]
                isA: "credential"
                issuer: SCID(04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8) [
                    dereferenceVia: URI(https://exampleledger.com/scid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8)
                    note: "Issued by the State of Example"
                ]
                note: "The State of Example recognizes JOHN SMITH as a Permanent Resident."
            ]
        } [
            verifiedBy: Signature [
                note: "Made by the State of Example."
            ]
        ]
        """
        XCTAssertEqual(johnSmithResidentCard.format, expectedFormat)
        
        // John wishes to identify himself to a third party using his government-issued
        // credential, but does not wish to reveal more than his name, his photo, and the
        // fact that the state has verified his identity.

        // Redaction is performed by building a set of `Digest`s that will be revealed. All
        // digests not present in the reveal-set will be replaced with redaction markers
        // containing only the hash of what has been redacted, thus preserving the hash
        // tree including revealed signatures. If a higher-level object is redacted, then
        // everything it contains will also be redacted, so if a deeper object is to be
        // revealed, all of its parent objects also need to be revealed, even though not
        // everything *about* the parent objects must be revealed.

        // Start a reveal-set
        var revealSet: Set<Digest> = []

        // Reveal the card. Without this, everything about the card would be redacted.
        let top = johnSmithResidentCard
        revealSet.insert(top)

        // Reveal everything about the state's signature on the card
        try revealSet.insert(top.assertion(predicate: .verifiedBy).deepDigests)

        // Reveal the top level subject of the card. This is John Smith's SCID.
        let topContent = top.subject.envelope!
        revealSet.insert(topContent.shallowDigests)

        // Reveal everything about the `isA` and `issuer` assertions at the top level of the card.
        try revealSet.insert(topContent.assertion(predicate: .isA).deepDigests)
        try revealSet.insert(topContent.assertion(predicate: .issuer).deepDigests)

        // Reveal the `holder` assertion on the card, but not any of its sub-assertions.
        let holder = try topContent.assertion(predicate: .holder)
        revealSet.insert(holder.shallowDigests)
        
        // Within the `holder` assertion, reveal everything about just the `givenName`, `familyName`, and `image` assertions.
        try revealSet.insert(holder.assertion(predicate: "givenName").deepDigests)
        try revealSet.insert(holder.assertion(predicate: "familyName").deepDigests)
        try revealSet.insert(holder.assertion(predicate: "image").deepDigests)
        
        // Perform the redaction
        let redactedCredential = top.redact(revealing: revealSet)
        
        // Verify that the redacted credential compares equal to the original credential.
        XCTAssertEqual(redactedCredential, johnSmithResidentCard)
        
        // Verify that the state's signature on the redacted card is still valid.
        try redactedCredential.validateSignature(from: statePublicKeys)
        
        let expectedRedactedFormat =
        """
        {
            SCID(174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8) [
                REDACTED
                REDACTED
                holder: SCID(78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc) [
                    REDACTED
                    REDACTED
                    REDACTED
                    REDACTED
                    REDACTED
                    REDACTED
                    REDACTED
                    REDACTED
                    "familyName": "SMITH"
                    "givenName": "JOHN"
                    "image": Digest(36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999) [
                        dereferenceVia: "https://exampleledger.com/digest/36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999"
                        note: "This is an image of John Smith."
                    ]
                ]
                isA: "credential"
                issuer: SCID(04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8) [
                    dereferenceVia: URI(https://exampleledger.com/scid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8)
                    note: "Issued by the State of Example"
                ]
            ]
        } [
            verifiedBy: Signature [
                note: "Made by the State of Example."
            ]
        ]
        """
        print(redactedCredential.format)
        XCTAssertEqual(redactedCredential.format, expectedRedactedFormat)
    }
    
    /// See [The Art of Immutable Architecture, by Michael L. Perry](https://amzn.to/3Kszr1p).
    func testHistoricalModeling() throws {
        //
        // Declare Actors
        //

//        let johnSmithIdentifier = SCID(‡"78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc")!
//        let johnSmithPrivateKeys = PrivateKeyBase(Seed(data: ‡"3e9271f46cdb85a3b584e7220b976918")!)
//        let johnSmithPublicKeys = johnSmithPrivateKeys.publicKeys
//        let johnSmithDocument = Envelope(johnSmithIdentifier)
//            .add(.hasName, "John Smith")
//            .add(.dereferenceVia, URL(string: "https://exampleledger.com/scid/78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc")!)

//        let acmeCorpPrivateKeys = PrivateKeyBase(Seed(data: ‡"3e9271f46cdb85a3b584e7220b976918")!)
//        let acmeCorpPublicKeys = acmeCorpPrivateKeys.publicKeys
        let acmeCorpIdentifier = SCID(‡"361235424efc81cedec7eb983a97bbe74d7972f778486f93881e5eed577d0aa7")!
        let acmeCorpDocument = Envelope(acmeCorpIdentifier)
            .add(.hasName, "Acme Corp.")
            .add(.dereferenceVia, URL(string: "https://exampleledger.com/scid/361235424efc81cedec7eb983a97bbe74d7972f778486f93881e5eed577d0aa7")!)
        
        //
        // Declare Products
        //

        let qualityProduct = Envelope(SCID(‡"5bcca01f5f370ceb3b7365f076e9600e294d4da6ddf7a616976c87775ea8f0f1")!)
            .add(.isA, "Product")
            .add(.hasName, "Quality Widget")
            .add("seller", acmeCorpDocument)
            .add("priceEach", "10.99")

        let cheapProduct = Envelope(SCID(‡"ae464c5f9569ae23ff9a75e83caf485fb581d1ef9da147ca086d10e3d6f93e64")!)
            .add(.isA, "Product")
            .add(.hasName, "Cheap Widget")
            .add("seller", acmeCorpDocument)
            .add("priceEach", "4.99")

        //
        // Declare a Purchase Order
        //

        // Since the line items of a PurchaseOrder may be mutated before being finalized,
        // they are not declared as part of the creation of the PurchaseOrder itself.
        
        let purchaseOrder = Envelope(SCID(‡"1bebb5b6e447f819d5a4cb86409c5da1207d1460672dfe903f55cde833549625")!)
            .add(.isA, "PurchaseOrder")
            .add(.hasName, "PO 123")
        
        //
        // Add Line Items to the Purchase Order
        //

        // A line item's subject is a reference to the digest of the specific purchase
        // order object. This forms a successor -> predecessor relationship to the purchase
        // order.
        //
        // A line item's product is the SCID of the product. The product document found by
        // referencing the product's SCID may change over time, for instance the price may
        // be updated. The line item therefore captures the current price from the product
        // document in its priceEach assertion.
        
        let line1 = try Envelope(purchaseOrder.digest)
            .add(.isA, "PurchaseOrderLineItem")
            .add("product", qualityProduct.extract(SCID.self))
            .add(.hasName, qualityProduct.extract(predicate: .hasName))
            .add("priceEach", qualityProduct.extract(predicate: "priceEach"))
            .add("quantity", 4)

        let line2 = try Envelope(purchaseOrder.digest)
            .add(.isA, "PurchaseOrderLineItem")
            .add("product", cheapProduct.extract(SCID.self))
            .add(.hasName, cheapProduct.extract(predicate: .hasName))
            .add("priceEach", cheapProduct.extract(predicate: "priceEach"))
            .add("quantity", 3)

        let line2ExpectedFormat =
        """
        Digest(6eda6278399769c825633f19c1e9591814f959a8781e459fd8531900d14b3d43) [
            "priceEach": "4.99"
            "product": SCID(ae464c5f9569ae23ff9a75e83caf485fb581d1ef9da147ca086d10e3d6f93e64)
            "quantity": 3
            hasName: "Cheap Widget"
            isA: "PurchaseOrderLineItem"
        ]
        """
        XCTAssertEqual(line2.format, line2ExpectedFormat)
        
//        let revokeLine1 = Envelope(purchaseOrder.digest)
//            .add(Assertion(revoke: Reference(digest: line1.digest)))
//        print(revokeLine1.format)
        
        let purchaseOrderProjection = purchaseOrder
            .add("lineItem", line1)
            .add("lineItem", line2)
//            .revoke(line1.digest)
        
        let purchaseOrderProjectionExpectedFormat =
        """
        SCID(1bebb5b6e447f819d5a4cb86409c5da1207d1460672dfe903f55cde833549625) [
            "lineItem": Digest(6eda6278399769c825633f19c1e9591814f959a8781e459fd8531900d14b3d43) [
                "priceEach": "10.99"
                "product": SCID(5bcca01f5f370ceb3b7365f076e9600e294d4da6ddf7a616976c87775ea8f0f1)
                "quantity": 4
                hasName: "Quality Widget"
                isA: "PurchaseOrderLineItem"
            ]
            "lineItem": Digest(6eda6278399769c825633f19c1e9591814f959a8781e459fd8531900d14b3d43) [
                "priceEach": "4.99"
                "product": SCID(ae464c5f9569ae23ff9a75e83caf485fb581d1ef9da147ca086d10e3d6f93e64)
                "quantity": 3
                hasName: "Cheap Widget"
                isA: "PurchaseOrderLineItem"
            ]
            hasName: "PO 123"
            isA: "PurchaseOrder"
        ]
        """
        XCTAssertEqual(purchaseOrderProjection.format, purchaseOrderProjectionExpectedFormat)
    }
}
