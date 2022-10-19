import XCTest
import BCSecureComponents
import WolfBase

class MermaidTests: XCTestCase {
    func testPlaintext() throws {
        let envelope = Envelope(plaintextHello)
        print(envelope.format)
        print(envelope.mermaidFormat())
    }
    
    func testSignedPlaintext() throws {
        let envelope = Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)
        print(envelope.format)
        print(envelope.mermaidFormat())
    }
    
    func testEncryptSubject() throws {
        let envelope = try Envelope("Alice")
            .addAssertion("knows", "Bob")
            .encryptSubject(with: SymmetricKey())
        print(envelope.format)
        print(envelope.mermaidFormat())
    }
    
    func testTopLevelAssertion() throws {
        let envelope = Envelope(predicate: "knows", object: "Bob")
        print(envelope.format)
        print(envelope.mermaidFormat())
    }

    func testElidedObject() throws {
        let envelope = Envelope("Alice")
            .addAssertion("knows", "Bob")
        let elided = try envelope.elideRemoving(Envelope("Bob"))
        print(elided.format)
        print(elided.mermaidFormat())
    }

    func testSignedSubject() throws {
        let envelope = Envelope("Alice")
            .addAssertion("knows", "Bob")
            .addAssertion("knows", "Carol")
            .sign(with: alicePrivateKeys)
        print(envelope.format)
        print(envelope.mermaidFormat())

        // Elided Assertions
        var target = Set<Digest>()
        target.insert(envelope)
        target.insert(envelope.subject)
        let elided = try envelope.elideRevealing(target)
        print(elided.format)
        print(elided.mermaidFormat())
    }

    func testWrapThenSign() throws {
        let envelope = Envelope("Alice")
            .addAssertion("knows", "Bob")
            .addAssertion("knows", "Carol")
            .wrap()
            .sign(with: alicePrivateKeys)
        print(envelope.format)
        print(envelope.mermaidFormat())
    }
    
    func testEncryptToRecipients() throws {
        // Alice encrypts a message so that it can only be decrypted by Bob or Carol.
        let contentKey = SymmetricKey()
        let envelope = try Envelope(plaintextHello)
            .encryptSubject(with: contentKey).checkEncoding()
            .addRecipient(bobPublicKeys, contentKey: contentKey).checkEncoding()
            .addRecipient(carolPublicKeys, contentKey: contentKey).checkEncoding()
        print(envelope.format)
        print(envelope.mermaidFormat(layoutDirection: .topToBottom))
    }

    func testAssertionPositions() throws {
        let predicate = Envelope("predicate")
            .addAssertion("predicate-predicate", "predicate-object")
        let object = Envelope("object")
            .addAssertion("object-predicate", "object-object")
        let envelope = try Envelope("subject")
            .addAssertion(predicate, object)
            .checkEncoding()
        print(envelope.format)
        print(envelope.mermaidFormat())
    }

    func testComplexMetadata() throws {
        // Assertions made about an CID are considered part of a distributed set. Which
        // assertions are returned depends on who resolves the CID and when it is
        // resolved. In other words, the referent of a CID is mutable.
        let author = try Envelope(CID(‡"9c747ace78a4c826392510dd6285551e7df4e5164729a1b36198e56e017666c8")!)
            .addAssertion(.dereferenceVia, "LibraryOfCongress")
            .addAssertion(.hasName, "Ayn Rand")
            .checkEncoding()

        // Assertions made on a literal value are considered part of the same set of
        // assertions made on the digest of that value.
        let name_en = Envelope("Atlas Shrugged")
            .addAssertion(.language, "en")

        let name_es = Envelope("La rebelión de Atlas")
            .addAssertion(.language, "es")

        let work = try Envelope(CID(‡"7fb90a9d96c07f39f75ea6acf392d79f241fac4ec0be2120f7c82489711e3e80")!)
            .addAssertion(.isA, "novel")
            .addAssertion("isbn", "9780451191144")
            .addAssertion("author", author)
            .addAssertion(.dereferenceVia, "LibraryOfCongress")
            .addAssertion(.hasName, name_en)
            .addAssertion(.hasName, name_es)
            .checkEncoding()

        let bookData = "This is the entire book “Atlas Shrugged” in EPUB format."
        // Assertions made on a digest are considered associated with that specific binary
        // object and no other. In other words, the referent of a Digest is immutable.
        let bookMetadata = try Envelope(Digest(bookData))
            .addAssertion("work", work)
            .addAssertion("format", "EPUB")
            .addAssertion(.dereferenceVia, "IPFS")
            .checkEncoding()
        
        print(bookMetadata.format)
        print(bookMetadata.mermaidFormat())
    }

    static let credential = try! Envelope(CID(‡"4676635a6e6068c2ef3ffd8ff726dd401fd341036e920f136a1d8af5e829496d")!)
        .addAssertion(.isA, "Certificate of Completion")
        .addAssertion(.issuer, "Example Electrical Engineering Board")
        .addAssertion(.controller, "Example Electrical Engineering Board")
        .addAssertion("firstName", "James")
        .addAssertion("lastName", "Maxwell")
        .addAssertion("issueDate", Date(iso8601: "2020-01-01"))
        .addAssertion("expirationDate", Date(iso8601: "2028-01-01"))
        .addAssertion("photo", "This is James Maxwell's photo.")
        .addAssertion("certificateNumber", "123-456-789")
        .addAssertion("subject", "RF and Microwave Engineering")
        .addAssertion("continuingEducationUnits", 1.5)
        .addAssertion("professionalDevelopmentHours", 15)
        .addAssertion("topics", ["Subject 1", "Subject 2"])
        .wrap()
        .sign(with: alicePrivateKeys)
        .addAssertion(.note, "Signed by Example Electrical Engineering Board")
        .checkEncoding()

    func testCredential() throws {
        print(Self.credential.format)
        print(Self.credential.mermaidFormat())
    }
    
    func testRedactedCredential() throws {
        let credential = Self.credential
        var target: Set<Digest> = []
        target.insert(credential)
        for assertion in credential.assertions {
            target.insert(assertion.deepDigests)
        }
        target.insert(credential.subject)
        let content = try credential.subject.unwrap()
        target.insert(content)
        target.insert(content.subject)
        target.insert(try content.assertion(withPredicate: "firstName").shallowDigests)
        target.insert(try content.assertion(withPredicate: "lastName").shallowDigests)
        target.insert(try content.assertion(withPredicate: .isA).shallowDigests)
        target.insert(try content.assertion(withPredicate: .issuer).shallowDigests)
        target.insert(try content.assertion(withPredicate: "subject").shallowDigests)
        target.insert(try content.assertion(withPredicate: "expirationDate").shallowDigests)
        let redactedCredential = try credential.elideRevealing(target)
        let warranty = try redactedCredential
            .wrap()
            .addAssertion("employeeHiredDate", Date(iso8601: "2022-01-01"))
            .addAssertion("employeeStatus", "active")
            .wrap()
            .addAssertion(.note, "Signed by Employer Corp.")
            .sign(with: bobPrivateKeys)
            .checkEncoding()
        print(warranty.format)
        print(warranty.mermaidFormat())
    }
}
