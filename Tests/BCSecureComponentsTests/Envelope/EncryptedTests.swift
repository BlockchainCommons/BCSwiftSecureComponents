import XCTest
import BCSecureComponents
import WolfBase

class EncryptedTests: XCTestCase {
    static let basicEnvelope = Envelope("Hello.")
    static let knownValueEnvelope = Envelope(KnownValue.note)
    static let wrappedEnvelope = Envelope(basicEnvelope)
    static let doubleWrappedEnvelope = Envelope(wrappedEnvelope)
    static let assertionEnvelope = Envelope("knows", "Bob")
    
    static let singleAssertionEnvelope = Envelope("Alice")
        .addAssertion("knows", "Bob")
    static let doubleAssertionEnvelope = singleAssertionEnvelope
        .addAssertion("knows", "Carol")
    
    func encryptedTest(_ e1: Envelope) throws {
        let e2 = try e1
            .encryptSubject(with: symmetricKey, testNonce: fakeNonce)
            .checkEncoding()
        
        XCTAssert(e1.isEquivalent(to: e2))
        XCTAssert(e1.subject.isEquivalent(to: e2.subject))
        
        let encryptedMessage = try e2.extractSubject(EncryptedMessage.self)
        XCTAssertEqual(encryptedMessage.digest, e1.subject.digest)
        
        let e3 = try e2
            .decryptSubject(with: symmetricKey)
        
        XCTAssert(e1.isEquivalent(to: e3))
    }
    
    func testEncrypted() throws {
        try encryptedTest(Self.basicEnvelope)
        try encryptedTest(Self.wrappedEnvelope)
        try encryptedTest(Self.doubleWrappedEnvelope)
        try encryptedTest(Self.knownValueEnvelope)
        try encryptedTest(Self.assertionEnvelope)
        try encryptedTest(Self.singleAssertionEnvelope)
        try encryptedTest(Self.doubleAssertionEnvelope)
    }
    
    func testSignWrapEncrypt() throws {
        let e1 = Self.basicEnvelope
        //print(e1.format)
        
        let e2 = e1
            .sign(with: alicePrivateKeys)
        //print(e2.format)
        
        let e3 = e2
            .wrap()
        //print(e3.format)
        
        let e4 = try e3
            .encryptSubject(with: symmetricKey)
        //print(e4.format)
        
        let d3 = try e4
            .decryptSubject(with: symmetricKey)
        //print(d3.format)
        XCTAssert(d3.isEquivalent(to: e3))
        
        let d2 = try d3
            .unwrap()
        //print(d2.format)
        XCTAssert(d2.isEquivalent(to: e2))
        
        try d2.verifySignature(from: alicePublicKeys)
        
        let d1 = d2.subject
        //print(d1.format)
        XCTAssert(d1.isEquivalent(to: e1))
    }
    
    func testSignWrapEncryptToRecipient() throws {
        let e1 = Self.basicEnvelope
            .sign(with: alicePrivateKeys)
            .wrap()
        //print(e1.format)
        
        let e2 = try e1
            .encryptSubject(with: symmetricKey)
        //print(e2.format)
        
        let e3 = e2
            .addRecipient(bobPublicKeys, contentKey: symmetricKey)
        //print(e3.format)
        
        let d1 = try e3.decrypt(to: bobPrivateKeys)
        //print(d1.format)
        XCTAssert(d1.isEquivalent(to: e1))
    }
    
    func testEncryptDecryptWithOrderedMapKeys() throws {
        var danSeed = Seed(data: ‡"59f2293a5bce7d4de59e71b4207ac5d2")!
        danSeed.name = "Dark Purple Aqua Love"
        danSeed.creationDate = try! Date(iso8601: "2021-02-24")
        danSeed.note = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
        
        let seedEnvelope = try Envelope(danSeed).checkEncoding()
        let encryptedSeedEnvelope = try seedEnvelope
            .encryptSubject(with: symmetricKey)
            .checkEncoding()
        XCTAssert(seedEnvelope.subject.isEquivalent(to: encryptedSeedEnvelope.subject))
        XCTAssert(seedEnvelope.isEquivalent(to: encryptedSeedEnvelope))
        
        let decryptedSeedEnvelope = try encryptedSeedEnvelope
            .decryptSubject(with: symmetricKey)
        XCTAssert(seedEnvelope.isEquivalent(to: decryptedSeedEnvelope))
    }
}
