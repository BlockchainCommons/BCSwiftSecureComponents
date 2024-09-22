import Testing
import WolfBase
import SecureComponents
import BCRandom

struct KeyTests {
    @Test func testAgreementKeys() {
        var rng = makeFakeRandomNumberGenerator()
        let privateKey = AgreementPrivateKey(using: &rng)
        let privateKeyUR = privateKey.urString
        #expect(privateKeyUR == "ur:agreement-private-key/hdcxkbrehkrkrsjztodseytknecfgewmgdmwfsvdvysbpmghuozsprknfwkpnehydlweynwkrtct")
        #expect(try! AgreementPrivateKey(urString: privateKeyUR) == privateKey)
        let publicKey = privateKey.publicKey
        let publicKeyUR = publicKey.urString
        #expect(publicKeyUR == "ur:agreement-public-key/hdcxwnryknkbbymnoxhswmptgydsotwswsghfmrkksfxntbzjyrnuornkildchgswtdahehpwkrl")
        #expect(try! AgreementPublicKey(urString: publicKeyUR) == publicKey)
        
        let derivedPrivateKey = AgreementPrivateKey(keyMaterial: "password")
        #expect(derivedPrivateKey.urString == "ur:agreement-private-key/hdcxkgcfkomeeyiemywkftvabnrdolmttlrnfhjnguvaiehlrldmdpemgyjlatdthsnecytdoxat")
    }
    
    @Test func testAgreement() {
        var rng = makeFakeRandomNumberGenerator()
        let alicePrivateKey = AgreementPrivateKey(using: &rng)
        let alicePublicKey = alicePrivateKey.publicKey
        
        let bobPrivateKey = AgreementPrivateKey(using: &rng)
        let bobPublicKey = bobPrivateKey.publicKey
        
        let aliceSharedKey = alicePrivateKey.sharedKey(with: bobPublicKey)
        let bobSharedKey = bobPrivateKey.sharedKey(with: alicePublicKey)
        #expect(aliceSharedKey == bobSharedKey)
    }
    
    @Test func testSigningKeys() {
        var rng = makeFakeRandomNumberGenerator()
        let privateKey = SigningPrivateKey(using: &rng)
        let privateKeyUR = privateKey.urString
        #expect(privateKeyUR == "ur:signing-private-key/hdcxkbrehkrkrsjztodseytknecfgewmgdmwfsvdvysbpmghuozsprknfwkpnehydlweynwkrtct")
        #expect(try! SigningPrivateKey(urString: privateKeyUR) == privateKey)
        
        let ecdsaPublicKey = privateKey.secp256k1ECDSAPublicKey
        let ecdsaPublicKeyUR = ecdsaPublicKey.urString
        #expect(ecdsaPublicKeyUR == "ur:signing-public-key/lfadhdclaojsrhdnidbgosndmobzwntdglzonnidmwoyrnuomdrpsptkcskerhfljssgaoidjedkwftboe")
        #expect(try! SigningPublicKey(urString: ecdsaPublicKeyUR) == ecdsaPublicKey)
        
        let schnorrPublicKey = privateKey.secp256k1SchnorrPublicKey
        let schnorrPublicKeyUR = schnorrPublicKey.urString
        #expect(schnorrPublicKeyUR == "ur:signing-public-key/hdcxjsrhdnidbgosndmobzwntdglzonnidmwoyrnuomdrpsptkcskerhfljssgaoidjewyjymhcp")
        #expect(try! SigningPublicKey(urString: schnorrPublicKeyUR) == schnorrPublicKey)
        
        let derivedPrivateKey = SigningPrivateKey(keyMaterial: "password")
        #expect(derivedPrivateKey.urString == "ur:signing-private-key/hdcxahsfgobtpkkpahmnhsfmhnjnmkmkzeuraonneshkbysseyjkoeayrlvtvsmndicwkkvattfs")
    }
}
