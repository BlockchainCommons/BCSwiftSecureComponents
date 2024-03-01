import XCTest
import WolfBase
import SecureComponents
import BCRandom

class KeyTests: XCTestCase {
    func testAgreementKeys() {
        var rng = makeFakeRandomNumberGenerator()
        let privateKey = AgreementPrivateKey(using: &rng)
        let privateKeyUR = privateKey.urString
        XCTAssertEqual(privateKeyUR, "ur:agreement-private-key/hdcxkbrehkrkrsjztodseytknecfgewmgdmwfsvdvysbpmghuozsprknfwkpnehydlweynwkrtct")
        XCTAssertEqual(try! AgreementPrivateKey(urString: privateKeyUR), privateKey)
        let publicKey = privateKey.publicKey
        let publicKeyUR = publicKey.urString
        XCTAssertEqual(publicKeyUR, "ur:agreement-public-key/hdcxwnryknkbbymnoxhswmptgydsotwswsghfmrkksfxntbzjyrnuornkildchgswtdahehpwkrl")
        XCTAssertEqual(try! AgreementPublicKey(urString: publicKeyUR), publicKey)
        
        let derivedPrivateKey = AgreementPrivateKey(keyMaterial: "password")
        XCTAssertEqual(derivedPrivateKey.urString, "ur:agreement-private-key/hdcxkgcfkomeeyiemywkftvabnrdolmttlrnfhjnguvaiehlrldmdpemgyjlatdthsnecytdoxat")
    }
    
    func testAgreement() {
        var rng = makeFakeRandomNumberGenerator()
        let alicePrivateKey = AgreementPrivateKey(using: &rng)
        let alicePublicKey = alicePrivateKey.publicKey
        
        let bobPrivateKey = AgreementPrivateKey(using: &rng)
        let bobPublicKey = bobPrivateKey.publicKey
        
        let aliceSharedKey = alicePrivateKey.sharedKey(with: bobPublicKey)
        let bobSharedKey = bobPrivateKey.sharedKey(with: alicePublicKey)
        XCTAssertEqual(aliceSharedKey, bobSharedKey)
    }
    
    func testSigningKeys() {
        var rng = makeFakeRandomNumberGenerator()
        let privateKey = SigningPrivateKey(using: &rng)
        let privateKeyUR = privateKey.urString
        XCTAssertEqual(privateKeyUR, "ur:signing-private-key/hdcxkbrehkrkrsjztodseytknecfgewmgdmwfsvdvysbpmghuozsprknfwkpnehydlweynwkrtct")
        XCTAssertEqual(try! SigningPrivateKey(urString: privateKeyUR), privateKey)
        
        let ecdsaPublicKey = privateKey.secp256k1ECDSAPublicKey
        let ecdsaPublicKeyUR = ecdsaPublicKey.urString
        XCTAssertEqual(ecdsaPublicKeyUR, "ur:signing-public-key/lfadhdclaojsrhdnidbgosndmobzwntdglzonnidmwoyrnuomdrpsptkcskerhfljssgaoidjedkwftboe")
        XCTAssertEqual(try! SigningPublicKey(urString: ecdsaPublicKeyUR), ecdsaPublicKey)
        
        let schnorrPublicKey = privateKey.secp256k1SchnorrPublicKey
        let schnorrPublicKeyUR = schnorrPublicKey.urString
        XCTAssertEqual(schnorrPublicKeyUR, "ur:signing-public-key/hdcxjsrhdnidbgosndmobzwntdglzonnidmwoyrnuomdrpsptkcskerhfljssgaoidjewyjymhcp")
        XCTAssertEqual(try! SigningPublicKey(urString: schnorrPublicKeyUR), schnorrPublicKey)
        
        let derivedPrivateKey = SigningPrivateKey(keyMaterial: "password")
        XCTAssertEqual(derivedPrivateKey.urString, "ur:signing-private-key/hdcxahsfgobtpkkpahmnhsfmhnjnmkmkzeuraonneshkbysseyjkoeayrlvtvsmndicwkkvattfs")
    }
}
