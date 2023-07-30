import XCTest
import WolfBase
import SecureComponents

fileprivate let privateKey = SigningPrivateKey(‡"322b5c1dd5a17c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36")!
fileprivate let message = "Wolf McNally"

class SchnorrSignatureTests: XCTestCase {
    let publicKey = privateKey.schnorrPublicKey
    let signature = privateKey.schnorrSign(message, tag: nil)

    func testSigning() {
        XCTAssertTrue(publicKey.verify(signature: signature, for: message))
        XCTAssertFalse(publicKey.verify(signature: signature, for: "Wolf Mcnally"))
        
        let anotherSignature = privateKey.schnorrSign(message, tag: nil)
        XCTAssertNotEqual(signature, anotherSignature)
        XCTAssertTrue(publicKey.verify(signature: anotherSignature, for: message))
    }
    
    func testCBOR() throws {
        var rng = makeFakeRandomNumberGenerator()
        let signature = privateKey.schnorrSign(message, tag: nil, using: &rng)
        let taggedCBOR = signature.cborData
        XCTAssertEqual(try CBOR(taggedCBOR).diagnostic(),
        """
        40020(
           h'c67bb76d5d85327a771819bb6d417ffc319737a4be8248b2814ba4fd1474494200a522fd9d2a7beccc3a05cdd527a84a8c731a43669b618d831a08104f77d82f'
        )
        """)
        let receivedSignature = try Signature(taggedCBORData: taggedCBOR)
        XCTAssertEqual(signature, receivedSignature)
    }
}

class ECDSASignatureTests: XCTestCase {
    let publicKey = privateKey.ecdsaPublicKey
    let signature = privateKey.ecdsaSign(message)

    func testSigning() {
        XCTAssertTrue(publicKey.verify(signature: signature, for: message))
        XCTAssertFalse(publicKey.verify(signature: signature, for: "Wolf Mcnally"))
        
        let anotherSignature = privateKey.ecdsaSign(message)
        XCTAssertEqual(signature, anotherSignature)
        XCTAssertTrue(publicKey.verify(signature: anotherSignature, for: message))
    }
    
    func testCBOR() throws {
        let taggedCBOR = signature.cborData
        XCTAssertEqual(try CBOR(taggedCBOR).diagnostic(),
        """
        40020(
           [
              1,
              h'1458d0f3d97e25109b38fd965782b43213134d02b01388a14e74ebf21e5dea4866f25a23866de9ecf0f9b72404d8192ed71fba4dc355cd89b47213e855cf6d23'
           ]
        )
        """)
        let receivedSignature = try Signature(taggedCBORData: taggedCBOR)
        XCTAssertEqual(signature, receivedSignature)
    }
}
