import Testing
import WolfBase
import SecureComponents
import BCRandom

fileprivate let privateKey = SigningPrivateKey(‡"322b5c1dd5a17c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36")!
fileprivate let message = "Wolf McNally"

struct SignatureTests {
    struct SchnorrSignatureTests {
        let publicKey = privateKey.secp256k1SchnorrPublicKey
        let signature = privateKey.secp256k1SchnorrSign(message)
        
        @Test func testSigning() {
            #expect(publicKey.verify(signature: signature, for: message))
            #expect(!publicKey.verify(signature: signature, for: "Wolf Mcnally"))
            
            let anotherSignature = privateKey.secp256k1SchnorrSign(message)
            #expect(signature != anotherSignature)
            #expect(publicKey.verify(signature: anotherSignature, for: message))
        }
        
        @Test func testCBOR() throws {
            var rng = makeFakeRandomNumberGenerator()
            let signature = privateKey.secp256k1SchnorrSign(message, using: &rng)
            let taggedCBOR = signature.cborData
            #expect(try CBOR(taggedCBOR).diagnostic(tags: nil) ==
        """
        40020(
           h'9d113392074dd52dfb7f309afb3698a1993cd14d32bc27c00070407092c9ec8c096643b5b1b535bb5277c44f256441ac660cd600739aa910b150d4f94757cf95'
        )
        """)
            let receivedSignature = try Signature(taggedCBORData: taggedCBOR)
            #expect(signature == receivedSignature)
        }
    }
    
    struct ECDSASignatureTests {
        let publicKey = privateKey.secp256k1ECDSAPublicKey
        let signature = privateKey.secp256k1ECDSASign(message)
        
        @Test func testSigning() {
            #expect(publicKey.verify(signature: signature, for: message))
            #expect(!publicKey.verify(signature: signature, for: "Wolf Mcnally"))
            
            let anotherSignature = privateKey.secp256k1ECDSASign(message)
            #expect(signature == anotherSignature)
            #expect(publicKey.verify(signature: anotherSignature, for: message))
        }
        
        @Test @MainActor func testCBOR() throws {
            addKnownTags()
            let taggedCBOR = signature.cborData
            #expect(try CBOR(taggedCBOR).diagnostic() ==
            """
            40020(   / signature /
               [
                  1,
                  h'1458d0f3d97e25109b38fd965782b43213134d02b01388a14e74ebf21e5dea4866f25a23866de9ecf0f9b72404d8192ed71fba4dc355cd89b47213e855cf6d23'
               ]
            )
            """)
            let receivedSignature = try Signature(taggedCBORData: taggedCBOR)
            #expect(signature == receivedSignature)
        }
    }
}
