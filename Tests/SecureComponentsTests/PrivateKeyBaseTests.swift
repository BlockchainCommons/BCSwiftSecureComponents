import Testing
import SecureComponents
import WolfBase

struct PrivateKeyBaseTests {
    @Test func testPrivateKeyBase() {
        let seed = ‡"59f2293a5bce7d4de59e71b4207ac5d2"
        let privateKeys = PrivateKeyBase(seed)
        
//         print(privateKeys.signingPrivateKey.data.hex)
//         print(privateKeys.signingPrivateKey.schnorrPublicKey.data.hex)
//         print(privateKeys.agreementPrivateKey.data.hex)
//         print(privateKeys.agreementPrivateKey.publicKey.data.hex)
        
        #expect(privateKeys.signingPrivateKey.data == ‡"9505a44aaf385ce633cf0e2bc49e65cc88794213bdfbf8caf04150b9c4905f5a")
        #expect(privateKeys.signingPrivateKey.secp256k1SchnorrPublicKey.data == ‡"fd4d22f9e8493da52d730aa402ac9e661deca099ef4db5503f519a73c3493e18")
        #expect(privateKeys.x25519AgreementPrivateKey.data == ‡"77ff838285a0403d3618aa8c30491f99f55221be0b944f50bfb371f43b897485")
        #expect(privateKeys.x25519AgreementPrivateKey.publicKey.data == ‡"863cf3facee3ba45dc54e5eedecb21d791d64adfb0a1c63bfb6fea366c1ee62b")
        
        let ur = privateKeys.urString
        #expect(ur == "ur:crypto-prvkeys/gdhkwzdtfthptokigtvwnnjsqzcxknsktdsfecsbbk")
        #expect(try! PrivateKeyBase(urString: ur) == privateKeys)
    }
}
