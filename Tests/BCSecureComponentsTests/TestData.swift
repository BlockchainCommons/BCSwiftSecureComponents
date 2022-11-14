import Foundation
import BCSecureComponents
import WolfBase

let plaintextHello = "Hello."
let plaintextMysteries = "Some mysteries aren't meant to be solved."

let symmetricKey = SymmetricKey(‡"38900719dea655e9a1bc1682aaccf0bfcd79a7239db672d39216e4acdd660dc0")!

let aliceIdentifier = CID(‡"d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f")!
let aliceSeed = Seed(data: ‡"82f32c855d3d542256180810797e0073")!
let alicePrivateKeys = PrivateKeyBase(aliceSeed)
let alicePublicKeys = alicePrivateKeys.publicKeys

let bobIdentifier = CID(‡"24b5b23d8aed462c5a3c02cc4972315eb71a6c5fdfc0063de28603f467ae499c")!
let bobSeed = Seed(data: ‡"187a5973c64d359c836eba466a44db7b")!
let bobPrivateKeys = PrivateKeyBase(bobSeed)
let bobPublicKeys = bobPrivateKeys.publicKeys

let carolIdentifier = CID(‡"06c777262faedf49a443277474c1c08531efcff4c58e9cb3b04f7fc1c0e6d60d")!
let carolSeed = Seed(data: ‡"8574afab18e229651c1be8f76ffee523")!
let carolPrivateKeys = PrivateKeyBase(carolSeed)
let carolPublicKeys = carolPrivateKeys.publicKeys

let exampleLedgerIdentifier = CID(‡"0eda5ce79a2b5619e387f490861a2e7211559029b3b369cf98fb749bd3ba9a5d")!
let exampleLedgerPrivateKeys = PrivateKeyBase(Seed(data: ‡"d6737ab34e4e8bb05b6ac035f9fba81a")!)
let exampleLedgerPublicKeys = exampleLedgerPrivateKeys.publicKeys

let stateIdentifier = CID(‡"04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8")!
let statePrivateKeys = PrivateKeyBase(Seed(data: ‡"3e9271f46cdb85a3b584e7220b976918")!)
let statePublicKeys = statePrivateKeys.publicKeys

let fakeContentKey = SymmetricKey(‡"526afd95b2229c5381baec4a1788507a3c4a566ca5cce64543b46ad12aff0035")!
let fakeNonce = Nonce(‡"4d785658f36c22fb5aed3ac0")!

func makeFakeRandomGenerator() -> RandomNumberGenerator {
    Xoroshiro256StarStar(state: (17295166580085024720, 422929670265678780, 5577237070365765850, 7953171132032326923))
}

func generateFakeRandomNumbers(_ count: Int) -> Data {
    var rng = makeFakeRandomGenerator()
    return rng.data(count: count)
}
