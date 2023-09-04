import Foundation
import SecureComponents
import WolfBase

let plaintextMysteries = "Some mysteries aren't meant to be solved."

let aliceIdentifier = ARID(‡"d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f")!
let aliceSeed = Seed(data: ‡"82f32c855d3d542256180810797e0073")!
let alicePrivateKeys = PrivateKeyBase(aliceSeed)
let alicePublicKeys = alicePrivateKeys.publicKeys

let bobIdentifier = ARID(‡"24b5b23d8aed462c5a3c02cc4972315eb71a6c5fdfc0063de28603f467ae499c")!
let bobSeed = Seed(data: ‡"187a5973c64d359c836eba466a44db7b")!
let bobPrivateKeys = PrivateKeyBase(bobSeed)
let bobPublicKeys = bobPrivateKeys.publicKeys

let carolIdentifier = ARID(‡"06c777262faedf49a443277474c1c08531efcff4c58e9cb3b04f7fc1c0e6d60d")!
let carolSeed = Seed(data: ‡"8574afab18e229651c1be8f76ffee523")!
let carolPrivateKeys = PrivateKeyBase(carolSeed)
let carolPublicKeys = carolPrivateKeys.publicKeys
