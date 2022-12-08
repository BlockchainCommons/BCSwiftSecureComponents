import XCTest
import BCSecureComponents
import WolfBase

class DiffTests: XCTestCase {
    func run1(_ e1: Envelope, _ e2: Envelope) throws {
        let edits = e1.diff(target: e2)
        //print(edits.format)
        let e3 = try e1.transform(edits: edits)
        XCTAssert(e3.isIdentical(to: e2))
    }
    
    func run(_ e1: Envelope, _ e2: Envelope) throws {
        try run1(e1, e2)
        try run1(e2, e1)
    }

    func test1() throws {
        let e1 = Envelope("Alice")
            .addAssertion("knows", "Bob")
            .addAssertion("knows", "Carol")
        let e2 = Envelope("Alice")
            .addAssertion("knows", "Bob")
            .addAssertion("knows", "Darla")
        try run(e1, e2)
    }
    
    func test2() throws {
        let e1 = Envelope("Alice")
            .addAssertion("knows", "Bob")
        let e2 = e1
            .wrap()
            .addAssertion(.verifiedBy, "Carol")
        try run(e1, e2)
    }
    
    func test3() throws {
        let e1 = Envelope("Alice")
            .addAssertion("knows", "Bob")
        let e2 = Envelope("Alice")
        try run(e1, e2)
    }
    
    func test4() throws {
        let e1 = Envelope("Alice")
            .addAssertion("knows", "Bob")
        let e2 = e1
            .wrap()
            .sign(with: PrivateKeyBase())
        try run(e1, e2)
    }
    
    func test5() throws {
        for _ in 0..<20 {
            let generator = EnvelopeGenerator(rng: makeRNG())
            let e1 = generator.envelope(count: 20)
            let e2 = generator.envelope(count: 30)
            try run(e1, e2)
        }
    }
    
    func makeRNG() -> some RandomNumberGenerator {
        let state: Xoroshiro256StarStar.State = (7943088474095033134, 2201563221578303974, 15451724982873067437, 14892261624674498107)
        return Xoroshiro256StarStar(state: state)
    }
}
