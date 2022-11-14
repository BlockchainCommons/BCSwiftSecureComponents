import XCTest
import BCSecureComponents
import WolfBase
import WolfLorem

class FuzzTests: XCTestCase {
    func testDeterministicGeneration1() {
//        let generator = EnvelopeGenerator()
//        let state = generator.state
//        print(state)

        let state: Xoroshiro256StarStar.State = (8868906800422719001, 2679026190770356715, 18168077958379133986, 11246974645108928109)
        let generator = EnvelopeGenerator(state: state)
        
        let e = generator.envelope(count: 400)
        XCTAssertEqual(e.digest.hex, "15fdc13a905bcb6c4095d068b62ad3991b8cefedbf57c83fa0d979ccba07f61c")
//        print(e.treeFormat)
//        print(e.mermaidFormat)
    }
    
    func testDeterministicGeneration2() {
        for _ in 0 ..< 10 {
//            let state: Xoroshiro256StarStar.State = (16613201003084073342, 15821912718973707888, 15152885056770712099, 16670797755942650989)
            
            let count = 100
            let state = EnvelopeGenerator().state
            let generator1 = EnvelopeGenerator(state: state)
            let e1 = generator1.envelope(count: count)
            let generator2 = EnvelopeGenerator(state: state)
            let e2 = generator2.envelope(count: count)
            if e1 != e2 {
                print(state)
                print(e1.diff(target: e2).format)
//                print(e1.format)
//                print(e.treeFormat)
//                print(e.mermaidFormat)
            }
            XCTAssertEqual(e1, e2)
        }
    }
}
