import XCTest
import BCSecureComponents
import WolfBase
import WolfLorem

class FuzzTests: XCTestCase {
    func test1() {
        //        let state: Xoroshiro256StarStar.State = (16613201003084073342, 15821912718973707888, 15152885056770712099, 16670797755942650989)
        //        let generator = EnvelopeGenerator(state: state)
        
        let generator = EnvelopeGenerator()
        let state = generator.state
        print(state)
        
        let e = generator.envelope(count: 400)
        print(e.format)
        //        print(e.treeFormat)
        //        print(e.mermaidFormat)
    }
    
    func test2() {
        for _ in 0 ..< 50 {
            let state: Xoroshiro256StarStar.State = (
                UInt64.random(in: UInt64.min ... UInt64.max),
                UInt64.random(in: UInt64.min ... UInt64.max),
                UInt64.random(in: UInt64.min ... UInt64.max),
                UInt64.random(in: UInt64.min ... UInt64.max)
            )
            
            //        let state: Xoroshiro256StarStar.State = (16613201003084073342, 15821912718973707888, 15152885056770712099, 16670797755942650989)
            
            let generator1 = EnvelopeGenerator(state: state)
            let generator2 = EnvelopeGenerator(state: state)
            
            let count = 200
            let e1 = generator1.envelope(count: count)
            let e2 = generator2.envelope(count: count)
//            print(e1.format)
            if e1 != e2 {
                print(state)
                print(e1.diff(target: e2).format)
            }
            XCTAssertEqual(e1, e2)
            //        print(e.treeFormat)
            //        print(e.mermaidFormat)
        }
    }
}
