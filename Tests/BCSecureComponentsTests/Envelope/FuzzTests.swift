import XCTest
import BCSecureComponents
import WolfBase
import WolfLorem

//class FuzzTests: XCTestCase {
//    func testDeterministicGeneration1() {
////        let generator = EnvelopeGenerator()
////        let state = generator.state
////        print(state)
//
//        let state: Xoroshiro256StarStar.State = (8868906800422719001, 2679026190770356715, 18168077958379133986, 11246974645108928109)
//        let generator = EnvelopeGenerator(state: state)
//        
//        let e = generator.envelope(count: 400)
//        print(e.mermaidFormat())
//        XCTAssertEqual(e.digest.hex, "15fdc13a905bcb6c4095d068b62ad3991b8cefedbf57c83fa0d979ccba07f61c")
////        print(e.structureFormat)
////        print(e.mermaidFormat)
//    }
//    
//    func testDeterministicGeneration2() {
//        for _ in 0 ..< 10 {
////            let state: Xoroshiro256StarStar.State = (16613201003084073342, 15821912718973707888, 15152885056770712099, 16670797755942650989)
//            
//            let count = 100
//            let state = Xoroshiro256StarStar().state
//            let generator1 = EnvelopeGenerator(state: state)
//            let e1 = generator1.envelope(count: count)
//            let generator2 = EnvelopeGenerator(state: state)
//            let e2 = generator2.envelope(count: count)
//            if e1 != e2 {
//                print(state)
//                print(e1.diff(target: e2).format)
////                print(e1.format)
////                print(e.structureFormat)
////                print(e.mermaidFormat)
//            }
//            XCTAssertEqual(e1, e2)
//        }
//    }
//    
////    func testDiff() throws {
////        for offset in 0..<100 {
////            print("offset: \(offset)")
////            let state: Xoroshiro256StarStar.State = (16613201003084073342 + UInt64(offset), 15821912718973707888, 15152885056770712099, 16670797755942650989)
////            let count = 10
////            let generator = EnvelopeGenerator(state: state)
////            let e1 = generator.envelope(count: count)
////            let e2 = generator.envelope(count: count)
////            let diff = e1.diff(target: e2)
////            guard let e3 = try? e1.applyDiff(diff) else {
////                print(e1.format)
////                print(e2.format)
////                print(diff.format)
////                break
////            }
////            if e3 != e2 {
////                print(e1.format)
////                print(e2.format)
////                print(diff.format)
////                print(e3.format)
////                break
////            }
//////            XCTAssertEqual(e3, e2)
////        }
////    }
//    
////    func testMutatingWalk() throws {
////        let e1 = Envelope("Alice").addAssertion("knows", Envelope("Bob").wrap())
////        print(e1.structureFormat)
////        e1.mutatingWalk { envelope, path, _ in
////            var comps: [String] = path.reduce(into: []) {
////                $0.append($1.digest.shortDescription)
////            }
////            comps.append(envelope.digest.shortDescription)
////            print(comps.joined(separator: " "))
////            //return envelope.addAssertion(1, 2)
////        }
////    }
//    
////    func testDiff() {
////        let generator = EnvelopeGenerator()
//////        let state = generator.state
////        let e1 = generator.envelope(count: 100)
////        print("===")
////        print(e1.format)
////        let e2 = generator.mutate(e1)
////        print("===")
////        print(e2.format)
////        print("===")
////        print(e1.diff(target: e2).format)
////    }
//}
