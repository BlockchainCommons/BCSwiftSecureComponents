import Foundation
import WolfBase
import BCCrypto
import BCRandom

/// A secure derivation scheme from a user-provided password to private key data.
///
/// Implemented using Scrypt.
///
/// https://datatracker.ietf.org/doc/html/rfc7914
public final class Password: Sendable {
    public let salt: Data
    public let data: Data
    public let n: Int
    public let r: Int
    public let p: Int
    
    public static let defaultN = 8192 // CPU/memory cost parameter – Must be a power of 2 (e.g. 1024)
    public static let defaultR = 8 // blocksize parameter, which fine-tunes sequential memory read size and performance.
    public static let defaultP = 1 // Parallelization parameter. (1 .. 232-1 * hLen/MFlen)
    public static let defaulDKLen = 32 // Desired Key Length
    
    public init(salt: Data, data: Data, n: Int, r: Int, p: Int) {
        self.salt = salt
        self.data = data
        self.n = n
        self.r = r
        self.p = p
    }
    
    public init?<T: RandomNumberGenerator>(_ password: DataProvider, salt: DataProvider? = nil, dkLen: Int = defaulDKLen, n: Int = defaultN, r: Int = defaultR, p: Int = defaultP, using rng: inout T) {
        self.n = n
        self.r = r
        self.p = p
        
        let salt = salt?.providedData ?? rng.randomData(16)
        self.salt = salt
        
        let password = password.providedData
        guard !password.isEmpty else {
            return nil
        }
        self.data = Scrypt.hash(password: password, salt: salt, dkLen: dkLen, n: n, r: r, p: p)
    }
    
    public convenience init?(_ password: DataProvider, salt: DataProvider? = nil, dkLen: Int = defaulDKLen, n: Int = defaultN, r: Int = defaultR, p: Int = defaultP) {
        var rng = SecureRandomNumberGenerator()
        self.init(password, salt: salt, dkLen: dkLen, n: n, r: r, p: p, using: &rng)
    }
    
    public func isValid(_ password: String) -> Bool {
        guard !password.isEmpty else {
            return false
        }
        let d = Scrypt.hash(password: password.utf8Data, salt: salt, dkLen: data.count, n: n, r: r, p: p)
        return data == d
    }
}

extension Password: PrivateKeysDataProvider {
    public var privateKeysData: Data {
        data
    }
}
