import XCTest
import SecureComponents
import WolfBase

class PasswordTests: XCTestCase {
    func testPassword() {
        let password = "fnord"
        let securePassword = Password(password, salt: "salt", n: 8)!
        XCTAssertEqual(securePassword.privateKeysData, ‡"5d6280a79431b6f21af75654591cc7a3ab49e3c64961c1c6914dae9822404624")
        XCTAssertTrue(securePassword.isValid(password))
        XCTAssertFalse(securePassword.isValid("blat"))
    }
}
