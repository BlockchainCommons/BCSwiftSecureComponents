import Testing
import SecureComponents
import WolfBase

struct PasswordTests {
    @Test func testPassword() {
        let password = "fnord"
        let securePassword = Password(password, salt: "salt", n: 8)!
        #expect(securePassword.privateKeysData == ‡"5d6280a79431b6f21af75654591cc7a3ab49e3c64961c1c6914dae9822404624")
        #expect(securePassword.isValid(password))
        #expect(!securePassword.isValid("blat"))
    }
}
