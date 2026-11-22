import Foundation
import XCTest
@testable import ConverterCore

final class TitleKeysTests: XCTestCase {
    func testParsesRightsIDTitleKeyPairsCaseInsensitively() throws {
        let rights = "010003000e1468000000000000000008"
        let encrypted = "8fa820b219781d331cca08968e6e5b52"
        let keys = try TitleKeys(text: "; comment\n\(rights.uppercased()) = \(encrypted) ; trailing comment\nnon-key line")
        XCTAssertEqual(keys.encryptedTitleKey(for: try data(rights)), try data(encrypted))
    }

    func testRejectsInvalidRightsIDAndTitleKeyLengths() {
        XCTAssertThrowsError(try TitleKeys(text: "abcd=00112233445566778899aabbccddeeff")) {
            XCTAssertEqual($0 as? TitleKeysError, .invalidRightsID(1))
        }
        XCTAssertThrowsError(try TitleKeys(text: "010003000e1468000000000000000008=abcd")) {
            XCTAssertEqual($0 as? TitleKeysError, .invalidTitleKey(1))
        }
    }

    func testRejectsDuplicateRightsIDs() {
        let line = "010003000e1468000000000000000008=00112233445566778899aabbccddeeff"
        XCTAssertThrowsError(try TitleKeys(text: line + "\n" + line)) {
            XCTAssertEqual($0 as? TitleKeysError,
                           .duplicateRightsID(2, "010003000e1468000000000000000008"))
        }
    }

    func testRejectsEmptyTitleKeysFile() {
        XCTAssertThrowsError(try TitleKeys(text: "; comment\nnot a pair")) {
            XCTAssertEqual($0 as? TitleKeysError, .noKeysFound)
        }
    }

    private func data(_ hex: String) throws -> Data {
        let chars = Array(hex)
        var result = Data()
        for i in stride(from: 0, to: chars.count, by: 2) {
            guard let byte = UInt8(String(chars[i...i+1]), radix: 16) else {
                throw NSError(domain: "test", code: 1)
            }
            result.append(byte)
        }
        return result
    }
}
