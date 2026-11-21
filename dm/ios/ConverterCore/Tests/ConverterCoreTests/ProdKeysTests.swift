import XCTest
@testable import ConverterCore

final class ProdKeysTests: XCTestCase {
    func testParsesCommentsWhitespaceAndHexValues() throws {
        let keys = try ProdKeys(text: """
            # console key dump
            master_key_00 = 001122aAbBcCdDeE
            header_key=ffeeddccbbaa9988
            """)
        XCTAssertEqual(keys.names, ["header_key", "master_key_00"])
        XCTAssertEqual(keys.value(for: "master_key_00"), Data([
            0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc, 0xdd, 0xee
        ]))
        XCTAssertTrue(keys.contains("header_key"))
        XCTAssertNil(keys.value(for: "missing_key"))
    }

    func testRejectsMalformedLine() {
        XCTAssertThrowsError(try ProdKeys(text: "not-a-key-line")) { error in
            XCTAssertEqual(error as? ProdKeysError, .malformedLine(1))
        }
    }

    func testRejectsOddLengthHex() {
        XCTAssertThrowsError(try ProdKeys(text: "header_key=abc")) { error in
            XCTAssertEqual(error as? ProdKeysError, .invalidHex(1))
        }
    }

    func testRejectsNonHexCharacters() {
        XCTAssertThrowsError(try ProdKeys(text: "header_key=00xz")) { error in
            XCTAssertEqual(error as? ProdKeysError, .invalidHex(1))
        }
    }

    func testRejectsDuplicateNames() {
        XCTAssertThrowsError(try ProdKeys(text: """
            header_key=0011
            header_key=2233
            """)) { error in
            XCTAssertEqual(error as? ProdKeysError, .duplicateKey(2, "header_key"))
        }
    }

    func testRejectsEmptyKeyFile() {
        XCTAssertThrowsError(try ProdKeys(text: "# only a comment\n\n")) { error in
            XCTAssertEqual(error as? ProdKeysError, .noKeysFound)
        }
    }
}
