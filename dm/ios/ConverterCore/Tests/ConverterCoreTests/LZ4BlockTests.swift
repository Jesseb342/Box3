import Foundation
import XCTest
@testable import ConverterCore

final class LZ4BlockTests: XCTestCase {
    func testDecodesLiteralOnlyBlock() throws {
        let encoded = Data([0x50, 0x48, 0x65, 0x6c, 0x6c, 0x6f])
        XCTAssertEqual(try LZ4Block.decompress(encoded, expectedSize: 5), Data("Hello".utf8))
    }

    func testDecodesOverlappingMatch() throws {
        // "abc" followed by a length-9 match at offset 3 -> "abcabcabcabc".
        let encoded = Data([0x35, 0x61, 0x62, 0x63, 0x03, 0x00])
        XCTAssertEqual(
            try LZ4Block.decompress(encoded, expectedSize: 12),
            Data("abcabcabcabc".utf8)
        )
    }

    func testDecodesExtendedLiteralLength() throws {
        let literal = Array(repeating: UInt8(0x41), count: 20)
        let encoded = Data([0xf5, 0x05] + literal)
        XCTAssertEqual(try LZ4Block.decompress(encoded, expectedSize: 20), Data(literal))
    }

    func testDecodesExtendedMatchLength() throws {
        // One literal followed by a match of 19 bytes at distance 1.
        // Token low nibble 15 means 19-byte match after the mandatory +4.
        let encoded = Data([0x1f, 0x41, 0x01, 0x00, 0x00])
        XCTAssertEqual(
            try LZ4Block.decompress(encoded, expectedSize: 20),
            Data(repeating: 0x41, count: 20)
        )
    }

    func testRejectsTruncatedLiteralLength() {
        XCTAssertThrowsError(try LZ4Block.decompress(Data([0xf0]), expectedSize: 15)) {
            XCTAssertEqual($0 as? LZ4BlockError, .truncatedLiteralLength)
        }
    }

    func testRejectsTruncatedLiterals() {
        XCTAssertThrowsError(try LZ4Block.decompress(Data([0x30, 1, 2]), expectedSize: 3)) {
            XCTAssertEqual($0 as? LZ4BlockError, .truncatedLiterals)
        }
    }

    func testRejectsZeroOffset() {
        XCTAssertThrowsError(
            try LZ4Block.decompress(Data([0x10, 0x41, 0x00, 0x00]), expectedSize: 5)
        ) {
            XCTAssertEqual($0 as? LZ4BlockError, .zeroMatchOffset)
        }
    }

    func testRejectsOffsetBeforeOutput() {
        XCTAssertThrowsError(
            try LZ4Block.decompress(Data([0x10, 0x41, 0x02, 0x00]), expectedSize: 5)
        ) {
            XCTAssertEqual($0 as? LZ4BlockError, .matchBeforeOutput)
        }
    }

    func testRejectsOutputOverrun() {
        XCTAssertThrowsError(
            try LZ4Block.decompress(Data([0x50, 1, 2, 3, 4, 5]), expectedSize: 4)
        ) {
            XCTAssertEqual($0 as? LZ4BlockError, .outputExceedsExpectedSize)
        }
    }

    func testRejectsOutputUnderrun() {
        XCTAssertThrowsError(
            try LZ4Block.decompress(Data([0x20, 1, 2]), expectedSize: 3)
        ) {
            XCTAssertEqual(
                $0 as? LZ4BlockError,
                .outputSizeMismatch(expected: 3, actual: 2)
            )
        }
    }

    func testRejectsTruncatedMatchOffset() {
        XCTAssertThrowsError(
            try LZ4Block.decompress(Data([0x10, 0x41, 0x01]), expectedSize: 5)
        ) {
            XCTAssertEqual($0 as? LZ4BlockError, .truncatedMatchOffset)
        }
    }

    func testRejectsTruncatedMatchLength() {
        // Literal, offset, then a match nibble requiring an extension byte.
        XCTAssertThrowsError(
            try LZ4Block.decompress(Data([0x1f, 0x41, 0x01, 0x00]), expectedSize: 20)
        ) {
            XCTAssertEqual($0 as? LZ4BlockError, .truncatedMatchLength)
        }
    }

    func testHandlesEmptyBlock() throws {
        XCTAssertEqual(try LZ4Block.decompress(Data(), expectedSize: 0), Data())
    }
}
