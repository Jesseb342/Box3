import XCTest
@testable import ConverterCore

final class AArch64EncoderTests: XCTestCase {
    func testKnownInstructionWords() throws {
        XCTAssertEqual(try AArch64Encoder.b(from: 0x1000, to: 0x1004), 0x14000001)
        XCTAssertEqual(try AArch64Encoder.beq(from: 0x1000, to: 0x1008), 0x54000040)
        XCTAssertEqual(try AArch64Encoder.stp(0, 1, base: 31, offset: -16), 0xA93F07E0)
        XCTAssertEqual(try AArch64Encoder.ldp(0, 1, base: 31, offset: 0), 0xA94007E0)
        XCTAssertEqual(try AArch64Encoder.mrsTPIDRRO(3), 0xD53BD063)
        XCTAssertEqual(try AArch64Encoder.branchRegister(16), 0xD61F0200)
        XCTAssertEqual(AArch64Encoder.nop, 0xD503201F)
    }

    func testEncodesSignedUnscaledOffsets() throws {
        XCTAssertEqual(try AArch64Encoder.stur(3, base: 4, offset: -8), 0xF81F8083)
        XCTAssertEqual(try AArch64Encoder.ldur(3, base: 4, offset: 8), 0xF8408083)
    }

    func testRejectsUnalignedBranch() {
        XCTAssertThrowsError(try AArch64Encoder.b(from: 0x1000, to: 0x1002)) {
            XCTAssertEqual($0 as? AArch64EncodingError, .unalignedBranch)
        }
    }

    func testRejectsOutOfRangeBranch() {
        XCTAssertThrowsError(try AArch64Encoder.b(from: 0, to: 0x10000000)) {
            XCTAssertEqual($0 as? AArch64EncodingError, .branchOutOfRange)
        }
    }

    func testRejectsInvalidPairOffset() {
        XCTAssertThrowsError(try AArch64Encoder.stp(0, 1, base: 31, offset: 7)) {
            XCTAssertEqual($0 as? AArch64EncodingError, .invalidImmediate)
        }
    }

    func testRejectsInvalidRegister() {
        XCTAssertThrowsError(try AArch64Encoder.branchRegister(32)) {
            XCTAssertEqual($0 as? AArch64EncodingError, .invalidRegister(32))
        }
    }

    func testEncodesADRPWithinPageRange() throws {
        XCTAssertEqual(
            try AArch64Encoder.adrp(3, pc: 0x1000, target: 0x3000),
            0xD0000003
        )
    }

    func testRejectsADRPOutOfRange() {
        XCTAssertThrowsError(
            try AArch64Encoder.adrp(0, pc: 0, target: Int64(1) << 33)
        ) {
            XCTAssertEqual($0 as? AArch64EncodingError, .adrpOutOfRange)
        }
    }
}
