import Foundation
import XCTest
@testable import ConverterCore

final class AArch64RegisterSubstitutionTests: XCTestCase {
    func testSubstitutesX18WithoutChangingOtherOperands() throws {
        let decoder = try AArch64Disassembler()
        let original = try XCTUnwrap(decoder.disassemble(
            Data([0x40, 0x02, 0x01, 0x8b]),
            at: 0x1000
        ).first)
        XCTAssertEqual(original.operandString, "x0, x18, x1")

        let rewritten = try AArch64RegisterSubstitution.replaceX18(
            in: original,
            with: 9,
            decoder: decoder
        )
        XCTAssertEqual(rewritten, 0x8B010120)

        var bytes = rewritten.littleEndian
        let rewrittenData = withUnsafeBytes(of: &bytes) { Data($0) }
        let decoded = try XCTUnwrap(decoder.disassemble(rewrittenData, at: 0x1000).first)
        XCTAssertEqual(decoded.mnemonic, original.mnemonic)
        XCTAssertEqual(decoded.operandString, "x0, x9, x1")
        XCTAssertFalse(decoded.mentionsX18)
    }

    func testRejectsReplacementOutsideScratchRegisterPool() throws {
        let decoder = try AArch64Disassembler()
        let original = try XCTUnwrap(decoder.disassemble(
            Data([0x40, 0x02, 0x01, 0x8b])
        ).first)
        XCTAssertThrowsError(try AArch64RegisterSubstitution.replaceX18(
            in: original,
            with: 18,
            decoder: decoder
        )) {
            XCTAssertEqual($0 as? AArch64SubstitutionError, .invalidReplacementRegister(18))
        }
    }

    func testRejectsInstructionWithoutX18() throws {
        let decoder = try AArch64Disassembler()
        let original = try XCTUnwrap(decoder.disassemble(
            Data([0x1f, 0x20, 0x03, 0xd5])
        ).first)
        XCTAssertThrowsError(try AArch64RegisterSubstitution.replaceX18(
            in: original,
            with: 9,
            decoder: decoder
        )) {
            XCTAssertEqual($0 as? AArch64SubstitutionError, .instructionDoesNotMentionX18)
        }
    }
}
