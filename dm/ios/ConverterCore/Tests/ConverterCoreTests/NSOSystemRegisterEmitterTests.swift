import Foundation
import XCTest
@testable import ConverterCore

final class NSOSystemRegisterEmitterTests: XCTestCase {
    func testEmitsTPIDRReadThroughTLSKey() throws {
        let site = NSORewriteSite(
            address: 0x1000,
            kind: .tpidrRead,
            argument: nil,
            instructionWord: 0xD53BD043,
            mnemonic: "mrs",
            operands: "x3, tpidr_el0"
        )
        let block = try NSORewriteEmitter.emitSystemRegisterRead(
            site,
            patchAddress: 0x2000,
            keyPageOffset: 0x8000
        )
        XCTAssertEqual(block.words.count, 8)
        XCTAssertEqual(block.fixups, [NSORewriteFixup(byteOffset: 8, key: "KTLS")])
        let decoder = try AArch64Disassembler()
        let decoded = try decoder.disassemble(block.data, at: 0x2000)
        XCTAssertEqual(decoded.count, 8)
        XCTAssertEqual(decoded[1].operandString, "x3, tpidrro_el0")
        XCTAssertEqual(decoded[4].mnemonic, "add")
        XCTAssertEqual(decoded[5].mnemonic, "ldr")
        XCTAssertEqual(decoded[7].mnemonic, "b")
    }

    func testEmitsTPIDRROReadThroughTLRKey() throws {
        let site = NSORewriteSite(
            address: 0x1000,
            kind: .tpidrroRead,
            argument: nil,
            instructionWord: 0xD53BD061,
            mnemonic: "mrs",
            operands: "x1, tpidrro_el0"
        )
        let block = try NSORewriteEmitter.emitSystemRegisterRead(
            site,
            patchAddress: 0x2000,
            keyPageOffset: 0x8000
        )
        XCTAssertEqual(block.fixups, [NSORewriteFixup(byteOffset: 8, key: "KTLR")])
        XCTAssertEqual(block.words.count, 8)
        let decoded = try AArch64Disassembler().disassemble(block.data, at: 0x2000)
        XCTAssertEqual(decoded.count, 8)
    }

    func testEmitsTPIDRWriteThroughTLSKey() throws {
        let site = NSORewriteSite(
            address: 0x1000,
            kind: .tpidrWrite,
            argument: nil,
            instructionWord: 0xD51BD047,
            mnemonic: "msr",
            operands: "tpidr_el0, x7"
        )
        let block = try NSORewriteEmitter.emitSystemRegisterWrite(
            site,
            patchAddress: 0x2000,
            keyPageOffset: 0x8000
        )
        XCTAssertEqual(block.words.count, 10)
        XCTAssertEqual(block.fixups, [NSORewriteFixup(byteOffset: 12, key: "KTLS")])
        let decoded = try AArch64Disassembler().disassemble(block.data, at: 0x2000)
        XCTAssertEqual(decoded.count, 10)
        XCTAssertEqual(decoded[6].mnemonic, "str")
        XCTAssertEqual(decoded[6].operandString, "x7, [x0]")
    }

    func testRejectsWrongSystemRegisterOpcode() {
        let site = NSORewriteSite(
            address: 0x1000,
            kind: .tpidrRead,
            argument: nil,
            instructionWord: 0xD53BE025,
            mnemonic: "mrs",
            operands: "x5, cntpct_el0"
        )
        XCTAssertThrowsError(try NSORewriteEmitter.emitSystemRegisterRead(
            site,
            patchAddress: 0x2000,
            keyPageOffset: 0x8000
        )) {
            XCTAssertEqual($0 as? NSORewriteEmissionError, .siteInstructionMismatch)
        }
    }
}
