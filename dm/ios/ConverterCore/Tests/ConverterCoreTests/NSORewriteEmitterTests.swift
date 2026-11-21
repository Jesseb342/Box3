import XCTest
@testable import ConverterCore

final class NSORewriteEmitterTests: XCTestCase {
    func testEmitsPlainX18BlockWithKeyPageFixup() throws {
        let decoder = try AArch64Disassembler()
        let decoded = try XCTUnwrap(decoder.disassemble(
            Data([0x40, 0x02, 0x01, 0x8b]),
            at: 0x1000
        ).first)
        let plan = try NSORewritePlanner.plan(
            instructions: [decoded],
            codeRanges: [try NSOCodeRange(start: 0x1000, end: 0x1004)]
        )
        let site = try XCTUnwrap(plan.sites.first)
        let block = try NSORewriteEmitter.emitPlainX18(
            site,
            patchAddress: 0x2000,
            keyPageOffset: 0x8000,
            decoder: decoder
        )
        XCTAssertEqual(block.words.count, 10)
        XCTAssertEqual(block.words[0], 0xA93F0FE2) // stp x2, x3, [sp, #-16]
        XCTAssertEqual(block.words[1], 0xD53BD063) // mrs x3, tpidrro_el0
        XCTAssertEqual(block.words[6], 0x8B010040) // add x0, x2, x1
        XCTAssertEqual(block.fixups, [NSORewriteFixup(byteOffset: 8, key: "K18")])
        XCTAssertEqual(block.data.count, 40)
        let decodedBlock = try decoder.disassemble(block.data, at: 0x2000)
        XCTAssertEqual(decodedBlock.count, 10)
        XCTAssertEqual(decodedBlock[0].mnemonic, "stp")
        XCTAssertEqual(decodedBlock[2].mnemonic, "adrp")
        XCTAssertEqual(decodedBlock[6].operandString, "x0, x2, x1")
        XCTAssertEqual(decodedBlock[9].mnemonic, "b")
    }

    func testRejectsStackPointerDestination() throws {
        let site = NSORewriteSite(
            address: 0x1000,
            kind: .x18StackPointer,
            argument: nil,
            instructionWord: 0x9100025F,
            mnemonic: "add",
            operands: "sp, x18, #0"
        )
        XCTAssertThrowsError(try NSORewriteEmitter.emitPlainX18(
            site,
            patchAddress: 0x2000,
            keyPageOffset: 0x8000,
            decoder: try AArch64Disassembler()
        )) {
            XCTAssertEqual($0 as? NSORewriteEmissionError, .unsupportedSite(.x18StackPointer))
        }
    }

    func testRejectsStackWritebackSiteEvenIfMisclassified() throws {
        let site = NSORewriteSite(
            address: 0x1000,
            kind: .x18Plain,
            argument: nil,
            instructionWord: 0xA9BF4FF2,
            mnemonic: "stp",
            operands: "x18, x19, [sp, #-0x10]!"
        )
        XCTAssertThrowsError(try NSORewriteEmitter.emitPlainX18(
            site,
            patchAddress: 0x2000,
            keyPageOffset: 0x8000,
            decoder: try AArch64Disassembler()
        )) {
            XCTAssertEqual($0 as? NSORewriteEmissionError, .stackPointerWritebackNotSupported)
        }
    }
}
