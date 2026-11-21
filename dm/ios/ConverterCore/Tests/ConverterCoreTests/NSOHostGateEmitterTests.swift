import XCTest
@testable import ConverterCore

final class NSOHostGateEmitterTests: XCTestCase {
    func testEmitsSVCGateAndReturnMetadata() throws {
        let site = NSORewriteSite(
            address: 0x1000,
            kind: .svc,
            argument: 0x80,
            instructionWord: 0xD4001001,
            mnemonic: "svc",
            operands: "#0x80"
        )
        let block = try NSORewriteEmitter.emitHostGate(
            site,
            patchAddress: 0x2000,
            keyPageOffset: 0x8000
        )
        XCTAssertEqual(block.words.count, 10)
        XCTAssertEqual(block.fixups, [NSORewriteFixup(byteOffset: 8, key: "KGATE")])
        XCTAssertEqual(block.gate, NSORewriteGate(
            returnAddress: 0x2020,
            kind: "svc",
            argument: 0x80,
            originalAddress: 0x1000
        ))
        let decoded = try AArch64Disassembler().disassemble(block.data, at: 0x2000)
        XCTAssertEqual(decoded.count, 10)
        XCTAssertEqual(decoded[0].mnemonic, "stp")
        XCTAssertEqual(decoded[7].mnemonic, "blr")
        XCTAssertEqual(decoded[8].mnemonic, "ldp")
        XCTAssertEqual(decoded[9].mnemonic, "b")
    }

    func testEmitsCounterReadGate() throws {
        let site = NSORewriteSite(
            address: 0x1000,
            kind: .counterPhysicalRead,
            argument: 5,
            instructionWord: 0xD53BE025,
            mnemonic: "mrs",
            operands: "x5, cntpct_el0"
        )
        let block = try NSORewriteEmitter.emitHostGate(
            site,
            patchAddress: 0x2000,
            keyPageOffset: 0x8000
        )
        XCTAssertEqual(block.gate?.kind, "cntpct")
        XCTAssertEqual(block.gate?.argument, 5)
    }

    func testEmitsStackAlignmentStub() throws {
        let site = NSORewriteSite(
            address: 0x1000,
            kind: .stackAlignment,
            argument: 9,
            instructionWord: 0xCB2963FF,
            mnemonic: "sub",
            operands: "sp, sp, x9"
        )
        let block = try NSORewriteEmitter.emitStackAlignment(
            site,
            patchAddress: 0x2000
        )
        XCTAssertEqual(block.words.count, 4)
        XCTAssertEqual(block.words[0], try AArch64Encoder.addImmediate(9, source: 9, immediate: 15))
        XCTAssertEqual(block.words[2], site.instructionWord)
        let decoded = try AArch64Disassembler().disassemble(block.data, at: 0x2000)
        XCTAssertEqual(decoded.count, 4)
        XCTAssertEqual(decoded[0].mnemonic, "add")
        XCTAssertEqual(decoded[1].mnemonic, "and")
        XCTAssertEqual(decoded[2].mnemonic, "sub")
        XCTAssertEqual(decoded[3].mnemonic, "b")
    }

    func testRejectsCounterSiteWithWrongEncoding() {
        let site = NSORewriteSite(
            address: 0x1000,
            kind: .counterPhysicalRead,
            argument: 5,
            instructionWord: 0xD53BD043,
            mnemonic: "mrs",
            operands: "x3, tpidr_el0"
        )
        XCTAssertThrowsError(try NSORewriteEmitter.emitHostGate(
            site,
            patchAddress: 0x2000,
            keyPageOffset: 0x8000
        )) {
            XCTAssertEqual($0 as? NSORewriteEmissionError, .siteInstructionMismatch)
        }
    }
}
