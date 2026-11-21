import Foundation
import XCTest
@testable import ConverterCore

final class AArch64DisassemblerTests: XCTestCase {
    func testDecodesNOPAndSystemRegisterRead() throws {
        let decoder = try AArch64Disassembler()
        let code = Data([
            0x1f, 0x20, 0x03, 0xd5, // nop
            0x63, 0xd0, 0x3b, 0xd5  // mrs x3, tpidrro_el0
        ])
        let instructions = try decoder.disassemble(code, at: 0x1000)
        XCTAssertEqual(instructions.count, 2)
        XCTAssertEqual(instructions[0].mnemonic, "nop")
        XCTAssertEqual(instructions[0].address, 0x1000)
        XCTAssertEqual(instructions[1].mnemonic, "mrs")
        XCTAssertTrue(instructions[1].operandString.contains("tpidrro_el0"))
    }

    func testExposesRegisterReadWriteDetail() throws {
        let decoder = try AArch64Disassembler()
        // add x0, x18, x1
        let code = Data([0x40, 0x02, 0x01, 0x8b])
        let instruction = try XCTUnwrap(decoder.disassemble(code).first)
        let reads = instruction.registersRead
        let writes = instruction.registersWritten
        XCTAssertTrue(reads.contains("x18"))
        XCTAssertTrue(writes.contains("x0"))
    }

    func testRejectsPartialInstruction() throws {
        let decoder = try AArch64Disassembler()
        XCTAssertThrowsError(try decoder.disassemble(Data([0x1f, 0x20, 0x03])))
        { XCTAssertEqual($0 as? AArch64DisassemblyError, .inputNotWordAligned(3)) }
    }

    func testAcceptsEmptyInput() throws {
        let decoder = try AArch64Disassembler()
        XCTAssertEqual(try decoder.disassemble(Data()), [])
    }

}
