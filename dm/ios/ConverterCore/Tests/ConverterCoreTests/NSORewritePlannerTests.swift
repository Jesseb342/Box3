import XCTest
@testable import ConverterCore

final class NSORewritePlannerTests: XCTestCase {
    func testClassifiesSystemCallsAndSystemRegisterSites() throws {
        let instructions = [
            decoded(0xD4001001, "svc", "#0x80"),
            decoded(0xD53BD043, "mrs", "x3, tpidr_el0"),
            decoded(0xD51BD047, "msr", "tpidr_el0, x7"),
            decoded(0xD53BD061, "mrs", "x1, tpidrro_el0"),
            decoded(0xD53BE025, "mrs", "x5, cntpct_el0"),
            decoded(0xD53BE046, "mrs", "x6, cntvct_el0"),
            decoded(0xD53B0027, "mrs", "x7, ctr_el0")
        ]
        let plan = try NSORewritePlanner.plan(
            instructions: instructions,
            codeRanges: [try NSOCodeRange(start: 0, end: 28)]
        )
        XCTAssertEqual(plan.sites.map(\.kind), [
            .svc, .tpidrRead, .tpidrWrite, .tpidrroRead,
            .counterPhysicalRead, .counterVirtualRead, .cacheTypeRead
        ])
        XCTAssertEqual(plan.sites[0].argument, 0x80)
        XCTAssertEqual(plan.sites[4].argument, 5)
    }

    func testClassifiesSimpleAndComplexX18SitesSeparately() throws {
        let instructions = [
            decoded(0x8B010240, "add", "x0, x18, x1", address: 0x1000, registers: ["x0", "x1", "x18"]),
            decoded(0xD61F0240, "br", "x18", address: 0x1004, registers: ["x18"]),
            decoded(0xD63F0240, "blr", "x18", address: 0x1008, registers: ["x18"]),
            decoded(0xB4000052, "cbz", "x18, #0x1010", address: 0x100C, registers: ["x18"]),
            decoded(0x90000012, "adrp", "x18, #0x2000", address: 0x1010, registers: ["x18"])
        ]
        let plan = try NSORewritePlanner.plan(
            instructions: instructions,
            codeRanges: [try NSOCodeRange(start: 0x1000, end: 0x1014)]
        )
        XCTAssertEqual(plan.sites.map(\.kind), [
            .x18Plain, .x18IndirectBranch, .x18IndirectCall,
            .x18Conditional, .x18PCRelative
        ])
    }

    func testDetectsStackPointerDestination() throws {
        let instruction = decoded(
            0x910003FF, "mov", "sp, x18",
            registers: ["sp", "x18"]
        )
        let plan = try NSORewritePlanner.plan(
            instructions: [instruction],
            codeRanges: [try NSOCodeRange(start: 0, end: 4)]
        )
        XCTAssertEqual(plan.sites.first?.kind, .x18StackPointer)
    }

    func testRejectsMissingInstructionInsideCodeRange() throws {
        XCTAssertThrowsError(try NSORewritePlanner.plan(
            instructions: [decoded(0xD503201F, "nop", "")],
            codeRanges: [try NSOCodeRange(start: 0, end: 8)]
        )) {
            XCTAssertEqual($0 as? NSORewritePlanningError, .nonContiguousCodeRange(4))
        }
    }

    func testRejectsOverlappingCodeRanges() throws {
        XCTAssertThrowsError(try NSORewritePlanner.plan(
            instructions: [],
            codeRanges: [
                try NSOCodeRange(start: 0, end: 8),
                try NSOCodeRange(start: 4, end: 12)
            ]
        )) {
            XCTAssertEqual($0 as? NSORewritePlanningError, .overlappingCodeRanges)
        }
    }

    private func decoded(
        _ word: UInt32,
        _ mnemonic: String,
        _ operands: String,
        address: UInt64 = 0,
        registers: Set<String> = []
    ) -> DecodedAArch64Instruction {
        DecodedAArch64Instruction(
            address: address,
            word: word,
            mnemonic: mnemonic,
            operandString: operands,
            registersRead: registers,
            registersWritten: registers,
            registersMentioned: registers
        )
    }
}
