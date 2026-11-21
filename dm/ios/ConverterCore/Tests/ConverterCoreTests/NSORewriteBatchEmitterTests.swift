import Foundation
import XCTest
@testable import ConverterCore

final class NSORewriteBatchEmitterTests: XCTestCase {
    func testBuildsNearImageAndAppendsPatchArea() throws {
        let decoder = try AArch64Disassembler()
        let original = try XCTUnwrap(decoder.disassemble(
            Data([0x40, 0x02, 0x01, 0x8b]),
            at: 0x1000
        ).first)
        let plan = try NSORewritePlanner.plan(
            instructions: [original],
            codeRanges: [try NSOCodeRange(start: 0x1000, end: 0x1004)]
        )
        let layout = try NSOPatchLayout.make(
            segments: [
                segment(0, 0, 0x2000),
                segment(1, 0x2000, 0x1000),
                segment(2, 0x3000, 0x1000)
            ],
            bssSize: 0x2000
        )
        var base = Data(repeating: 0, count: Int(layout.fileImageLength))
        base[0x1000] = 0x40
        base[0x1001] = 0x02
        base[0x1002] = 0x01
        base[0x1003] = 0x8b

        let result = try NSORewriteBatchEmitter.emitSupportedSites(
            baseImage: base,
            plan: plan,
            layout: layout,
            decoder: decoder
        )
        XCTAssertEqual(result.patchedSiteCount, 1)
        XCTAssertEqual(result.patchData.count, 40)
        XCTAssertEqual(result.fixups, [NSORewriteFixup(byteOffset: 8, key: "K18")])
        XCTAssertEqual(result.fileData.count, Int(layout.patchOffset) + 40)

        let branchBytes = result.fileData[0x1000..<0x1004]
        let branchWord = branchBytes.enumerated().reduce(UInt32(0)) {
            $0 | (UInt32($1.element) << (8 * $1.offset))
        }
        XCTAssertEqual(branchWord, try AArch64Encoder.b(from: 0x1000, to: layout.patchOffset))
    }

    func testBatchEmitsX18ADRPRewrite() throws {
        let decoder = try AArch64Disassembler()
        let code = Data([0x32, 0x00, 0x00, 0x90]) // adrp x18, #0x5000 at 0x1000
        let instruction = try XCTUnwrap(decoder.disassemble(code, at: 0x1000).first)
        let plan = try NSORewritePlanner.plan(
            instructions: [instruction],
            codeRanges: [try NSOCodeRange(start: 0x1000, end: 0x1004)]
        )
        let layout = try NSOPatchLayout.make(
            segments: [
                segment(0, 0, 0x2000),
                segment(1, 0x2000, 0x1000),
                segment(2, 0x3000, 0x1000)
            ],
            bssSize: 0x2000
        )
        var base = Data(repeating: 0, count: Int(layout.fileImageLength))
        base.replaceSubrange(0x1000..<0x1004, with: code)
        let result = try NSORewriteBatchEmitter.emitSupportedSites(
            baseImage: base, plan: plan, layout: layout, decoder: decoder
        )
        XCTAssertEqual(result.patchedSiteCount, 1)
        XCTAssertEqual(result.patchData.count, 36)
        XCTAssertEqual(result.fixups, [NSORewriteFixup(byteOffset: 8, key: "K18")])
    }

    func testCombinesPlainX18AndTPIDRReadStubs() throws {
        let decoder = try AArch64Disassembler()
        let code = Data([
            0x40, 0x02, 0x01, 0x8b, // add x0, x18, x1
            0x43, 0xd0, 0x3b, 0xd5  // mrs x3, tpidr_el0
        ])
        let instructions = try decoder.disassemble(code)
        let plan = try NSORewritePlanner.plan(
            instructions: instructions,
            codeRanges: [try NSOCodeRange(start: 0, end: 8)]
        )
        let layout = try NSOPatchLayout.make(
            segments: [
                segment(0, 0, 0x2000),
                segment(1, 0x2000, 0x1000),
                segment(2, 0x3000, 0x1000)
            ],
            bssSize: 0x2000
        )
        var base = Data(repeating: 0, count: Int(layout.fileImageLength))
        base.replaceSubrange(0..<8, with: code)
        let result = try NSORewriteBatchEmitter.emitSupportedSites(
            baseImage: base,
            plan: plan,
            layout: layout,
            decoder: decoder
        )
        XCTAssertEqual(result.patchedSiteCount, 2)
        XCTAssertEqual(result.patchData.count, 72)
        XCTAssertEqual(result.fixups, [
            NSORewriteFixup(byteOffset: 8, key: "K18"),
            NSORewriteFixup(byteOffset: 48, key: "KTLS")
        ])
    }

    func testBatchEmitsHostGatesStackAlignmentAndCTRConstant() throws {
        let decoder = try AArch64Disassembler()
        let layout = try NSOPatchLayout.make(
            segments: [
                segment(0, 0, 0x2000),
                segment(1, 0x2000, 0x1000),
                segment(2, 0x3000, 0x1000)
            ],
            bssSize: 0x2000
        )
        var base = Data(repeating: 0, count: Int(layout.fileImageLength))
        let code = Data([
            0x01, 0x10, 0x00, 0xd4, // svc #0x80
            0x45, 0xe0, 0x3b, 0xd5, // mrs x5, cntvct_el0
            0xff, 0x63, 0x29, 0xcb, // sub sp, sp, x9
            0x27, 0x00, 0x3b, 0xd5  // mrs x7, ctr_el0
        ])
        base.replaceSubrange(0x1000..<0x1010, with: code)
        let instructions = try decoder.disassemble(code, at: 0x1000)
        let plan = try NSORewritePlanner.plan(
            instructions: instructions,
            codeRanges: [try NSOCodeRange(start: 0x1000, end: 0x1010)]
        )
        let result = try NSORewriteBatchEmitter.emitSupportedSites(
            baseImage: base,
            plan: plan,
            layout: layout,
            decoder: decoder
        )
        XCTAssertEqual(result.patchedSiteCount, 4)
        XCTAssertEqual(result.patchData.count, 96)
        XCTAssertEqual(result.fixups, [
            NSORewriteFixup(byteOffset: 8, key: "KGATE"),
            NSORewriteFixup(byteOffset: 48, key: "KGATE")
        ])
        XCTAssertEqual(result.gates, [
            NSORewriteGate(returnAddress: 0x10020, kind: "svc", argument: 0x80, originalAddress: 0x1000),
            NSORewriteGate(returnAddress: 0x10048, kind: "cntvct", argument: 5, originalAddress: 0x1004)
        ])
        let ctr = result.fileData[0x100C..<0x1010].enumerated().reduce(UInt32(0)) {
            $0 | (UInt32($1.element) << (8 * $1.offset))
        }
        XCTAssertEqual(ctr, 0xD2A00087)
    }

    func testRejectsMixedUnimplementedSiteKindsWithoutPartialOutput() throws {
        let plan = NSORewritePlan(
            sites: [
                NSORewriteSite(
                    address: 0x1000,
                    kind: .x18Plain,
                    argument: nil,
                    instructionWord: 0,
                    mnemonic: "add",
                    operands: "x0, x18, x1"
                ),
                NSORewriteSite(
                    address: 0x1004,
                    kind: .x18IndirectBranch,
                    argument: nil,
                    instructionWord: 0xD61F0240,
                    mnemonic: "br",
                    operands: "x18"
                )
            ],
            counts: [.x18Plain: 1, .svc: 1],
            undecodableAddresses: []
        )
        let layout = try NSOPatchLayout.make(
            segments: [
                segment(0, 0, 0x2000),
                segment(1, 0x2000, 0x1000),
                segment(2, 0x3000, 0x1000)
            ],
            bssSize: 0x2000
        )
        XCTAssertThrowsError(try NSORewriteBatchEmitter.emitSupportedSites(
            baseImage: Data(repeating: 0, count: Int(layout.fileImageLength)),
            plan: plan,
            layout: layout,
            decoder: try AArch64Disassembler()
        )) {
            XCTAssertEqual($0 as? NSORewriteBatchError, .unsupportedSite(.x18IndirectBranch, 0x1004))
        }
    }

    func testRejectsAnyUndecodableInstructionBeforeEmission() throws {
        let plan = NSORewritePlan(
            sites: [],
            counts: [:],
            undecodableAddresses: [0x1004]
        )
        let layout = try NSOPatchLayout.make(
            segments: [
                segment(0, 0, 0x2000),
                segment(1, 0x2000, 0x1000),
                segment(2, 0x3000, 0x1000)
            ],
            bssSize: 0x2000
        )
        XCTAssertThrowsError(try NSORewriteBatchEmitter.emitSupportedSites(
            baseImage: Data(repeating: 0, count: Int(layout.fileImageLength)),
            plan: plan,
            layout: layout,
            decoder: try AArch64Disassembler()
        )) {
            XCTAssertEqual(
                $0 as? NSORewriteBatchError,
                .containsUndecodableInstructions([0x1004])
            )
        }
    }

    func testRejectsChangedOriginalInstruction() throws {
        let decoder = try AArch64Disassembler()
        let instruction = try XCTUnwrap(decoder.disassemble(
            Data([0x40, 0x02, 0x01, 0x8b]),
            at: 0x1000
        ).first)
        let plan = try NSORewritePlanner.plan(
            instructions: [instruction],
            codeRanges: [try NSOCodeRange(start: 0x1000, end: 0x1004)]
        )
        let layout = try NSOPatchLayout.make(
            segments: [
                segment(0, 0, 0x2000),
                segment(1, 0x2000, 0x1000),
                segment(2, 0x3000, 0x1000)
            ],
            bssSize: 0x2000
        )
        XCTAssertThrowsError(try NSORewriteBatchEmitter.emitSupportedSites(
            baseImage: Data(repeating: 0, count: Int(layout.fileImageLength)),
            plan: plan,
            layout: layout,
            decoder: decoder
        )) {
            XCTAssertEqual(
                $0 as? NSORewriteBatchError,
                .originalInstructionMismatch(0x1000, expected: 0x8B010240, actual: 0)
            )
        }
    }

    func testBatchEmitsADREwriteAndPreservesAbsoluteAddressSemantics() throws {
        let decoder = try AArch64Disassembler()
        // Independently assembled ADR x18, #0x10 at 0x1FFC => 0x200C.
        let siteAddress: UInt64 = 0x1FFC
        let code = Data([0x92, 0x00, 0x00, 0x10])
        let instruction = try XCTUnwrap(decoder.disassemble(code, at: siteAddress).first)
        let plan = try NSORewritePlanner.plan(
            instructions: [instruction],
            codeRanges: [try NSOCodeRange(start: siteAddress, end: siteAddress + 4)]
        )
        let layout = try NSOPatchLayout.make(
            segments: [
                segment(0, 0, 0x2000),
                segment(1, 0x2000, 0x1000),
                segment(2, 0x3000, 0x1000)
            ],
            bssSize: 0x2000
        )
        var base = Data(repeating: 0, count: Int(layout.fileImageLength))
        base.replaceSubrange(Int(siteAddress)..<Int(siteAddress + 4), with: code)

        let result = try NSORewriteBatchEmitter.emitSupportedSites(
            baseImage: base, plan: plan, layout: layout, decoder: decoder
        )
        XCTAssertEqual(result.patchedSiteCount, 1)
        XCTAssertEqual(result.fixups, [NSORewriteFixup(byteOffset: 8, key: "K18")])

        let branchWord = readWord(result.fileData, at: Int(siteAddress))
        XCTAssertEqual(branchTarget(branchWord, pc: Int64(siteAddress)), layout.patchOffset)

        let patchInstructions = try decoder.disassemble(
            result.patchData, at: UInt64(layout.patchOffset)
        )
        XCTAssertEqual(patchInstructions.map(\\.mnemonic),
                       ["stp", "mrs", "adrp", "ldr", "add", "adrp", "add", "str", "ldp", "b"])

        // Decode the emitted ADRP using the architectural immediate fields,
        // not Capstone's formatted operand text, then apply the ADD low bits.
        let targetPage = adrpTarget(
            patchInstructions[5].word,
            pc: Int64(layout.patchOffset) + 20
        )
        let lowOffset = Int((patchInstructions[6].word >> 10) & 0xFFF)
        XCTAssertEqual(targetPage + Int64(lowOffset), 0x200C)
        XCTAssertEqual(patchInstructions[8].mnemonic, "ldp")
        XCTAssertEqual(patchInstructions[9].mnemonic, "b")
        XCTAssertEqual(branchTarget(patchInstructions[9].word,
                                    pc: Int64(layout.patchOffset) + 36),
                       Int64(siteAddress + 4))
    }

    private func readWord(_ data: Data, at offset: Int) -> UInt32 {
        UInt32(data[offset]) |
            (UInt32(data[offset + 1]) << 8) |
            (UInt32(data[offset + 2]) << 16) |
            (UInt32(data[offset + 3]) << 24)
    }

    private func signExtend(_ value: UInt64, bits: Int) -> Int64 {
        let shift = 64 - bits
        return Int64(bitPattern: value << shift) >> shift
    }

    private func adrpTarget(_ word: UInt32, pc: Int64) -> Int64 {
        let immlo = UInt64((word >> 29) & 0x3)
        let immhi = UInt64((word >> 5) & 0x7FFFF)
        let pages = signExtend((immhi << 2) | immlo, bits: 21)
        return (pc & ~Int64(0xFFF)) + pages * 0x1000
    }

    private func branchTarget(_ word: UInt32, pc: Int64) -> Int64 {
        let immediate = signExtend(UInt64(word & 0x03FFFFFF), bits: 26)
        return pc + immediate * 4
    }

    private func segment(_ index: Int, _ offset: UInt32, _ size: UInt32) -> NSOImage.Segment {
        NSOImage.Segment(
            index: index,
            fileOffset: 0x100,
            memoryOffset: offset,
            memorySize: size,
            storedSize: size,
            isCompressed: false
        )
    }
}
