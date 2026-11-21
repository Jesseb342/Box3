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

    func testCombinesPlainX18AndTPIDRReadStubs() throws {
        let decoder = try AArch64Disassembler()
        let code = Data([
            0x40, 0x02, 0x01, 0x8b, // add x0, x18, x1
            0x43, 0xd0, 0x3b, 0xd5  // mrs x3, tpidr_el0
        ])
        let plan = try NSORewritePlanner.plan(
            image: code,
            codeRanges: [try NSOCodeRange(start: 0, end: 8)],
            decoder: decoder
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
        let plan = try NSORewritePlanner.plan(
            image: base,
            codeRanges: [try NSOCodeRange(start: 0x1000, end: 0x1010)],
            decoder: decoder
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
                    kind: .x18Conditional,
                    argument: nil,
                    instructionWord: 0xB4000052,
                    mnemonic: "cbz",
                    operands: "x18, #0x1010"
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
            XCTAssertEqual($0 as? NSORewriteBatchError, .unsupportedSite(.x18Conditional, 0x1004))
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
