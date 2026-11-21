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

        let result = try NSORewriteBatchEmitter.emitPlainX18Sites(
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
                    kind: .svc,
                    argument: 0x80,
                    instructionWord: 0xD4001001,
                    mnemonic: "svc",
                    operands: "#0x80"
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
        XCTAssertThrowsError(try NSORewriteBatchEmitter.emitPlainX18Sites(
            baseImage: Data(repeating: 0, count: Int(layout.fileImageLength)),
            plan: plan,
            layout: layout,
            decoder: try AArch64Disassembler()
        )) {
            XCTAssertEqual($0 as? NSORewriteBatchError, .unsupportedSite(.svc, 0x1004))
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
        XCTAssertThrowsError(try NSORewriteBatchEmitter.emitPlainX18Sites(
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
