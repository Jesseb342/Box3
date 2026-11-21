import Foundation
import XCTest
@testable import ConverterCore

final class NSORewritePipelineTests: XCTestCase {
    func testRunsNSOReconstructionPlanningAndEmissionAsOneOperation() throws {
        let file = makeNSO(text: Data([
            0x40, 0x02, 0x01, 0x8b // add x0, x18, x1
        ]), codeOffset: 0x100)
        let result = try NSORewritePipeline.process(
            file: file,
            codeRanges: [try NSOCodeRange(start: 0x100, end: 0x104)]
        )

        XCTAssertEqual(result.module.buildIDHex, "0102030405060708090a0b0c0d0e0f10")
        XCTAssertFalse(result.layout.isFar)
        XCTAssertEqual(result.plan.sites.map(\.kind), [.x18Plain])
        XCTAssertEqual(result.emission.patchedSiteCount, 1)
        XCTAssertEqual(result.emission.fixups, [
            NSORewriteFixup(byteOffset: 8, key: "K18")
        ])
        XCTAssertEqual(result.outputData.count,
                       Int(result.layout.patchOffset) + result.emission.patchData.count)
    }

    func testRejectsCodeRangesOutsideTextBeforeEmission() throws {
        let file = makeNSO(text: Data([0, 0, 0, 0]), codeOffset: 0)
        XCTAssertThrowsError(try NSORewritePipeline.process(
            file: file,
            codeRanges: [try NSOCodeRange(start: 0x1000, end: 0x1004)]
        )) {
            XCTAssertEqual(
                $0 as? NSORewritePipelineError,
                .codeRangeOutsideText(start: 0x1000, end: 0x1004, textSize: 0x1000)
            )
        }
    }

    func testRejectsEmptyCodeRangeList() throws {
        let file = makeNSO(text: Data([0, 0, 0, 0]), codeOffset: 0)
        XCTAssertThrowsError(try NSORewritePipeline.process(file: file, codeRanges: [])) {
            XCTAssertEqual($0 as? NSORewritePipelineError, .noCodeRanges)
        }
    }

    private func makeNSO(text: Data, codeOffset: Int) -> Data {
        let segmentSize = 0x1000
        let fileOffsets = [0x70, 0x70 + segmentSize, 0x70 + 2 * segmentSize]
        var file = Data(repeating: 0, count: 0x70 + 3 * segmentSize)
        file.replaceSubrange(0..<4, with: Data("NSO0".utf8))
        write32(0, to: &file, at: 0x04)
        write32(0, to: &file, at: 0x0c)

        let memoryOffsets = [0, segmentSize, 2 * segmentSize]
        for index in 0..<3 {
            let descriptor = 0x10 + index * 0x10
            write32(UInt32(fileOffsets[index]), to: &file, at: descriptor)
            write32(UInt32(memoryOffsets[index]), to: &file, at: descriptor + 4)
            write32(UInt32(segmentSize), to: &file, at: descriptor + 8)
            write32(UInt32(segmentSize), to: &file, at: 0x60 + index * 4)
        }
        write32(0x1000, to: &file, at: 0x3c)
        file.replaceSubrange(0x40..<0x50, with: Data((1...16).map(UInt8.init)))
        file.replaceSubrange(
            (fileOffsets[0] + codeOffset)..<(fileOffsets[0] + codeOffset + text.count),
            with: text
        )
        return file
    }

    private func write32(_ value: UInt32, to data: inout Data, at offset: Int) {
        for index in 0..<4 {
            data[offset + index] = UInt8((value >> (index * 8)) & 0xff)
        }
    }
}
