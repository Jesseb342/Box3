import Foundation
import XCTest
@testable import ConverterCore

final class NSOSegmentLoaderTests: XCTestCase {
    func testReconstructsUncompressedSegments() throws {
        let file = makeNSO()
        let image = try NSOImage(data: file)
        let segments = try image.decompressedSegments(from: file)
        XCTAssertEqual(segments.count, 3)
        XCTAssertEqual(segments[0], Data(repeating: 0x11, count: 4))
        XCTAssertEqual(segments[1], Data(repeating: 0x22, count: 4))
        XCTAssertEqual(segments[2], Data(repeating: 0x33, count: 4))
    }

    func testDecompressesCompressedSegment() throws {
        var file = makeNSO()
        // Segment 0: four stored bytes decode to eight repeated 0x11 bytes.
        file.replaceSubrange(0x100..<0x104, with: Data([0x13, 0x11, 0x01, 0x00]))
        putLE(UInt32(4), at: 0x60, in: &file)
        putLE(UInt32(8), at: 0x18, in: &file)
        putLE(UInt32(8), at: 0x24, in: &file)
        // Keep segment 1 and 2 payload ranges non-overlapping.
        putLE(UInt32(0x108), at: 0x20, in: &file)
        putLE(UInt32(0x10c), at: 0x30, in: &file)
        file.replaceSubrange(0x108..<0x10c, with: Data(repeating: 0x22, count: 4))
        file.replaceSubrange(0x10c..<0x110, with: Data(repeating: 0x33, count: 4))
        putLE(UInt32(4), at: 0x64, in: &file)
        putLE(UInt32(4), at: 0x68, in: &file)
        putLE(UInt32(0b001), at: 0x0c, in: &file)

        let image = try NSOImage(data: file)
        let segments = try image.decompressedSegments(from: file)
        XCTAssertEqual(segments[0], Data(repeating: 0x11, count: 8))
    }

    func testRejectsDifferentSourceFile() throws {
        let file = makeNSO()
        let image = try NSOImage(data: file)
        XCTAssertThrowsError(try image.decompressedSegments(from: Data()))
    }

    func testReconstructsContiguousNearImageWithZeroFilledGapsAndKeyPage() throws {
        let file = makeNSO()
        let nso = try NSOImage(data: file)
        let layout = try NSOPatchLayout.make(segments: nso.segments, bssSize: nso.bssSize)

        XCTAssertFalse(layout.isFar)
        XCTAssertEqual(layout.keyPageOffset, 0x4000)
        XCTAssertEqual(layout.fileImageLength, 0x8000)

        let image = try nso.reconstructedImage(from: file, layout: layout)
        XCTAssertEqual(image.count, Int(layout.fileImageLength))
        XCTAssertEqual(image.subdata(in: 0..<4), Data(repeating: 0x11, count: 4))
        XCTAssertEqual(image.subdata(in: 0x10..<0x14), Data(repeating: 0x22, count: 4))
        XCTAssertEqual(image.subdata(in: 0x20..<0x24), Data(repeating: 0x33, count: 4))
        XCTAssertEqual(image.subdata(in: 0x04..<0x10), Data(repeating: 0, count: 0x0c))
        XCTAssertEqual(image.subdata(in: 0x4000..<0x8000), Data(repeating: 0, count: 0x4000))
    }

    func testReconstructsFarImageWithoutMaterializingBSSOrKeyPage() throws {
        var file = makeNSO()
        putLE(UInt32(0x07000000), at: 0x3c, in: &file)
        let nso = try NSOImage(data: file)
        let layout = try NSOPatchLayout.make(segments: nso.segments, bssSize: nso.bssSize)

        XCTAssertTrue(layout.isFar)
        XCTAssertGreaterThan(layout.keyPageOffset, layout.fileImageLength)
        let image = try nso.reconstructedImage(from: file, layout: layout)
        XCTAssertEqual(image.count, Int(layout.fileImageLength))
        XCTAssertEqual(image.subdata(in: 0..<4), Data(repeating: 0x11, count: 4))
        XCTAssertEqual(image.subdata(in: 0x20..<0x24), Data(repeating: 0x33, count: 4))
    }

    private func makeNSO() -> Data {
        var data = Data(repeating: 0, count: 0x200)
        data.replaceSubrange(0..<4, with: Data("NSO0".utf8))
        putLE(UInt32(0), at: 0x04, in: &data)
        putLE(UInt32(0), at: 0x0c, in: &data)
        let descriptors: [(UInt32, UInt32, UInt32, UInt8)] = [
            (0x100, 0x000, 4, 0x11),
            (0x110, 0x010, 4, 0x22),
            (0x120, 0x020, 4, 0x33)
        ]
        for (index, item) in descriptors.enumerated() {
            let offset = 0x10 + index * 0x10
            putLE(item.0, at: offset, in: &data)
            putLE(item.1, at: offset + 4, in: &data)
            putLE(item.2, at: offset + 8, in: &data)
            putLE(item.2, at: 0x60 + index * 4, in: &data)
            data.replaceSubrange(Int(item.0)..<(Int(item.0) + Int(item.2)),
                                 with: Data(repeating: item.3, count: Int(item.2)))
        }
        data.replaceSubrange(0x40..<0x60, with: Data(repeating: 0xab, count: 0x20))
        return data
    }

    private func putLE<T: FixedWidthInteger>(_ value: T, at offset: Int, in data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) {
            data.replaceSubrange(offset..<(offset + $0.count), with: $0)
        }
    }
}
