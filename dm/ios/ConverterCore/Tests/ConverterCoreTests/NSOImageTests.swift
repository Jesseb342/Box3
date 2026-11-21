import Foundation
import XCTest
@testable import ConverterCore

final class NSOImageTests: XCTestCase {
    func testParsesThreeSegmentNSO() throws {
        let data = makeNSO()
        let image = try NSOImage(data: data)
        XCTAssertEqual(image.version, 0)
        XCTAssertEqual(image.flags, 0)
        XCTAssertEqual(image.segments.count, 3)
        XCTAssertEqual(image.segments[0].fileOffset, 0x100)
        XCTAssertEqual(image.segments[0].memoryOffset, 0)
        XCTAssertEqual(image.segments[0].memorySize, 0x20)
        XCTAssertEqual(image.segments[0].storedSize, 0x20)
        XCTAssertFalse(image.hasCompressedSegments)
        XCTAssertEqual(image.bssSize, 0x40)
        XCTAssertEqual(image.buildIDHex, String(repeating: "ab", count: 16))
    }

    func testRecognizesCompressedSegments() throws {
        var data = makeNSO(flags: 0b101)
        putLE(UInt32(0x10), at: 0x60, in: &data)
        putLE(UInt32(0x10), at: 0x68, in: &data)
        let image = try NSOImage(data: data)
        XCTAssertTrue(image.segments[0].isCompressed)
        XCTAssertFalse(image.segments[1].isCompressed)
        XCTAssertTrue(image.segments[2].isCompressed)
        XCTAssertTrue(image.hasCompressedSegments)
    }

    func testRejectsTruncatedHeader() {
        XCTAssertThrowsError(try NSOImage(data: Data(repeating: 0, count: 0x6f))) {
            XCTAssertEqual($0 as? NSOError, .truncatedHeader)
        }
    }

    func testRejectsWrongMagic() {
        var data = makeNSO()
        data.replaceSubrange(0..<4, with: Data("NOPE".utf8))
        XCTAssertThrowsError(try NSOImage(data: data)) {
            XCTAssertEqual($0 as? NSOError, .invalidMagic)
        }
    }

    func testRejectsUnsupportedVersion() {
        var data = makeNSO()
        putLE(UInt32(1), at: 0x04, in: &data)
        XCTAssertThrowsError(try NSOImage(data: data)) {
            XCTAssertEqual($0 as? NSOError, .unsupportedVersion(1))
        }
    }

    func testRejectsSegmentOutsideFile() {
        var data = makeNSO()
        putLE(UInt32(0xffff), at: 0x10, in: &data)
        XCTAssertThrowsError(try NSOImage(data: data)) {
            XCTAssertEqual($0 as? NSOError, .segmentOutsideFile(0))
        }
    }

    func testRejectsOverlappingFileSegments() {
        var data = makeNSO()
        putLE(UInt32(0x110), at: 0x20, in: &data)
        XCTAssertThrowsError(try NSOImage(data: data)) {
            XCTAssertEqual($0 as? NSOError, .overlappingFileSegments(0, 1))
        }
    }

    func testRejectsOverlappingMemorySegments() {
        var data = makeNSO()
        putLE(UInt32(0x10), at: 0x24, in: &data)
        XCTAssertThrowsError(try NSOImage(data: data)) {
            XCTAssertEqual($0 as? NSOError, .overlappingMemorySegments(0, 1))
        }
    }

    func testRejectsZeroCompressedSize() {
        var data = makeNSO(flags: 0b001)
        putLE(UInt32(0), at: 0x60, in: &data)
        XCTAssertThrowsError(try NSOImage(data: data)) {
            XCTAssertEqual($0 as? NSOError, .invalidCompressedSize(0))
        }
    }

    func testRejectsZeroBuildID() {
        var data = makeNSO()
        data.replaceSubrange(0x40..<0x60, with: Data(repeating: 0, count: 0x20))
        XCTAssertThrowsError(try NSOImage(data: data)) {
            XCTAssertEqual($0 as? NSOError, .invalidBuildID)
        }
    }

    private func makeNSO(flags: UInt32 = 0) -> Data {
        var data = Data(repeating: 0, count: 0x200)
        data.replaceSubrange(0..<4, with: Data("NSO0".utf8))
        putLE(UInt32(0), at: 0x04, in: &data)
        putLE(flags, at: 0x0c, in: &data)
        let descriptors: [(UInt32, UInt32, UInt32)] = [
            (0x100, 0x000, 0x20),
            (0x120, 0x020, 0x20),
            (0x140, 0x040, 0x20)
        ]
        for (index, item) in descriptors.enumerated() {
            let offset = 0x10 + index * 0x10
            putLE(item.0, at: offset, in: &data)
            putLE(item.1, at: offset + 4, in: &data)
            putLE(item.2, at: offset + 8, in: &data)
            putLE(item.2, at: 0x60 + index * 4, in: &data)
        }
        putLE(UInt32(0x40), at: 0x3c, in: &data)
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
