import Foundation
import XCTest
@testable import ConverterCore

final class NCAHierarchicalSHA256SuperblockTests: XCTestCase {
    func testParsesTwoLayerPFS0Superblock() throws {
        var data = Data(repeating: 0, count: 0xF8)
        data.replaceSubrange(0..<0x20, with: Data(repeating: 0xA5, count: 0x20))
        put32(0x1000, into: &data, at: 0x20)
        put32(2, into: &data, at: 0x24)
        put64(0, into: &data, at: 0x28)
        put64(0x40, into: &data, at: 0x30)
        put64(0x200, into: &data, at: 0x38)
        put64(0x2000, into: &data, at: 0x40)

        let parsed = try NCAHierarchicalSHA256Superblock(hashData: data, sectionSize: 0x3000)
        XCTAssertEqual(parsed.masterHash, Data(repeating: 0xA5, count: 0x20))
        XCTAssertEqual(parsed.blockSize, 0x1000)
        XCTAssertEqual(parsed.hashTableOffset, 0)
        XCTAssertEqual(parsed.hashTableSize, 0x40)
        XCTAssertEqual(parsed.pfs0Offset, 0x200)
        XCTAssertEqual(parsed.pfs0Size, 0x2000)
    }

    func testRejectsInvalidLayerCountAndBlockSize() throws {
        var data = validData()
        put32(1, into: &data, at: 0x24)
        XCTAssertThrowsError(try NCAHierarchicalSHA256Superblock(hashData: data, sectionSize: 0x3000)) {
            XCTAssertEqual($0 as? NCAHierarchicalSHA256SuperblockError, .unsupportedLayerCount(1))
        }

        data = validData()
        put32(0x1800, into: &data, at: 0x20)
        XCTAssertThrowsError(try NCAHierarchicalSHA256Superblock(hashData: data, sectionSize: 0x3000)) {
            XCTAssertEqual($0 as? NCAHierarchicalSHA256SuperblockError, .invalidBlockSize(0x1800))
        }
    }

    func testRejectsIncorrectHashTableSizeAndOutOfBoundsRegions() throws {
        var data = validData()
        put64(0x20, into: &data, at: 0x30)
        XCTAssertThrowsError(try NCAHierarchicalSHA256Superblock(hashData: data, sectionSize: 0x3000)) {
            XCTAssertEqual($0 as? NCAHierarchicalSHA256SuperblockError,
                           .hashTableSizeMismatch(expected: 0x40, actual: 0x20))
        }

        data = validData()
        put64(0x2FF0, into: &data, at: 0x38)
        XCTAssertThrowsError(try NCAHierarchicalSHA256Superblock(hashData: data, sectionSize: 0x3000)) {
            XCTAssertEqual($0 as? NCAHierarchicalSHA256SuperblockError, .pfs0OutOfBounds)
        }
    }

    func testRejectsOverlappingRegionsAndShortHashData() throws {
        var data = validData()
        put64(0x20, into: &data, at: 0x38)
        XCTAssertThrowsError(try NCAHierarchicalSHA256Superblock(hashData: data, sectionSize: 0x3000)) {
            XCTAssertEqual($0 as? NCAHierarchicalSHA256SuperblockError, .overlappingRegions)
        }
        XCTAssertThrowsError(try NCAHierarchicalSHA256Superblock(hashData: Data(), sectionSize: 0x3000)) {
            XCTAssertEqual($0 as? NCAHierarchicalSHA256SuperblockError, .invalidHashDataLength(0))
        }
    }

    private func validData() -> Data {
        var data = Data(repeating: 0, count: 0xF8)
        put32(0x1000, into: &data, at: 0x20)
        put32(2, into: &data, at: 0x24)
        put64(0, into: &data, at: 0x28)
        put64(0x40, into: &data, at: 0x30)
        put64(0x200, into: &data, at: 0x38)
        put64(0x2000, into: &data, at: 0x40)
        return data
    }

    private func put32(_ value: UInt32, into data: inout Data, at offset: Int) {
        for index in 0..<4 { data[offset + index] = UInt8((value >> (index * 8)) & 0xFF) }
    }

    private func put64(_ value: UInt64, into data: inout Data, at offset: Int) {
        for index in 0..<8 { data[offset + index] = UInt8((value >> (index * 8)) & 0xFF) }
    }
}
