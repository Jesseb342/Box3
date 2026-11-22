import Foundation
import XCTest
@testable import ConverterCore

final class RomFSArchiveTests: XCTestCase {
    func testParsesDirectoryTreeAndStreamsFilePayloads() throws {
        let image = makeImage()
        let source = try writeTemporary(image)
        defer { try? FileManager.default.removeItem(at: source) }
        let archive = try RomFSArchive(url: source)
        XCTAssertEqual(archive.entries.map(\.path), ["", "hello.txt", "assets", "assets/data.bin"])
        XCTAssertEqual(archive.entries.filter { !$0.isDirectory }.map(\.size), [5, 4])
        let destination = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: destination) }
        try archive.extractAll(to: destination, chunkSize: 2)
        XCTAssertEqual(try Data(contentsOf: destination.appendingPathComponent("hello.txt")), Data("hello".utf8))
        XCTAssertEqual(try Data(contentsOf: destination.appendingPathComponent("assets/data.bin")), Data([1,2,3,4]))
    }

    func testRejectsBadHeaderSize() throws {
        var data = Data(repeating: 0, count: 0x50)
        put64(0x48, into: &data, at: 0)
        let source = try writeTemporary(data)
        defer { try? FileManager.default.removeItem(at: source) }
        XCTAssertThrowsError(try RomFSArchive(url: source)) { XCTAssertEqual($0 as? RomFSError, .invalidHeaderSize(0x48)) }
    }

    func testRejectsUnsafeFileName() throws {
        var image = makeImage()
        // Root's first file name starts at file table offset + 0x20.
        let nameOffset = Int(read64(image, 56) + 0x20)
        image.replaceSubrange(nameOffset..<(nameOffset + 9), with: Data("../evil\0".utf8))
        let source = try writeTemporary(image)
        defer { try? FileManager.default.removeItem(at: source) }
        XCTAssertThrowsError(try RomFSArchive(url: source))
    }

    private func makeImage() -> Data {
        let dirHashOffset: UInt64 = 0x50, dirHashSize: UInt64 = 4
        let dirOffset: UInt64 = 0x54, dirSize: UInt64 = 0x40
        let fileHashOffset: UInt64 = 0x94, fileHashSize: UInt64 = 4
        let fileOffset: UInt64 = 0x98, fileSize: UInt64 = 0x54
        let dataOffset: UInt64 = 0xEC
        var data = Data()
        for value: UInt64 in [0x50, dirHashOffset, dirHashSize, dirOffset, dirSize,
                              fileHashOffset, fileHashSize, fileOffset, fileSize, dataOffset] {
            put64(value, into: &data, at: data.count)
        }
        data.append(contentsOf: [0,0,0,0]) // directory hash buckets
        // Root directory: parent=0, sibling/children empty, name length 0.
        append32(0, &data); append32(UInt32.max, &data); append32(0x18, &data)
        append32(0, &data); append32(UInt32.max, &data); append32(0, &data)
        // Child directory "assets" at 0x18.
        append32(0, &data); append32(UInt32.max, &data); append32(UInt32.max, &data)
        append32(0x20, &data); append32(UInt32.max, &data); append32(6, &data)
        data.append(contentsOf: "assets".utf8); data.append(contentsOf: [0,0])
        data.append(contentsOf: [0,0,0,0]) // file hash buckets
        // Root file hello.txt at 0, sibling empty, data offset 0, size 5.
        append32(0, &data); append32(UInt32.max, &data); put64(0, into: &data, at: data.count)
        put64(5, into: &data, at: data.count); append32(UInt32.max, &data); append32(9, &data)
        data.append(contentsOf: "hello.txt".utf8); data.append(contentsOf: [0,0,0])
        // Child file data.bin at 0x28, parent dir 0x18, data offset 5.
        append32(0x18, &data); append32(UInt32.max, &data); put64(5, into: &data, at: data.count)
        put64(4, into: &data, at: data.count); append32(UInt32.max, &data); append32(8, &data)
        data.append(contentsOf: "data.bin".utf8)
        data.append(contentsOf: [0,0,0,0]) // alignment padding
        data.append(contentsOf: "hello".utf8); data.append(contentsOf: [1,2,3,4])
        return data
    }

    private func writeTemporary(_ data: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try data.write(to: url)
        return url
    }
    private func append32(_ value: UInt32, _ data: inout Data) {
        var v = value.littleEndian; withUnsafeBytes(of: &v) { data.append(contentsOf: $0) }
    }
    private func put64(_ value: UInt64, into data: inout Data, at offset: Int) {
        var v = value.littleEndian
        let bytes = withUnsafeBytes(of: &v) { Data($0) }
        if offset == data.count { data.append(bytes) }
        else { data.replaceSubrange(offset..<(offset+8), with: bytes) }
    }
    private func read64(_ data: Data, _ offset: Int) -> UInt64 {
        UInt64(data[offset]) | (UInt64(data[offset+1]) << 8) |
        (UInt64(data[offset+2]) << 16) | (UInt64(data[offset+3]) << 24) |
        (UInt64(data[offset+4]) << 32) | (UInt64(data[offset+5]) << 40) |
        (UInt64(data[offset+6]) << 48) | (UInt64(data[offset+7]) << 56)
    }
}
