import Foundation
import CryptoKit
import XCTest
@testable import ConverterCore

final class NCASectionRomFSExtractorTests: XCTestCase {
    func testExtractsStandaloneRomFSOnlyAfterFullIVFCVerification() throws {
        let fixture = try makeFixture()
        defer {
            try? FileManager.default.removeItem(at: fixture.sectionURL)
            try? FileManager.default.removeItem(at: fixture.outputURL)
        }

        let result = try NCASectionRomFSExtractor.extract(
            decryptedSectionURL: fixture.sectionURL,
            sectionSize: UInt64(fixture.section.count),
            fileSystemHeader: fixture.fileSystemHeader,
            to: fixture.outputURL
        )

        XCTAssertEqual(result.imageSize, UInt64(fixture.romFS.count))
        XCTAssertEqual(result.entryCount, 1)
        XCTAssertEqual(try Data(contentsOf: fixture.outputURL), fixture.romFS)
        XCTAssertEqual(try RomFSArchive(url: fixture.outputURL).entries.count, 1)
    }

    func testRejectsTamperedRomFSBeforePublishingOutput() throws {
        let fixture = try makeFixture()
        defer {
            try? FileManager.default.removeItem(at: fixture.sectionURL)
            try? FileManager.default.removeItem(at: fixture.outputURL)
        }
        var tampered = fixture.section
        tampered[0x290] ^= 0x80
        try tampered.write(to: fixture.sectionURL)

        XCTAssertThrowsError(try NCASectionRomFSExtractor.extract(
            decryptedSectionURL: fixture.sectionURL,
            sectionSize: UInt64(tampered.count),
            fileSystemHeader: fixture.fileSystemHeader,
            to: fixture.outputURL
        ))
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.outputURL.path))
    }

    private struct Fixture {
        let sectionURL: URL
        let outputURL: URL
        let section: Data
        let romFS: Data
        let fileSystemHeader: NCAFileSystemHeader
    }

    private func makeFixture() throws -> Fixture {
        let blockSize = 64
        var romFS = Data(repeating: 0, count: 0x70)
        put64(0x50, at: 0, in: &romFS)
        put64(0x50, at: 8, in: &romFS)
        put64(4, at: 16, in: &romFS)
        put64(0x54, at: 24, in: &romFS)
        put64(0x18, at: 32, in: &romFS)
        put64(0x6C, at: 40, in: &romFS)
        put64(4, at: 48, in: &romFS)
        put64(0x70, at: 56, in: &romFS)
        put64(0, at: 64, in: &romFS)
        put64(0x70, at: 72, in: &romFS)
        put32(0, at: 0x54, in: &romFS)
        put32(UInt32.max, at: 0x58, in: &romFS)
        put32(UInt32.max, at: 0x5C, in: &romFS)
        put32(UInt32.max, at: 0x60, in: &romFS)
        put32(0, at: 0x64, in: &romFS)
        put32(0, at: 0x68, in: &romFS)

        let offsets: [UInt64] = [0x100, 0x140, 0x180, 0x1C0, 0x200, 0x280]
        let sizes: [UInt64] = [0x20, 0x20, 0x20, 0x20, 0x40, UInt64(romFS.count)]
        var section = Data(repeating: 0, count: 0x400)
        section.replaceSubrange(Int(offsets[5])..<(Int(offsets[5]) + romFS.count), with: romFS)

        func digest(_ data: Data) -> Data {
            var padded = data
            if padded.count < blockSize {
                padded.append(Data(repeating: 0, count: blockSize - padded.count))
            }
            return Data(SHA256.hash(data: padded))
        }
        func table(_ data: Data) -> Data {
            var result = Data()
            var cursor = 0
            while cursor < data.count {
                let end = min(cursor + blockSize, data.count)
                result.append(digest(data.subdata(in: cursor..<end)))
                cursor = end
            }
            return result
        }

        let l4 = table(romFS)
        section.replaceSubrange(Int(offsets[4])..<(Int(offsets[4]) + l4.count), with: l4)
        let l3 = table(l4)
        section.replaceSubrange(Int(offsets[3])..<(Int(offsets[3]) + l3.count), with: l3)
        let l2 = table(l3)
        section.replaceSubrange(Int(offsets[2])..<(Int(offsets[2]) + l2.count), with: l2)
        let l1 = table(l2)
        section.replaceSubrange(Int(offsets[1])..<(Int(offsets[1]) + l1.count), with: l1)
        let l0 = table(l1)
        section.replaceSubrange(Int(offsets[0])..<(Int(offsets[0]) + l0.count), with: l0)
        let master = digest(l0)

        var hashData = Data(repeating: 0, count: 0xF8)
        put32(0x43465649, at: 0, in: &hashData)
        put32(0x00020000, at: 4, in: &hashData)
        put32(0x20, at: 8, in: &hashData)
        put32(6, at: 0x0C, in: &hashData)
        for index in 0..<6 {
            let at = 0x10 + index * 0x18
            put64(offsets[index], at: at, in: &hashData)
            put64(sizes[index], at: at + 8, in: &hashData)
            put32(6, at: at + 0x10, in: &hashData)
        }
        hashData.replaceSubrange(0xC0..<0xE0, with: master)

        var ncaHeader = Data(repeating: 0, count: 0xC00)
        var rawFSHeader = Data(repeating: 0, count: 0x200)
        put16(2, at: 0, in: &rawFSHeader)
        rawFSHeader[2] = 0 // RomFS
        rawFSHeader[3] = 3 // hierarchical integrity
        rawFSHeader[4] = 3 // AES-CTR
        rawFSHeader.replaceSubrange(0x08..<0x100, with: hashData)
        ncaHeader.replaceSubrange(0x400..<0x600, with: rawFSHeader)
        let expectedHash = Data(SHA256.hash(data: rawFSHeader))
        let fsHeader = try NCAFileSystemHeader(
            decryptedNCAHeader: ncaHeader,
            sectionIndex: 0,
            expectedHash: expectedHash
        )

        let sectionURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let outputURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try section.write(to: sectionURL)
        return Fixture(sectionURL: sectionURL, outputURL: outputURL,
                       section: section, romFS: romFS, fileSystemHeader: fsHeader)
    }

    private func put16(_ value: UInt16, at offset: Int, in data: inout Data) {
        var value = value.littleEndian
        withUnsafeBytes(of: &value) { data.replaceSubrange(offset..<(offset + 2), with: $0) }
    }
    private func put32(_ value: UInt32, at offset: Int, in data: inout Data) {
        var value = value.littleEndian
        withUnsafeBytes(of: &value) { data.replaceSubrange(offset..<(offset + 4), with: $0) }
    }
    private func put64(_ value: UInt64, at offset: Int, in data: inout Data) {
        var value = value.littleEndian
        withUnsafeBytes(of: &value) { data.replaceSubrange(offset..<(offset + 8), with: $0) }
    }
}
