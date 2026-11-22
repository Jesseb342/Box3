import Foundation
import CryptoKit
import XCTest
@testable import ConverterCore

final class NCASectionPFS0ExtractorTests: XCTestCase {
    func testVerifiesAndExtractsPFS0EntriesFromDecryptedSection() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.sectionURL) }
        let output = temporaryURL()
        defer { try? FileManager.default.removeItem(at: output) }

        let result = try NCASectionPFS0Extractor.extract(
            decryptedSectionURL: fixture.sectionURL,
            sectionSize: UInt64(fixture.section.count),
            fileSystemHeader: fixture.fileSystemHeader,
            to: output
        )
        XCTAssertEqual(result.entryCount, 2)
        XCTAssertEqual(result.totalExtractedBytes, 7)
        XCTAssertEqual(result.verifiedBlockCount, 1)
        XCTAssertEqual(try Data(contentsOf: output.appendingPathComponent("main.nso")), Data("NSO!".utf8))
        XCTAssertEqual(try Data(contentsOf: output.appendingPathComponent("control.nacp")), Data("abc".utf8))
    }

    func testRejectsIntegrityFailureWithoutPublishingOutput() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.sectionURL) }
        let handle = try FileHandle(forWritingTo: fixture.sectionURL)
        try handle.seek(toOffset: fixture.pfs0Offset + 0x20)
        try handle.write(contentsOf: Data([0xFF]))
        try handle.close()
        let output = temporaryURL()
        defer { try? FileManager.default.removeItem(at: output) }

        XCTAssertThrowsError(try NCASectionPFS0Extractor.extract(
            decryptedSectionURL: fixture.sectionURL,
            sectionSize: UInt64(fixture.section.count),
            fileSystemHeader: fixture.fileSystemHeader,
            to: output
        ))
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
    }

    func testRejectsExistingDestination() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.sectionURL) }
        let output = temporaryURL()
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: output) }

        XCTAssertThrowsError(try NCASectionPFS0Extractor.extract(
            decryptedSectionURL: fixture.sectionURL,
            sectionSize: UInt64(fixture.section.count),
            fileSystemHeader: fixture.fileSystemHeader,
            to: output
        )) {
            XCTAssertEqual($0 as? NCASectionPFS0ExtractorError, .destinationAlreadyExists)
        }
    }

    private struct Fixture {
        let sectionURL: URL
        let section: Data
        let fileSystemHeader: NCAFileSystemHeader
        let pfs0Offset: UInt64
    }

    private func makeFixture() throws -> Fixture {
        let pfs0 = makePFS0([
            ("main.nso", Data("NSO!".utf8)),
            ("control.nacp", Data("abc".utf8))
        ])
        let pfsOffset = 0x200
        let hashOffset = 0x100
        let blockSize = 0x100
        var section = Data(repeating: 0, count: pfsOffset + pfs0.count)
        section.replaceSubrange(pfsOffset..<(pfsOffset + pfs0.count), with: pfs0)
        let blockHash = Data(SHA256.hash(data: pfs0))
        let hashTable = blockHash
        let masterHash = Data(SHA256.hash(data: hashTable))
        section.replaceSubrange(hashOffset..<(hashOffset + hashTable.count), with: hashTable)

        var ncaHeader = Data(repeating: 0, count: 0xC00)
        let fsOffset = 0x400
        ncaHeader[fsOffset] = 2
        ncaHeader[fsOffset + 2] = NCAFileSystemHeader.FileSystemType.partitionFS.rawValue
        ncaHeader[fsOffset + 3] = NCAFileSystemHeader.HashType.hierarchicalSHA256.rawValue
        ncaHeader[fsOffset + 4] = NCAFileSystemHeader.EncryptionType.aesCTR.rawValue
        var hashData = Data(repeating: 0, count: 0xF8)
        hashData.replaceSubrange(0..<0x20, with: masterHash)
        put32(UInt32(blockSize), into: &hashData, at: 0x20)
        put32(2, into: &hashData, at: 0x24)
        put64(UInt64(hashOffset), into: &hashData, at: 0x28)
        put64(UInt64(hashTable.count), into: &hashData, at: 0x30)
        put64(UInt64(pfsOffset), into: &hashData, at: 0x38)
        put64(UInt64(pfs0.count), into: &hashData, at: 0x40)
        ncaHeader.replaceSubrange((fsOffset + 0x8)..<(fsOffset + 0x100), with: hashData)
        let rawFS = ncaHeader.subdata(in: fsOffset..<(fsOffset + 0x200))
        let fsHeader = try NCAFileSystemHeader(
            decryptedNCAHeader: ncaHeader, sectionIndex: 0,
            expectedHash: Data(SHA256.hash(data: rawFS))
        )
        let url = temporaryURL()
        try section.write(to: url)
        return Fixture(sectionURL: url, section: section, fileSystemHeader: fsHeader,
                       pfs0Offset: UInt64(pfsOffset))
    }

    private func makePFS0(_ files: [(String, Data)]) -> Data {
        var strings = Data()
        var nameOffsets: [UInt32] = []
        for (name, _) in files {
            nameOffsets.append(UInt32(strings.count))
            strings.append(contentsOf: name.utf8)
            strings.append(0)
        }
        var result = Data("PFS0".utf8)
        appendLE(UInt32(files.count), to: &result)
        appendLE(UInt32(strings.count), to: &result)
        appendLE(UInt32(0), to: &result)
        var offset: UInt64 = 0
        for i in files.indices {
            appendLE(offset, to: &result)
            appendLE(UInt64(files[i].1.count), to: &result)
            appendLE(nameOffsets[i], to: &result)
            appendLE(UInt32(0), to: &result)
            offset += UInt64(files[i].1.count)
        }
        result.append(strings)
        for file in files { result.append(file.1) }
        return result
    }

    private func temporaryURL() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    }

    private func appendLE<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
    }

    private func put32(_ value: UInt32, into data: inout Data, at offset: Int) {
        var v = value.littleEndian
        withUnsafeBytes(of: &v) { data.replaceSubrange(offset..<(offset + 4), with: $0) }
    }

    private func put64(_ value: UInt64, into data: inout Data, at offset: Int) {
        var v = value.littleEndian
        withUnsafeBytes(of: &v) { data.replaceSubrange(offset..<(offset + 8), with: $0) }
    }
}
