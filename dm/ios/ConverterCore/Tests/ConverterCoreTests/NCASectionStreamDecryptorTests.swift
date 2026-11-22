import Foundation
import CryptoKit
import XCTest
@testable import ConverterCore

final class NCASectionStreamDecryptorTests: XCTestCase {
    private let sectionKey = Data((0..<16).map { UInt8($0 & 0xFF) })
    private let seed = Data([0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87])

    func testDecryptsSectionAcrossUnalignedStreamingChunks() throws {
        let fixture = try makeFixture(encryption: .aesCTR)
        defer { try? FileManager.default.removeItem(at: fixture.inputURL) }
        let output = temporaryURL()
        defer { try? FileManager.default.removeItem(at: output) }

        let count = try NCASectionStreamDecryptor.decryptSection(
            inputURL: fixture.inputURL,
            outputURL: output,
            section: fixture.section,
            fileSystemHeader: fixture.fileSystemHeader,
            key: sectionKey,
            chunkSize: 0x523
        )

        XCTAssertEqual(count, UInt64(fixture.plainSection.count))
        XCTAssertEqual(try Data(contentsOf: output), fixture.plainSection)
        XCTAssertEqual(try Data(contentsOf: fixture.inputURL), fixture.encryptedFile)
    }

    func testRejectsUnsupportedEncryptionModesBeforeCreatingOutput() throws {
        for mode in [NCAFileSystemHeader.EncryptionType.aesXTS, .aesCTREx, .aesCTRSkipLayerHash, .aesCTRExSkipLayerHash, .automatic, .none] {
            let fixture = try makeFixture(encryption: mode)
            defer { try? FileManager.default.removeItem(at: fixture.inputURL) }
            let output = temporaryURL()
            XCTAssertThrowsError(try NCASectionStreamDecryptor.decryptSection(
                inputURL: fixture.inputURL,
                outputURL: output,
                section: fixture.section,
                fileSystemHeader: fixture.fileSystemHeader,
                key: sectionKey
            )) { error in
                XCTAssertEqual(
                    error as? NCASectionStreamDecryptorError,
                    .unsupportedEncryptionType(mode)
                )
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        }
    }

    func testRejectsSectionIndexMismatchAndInvalidChunkSize() throws {
        let fixture = try makeFixture(encryption: .aesCTR)
        defer { try? FileManager.default.removeItem(at: fixture.inputURL) }
        let output = temporaryURL()
        XCTAssertThrowsError(try NCASectionStreamDecryptor.decryptSection(
            inputURL: fixture.inputURL, outputURL: output,
            section: fixture.section,
            fileSystemHeader: try makeFileSystemHeader(index: 1, encryption: .aesCTR),
            key: sectionKey
        )) { error in
            XCTAssertEqual(error as? NCASectionStreamDecryptorError,
                           .sectionIndexMismatch(expected: 0, actual: 1))
        }
        XCTAssertThrowsError(try NCASectionStreamDecryptor.decryptSection(
            inputURL: fixture.inputURL, outputURL: output,
            section: fixture.section, fileSystemHeader: fixture.fileSystemHeader,
            key: sectionKey, chunkSize: 0
        )) { error in
            XCTAssertEqual(error as? NCASectionStreamDecryptorError, .invalidChunkSize(0))
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
    }

    func testRejectsSectionOutsideInputFileAndDoesNotLeavePartialOutput() throws {
        let fixture = try makeFixture(encryption: .aesCTR)
        defer { try? FileManager.default.removeItem(at: fixture.inputURL) }
        let shortInput = temporaryURL()
        try Data(repeating: 0, count: Int(fixture.section.byteOffset + 0x100)).write(to: shortInput)
        defer { try? FileManager.default.removeItem(at: shortInput) }
        let output = temporaryURL()

        XCTAssertThrowsError(try NCASectionStreamDecryptor.decryptSection(
            inputURL: shortInput, outputURL: output,
            section: fixture.section, fileSystemHeader: fixture.fileSystemHeader,
            key: sectionKey
        )) { error in
            XCTAssertEqual(
                error as? NCASectionStreamDecryptorError,
                .sectionOutsideFile(
                    offset: fixture.section.byteOffset,
                    size: fixture.section.byteSize,
                    fileSize: fixture.section.byteOffset + 0x100
                )
            )
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
    }

    func testRejectsExistingOutputAndInputOutputCollision() throws {
        let fixture = try makeFixture(encryption: .aesCTR)
        defer { try? FileManager.default.removeItem(at: fixture.inputURL) }
        XCTAssertThrowsError(try NCASectionStreamDecryptor.decryptSection(
            inputURL: fixture.inputURL, outputURL: fixture.inputURL,
            section: fixture.section, fileSystemHeader: fixture.fileSystemHeader,
            key: sectionKey
        )) { error in
            XCTAssertEqual(error as? NCASectionStreamDecryptorError, .inputOutputCollision)
        }
        let existing = temporaryURL()
        try Data([1, 2, 3]).write(to: existing)
        defer { try? FileManager.default.removeItem(at: existing) }
        XCTAssertThrowsError(try NCASectionStreamDecryptor.decryptSection(
            inputURL: fixture.inputURL, outputURL: existing,
            section: fixture.section, fileSystemHeader: fixture.fileSystemHeader,
            key: sectionKey
        )) { error in
            XCTAssertEqual(error as? NCASectionStreamDecryptorError, .outputAlreadyExists)
        }
        XCTAssertEqual(try Data(contentsOf: existing), Data([1, 2, 3]))
    }

    private struct Fixture {
        let inputURL: URL
        let section: NCAHeader.Section
        let fileSystemHeader: NCAFileSystemHeader
        let plainSection: Data
        let encryptedFile: Data
    }

    private func makeFixture(encryption: NCAFileSystemHeader.EncryptionType) throws -> Fixture {
        let sectionOffset: UInt64 = 0x1000
        let sectionSize: UInt64 = 0x3000
        let fileSize = Int(sectionOffset + sectionSize)
        var headerBytes = Data(repeating: 0, count: 0xC00)
        headerBytes.replaceSubrange(0x200..<0x204, with: Data("NCA3".utf8))
        putLE(UInt64(fileSize), at: 0x208, in: &headerBytes)
        putLE(UInt32(8), at: 0x240, in: &headerBytes)
        putLE(UInt32(32), at: 0x244, in: &headerBytes)

        let fsOffset = 0x400
        headerBytes[fsOffset] = 2
        headerBytes[fsOffset + 2] = 1
        headerBytes[fsOffset + 3] = 2
        headerBytes[fsOffset + 4] = encryption.rawValue
        headerBytes.replaceSubrange((fsOffset + 0x140)..<(fsOffset + 0x148), with: seed)
        let rawFSHeader = headerBytes.subdata(in: fsOffset..<(fsOffset + 0x200))
        headerBytes.replaceSubrange(0x280..<0x2A0, with: Data(SHA256.hash(data: rawFSHeader)))
        let header = try NCAHeader(plaintextHeader: headerBytes)
        let section = try XCTUnwrap(header.sections.first)
        let fsHeader = try NCAFileSystemHeader(
            decryptedNCAHeader: headerBytes, sectionIndex: 0,
            expectedHash: header.sectionHeaderHashes[0]
        )

        let plainSection = Data((0..<Int(sectionSize)).map { UInt8(($0 * 31 + 7) & 0xFF) })
        let encryptedSection = try NCASectionCTRCrypt.crypt(
            data: plainSection, key: sectionKey, sectionCounter: seed,
            sectionFileOffset: sectionOffset, offsetWithinSection: 0
        )
        var encryptedFile = Data(repeating: 0xCC, count: fileSize)
        encryptedFile.replaceSubrange(Int(sectionOffset)..<fileSize, with: encryptedSection)
        let inputURL = temporaryURL()
        try encryptedFile.write(to: inputURL)
        return Fixture(inputURL: inputURL, section: section, fileSystemHeader: fsHeader,
                       plainSection: plainSection, encryptedFile: encryptedFile)
    }

    private func makeFileSystemHeader(index: Int, encryption: NCAFileSystemHeader.EncryptionType) throws -> NCAFileSystemHeader {
        var bytes = Data(repeating: 0, count: 0xC00)
        let offset = 0x400 + index * 0x200
        bytes[offset] = 2
        bytes[offset + 2] = 1
        bytes[offset + 3] = 2
        bytes[offset + 4] = encryption.rawValue
        bytes.replaceSubrange((offset + 0x140)..<(offset + 0x148), with: seed)
        let raw = bytes.subdata(in: offset..<(offset + 0x200))
        return try NCAFileSystemHeader(
            decryptedNCAHeader: bytes, sectionIndex: index,
            expectedHash: Data(SHA256.hash(data: raw))
        )
    }

    private func temporaryURL() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    }

    private func putLE<T: FixedWidthInteger>(_ value: T, at offset: Int, in data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) {
            data.replaceSubrange(offset..<(offset + $0.count), with: $0)
        }
    }
}
