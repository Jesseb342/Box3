import Foundation
import CryptoKit
import XCTest
@testable import ConverterCore

final class NCAHierarchicalSHA256VerifierTests: XCTestCase {
    func testVerifiesMasterHashAndEveryPFS0Block() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.url) }

        let result = try NCAHierarchicalSHA256Verifier.verify(
            decryptedSectionURL: fixture.url,
            sectionSize: fixture.sectionSize,
            superblock: fixture.superblock
        )
        XCTAssertEqual(result.verifiedBlockCount, 2)
        XCTAssertEqual(result.pfs0Offset, 0x200)
        XCTAssertEqual(result.pfs0Size, 0x2000)
    }

    func testRejectsMasterHashMismatch() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.url) }
        let bad = try makeSuperblock(masterHash: Data(repeating: 0xFF, count: 0x20))
        XCTAssertThrowsError(try NCAHierarchicalSHA256Verifier.verify(
            decryptedSectionURL: fixture.url, sectionSize: fixture.sectionSize, superblock: bad
        )) {
            XCTAssertEqual($0 as? NCAHierarchicalSHA256VerifierError, .masterHashMismatch)
        }
    }

    func testRejectsCorruptPFS0Block() throws {
        let fixture = try makeFixture(corruptBlock: true)
        defer { try? FileManager.default.removeItem(at: fixture.url) }
        XCTAssertThrowsError(try NCAHierarchicalSHA256Verifier.verify(
            decryptedSectionURL: fixture.url, sectionSize: fixture.sectionSize, superblock: fixture.superblock
        )) {
            XCTAssertEqual($0 as? NCAHierarchicalSHA256VerifierError, .blockHashMismatch(1))
        }
    }

    func testRejectsNonPFS0Payload() throws {
        let fixture = try makeFixture(invalidMagic: true)
        defer { try? FileManager.default.removeItem(at: fixture.url) }
        XCTAssertThrowsError(try NCAHierarchicalSHA256Verifier.verify(
            decryptedSectionURL: fixture.url, sectionSize: fixture.sectionSize, superblock: fixture.superblock
        )) {
            XCTAssertEqual($0 as? NCAHierarchicalSHA256VerifierError, .invalidPFS0Magic)
        }
    }

    func testRejectsSectionOutsideFile() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.url) }
        XCTAssertThrowsError(try NCAHierarchicalSHA256Verifier.verify(
            decryptedSectionURL: fixture.url, sectionOffset: 0x1000,
            sectionSize: fixture.sectionSize, superblock: fixture.superblock
        )) {
            XCTAssertEqual($0 as? NCAHierarchicalSHA256VerifierError, .sectionOutsideFile)
        }
    }

    func testSectionIntegrityFacadeParsesAndVerifiesPFS0Header() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.url) }
        let fsHeader = try makeFileSystemHeader(
            fileSystemType: .partitionFS, hashType: .hierarchicalSHA256,
            superblock: fixture.superblock
        )
        let result = try NCASectionIntegrityVerifier.verify(
            decryptedSectionURL: fixture.url, sectionSize: fixture.sectionSize,
            fileSystemHeader: fsHeader
        )
        XCTAssertEqual(result.verifiedBlockCount, 2)
        XCTAssertEqual(result.pfs0Offset, 0x200)
    }

    func testSectionIntegrityFacadeRejectsUnsupportedFilesystemAndHashModes() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.url) }
        let romFS = try makeFileSystemHeader(
            fileSystemType: .romFS, hashType: .hierarchicalSHA256,
            superblock: fixture.superblock
        )
        XCTAssertThrowsError(try NCASectionIntegrityVerifier.verify(
            decryptedSectionURL: fixture.url, sectionSize: fixture.sectionSize,
            fileSystemHeader: romFS
        )) {
            XCTAssertEqual($0 as? NCASectionIntegrityVerifierError, .unsupportedFileSystemType)
        }
        let noHash = try makeFileSystemHeader(
            fileSystemType: .partitionFS, hashType: .none,
            superblock: fixture.superblock
        )
        XCTAssertThrowsError(try NCASectionIntegrityVerifier.verify(
            decryptedSectionURL: fixture.url, sectionSize: fixture.sectionSize,
            fileSystemHeader: noHash
        )) {
            XCTAssertEqual($0 as? NCASectionIntegrityVerifierError, .unsupportedHashType)
        }
    }

    private func makeFileSystemHeader(
        fileSystemType: NCAFileSystemHeader.FileSystemType,
        hashType: NCAFileSystemHeader.HashType,
        superblock: NCAHierarchicalSHA256Superblock
    ) throws -> NCAFileSystemHeader {
        var ncaHeader = Data(repeating: 0, count: 0xC00)
        let offset = 0x400
        ncaHeader[offset] = 2
        ncaHeader[offset + 2] = fileSystemType.rawValue
        ncaHeader[offset + 3] = hashType.rawValue
        ncaHeader[offset + 4] = NCAFileSystemHeader.EncryptionType.aesCTR.rawValue
        var hashData = Data(repeating: 0, count: 0xF8)
        hashData.replaceSubrange(0..<0x20, with: superblock.masterHash)
        put32(superblock.blockSize, into: &hashData, at: 0x20)
        put32(2, into: &hashData, at: 0x24)
        put64(superblock.hashTableOffset, into: &hashData, at: 0x28)
        put64(superblock.hashTableSize, into: &hashData, at: 0x30)
        put64(superblock.pfs0Offset, into: &hashData, at: 0x38)
        put64(superblock.pfs0Size, into: &hashData, at: 0x40)
        ncaHeader.replaceSubrange((offset + 0x8)..<(offset + 0x100), with: hashData)
        let raw = ncaHeader.subdata(in: offset..<(offset + 0x200))
        return try NCAFileSystemHeader(
            decryptedNCAHeader: ncaHeader, sectionIndex: 0,
            expectedHash: Data(SHA256.hash(data: raw))
        )
    }

    private struct Fixture {
        let url: URL
        let sectionSize: UInt64
        let superblock: NCAHierarchicalSHA256Superblock
    }

    private func makeFixture(corruptBlock: Bool = false, invalidMagic: Bool = false) throws -> Fixture {
        let sectionSize: UInt64 = 0x3000
        var section = Data(repeating: 0, count: Int(sectionSize))
        let pfsOffset = 0x200
        let pfsSize = 0x2000
        section.replaceSubrange(pfsOffset..<(pfsOffset + 4),
                                with: invalidMagic ? Data("NOPE".utf8) : Data("PFS0".utf8))
        for i in 4..<pfsSize { section[pfsOffset + i] = UInt8(truncatingIfNeeded: i) }
        let blockSize = 0x1000
        var hashTable = Data()
        for block in 0..<2 {
            let start = pfsOffset + block * blockSize
            let bytes = section.subdata(in: start..<(start + blockSize))
            hashTable.append(contentsOf: SHA256.hash(data: bytes))
        }
        section.replaceSubrange(0..<hashTable.count, with: hashTable)
        let masterHash = Data(SHA256.hash(data: hashTable))
        let superblock = try makeSuperblock(masterHash: masterHash)
        if corruptBlock { section[pfsOffset + 0x1000] ^= 0xFF }

        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try section.write(to: url)
        return Fixture(url: url, sectionSize: sectionSize, superblock: superblock)
    }

    private func makeSuperblock(masterHash: Data) throws -> NCAHierarchicalSHA256Superblock {
        var data = Data(repeating: 0, count: 0xF8)
        data.replaceSubrange(0..<0x20, with: masterHash)
        put32(0x1000, into: &data, at: 0x20)
        put32(2, into: &data, at: 0x24)
        put64(0, into: &data, at: 0x28)
        put64(0x40, into: &data, at: 0x30)
        put64(0x200, into: &data, at: 0x38)
        put64(0x2000, into: &data, at: 0x40)
        return try NCAHierarchicalSHA256Superblock(hashData: data, sectionSize: 0x3000)
    }

    private func put32(_ value: UInt32, into data: inout Data, at offset: Int) {
        for index in 0..<4 { data[offset + index] = UInt8((value >> (index * 8)) & 0xFF) }
    }

    private func put64(_ value: UInt64, into data: inout Data, at offset: Int) {
        for index in 0..<8 { data[offset + index] = UInt8((value >> (index * 8)) & 0xFF) }
    }
}
