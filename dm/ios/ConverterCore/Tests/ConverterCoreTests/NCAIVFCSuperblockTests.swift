import Foundation
import CryptoKit
import XCTest
@testable import ConverterCore

final class NCAIVFCSuperblockTests: XCTestCase {
    func testParsesAndVerifiesSixLevelRomFSIntegrityTree() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.url) }

        let superblock = try NCAIVFCSuperblock(hashData: fixture.hashData,
                                                sectionSize: UInt64(fixture.section.count))
        XCTAssertEqual(superblock.version, 0x00020000)
        XCTAssertEqual(superblock.masterHashSize, 0x20)
        XCTAssertEqual(superblock.levels.count, 6)
        XCTAssertEqual(superblock.levels[5].logicalOffset, 0x600)
        XCTAssertEqual(superblock.levels[5].dataSize, 0x50)

        let result = try NCAIVFCVerifier.verify(
            decryptedSectionURL: fixture.url,
            sectionSize: UInt64(fixture.section.count),
            superblock: superblock
        )
        XCTAssertEqual(result.romFSOffset, 0x600)
        XCTAssertEqual(result.romFSSize, 0x50)
        XCTAssertEqual(result.verifiedBlockCount, 7)
    }

    func testVerifiesNonUniformLevelBlockSizesAndZeroPaddedFinalBlock() throws {
        let fixture = try makeFixture(blockExponents: [6, 7, 6, 8, 7, 6])
        defer { try? FileManager.default.removeItem(at: fixture.url) }

        let superblock = try NCAIVFCSuperblock(
            hashData: fixture.hashData,
            sectionSize: UInt64(fixture.section.count)
        )
        XCTAssertEqual(superblock.levels.map(\.blockSizeExponent), [6, 7, 6, 8, 7, 6])
        let result = try NCAIVFCVerifier.verify(
            decryptedSectionURL: fixture.url,
            sectionSize: UInt64(fixture.section.count),
            superblock: superblock
        )
        XCTAssertEqual(result.romFSOffset, 0x600)
        XCTAssertEqual(result.romFSSize, 0x50)
        XCTAssertEqual(result.verifiedBlockCount, 7)
    }

    func testRejectsTamperedRomFSData() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.url) }
        var tampered = fixture.section
        tampered[0x620] ^= 0xFF
        try tampered.write(to: fixture.url)
        let superblock = try NCAIVFCSuperblock(hashData: fixture.hashData,
                                                sectionSize: UInt64(tampered.count))
        XCTAssertThrowsError(try NCAIVFCVerifier.verify(
            decryptedSectionURL: fixture.url,
            sectionSize: UInt64(tampered.count),
            superblock: superblock
        )) { error in
            XCTAssertEqual(error as? NCAIVFCVerifierError,
                           .levelHashMismatch(level: 5, block: 0))
        }
    }

    func testRejectsInvalidMagicVersionLayerCountAndBounds() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.url) }

        var bad = fixture.hashData
        bad[0] = 0
        XCTAssertThrowsError(try NCAIVFCSuperblock(hashData: bad,
                                                    sectionSize: UInt64(fixture.section.count))) {
            XCTAssertEqual($0 as? NCAIVFCSuperblockError, .invalidMagic)
        }

        bad = fixture.hashData
        bad[4] = 1
        XCTAssertThrowsError(try NCAIVFCSuperblock(hashData: bad,
                                                    sectionSize: UInt64(fixture.section.count))) {
            XCTAssertEqual($0 as? NCAIVFCSuperblockError, .unsupportedVersion(0x00020001))
        }

        bad = fixture.hashData
        bad[0x0C] = 5
        XCTAssertThrowsError(try NCAIVFCSuperblock(hashData: bad,
                                                    sectionSize: UInt64(fixture.section.count))) {
            XCTAssertEqual($0 as? NCAIVFCSuperblockError, .unsupportedLayerCount(5))
        }

        bad = fixture.hashData
        put64(0xFFFF, at: 0x10, in: &bad)
        XCTAssertThrowsError(try NCAIVFCSuperblock(hashData: bad,
                                                    sectionSize: UInt64(fixture.section.count))) {
            XCTAssertEqual($0 as? NCAIVFCSuperblockError, .levelOutsideSection(0))
        }
    }

    func testRejectsMissingParentHashCapacity() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.url) }
        var bad = fixture.hashData
        put64(65, at: 0x10 + 0x18 + 8, in: &bad)
        XCTAssertThrowsError(try NCAIVFCSuperblock(hashData: bad,
                                                    sectionSize: UInt64(fixture.section.count)))
    }

    private struct Fixture {
        let url: URL
        let section: Data
        let hashData: Data
    }

    private func makeFixture(blockExponents: [UInt32] = [6, 6, 6, 6, 6, 6]) throws -> Fixture {
        let offsets: [UInt64] = [0x100, 0x200, 0x300, 0x400, 0x500, 0x600]
        let sizes: [UInt64] = [0x20, 0x20, 0x20, 0x20, 0x40, 0x50]
        guard blockExponents.count == 6 else { throw NSError(domain: "IVFC fixture", code: 1) }
        let offsets: [UInt64] = [0x100, 0x200, 0x300, 0x400, 0x500, 0x600]
        var section = Data(repeating: 0, count: 0x800)
        let romFS = Data((0..<0x50).map { UInt8(($0 * 13 + 9) & 0xFF) })
        var levelData = Array(repeating: Data(), count: 6)
        levelData[5] = romFS

        // Match hactool's full-block SHA-256 rule: the final short block is
        // zero-filled to the configured block size before hashing.
        for childIndex in stride(from: 5, through: 1, by: -1) {
            let blockSize = 1 << Int(blockExponents[childIndex])
            let child = levelData[childIndex]
            var hashes = Data()
            var cursor = 0
            while cursor < child.count {
                let end = min(cursor + blockSize, child.count)
                var block = child.subdata(in: cursor..<end)
                if block.count < blockSize {
                    block.append(Data(repeating: 0, count: blockSize - block.count))
                }
                hashes.append(Data(SHA256.hash(data: block)))
                cursor = end
            }
            levelData[childIndex - 1] = hashes
        }

        for index in 0..<6 {
            let data = levelData[index]
            section.replaceSubrange(
                Int(offsets[index])..<(Int(offsets[index]) + data.count),
                with: data
            )
        }

        let masterBlockSize = 1 << Int(blockExponents[0])
        var masterBlock = levelData[0]
        if masterBlock.count < masterBlockSize {
            masterBlock.append(Data(repeating: 0, count: masterBlockSize - masterBlock.count))
        }
        let master = Data(SHA256.hash(data: masterBlock))

        var hashData = Data(repeating: 0, count: 0xF8)
        put32(0x43465649, at: 0, in: &hashData)
        put32(0x00020000, at: 4, in: &hashData)
        put32(0x20, at: 8, in: &hashData)
        put32(6, at: 0x0C, in: &hashData)
        for index in 0..<6 {
            let at = 0x10 + index * 0x18
            put64(offsets[index], at: at, in: &hashData)
            put64(UInt64(levelData[index].count), at: at + 8, in: &hashData)
            put32(blockExponents[index], at: at + 0x10, in: &hashData)
        }
        hashData.replaceSubrange(0xC0..<0xE0, with: master)

        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try section.write(to: url)
        return Fixture(url: url, section: section, hashData: hashData)
    }

    private func put32(_ value: UInt32, at offset: Int, in data: inout Data) {
        var value = value.littleEndian
        withUnsafeBytes(of: &value) {
            data.replaceSubrange(offset..<(offset + 4), with: $0)
        }
    }

    private func put64(_ value: UInt64, at offset: Int, in data: inout Data) {
        var value = value.littleEndian
        withUnsafeBytes(of: &value) {
            data.replaceSubrange(offset..<(offset + 8), with: $0)
        }
    }
}
