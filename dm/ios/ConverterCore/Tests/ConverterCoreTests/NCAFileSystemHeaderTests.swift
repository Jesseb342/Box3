import Foundation
import CryptoKit
import XCTest
@testable import ConverterCore

final class NCAFileSystemHeaderTests: XCTestCase {
    func testParsesAndVerifiesPartitionFSHeader() throws {
        var data = Data(repeating: 0, count: 0xC00)
        let offset = 0x400 + 2 * 0x200
        data[offset] = 2
        data[offset + 1] = 0
        data[offset + 2] = 1
        data[offset + 3] = 2
        data[offset + 4] = 3
        data[offset + 5] = 1
        data[offset + 8] = 0xA5
        data[offset + 0x100] = 0x5A
        for i in 0..<8 { data[offset + 0x140 + i] = UInt8(0xC3 + i) }
        let raw = data.subdata(in: offset..<(offset + 0x200))
        let digest = Data(SHA256.hash(data: raw))

        let header = try NCAFileSystemHeader(
            decryptedNCAHeader: data,
            sectionIndex: 2,
            expectedHash: digest
        )

        XCTAssertEqual(header.sectionIndex, 2)
        XCTAssertEqual(header.version, 2)
        XCTAssertEqual(header.fileSystemType, .partitionFS)
        XCTAssertEqual(header.hashType, .hierarchicalSHA256)
        XCTAssertEqual(header.encryptionType, .aesCTR)
        XCTAssertEqual(header.metadataHashType, 1)
        XCTAssertEqual(header.hashData.count, 0xF8)
        XCTAssertEqual(header.hashData[0], 0xA5)
        XCTAssertEqual(header.extensionData.count, 0x40)
        XCTAssertEqual(header.extensionData[0], 0x5A)
        XCTAssertEqual(header.sectionCounter, Data((0xC3...0xCA).map(UInt8.init)))
        XCTAssertEqual(header.trailingData.count, 0xB8)
        XCTAssertEqual(header.trailingData[0], 0)
    }

    func testRejectsHeaderHashMismatch() throws {
        let data = Data(repeating: 0, count: 0xC00)
        XCTAssertThrowsError(try NCAFileSystemHeader(
            decryptedNCAHeader: data,
            sectionIndex: 0,
            expectedHash: Data(repeating: 0, count: 0x20)
        )) { error in
            XCTAssertEqual(error as? NCAFileSystemHeaderError, .headerHashMismatch(0))
        }
    }

    func testRejectsUnsupportedVersion() throws {
        var data = Data(repeating: 0, count: 0xC00)
        let offset = 0x400
        data[offset] = 3
        let raw = data.subdata(in: offset..<(offset + 0x200))
        XCTAssertThrowsError(try NCAFileSystemHeader(
            decryptedNCAHeader: data,
            sectionIndex: 0,
            expectedHash: Data(SHA256.hash(data: raw))
        )) { error in
            XCTAssertEqual(error as? NCAFileSystemHeaderError, .unsupportedVersion(3))
        }
    }

    func testRejectsInvalidSectionIndexAndDigestLength() throws {
        let data = Data(repeating: 0, count: 0xC00)
        XCTAssertThrowsError(try NCAFileSystemHeader(
            decryptedNCAHeader: data, sectionIndex: 4,
            expectedHash: Data(repeating: 0, count: 0x20)
        )) { error in
            XCTAssertEqual(error as? NCAFileSystemHeaderError, .invalidSectionIndex(4))
        }
        XCTAssertThrowsError(try NCAFileSystemHeader(
            decryptedNCAHeader: data, sectionIndex: 0,
            expectedHash: Data())
        ) { error in
            XCTAssertEqual(error as? NCAFileSystemHeaderError, .invalidHeaderHashLength(0))
        }
    }

    func testRejectsUnknownFilesystemHashAndEncryptionValues() throws {
        for (fieldOffset, value, expected) in [
            (2, UInt8(2), NCAFileSystemHeaderError.unsupportedFileSystemType(2)),
            (3, UInt8(7), NCAFileSystemHeaderError.unsupportedHashType(7)),
            (4, UInt8(7), NCAFileSystemHeaderError.unsupportedEncryptionType(7)),
            (5, UInt8(2), NCAFileSystemHeaderError.unsupportedMetadataHashType(2))
        ] {
            var data = Data(repeating: 0, count: 0xC00)
            let offset = 0x400
            data[offset] = 2
            data[offset + fieldOffset] = value
            let raw = data.subdata(in: offset..<(offset + 0x200))
            XCTAssertThrowsError(try NCAFileSystemHeader(
                decryptedNCAHeader: data, sectionIndex: 0,
                expectedHash: Data(SHA256.hash(data: raw))
            )) { error in
                XCTAssertEqual(error as? NCAFileSystemHeaderError, expected)
            }
        }
    }
}
