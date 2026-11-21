import Foundation
import XCTest
import CryptoKit
@testable import ConverterCore

final class NCAFileInspectorTests: XCTestCase {
    private let fileSize: UInt64 = 0x4000
    private let headerKey = Data((0..<32).map { UInt8($0) })

    func testInspectsEncryptedNCA3HeaderWithoutReadingPayload() throws {
        let url = try makeNCAFile()
        defer { try? FileManager.default.removeItem(at: url) }

        let keys = try ProdKeys(text: "header_key=\(headerKey.map { String(format: "%02x", $0) }.joined())")
        let result = try NCAFileInspector.inspect(url: url, keys: keys)

        XCTAssertEqual(result.fileSize, fileSize)
        XCTAssertEqual(result.header.magic, "NCA3")
        XCTAssertEqual(result.header.contentType, .program)
        XCTAssertEqual(result.header.titleID, 0x010015100B514000)
        XCTAssertEqual(result.header.sections.count, 1)
        let section = try XCTUnwrap(result.header.sections.first)
        let fsHeader = try result.fileSystemHeader(for: section)
        XCTAssertEqual(fsHeader.fileSystemType, .partitionFS)
        XCTAssertEqual(fsHeader.hashType, .hierarchicalSHA256)
        XCTAssertEqual(fsHeader.encryptionType, .aesCTR)
    }

    func testRejectsMissingHeaderKey() throws {
        let url = try makeNCAFile()
        defer { try? FileManager.default.removeItem(at: url) }
        let keys = try ProdKeys(text: "master_key_00=00112233")

        XCTAssertThrowsError(try NCAFileInspector.inspect(url: url, keys: keys)) { error in
            XCTAssertEqual(error as? NCAFileInspectorError, .missingHeaderKey)
        }
    }

    func testRejectsWrongHeaderKeyLength() throws {
        let url = try makeNCAFile()
        defer { try? FileManager.default.removeItem(at: url) }
        let keys = try ProdKeys(text: "header_key=0011223344556677")

        XCTAssertThrowsError(try NCAFileInspector.inspect(url: url, keys: keys)) { error in
            XCTAssertEqual(error as? NCAFileInspectorError, .invalidHeaderKeyLength(8))
        }
    }

    func testRejectsTruncatedFileBeforeDecrypting() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try Data(repeating: 0, count: 0xBFF).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let keys = try ProdKeys(text: "header_key=\(headerKey.map { String(format: "%02x", $0) }.joined())")

        XCTAssertThrowsError(try NCAFileInspector.inspect(url: url, keys: keys)) { error in
            XCTAssertEqual(error as? NCAFileInspectorError, .fileTooSmall(0xBFF))
        }
    }

    private func makeNCAFile() throws -> URL {
        var plaintext = Data(repeating: 0, count: 0xC00)
        plaintext.replaceSubrange(0x200..<0x204, with: Data("NCA3".utf8))
        plaintext[0x205] = 0
        let fsOffset = 0x400
        plaintext[fsOffset] = 2
        plaintext[fsOffset + 1] = 0
        plaintext[fsOffset + 2] = 1
        plaintext[fsOffset + 3] = 2
        plaintext[fsOffset + 4] = 3
        let fsHeader = plaintext.subdata(in: fsOffset..<(fsOffset + 0x200))
        let fsDigest = Data(SHA256.hash(data: fsHeader))
        plaintext.replaceSubrange(0x280..<0x2A0, with: fsDigest)
        putLE(fileSize, at: 0x208, in: &plaintext)
        putLE(UInt64(0x010015100B514000), at: 0x210, in: &plaintext)
        putLE(UInt32(2), at: 0x240, in: &plaintext)
        putLE(UInt32(0x10), at: 0x244, in: &plaintext)

        var encrypted = Data()
        for sector in 0..<6 {
            let start = sector * 0x200
            let clear = plaintext.subdata(in: start..<(start + 0x200))
            encrypted.append(try AESXTS.encrypt(
                dataUnit: clear,
                combinedKey: headerKey,
                tweak: AESXTS.ncaSectorTweak(UInt64(sector))
            ))
        }
        encrypted.append(Data(repeating: 0, count: Int(fileSize) - encrypted.count))

        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try encrypted.write(to: url)
        return url
    }

    private func putLE<T: FixedWidthInteger>(_ value: T, at offset: Int, in data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) {
            data.replaceSubrange(offset..<(offset + $0.count), with: $0)
        }
    }
}
