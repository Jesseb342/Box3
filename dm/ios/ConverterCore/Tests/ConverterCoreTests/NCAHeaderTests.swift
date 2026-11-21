import Foundation
import XCTest
@testable import ConverterCore

final class NCAHeaderTests: XCTestCase {
    func testParsesPlaintextNCA3Header() throws {
        var data = Data(repeating: 0, count: 0xC00)
        data.replaceSubrange(0x200..<0x204, with: Data("NCA3".utf8))
        data[0x204] = 1
        data[0x205] = 0
        data[0x206] = 2
        data[0x207] = 0
        putLE(UInt64(0x4000), at: 0x208, in: &data)
        putLE(UInt64(0x010015100B514000), at: 0x210, in: &data)
        putLE(UInt32(7), at: 0x218, in: &data)
        data[0x220] = 8
        putLE(UInt32(2), at: 0x240, in: &data)
        putLE(UInt32(0x10), at: 0x244, in: &data)

        let header = try NCAHeader(plaintextHeader: data, actualFileSize: 0x4000)
        XCTAssertEqual(header.magic, "NCA3")
        XCTAssertEqual(header.contentType, .program)
        XCTAssertEqual(header.titleID, 0x010015100B514000)
        XCTAssertEqual(header.contentIndex, 7)
        XCTAssertEqual(header.keyGeneration, 8)
        XCTAssertFalse(header.usesTitleKeyCrypto)
        XCTAssertEqual(header.sections.count, 1)
        XCTAssertEqual(header.sections[0].byteOffset, 0x400)
        XCTAssertEqual(header.sections[0].byteSize, 0x1C00)
    }

    func testDetectsTitleKeyCrypto() throws {
        var data = makeHeader()
        data[0x230] = 0x12
        let header = try NCAHeader(plaintextHeader: data)
        XCTAssertTrue(header.usesTitleKeyCrypto)
    }

    func testRejectsUnknownMagic() {
        var data = makeHeader()
        data.replaceSubrange(0x200..<0x204, with: Data("NOPE".utf8))
        XCTAssertThrowsError(try NCAHeader(plaintextHeader: data)) { error in
            XCTAssertEqual(error as? NCAHeaderError, .invalidMagic)
        }
    }

    func testRejectsFileSizeMismatch() {
        XCTAssertThrowsError(try NCAHeader(plaintextHeader: makeHeader(), actualFileSize: 0x2000)) { error in
            XCTAssertEqual(error as? NCAHeaderError, .fileSizeMismatch)
        }
    }

    func testRejectsOutOfBoundsSection() {
        var data = makeHeader()
        putLE(UInt32(0x7f), at: 0x240, in: &data)
        putLE(UInt32(0x100), at: 0x244, in: &data)
        XCTAssertThrowsError(try NCAHeader(plaintextHeader: data)) { error in
            XCTAssertEqual(error as? NCAHeaderError, .invalidSectionRange(0))
        }
    }

    private func makeHeader() -> Data {
        var data = Data(repeating: 0, count: 0xC00)
        data.replaceSubrange(0x200..<0x204, with: Data("NCA3".utf8))
        putLE(UInt64(0x4000), at: 0x208, in: &data)
        return data
    }

    private func putLE<T: FixedWidthInteger>(_ value: T, at offset: Int, in data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.replaceSubrange(offset..<(offset + $0.count), with: $0) }
    }
}
