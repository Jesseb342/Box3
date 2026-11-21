import Foundation
import XCTest
@testable import ConverterCore

final class NCASectionCTRCryptTests: XCTestCase {
    func testMatchesNISTAES128CTRKnownAnswer() throws {
        let key = try Self.hex("2b7e151628aed2a6abf7158809cf4f3c")
        let counter = try Self.hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        let plaintext = try Self.hex("6bc1bee22e409f96e93d7e117393172a")
        let expected = try Self.hex("874d6191b620e3261bef6864990db6ce")
        XCTAssertEqual(try NCASectionCTRCrypt.crypt(
            data: plaintext, key: key, initialCounter: counter
        ), expected)
    }

    func testNCAUnalignedRangeMatchesSliceOfWholeSectionTransform() throws {
        let key = Data((0..<16).map(UInt8.init))
        let seed = Data([0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87])
        let sectionStart: UInt64 = 0x4000
        let plaintext = Data((0..<97).map { UInt8(($0 * 13) & 0xff) })
        let whole = try NCASectionCTRCrypt.crypt(
            data: plaintext, key: key, sectionCounter: seed,
            sectionFileOffset: sectionStart, offsetWithinSection: 0
        )
        let start = 7, length = 51
        let slice = try NCASectionCTRCrypt.crypt(
            data: plaintext.subdata(in: start..<(start + length)),
            key: key, sectionCounter: seed,
            sectionFileOffset: sectionStart, offsetWithinSection: UInt64(start)
        )
        XCTAssertEqual(slice, whole.subdata(in: start..<(start + length)))
    }

    func testCTRIsSymmetricAndHandlesEmptyInput() throws {
        let key = Data(repeating: 0xA5, count: 32)
        let counter = Data(repeating: 0x3C, count: 16)
        let plaintext = Data((0..<53).map { UInt8($0) })
        let encrypted = try NCASectionCTRCrypt.crypt(data: plaintext, key: key, initialCounter: counter)
        let decrypted = try NCASectionCTRCrypt.crypt(data: encrypted, key: key, initialCounter: counter)
        XCTAssertEqual(decrypted, plaintext)
        XCTAssertEqual(try NCASectionCTRCrypt.crypt(data: Data(), key: key, initialCounter: counter), Data())
    }

    func testRejectsInvalidKeyCounterAndByteOffset() throws {
        let counter = Data(repeating: 0, count: 16)
        XCTAssertThrowsError(try NCASectionCTRCrypt.crypt(
            data: Data([1]), key: Data(), initialCounter: counter
        )) { XCTAssertEqual($0 as? NCASectionCTRCryptError, .invalidAESKeyLength(0)) }
        XCTAssertThrowsError(try NCASectionCTRCrypt.crypt(
            data: Data([1]), key: Data(repeating: 0, count: 16), initialCounter: Data()
        )) { XCTAssertEqual($0 as? NCASectionCTRCryptError, .invalidCounterLength(0)) }
        XCTAssertThrowsError(try NCASectionCTRCrypt.crypt(
            data: Data([1]), key: Data(repeating: 0, count: 16),
            initialCounter: counter, byteOffsetInBlock: 16
        )) { XCTAssertEqual($0 as? NCASectionCTRCryptError, .invalidByteOffset(16)) }
    }

    func testRejectsLow64CounterWrapWhenMoreDataRemains() throws {
        var counter = Data(repeating: 0, count: 16)
        for index in 8..<16 { counter[index] = 0xFF }
        XCTAssertThrowsError(try NCASectionCTRCrypt.crypt(
            data: Data(repeating: 0, count: 17),
            key: Data(repeating: 0, count: 16), initialCounter: counter
        )) { XCTAssertEqual($0 as? NCASectionCTRCryptError, .counterOverflow) }
    }

    private static func hex(_ string: String) throws -> Data {
        var result = Data()
        let bytes = Array(string.utf8)
        guard bytes.count.isMultiple(of: 2) else { throw NSError(domain: "hex", code: 1) }
        for index in stride(from: 0, to: bytes.count, by: 2) {
            guard let high = UInt8(String(decoding: [bytes[index]], as: UTF8.self), radix: 16),
                  let low = UInt8(String(decoding: [bytes[index + 1]], as: UTF8.self), radix: 16) else {
                throw NSError(domain: "hex", code: 2)
            }
            result.append((high << 4) | low)
        }
        return result
    }
}
