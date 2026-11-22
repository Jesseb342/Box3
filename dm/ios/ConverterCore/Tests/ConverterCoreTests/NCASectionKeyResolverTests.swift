import Foundation
import XCTest
@testable import ConverterCore

final class NCASectionKeyResolverTests: XCTestCase {
    func testDecryptsCorrectGenerationAndApplicationKeyAreaAndSelectsSlotTwo() throws {
        let wrappingKey = Data(repeating: 0x42, count: 16)
        let slots = (0..<4).map { Data(repeating: UInt8(0x10 + $0), count: 16) }
        let encrypted = try AESXTS.encryptECB(slots.reduce(into: Data()) { $0.append($1) }, key: wrappingKey)
        let header = try makeHeader(oldGeneration: 1, newGeneration: 3, area: 0, encrypted: encrypted)
        let keys = try ProdKeys(text: [
            "key_area_key_application_00=\(hex(Data(repeating: 0x99, count: 16)))",
            "key_area_key_application_02=\(hex(wrappingKey))"
        ].joined(separator: "\n"))

        let decrypted = try NCASectionKeyResolver.decryptKeyArea(header: header, keys: keys)
        XCTAssertEqual(decrypted, slots)
        XCTAssertEqual(try NCASectionKeyResolver.sectionCTRKey(header: header, keys: keys), slots[2])
        XCTAssertEqual(header.keyAreaGenerationIndex, 2)
    }

    func testSelectsOceanAndSystemKeyNames() throws {
        let key = Data(repeating: 0x55, count: 16)
        let slots = Data(repeating: 0xA7, count: 0x40)
        let encrypted = try AESXTS.encryptECB(slots, key: key)
        for (area, name) in [(UInt8(1), "ocean"), (UInt8(2), "system")] {
            let header = try makeHeader(oldGeneration: 0, newGeneration: 0, area: area, encrypted: encrypted)
            let keys = try ProdKeys(text: "key_area_key_\(name)_00=\(hex(key))")
            XCTAssertEqual(try NCASectionKeyResolver.decryptKeyArea(header: header, keys: keys).count, 4)
        }
    }

    func testRejectsMissingWrappingKeyAndInvalidAreaIndex() throws {
        let encrypted = Data(repeating: 0, count: 0x40)
        let header = try makeHeader(oldGeneration: 0, newGeneration: 0, area: 0, encrypted: encrypted)
        let empty = try ProdKeys(text: "header_key=\(hex(Data(repeating: 0, count: 32)))")
        XCTAssertThrowsError(try NCASectionKeyResolver.decryptKeyArea(header: header, keys: empty)) {
            XCTAssertEqual($0 as? NCASectionKeyResolverError, .missingKeyAreaKey("key_area_key_application_00"))
        }
        let invalid = try makeHeader(oldGeneration: 0, newGeneration: 0, area: 3, encrypted: encrypted)
        XCTAssertThrowsError(try NCASectionKeyResolver.decryptKeyArea(header: invalid, keys: empty)) {
            XCTAssertEqual($0 as? NCASectionKeyResolverError, .invalidKeyAreaKeyIndex(3))
        }
    }

    func testRejectsTitleKeyCryptoUntilTitleKeyPathExists() throws {
        var bytes = makePlainHeader(oldGeneration: 0, newGeneration: 0, area: 0, encrypted: Data(repeating: 0, count: 0x40))
        bytes[0x230] = 1
        let header = try NCAHeader(plaintextHeader: bytes)
        let keys = try ProdKeys(text: "key_area_key_application_00=\(hex(Data(repeating: 0, count: 16)))")
        XCTAssertThrowsError(try NCASectionKeyResolver.decryptKeyArea(header: header, keys: keys)) {
            XCTAssertEqual($0 as? NCASectionKeyResolverError, .titleKeyCryptoRequiresTitleKeySupport)
        }
    }


    func testDecryptsRightsIDTitleKeyWithMatchingTitleKekGeneration() throws {
        let titleKek = Data(repeating: 0x6D, count: 16)
        let clearTitleKey = Data((0..<16).map { UInt8(0xA0 + $0) })
        let encryptedTitleKey = try AESXTS.encryptECB(clearTitleKey, key: titleKek)
        let rightsID = Data((0..<16).map { UInt8($0 + 1) })
        var bytes = makePlainHeader(oldGeneration: 1, newGeneration: 3, area: 0, encrypted: Data(repeating: 0, count: 0x40))
        bytes.replaceSubrange(0x230..<0x240, with: rightsID)
        let header = try NCAHeader(plaintextHeader: bytes)
        let keys = try ProdKeys(text: "titlekek_02=\\(hex(titleKek))")
        let titleKeys = try TitleKeys(text: "\\(hex(rightsID))=\\(hex(encryptedTitleKey))")

        XCTAssertEqual(try NCASectionKeyResolver.titleKey(header: header, keys: keys, titleKeys: titleKeys), clearTitleKey)
        XCTAssertEqual(try NCASectionKeyResolver.sectionCTRKey(header: header, keys: keys, titleKeys: titleKeys), clearTitleKey)
    }

    func testAcceptsLibNXTicketCommonKeyAliasForTitleKek() throws {
        let titleKek = Data(repeating: 0x31, count: 16)
        let clearTitleKey = Data(repeating: 0x72, count: 16)
        let encryptedTitleKey = try AESXTS.encryptECB(clearTitleKey, key: titleKek)
        let rightsID = Data(repeating: 0x19, count: 16)
        var bytes = makePlainHeader(oldGeneration: 0, newGeneration: 0, area: 0, encrypted: Data(repeating: 0, count: 0x40))
        bytes.replaceSubrange(0x230..<0x240, with: rightsID)
        let header = try NCAHeader(plaintextHeader: bytes)
        let keys = try ProdKeys(text: "ticket_commonkey_00=\\(hex(titleKek))")
        let titleKeys = try TitleKeys(text: "\\(hex(rightsID))=\\(hex(encryptedTitleKey))")
        XCTAssertEqual(try NCASectionKeyResolver.titleKey(header: header, keys: keys, titleKeys: titleKeys), clearTitleKey)
    }

    func testRejectsMissingTitleKeyAndTitleKek() throws {
        let rightsID = Data(repeating: 0x2A, count: 16)
        var bytes = makePlainHeader(oldGeneration: 0, newGeneration: 0, area: 0, encrypted: Data(repeating: 0, count: 0x40))
        bytes.replaceSubrange(0x230..<0x240, with: rightsID)
        let header = try NCAHeader(plaintextHeader: bytes)
        let keys = try ProdKeys(text: "header_key=\\(hex(Data(repeating: 0, count: 32)))")
        let emptyTitles = try TitleKeys(text: "010003000e1468000000000000000008=00112233445566778899aabbccddeeff")
        XCTAssertThrowsError(try NCASectionKeyResolver.titleKey(header: header, keys: keys, titleKeys: emptyTitles)) {
            XCTAssertEqual($0 as? NCASectionKeyResolverError, .missingTitleKey(hex(rightsID)))
        }
        let titles = try TitleKeys(text: "\\(hex(rightsID))=00112233445566778899aabbccddeeff")
        XCTAssertThrowsError(try NCASectionKeyResolver.titleKey(header: header, keys: keys, titleKeys: titles)) {
            XCTAssertEqual($0 as? NCASectionKeyResolverError, .missingTitleKek("titlekek_00"))
        }
    }
\n    private func makeHeader(oldGeneration: UInt8, newGeneration: UInt8, area: UInt8, encrypted: Data) throws -> NCAHeader {
        try NCAHeader(plaintextHeader: makePlainHeader(oldGeneration: oldGeneration, newGeneration: newGeneration, area: area, encrypted: encrypted))
    }

    private func makePlainHeader(oldGeneration: UInt8, newGeneration: UInt8, area: UInt8, encrypted: Data) -> Data {
        var bytes = Data(repeating: 0, count: 0xC00)
        bytes.replaceSubrange(0x200..<0x204, with: Data("NCA3".utf8))
        putLE(UInt64(0x4000), at: 0x208, in: &bytes)
        bytes[0x206] = oldGeneration
        bytes[0x207] = area
        bytes[0x220] = newGeneration
        bytes.replaceSubrange(0x300..<0x340, with: encrypted)
        return bytes
    }

    private func putLE<T: FixedWidthInteger>(_ value: T, at offset: Int, in data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.replaceSubrange(offset..<(offset + $0.count), with: $0) }
    }

    private func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
}
