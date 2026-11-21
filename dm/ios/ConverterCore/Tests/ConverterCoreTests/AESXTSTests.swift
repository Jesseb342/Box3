import Foundation
import CryptoKit
import XCTest
@testable import ConverterCore

final class AESXTSTests: XCTestCase {
    func testIEEE1619Vector2EncryptsAndDecrypts() throws {
        // IEEE Std 1619-2007 Annex B, Vector 2.
        let key = Data(repeating: 0x11, count: 16) + Data(repeating: 0x22, count: 16)
        let plaintext = Data(repeating: 0x44, count: 32)
        let sequenceNumber: UInt64 = 0x3333333333
        var tweak = Data(repeating: 0, count: 16)
        var value = sequenceNumber
        for index in 0..<8 {
            tweak[index] = UInt8(value & 0xff)
            value >>= 8
        }
        let expected = try XCTUnwrap(Data(hex: "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0"))

        let encrypted = try AESXTS.encrypt(dataUnit: plaintext, combinedKey: key, tweak: tweak)
        XCTAssertEqual(encrypted, expected)
        XCTAssertEqual(try AESXTS.decrypt(dataUnit: encrypted, combinedKey: key, tweak: tweak), plaintext)
    }

    func testNintendoSectorXTSKnownAnswerVectors() throws {
        // Independent AES-XTS known-answer outputs for the Nintendo NCA tweak
        // layout. Reference ciphertexts were generated outside this Swift
        // implementation; full-sector SHA-256 catches any block/tweak mismatch.
        let key = Data((0..<32).map { UInt8($0 + 1) })
        let vectors: [(sector: Int, sha256: String)] = [
            (0, "5826fc86da1c216812215341386e4a16f13de7e26fd36cbbe0f42d218bf550ab"),
            (1, "b2cda8fd88c7a975591dac22306a2930afcfbb303779ca56dee0f2269a9cf000"),
            (5, "84607b126fad64191b2e01c98b4366c1fb8cafa3037b20ff63afb299d9023dd0")
        ]

        for vector in vectors {
            let plaintext = Data((0..<0x200).map {
                UInt8(($0 * 13 + vector.sector * 7) & 0xff)
            })
            let tweak = AESXTS.ncaSectorTweak(UInt64(vector.sector))
            let encrypted = try AESXTS.encrypt(
                dataUnit: plaintext,
                combinedKey: key,
                tweak: tweak
            )
            let digest = SHA256.hash(data: encrypted)
                .map { String(format: "%02x", $0) }
                .joined()
            XCTAssertEqual(digest, vector.sha256, "sector \(vector.sector)")
            XCTAssertEqual(
                try AESXTS.decrypt(dataUnit: encrypted, combinedKey: key, tweak: tweak),
                plaintext
            )
        }
    }

    func testNintendoSectorTweakUsesBigEndianSectorNumber() {
        XCTAssertEqual(
            AESXTS.ncaSectorTweak(0x0102030405060708),
            Data([UInt8](repeating: 0, count: 8) + [1, 2, 3, 4, 5, 6, 7, 8])
        )
    }

    func testRejectsPartialAESBlock() {
        XCTAssertThrowsError(
            try AESXTS.decrypt(
                dataUnit: Data(repeating: 0, count: 17),
                combinedKey: Data(repeating: 1, count: 32),
                tweak: Data(repeating: 0, count: 16)
            )
        ) { error in
            XCTAssertEqual(error as? AESXTSError, .dataUnitNotBlockAligned)
        }
    }


    func testNCAHeaderDecryptsSixNintendoSectors() throws {
        let key = Data((0..<32).map { UInt8($0 + 1) })
        let plaintext = Data((0..<0xC00).map { UInt8(($0 * 13) & 0xff) })
        var encrypted = Data()
        for sector in 0..<6 {
            let start = sector * 0x200
            let clear = plaintext.subdata(in: start..<(start + 0x200))
            encrypted.append(try AESXTS.encrypt(
                dataUnit: clear,
                combinedKey: key,
                tweak: AESXTS.ncaSectorTweak(UInt64(sector))
            ))
        }
        XCTAssertEqual(try AESXTS.decryptNCAHeader(encrypted, headerKey: key), plaintext)
    }

    func testRejectsWrongHeaderLength() {
        XCTAssertThrowsError(
            try AESXTS.decryptNCAHeader(Data(repeating: 0, count: 0xA00), headerKey: Data(repeating: 0, count: 32))
        ) { error in
            XCTAssertEqual(error as? AESXTSError, .invalidNCAHeaderLength)
        }
    }
}

private extension Data {
    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}
