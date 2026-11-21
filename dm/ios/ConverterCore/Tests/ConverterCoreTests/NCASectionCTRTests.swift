import Foundation
import XCTest
@testable import ConverterCore

final class NCASectionCTRTests: XCTestCase {
    func testBuildsCounterFromReversedSectionSeedAndAbsoluteOffset() throws {
        let seed = Data([0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87])
        let counter = try NCASectionCTR.counter(
            sectionCounter: seed,
            sectionFileOffset: 0x123456789ABC,
            offsetWithinSection: 0x30
        )
        XCTAssertEqual(
            counter,
            Data([
                0x87, 0x76, 0x65, 0x54, 0x43, 0x32, 0x21, 0x10,
                0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xCF
            ])
        )
    }

    func testUsesContainingAESBlockForUnalignedOffset() throws {
        let seed = Data(repeating: 0, count: 8)
        let counter = try NCASectionCTR.counter(
            sectionCounter: seed,
            sectionFileOffset: 0x200,
            offsetWithinSection: 0x1F
        )
        XCTAssertEqual(Array(counter.suffix(8)), [0, 0, 0, 0, 0, 0, 0, 0x21])
    }

    func testRejectsInvalidSeedAndOverflow() throws {
        XCTAssertThrowsError(try NCASectionCTR.counter(
            sectionCounter: Data(), sectionFileOffset: 0
        )) {
            XCTAssertEqual($0 as? NCASectionCTRError, .invalidSectionCounterLength(0))
        }
        XCTAssertThrowsError(try NCASectionCTR.counter(
            sectionCounter: Data(repeating: 0, count: 8),
            sectionFileOffset: UInt64.max,
            offsetWithinSection: 1
        )) {
            XCTAssertEqual($0 as? NCASectionCTRError, .arithmeticOverflow)
        }
    }
}
