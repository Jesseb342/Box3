import XCTest
@testable import ConverterCore

final class NSOPatchLayoutTests: XCTestCase {
    func testNearLayoutPlacesKeyPageAfterBSS() throws {
        let layout = try NSOPatchLayout.make(
            segments: segments(text: 0x1000, ro: 0x1000, data: 0x1000),
            bssSize: 0x2000
        )
        XCTAssertFalse(layout.isFar)
        XCTAssertFalse(layout.isBigText)
        XCTAssertEqual(layout.keyPageOffset, 0x8000)
        XCTAssertEqual(layout.fileImageLength, 0xC000)
        XCTAssertEqual(layout.imageSize, 0xC000)
        XCTAssertEqual(layout.patchOffset, 0x10000)
    }

    func testFarLayoutKeepsBSSOutOfFileImage() throws {
        let layout = try NSOPatchLayout.make(
            segments: segments(text: 0x1000, ro: 0x1000, data: 0x7000000),
            bssSize: 0x100000
        )
        XCTAssertTrue(layout.isFar)
        XCTAssertFalse(layout.isBigText)
        XCTAssertEqual(layout.patchOffset, -0x02000000)
        XCTAssertEqual(layout.keyPageOffset, 0x07104000)
        XCTAssertEqual(layout.fileImageLength, 0x07004000)
    }

    func testBigTextReducesFrontPlacement() throws {
        let layout = try NSOPatchLayout.make(
            segments: segments(text: 0x7000000, ro: 0x1000, data: 0x1000),
            bssSize: 0x100000
        )
        XCTAssertTrue(layout.isFar)
        XCTAssertTrue(layout.isBigText)
        XCTAssertLessThan(abs(layout.patchOffset), NSOPatchLayout.defaultFront)
        XCTAssertEqual(UInt64(-layout.patchOffset) & 0xffff, 0)
    }

    func testHonorsExplicitFrontOverride() throws {
        let layout = try NSOPatchLayout.make(
            segments: segments(text: 0x1000, ro: 0x1000, data: 0x7000000),
            bssSize: 0,
            frontOverride: 0x01000000
        )
        XCTAssertEqual(layout.patchOffset, -0x00f00000)
    }

    func testRejectsIncorrectSegmentOrder() {
        XCTAssertThrowsError(
            try NSOPatchLayout.make(
                segments: [
                    segment(index: 0, offset: 0, size: 0x1000),
                    segment(index: 1, offset: 0x800, size: 0x1000),
                    segment(index: 2, offset: 0x2000, size: 0x1000)
                ],
                bssSize: 0
            )
        ) {
            XCTAssertEqual($0 as? NSOPatchLayoutError, .invalidSegmentLayout)
        }
    }

    private func segments(text: UInt32, ro: UInt32, data: UInt32) -> [NSOImage.Segment] {
        [
            segment(index: 0, offset: 0, size: text),
            segment(index: 1, offset: text, size: ro),
            segment(index: 2, offset: text + ro, size: data)
        ]
    }

    private func segment(index: Int, offset: UInt32, size: UInt32) -> NSOImage.Segment {
        NSOImage.Segment(
            index: index,
            fileOffset: 0x100,
            memoryOffset: offset,
            memorySize: size,
            storedSize: size,
            isCompressed: false
        )
    }
}
