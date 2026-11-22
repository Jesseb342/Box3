import CryptoKit
import Foundation
import XCTest
@testable import ConverterCore

final class RustNSOLoaderTests: XCTestCase {
    func testLoadsNSOThroughRustCBridgeAndMatchesSegmentMetadata() throws {
        let fixture = makeNSO()
        let inspected = try NSOImage(data: fixture)
        let loaded = try RustNSOLoader.load(fixture)

        XCTAssertEqual(loaded.bssSize, inspected.bssSize)
        XCTAssertEqual(Array(loaded.buildID.prefix(16)), Array(inspected.buildID))
        XCTAssertEqual(loaded.buildID.count, 32)
        XCTAssertEqual(loaded.segments.map(\.offset), [0, 0x1000, 0x2000])
        XCTAssertEqual(loaded.segments.map(\.size), [0x1000, 0x1000, 0x1000])
        XCTAssertEqual(loaded.image.count, 0x3000)

        for index in 0..<3 {
            let start = 0x100 + index * 0x1000
            let expected = fixture.subdata(in: start..<(start + 0x1000))
            let offset = index * 0x1000
            XCTAssertEqual(loaded.image.subdata(in: offset..<(offset + 0x1000)), expected)
        }
    }

    func testRustRewriteBridgeProcessesValidSyntheticNSO() throws {
        let rewritten = try RustNSORewriter.rewrite(makeNSO(), moduleName: "rtld")
        XCTAssertFalse(rewritten.image.isEmpty)
        XCTAssertGreaterThanOrEqual(rewritten.padTo, rewritten.image.count)
        XCTAssertTrue(rewritten.fixups.contains("# BUILD_ID\t"))
        XCTAssertTrue(rewritten.fixups.contains("# KEY_PAGE_SIZE\t0x4000"))
    }

    func testRustRewriteBridgeRejectsMalformedNSO() {
        XCTAssertThrowsError(try RustNSORewriter.rewrite(Data("not an NSO".utf8), moduleName: "main"))
    }

    func testRustRewriteOutputPadsImageBeforePatch() throws {
        let result = RustNSORewrite(image: Data([1, 2]), patch: Data([9, 8]), padTo: 4, fixups: "", gates: "", sites: "", cuts: "", changed: "", observations: "")
        XCTAssertEqual(try result.makePatchedData(), Data([1, 2, 0, 0, 9, 8]))
    }

    func testRustRewriteOutputRejectsInvalidPadding() {
        let result = RustNSORewrite(image: Data([1, 2, 3]), patch: Data([9]), padTo: 2, fixups: "", gates: "", sites: "", cuts: "", changed: "", observations: "")
        XCTAssertThrowsError(try result.makePatchedData())
    }

    func testRustBridgeRejectsSegmentHashMismatch() throws {
        var fixture = makeNSO()
        fixture[0x100] ^= 0x80
        XCTAssertThrowsError(try RustNSOLoader.load(fixture))
    }

    private func makeNSO() -> Data {
        var image = Data(repeating: 0, count: 0x100)
        image.replaceSubrange(0..<4, with: Data("NSO0".utf8))
        put32(0x38, into: &image, at: 0x0c) // SHA-256 checks for all three segments
        put32(0x400, into: &image, at: 0x3c)
        for index in 0..<32 { image[0x40 + index] = UInt8(index + 1) }

        for index in 0..<3 {
            let fileOffset = UInt32(0x100 + index * 0x1000)
            let memoryOffset = UInt32(index * 0x1000)
            let nop: [UInt8] = [0x1f, 0x20, 0x03, 0xd5]
            let payload = index == 0
                ? Data((0..<0x1000).map { nop[$0 % 4] })
                : Data((0..<0x1000).map { UInt8(($0 + index * 17) % 251) })
            let descriptor = 0x10 + index * 0x10
            put32(fileOffset, into: &image, at: descriptor)
            put32(memoryOffset, into: &image, at: descriptor + 4)
            put32(0x1000, into: &image, at: descriptor + 8)
            put32(0x1000, into: &image, at: 0x60 + index * 4)
            let digest = Data(SHA256.hash(data: payload))
            image.replaceSubrange((0xa0 + index * 0x20)..<(0xc0 + index * 0x20), with: digest)
            image.append(payload)
        }
        // Minimal valid MOD0 + empty eh_frame_hdr/dynamic table for the rewriter's code-range analysis.
        put32(0x100, into: &image, at: 0x104)
        image.replaceSubrange(0x200..<0x204, with: Data("MOD0".utf8))
        put32(0x700, into: &image, at: 0x204)
        put32(0x100, into: &image, at: 0x210)
        put32(0x10c, into: &image, at: 0x214)
        image.replaceSubrange(0x300..<0x304, with: Data([1, 3, 3, 3]))
        put32(0, into: &image, at: 0x304)
        put32(0, into: &image, at: 0x308)
        image.replaceSubrange(0x800..<0x810, with: Data(repeating: 0, count: 0x10))
        return image
    }

    private func put32(_ value: UInt32, into data: inout Data, at offset: Int) {
        var littleEndian = value.littleEndian
        let bytes = withUnsafeBytes(of: &littleEndian) { Array($0) }
        data.replaceSubrange(offset..<(offset + 4), with: bytes)
    }
}
