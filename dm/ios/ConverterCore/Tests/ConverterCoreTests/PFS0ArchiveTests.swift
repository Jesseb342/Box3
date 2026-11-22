import Foundation
import XCTest
@testable import ConverterCore

final class PFS0ArchiveTests: XCTestCase {
    func testReadsMetadataAndStreamsEntries() throws {
        let fixture = makeArchive([
            ("base.nca", Data("ABC".utf8)),
            ("control.nca", Data("de".utf8)),
            ("empty.nca", Data())
        ])
        let source = try writeTemporary(fixture)
        let archive = try PFS0Archive(url: source)

        XCTAssertEqual(archive.entries.map(\.name), ["base.nca", "control.nca", "empty.nca"])
        XCTAssertEqual(archive.entry(named: "base.nca")?.size, 3)
        XCTAssertEqual(archive.entry(named: "control.nca")?.offset, 3)

        let output = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try archive.extractAll(to: output)
        XCTAssertEqual(try Data(contentsOf: output.appendingPathComponent("base.nca")), Data("ABC".utf8))
        XCTAssertEqual(try Data(contentsOf: output.appendingPathComponent("control.nca")), Data("de".utf8))
        XCTAssertEqual(try Data(contentsOf: output.appendingPathComponent("empty.nca")), Data())
    }

    func testReadsPFS0AtOffsetWithinLargerDecryptedSection() throws {
        let archiveBytes = makeArchive([("program.nso", Data("NSO!".utf8))])
        var container = Data(repeating: 0xA5, count: 0x200)
        container.append(archiveBytes)
        container.append(Data(repeating: 0x5A, count: 0x80))
        let source = try writeTemporary(container)
        defer { try? FileManager.default.removeItem(at: source) }

        let archive = try PFS0Archive(url: source, offset: 0x200, size: UInt64(archiveBytes.count))
        XCTAssertEqual(archive.entries.map(\\.name), ["program.nso"])
        let output = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: output) }
        try archive.copyEntry(named: "program.nso", to: output)
        XCTAssertEqual(try Data(contentsOf: output), Data("NSO!".utf8))
    }

    func testRegionBoundsPreventTrailingContainerBytesFromHidingInvalidEntry() throws {
        let archiveBytes = makeArchive([("bad.nca", Data("x".utf8))], declaredSize: 100)
        var container = archiveBytes
        container.append(Data(repeating: 0, count: 256))
        let source = try writeTemporary(container)
        defer { try? FileManager.default.removeItem(at: source) }

        XCTAssertThrowsError(try PFS0Archive(
            url: source, offset: 0, size: UInt64(archiveBytes.count)
        )) { error in
            XCTAssertEqual(error as? PFS0Error, .entryOutsideArchive("bad.nca"))
        }
    }

    func testRejectsRegionOutsideSourceFile() throws {
        let source = try writeTemporary(Data(repeating: 0, count: 32))
        defer { try? FileManager.default.removeItem(at: source) }
        XCTAssertThrowsError(try PFS0Archive(url: source, offset: 16, size: 32)) { error in
            XCTAssertEqual(error as? PFS0Error, .truncatedData)
        }
    }

    func testRejectsWrongMagic() throws {
        let source = try writeTemporary(Data(repeating: 0, count: 32))
        XCTAssertThrowsError(try PFS0Archive(url: source)) { error in
            XCTAssertEqual(error as? PFS0Error, .invalidMagic)
        }
    }

    func testRejectsEntryOutsideFile() throws {
        let source = try writeTemporary(makeArchive([("broken.nca", Data("x".utf8))], declaredSize: 100))
        XCTAssertThrowsError(try PFS0Archive(url: source)) { error in
            XCTAssertEqual(error as? PFS0Error, .entryOutsideArchive("broken.nca"))
        }
    }

    func testRejectsPathTraversalName() throws {
        let source = try writeTemporary(makeArchive([("../escape", Data())]))
        XCTAssertThrowsError(try PFS0Archive(url: source)) { error in
            XCTAssertEqual(error as? PFS0Error, .unsafeEntryName("../escape"))
        }
    }

    func testRejectsDuplicateNames() throws {
        let source = try writeTemporary(makeArchive([
            ("same.nca", Data()),
            ("same.nca", Data())
        ]))
        XCTAssertThrowsError(try PFS0Archive(url: source)) { error in
            XCTAssertEqual(error as? PFS0Error, .duplicateEntryName("same.nca"))
        }
    }

    private func writeTemporary(_ data: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try data.write(to: url)
        return url
    }

    private func makeArchive(
        _ files: [(String, Data)],
        declaredSize: UInt64? = nil
    ) -> Data {
        var strings = Data()
        var offsets: [UInt32] = []
        for (name, _) in files {
            offsets.append(UInt32(strings.count))
            strings.append(contentsOf: name.utf8)
            strings.append(0)
        }

        var result = Data("PFS0".utf8)
        appendLE(UInt32(files.count), to: &result)
        appendLE(UInt32(strings.count), to: &result)
        appendLE(UInt32(0), to: &result)

        var payloadOffset: UInt64 = 0
        for (index, file) in files.enumerated() {
            appendLE(payloadOffset, to: &result)
            appendLE(declaredSize ?? UInt64(file.1.count), to: &result)
            appendLE(offsets[index], to: &result)
            appendLE(UInt32(0), to: &result)
            payloadOffset += UInt64(file.1.count)
        }

        result.append(strings)
        for (_, payload) in files { result.append(payload) }
        return result
    }

    private func appendLE<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
    }
}
