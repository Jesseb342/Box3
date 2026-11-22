import Foundation
import XCTest
@testable import ConverterCore

final class NSPArchiveTests: XCTestCase {
    func testDiscoversNCAEntriesCaseInsensitivelyAndExtractsSelectedEntry() throws {
        let source = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let output = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer {
            try? FileManager.default.removeItem(at: source)
            try? FileManager.default.removeItem(at: output)
        }
        try makePFS0([
            ("control.nca", Data("CONTROL".utf8)),
            ("00A1.NCA", Data("PROGRAM".utf8)),
            ("meta.cnmt", Data("META".utf8)),
            ("readme.txt", Data("TEXT".utf8))
        ]).write(to: source)

        let archive = try NSPArchive(url: source)
        XCTAssertEqual(archive.ncaEntries.map(\.name), ["00A1.NCA", "control.nca"])
        try archive.extractNCA(named: "00A1.NCA", to: output)
        XCTAssertEqual(try Data(contentsOf: output), Data("PROGRAM".utf8))
        XCTAssertThrowsError(try archive.extractNCA(named: "meta.cnmt", to: output.appendingPathExtension("other")))
    }

    func testRejectsNSPWithoutNCAs() throws {
        let source = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: source) }
        try makePFS0([("meta.cnmt", Data("META".utf8))]).write(to: source)
        let archive = try NSPArchive(url: source)
        XCTAssertTrue(archive.ncaEntries.isEmpty)
    }

    private func makePFS0(_ files: [(String, Data)]) -> Data {
        var strings = Data()
        var nameOffsets: [UInt32] = []
        for (name, _) in files {
            nameOffsets.append(UInt32(strings.count))
            strings.append(contentsOf: name.utf8)
            strings.append(0)
        }
        var result = Data("PFS0".utf8)
        appendLE(UInt32(files.count), to: &result)
        appendLE(UInt32(strings.count), to: &result)
        appendLE(UInt32(0), to: &result)
        var offset: UInt64 = 0
        for (index, file) in files.enumerated() {
            appendLE(offset, to: &result)
            appendLE(UInt64(file.1.count), to: &result)
            appendLE(nameOffsets[index], to: &result)
            appendLE(UInt32(0), to: &result)
            offset += UInt64(file.1.count)
        }
        result.append(strings)
        for file in files { result.append(file.1) }
        return result
    }

    private func appendLE<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
    }
}
