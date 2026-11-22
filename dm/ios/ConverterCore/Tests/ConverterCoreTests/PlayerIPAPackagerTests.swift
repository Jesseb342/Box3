import Foundation
import ZIPFoundation
import XCTest
@testable import ConverterCore

final class PlayerIPAPackagerTests: XCTestCase {
    func testCreatesOneSelfContainedIPAWithRomFSInsidePayload() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let result = try PlayerIPAPackager.package(appURL: fixture.app, outputIPAURL: fixture.ipa)
        XCTAssertEqual(result.titleID, "01009bf0072d4000")
        XCTAssertEqual(result.romFSSize, 8)
        XCTAssertGreaterThan(result.entryCount, 4)
        XCTAssertGreaterThan(result.archiveSize, 0)

        let archive = try Archive(url: fixture.ipa, accessMode: .read)
        XCTAssertNotNil(archive["Payload/Captain Toad.app/GameApp"])
        XCTAssertNotNil(archive["Payload/Captain Toad.app/Frameworks/DmGameProbe.framework/DmGameProbe"])
        XCTAssertNotNil(archive["Payload/Captain Toad.app/ExportedGame/manifest.tsv"])
        XCTAssertNotNil(archive["Payload/Captain Toad.app/ExportedGame/extract/RomFS.img"])
        XCTAssertNotNil(archive["Payload/Captain Toad.app/ExportedGame/shaders/01009bf0072d4000/library.metallib"])
        XCTAssertNotNil(archive["Payload/Captain Toad.app/ExportedGame/documents/profile.tsv"])
        XCTAssertNil(archive["Captain Toad.romfs"])
    }

    func testRejectsMissingBundledRomFS() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        try FileManager.default.removeItem(at: fixture.app.appendingPathComponent("ExportedGame/extract/RomFS.img"))
        XCTAssertThrowsError(try PlayerIPAPackager.package(appURL: fixture.app, outputIPAURL: fixture.ipa)) { error in
            XCTAssertEqual(error as? PlayerIPAPackagerError, .missingRomFS)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.ipa.path))
    }

    private struct Fixture {
        let root: URL
        let app: URL
        let ipa: URL
    }

    private func makeFixture() throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("PlayerIPAPackagerTests-\(UUID().uuidString)", isDirectory: true)
        let app = root.appendingPathComponent("Captain Toad.app", isDirectory: true)
        let ipa = root.appendingPathComponent("Captain Toad.ipa")
        let manager = FileManager.default
        let framework = app.appendingPathComponent("Frameworks/DmGameProbe.framework", isDirectory: true)
        let gameRoot = app.appendingPathComponent("ExportedGame", isDirectory: true)
        let flat = gameRoot.appendingPathComponent("extract/flat", isDirectory: true)
        let shaders = gameRoot.appendingPathComponent("shaders/01009bf0072d4000", isDirectory: true)
        let documents = gameRoot.appendingPathComponent("documents", isDirectory: true)

        try manager.createDirectory(at: framework, withIntermediateDirectories: true)
        try manager.createDirectory(at: flat, withIntermediateDirectories: true)
        try manager.createDirectory(at: shaders, withIntermediateDirectories: true)
        try manager.createDirectory(at: documents, withIntermediateDirectories: true)
        try Data("player".utf8).write(to: app.appendingPathComponent("GameApp"))
        let plist: [String: Any] = ["CFBundleIdentifier": "dev.swapp.player.game", "CFBundleDisplayName": "Captain Toad"]
        let plistData = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try plistData.write(to: app.appendingPathComponent("Info.plist"))
        try Data("framework".utf8).write(to: framework.appendingPathComponent("DmGameProbe"))
        try Data("module".utf8).write(to: flat.appendingPathComponent("main.patched.bin"))
        try Data("romfs123".utf8).write(to: gameRoot.appendingPathComponent("extract/RomFS.img"))
        try Data("metallib".utf8).write(to: shaders.appendingPathComponent("library.metallib"))
        try Data("title_id\t01009bf0072d4000\n".utf8).write(to: documents.appendingPathComponent("profile.tsv"))
        let manifest = "title_id\t01009bf0072d4000\ndump\tCaptainToad.nsp\nname\tCaptain Toad\napp_build\tswapp-test\nexported\t2026-11-22T00:00:00Z\n"
        try Data(manifest.utf8).write(to: gameRoot.appendingPathComponent("manifest.tsv"))
        return Fixture(root: root, app: app, ipa: ipa)
    }
}
