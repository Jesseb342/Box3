import Foundation
import CryptoKit
import XCTest
@testable import ConverterCore

final class PlayerBundleStagerTests: XCTestCase {
    private struct Fixture {
        let root: URL
        let template: URL
        let host: URL
        let framework: URL
        let modules: URL
        let romFS: URL
        let shaders: URL
        let profile: URL
        let output: URL
        let hostHash: String
    }

    func testStagesFullPlayerBundleWithBundledRomFS() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let request = makeRequest(fixture)
        let result = try PlayerBundleStager.stage(request)

        XCTAssertEqual(result.titleID, "01009bf0072d4000")
        XCTAssertEqual(result.copiedRomFSSize, 8)
        XCTAssertEqual(result.hostSHA256, fixture.hostHash)
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: fixture.output.appendingPathComponent("GameApp").path
        ))
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: fixture.output.appendingPathComponent("Frameworks/DmGameProbe.framework/DmGameProbe").path
        ))
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: fixture.output.appendingPathComponent("ExportedGame/extract/flat/main.patched.bin").path
        ))
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: fixture.output.appendingPathComponent("ExportedGame/extract/RomFS.img").path
        ))
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: fixture.output.appendingPathComponent("ExportedGame/shaders/01009bf0072d4000/library.metallib").path
        ))
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: fixture.output.appendingPathComponent("ExportedGame/documents/profile.tsv").path
        ))
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: fixture.output.appendingPathComponent("ExportedGame/manifest.tsv").path
        ))
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: fixture.output.appendingPathComponent("_CodeSignature").path
        ))

        let infoURL = fixture.output.appendingPathComponent("Info.plist")
        let info = try PropertyListSerialization.propertyList(
            from: Data(contentsOf: infoURL), options: [], format: nil
        ) as! [String: Any]
        XCTAssertEqual(info["CFBundleDisplayName"] as? String, "Captain Toad")
        XCTAssertEqual(info["CFBundleIdentifier"] as? String, "dev.ibuilder.app.g01009bf0072d4000")
    }

    func testRejectsDisabledBCFallback() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        var request = makeRequest(fixture)
        request = PlayerBundleStageRequest(
            templateAppURL: request.templateAppURL,
            hostURL: request.hostURL,
            expectedHostSHA256: request.expectedHostSHA256,
            frameworkURL: request.frameworkURL,
            rewrittenModulesURL: request.rewrittenModulesURL,
            romFSURL: request.romFSURL,
            shadersURL: request.shadersURL,
            profileURL: request.profileURL,
            playerManifest: request.playerManifest,
            titleID: request.titleID,
            displayName: request.displayName,
            outputAppURL: request.outputAppURL,
            bcFallbackEnabled: false
        )
        XCTAssertThrowsError(try PlayerBundleStager.stage(request)) { error in
            XCTAssertEqual(error as? PlayerBundleStagerError, .bcFallbackRequired)
        }
    }

    func testRejectsHostHashMismatchBeforeStaging() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let request = PlayerBundleStageRequest(
            templateAppURL: fixture.template,
            hostURL: fixture.host,
            expectedHostSHA256: String(repeating: "0", count: 64),
            frameworkURL: fixture.framework,
            rewrittenModulesURL: fixture.modules,
            romFSURL: fixture.romFS,
            shadersURL: fixture.shaders,
            profileURL: fixture.profile,
            playerManifest: Data("dump\tfixture.nsp\n".utf8),
            titleID: "01009bf0072d4000",
            displayName: "Captain Toad",
            outputAppURL: fixture.output,
            bcFallbackEnabled: true
        )
        XCTAssertThrowsError(try PlayerBundleStager.stage(request)) { error in
            XCTAssertEqual(error as? PlayerBundleStagerError, .hostHashMismatch)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.output.path))
    }

    private func makeRequest(_ fixture: Fixture) -> PlayerBundleStageRequest {
        PlayerBundleStageRequest(
            templateAppURL: fixture.template,
            hostURL: fixture.host,
            expectedHostSHA256: fixture.hostHash,
            frameworkURL: fixture.framework,
            rewrittenModulesURL: fixture.modules,
            romFSURL: fixture.romFS,
            shadersURL: fixture.shaders,
            profileURL: fixture.profile,
            playerManifest: Data("dump\tfixture.nsp\n".utf8),
            titleID: "01009bf0072d4000",
            displayName: "Captain Toad",
            outputAppURL: fixture.output,
            bcFallbackEnabled: true
        )
    }

    private func makeFixture() throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("PlayerBundleStagerTests-\(UUID().uuidString)", isDirectory: true)
        let template = root.appendingPathComponent("GameApp.app", isDirectory: true)
        let host = root.appendingPathComponent("host-prebuilt.dylib")
        let framework = root.appendingPathComponent("DmGameProbe.framework", isDirectory: true)
        let modules = root.appendingPathComponent("flat", isDirectory: true)
        let romFS = root.appendingPathComponent("RomFS.img")
        let shaders = root.appendingPathComponent("shaders", isDirectory: true)
        let profile = root.appendingPathComponent("profile.tsv")
        let output = root.appendingPathComponent("Captain Toad.app", isDirectory: true)

        try FileManager.default.createDirectory(at: template, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: template.appendingPathComponent("_CodeSignature"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: framework, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: modules, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: shaders, withIntermediateDirectories: true)
        try Data("player".utf8).write(to: template.appendingPathComponent("GameApp"))
        let appPlist: [String: Any] = [
            "CFBundleIdentifier": "dev.ibuilder.app",
            "CFBundleDisplayName": "iBuilder",
            "CFBundleName": "iBuilder"
        ]
        let appPlistData = try PropertyListSerialization.data(fromPropertyList: appPlist, format: .xml, options: 0)
        try appPlistData.write(to: template.appendingPathComponent("Info.plist"))
        try Data("signature".utf8).write(to: template.appendingPathComponent("_CodeSignature/CodeResources"))
        try Data("host-runtime".utf8).write(to: host)
        try Data("framework".utf8).write(to: framework.appendingPathComponent("DmGameProbe"))
        let frameworkPlist: [String: Any] = ["CFBundleExecutable": "DmGameProbe"]
        let frameworkPlistData = try PropertyListSerialization.data(fromPropertyList: frameworkPlist, format: .xml, options: 0)
        try frameworkPlistData.write(to: framework.appendingPathComponent("Info.plist"))
        try Data("module".utf8).write(to: modules.appendingPathComponent("main.patched.bin"))
        try Data("romfs123".utf8).write(to: romFS)
        try Data("shader".utf8).write(to: shaders.appendingPathComponent("library.metallib"))
        try Data("profile".utf8).write(to: profile)

        let hostHash = SHA256.hash(data: Data("host-runtime".utf8))
            .map { String(format: "%02x", $0) }.joined()
        return Fixture(
            root: root, template: template, host: host, framework: framework,
            modules: modules, romFS: romFS, shaders: shaders, profile: profile,
            output: output, hostHash: hostHash
        )
    }
}
