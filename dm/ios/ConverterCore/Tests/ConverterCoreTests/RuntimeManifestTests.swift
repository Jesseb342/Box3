import Foundation
import XCTest
import CryptoKit
@testable import ConverterCore

final class RuntimeManifestTests: XCTestCase {
    private let validHash = String(repeating: "a", count: 64)

    private func manifest(
        schemaVersion: Int = 1,
        titleID: String = "010015100B514000",
        modules: [RuntimeManifest.Module]? = nil,
        resources: [RuntimeManifest.Resource] = []
    ) -> RuntimeManifest {
        RuntimeManifest(
            schemaVersion: schemaVersion,
            titleID: titleID,
            displayName: "Fixture Game",
            modules: modules ?? [
                .init(name: "main", path: "modules/main.bin", sha256: validHash),
                .init(name: "sdk", path: "modules/sdk.bin", sha256: validHash)
            ],
            resources: resources,
            bcFallbackEnabled: true
        )
    }

    func testRoundTripsDeterministically() throws {
        let value = manifest()
        let first = try value.encoded()
        let second = try value.encoded()
        XCTAssertEqual(first, second)
        XCTAssertEqual(try RuntimeManifest.decode(first), value)
    }

    func testAllowsDifferentGenericModuleSets() throws {
        let value = manifest(modules: [
            .init(name: "main", path: "guest/main", sha256: validHash),
            .init(name: "rtld", path: "guest/rtld", sha256: validHash),
            .init(name: "subsdk9", path: "guest/subsdk9", sha256: validHash)
        ])
        XCTAssertNoThrow(try value.validate())
    }

    func testRejectsUnknownSchemaVersion() {
        XCTAssertThrowsError(try manifest(schemaVersion: 2).validate()) {
            XCTAssertEqual($0 as? RuntimeManifestError, .unsupportedSchemaVersion(2))
        }
    }

    func testRejectsInvalidTitleID() {
        XCTAssertThrowsError(try manifest(titleID: "../not-a-title-id").validate()) {
            XCTAssertEqual($0 as? RuntimeManifestError, .invalidTitleID)
        }
    }

    func testRequiresMainModule() {
        let value = manifest(modules: [
            .init(name: "sdk", path: "modules/sdk", sha256: validHash)
        ])
        XCTAssertThrowsError(try value.validate()) {
            XCTAssertEqual($0 as? RuntimeManifestError, .missingMainModule)
        }
    }

    func testRejectsDuplicateModuleNames() {
        let value = manifest(modules: [
            .init(name: "main", path: "modules/main", sha256: validHash),
            .init(name: "main", path: "modules/other", sha256: validHash)
        ])
        XCTAssertThrowsError(try value.validate()) {
            XCTAssertEqual($0 as? RuntimeManifestError, .duplicateModuleName("main"))
        }
    }

    func testRejectsTraversalAndAbsolutePaths() {
        for path in ["../outside", "/absolute/file", "modules//main", "modules/./main", "modules\\main"] {
            let value = manifest(modules: [
                .init(name: "main", path: path, sha256: validHash)
            ])
            XCTAssertThrowsError(try value.validate(), "accepted path: \(path)") {
                XCTAssertEqual($0 as? RuntimeManifestError, .invalidRelativePath(path))
            }
        }
    }

    func testRejectsDuplicatePathsAcrossModulesAndResources() {
        let value = manifest(resources: [
            .init(path: "modules/main.bin", sha256: validHash)
        ])
        XCTAssertThrowsError(try value.validate()) {
            XCTAssertEqual($0 as? RuntimeManifestError, .duplicatePath("modules/main.bin"))
        }
    }

    func testRejectsMalformedHash() {
        let value = manifest(modules: [
            .init(name: "main", path: "modules/main", sha256: "xyz")
        ])
        XCTAssertThrowsError(try value.validate()) {
            XCTAssertEqual($0 as? RuntimeManifestError, .invalidSHA256("modules/main"))
        }
    }

    func testVerifiesStagedFilesAndHashes() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let payload = Data("fixture executable".utf8)
        let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        let moduleURL = root.appendingPathComponent("modules/main.bin")
        try FileManager.default.createDirectory(
            at: moduleURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try payload.write(to: moduleURL)

        let value = manifest(modules: [
            .init(name: "main", path: "modules/main.bin", sha256: digest)
        ])
        XCTAssertNoThrow(try value.verifyFiles(rootURL: root))
    }

    func testRejectsHashMismatch() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("wrong".utf8).write(to: root.appendingPathComponent("main.bin"))

        let value = manifest(modules: [
            .init(name: "main", path: "main.bin", sha256: validHash)
        ])
        XCTAssertThrowsError(try value.verifyFiles(rootURL: root)) {
            XCTAssertEqual($0 as? RuntimeManifestError, .fileHashMismatch("main.bin"))
        }
    }
}
