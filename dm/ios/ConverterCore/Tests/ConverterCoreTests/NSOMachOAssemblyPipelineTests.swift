import Foundation
import XCTest
@testable import ConverterCore

final class NSOMachOAssemblyPipelineTests: XCTestCase {
    func testValidModuleSetPassesPreflight() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("SwappAssemblyPreflight-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let modules = root.appendingPathComponent("modules", isDirectory: true)
        try FileManager.default.createDirectory(at: modules, withIntermediateDirectories: true)
        let host = root.appendingPathComponent("host.dylib")
        try Data([0xCF, 0xFA, 0xED, 0xFE]).write(to: host)
        for name in ["main", "sdk", "subsdk0"] {
            try Data([0x01]).write(to: modules.appendingPathComponent("\(name).patched.bin"))
            try Data("header\n".utf8).write(to: modules.appendingPathComponent("\(name).fixups.tsv"))
            try Data("gate\n".utf8).write(to: modules.appendingPathComponent("\(name).gates.tsv"))
        }
        let output = root.appendingPathComponent("Game.framework.dylib")
        let selected = try NSOMachOAssemblyPipeline.validateInputs(
            hostURL: host,
            rewrittenModulesDirectory: modules,
            modules: ["main", "sdk", "subsdk0"],
            outputURL: output
        )
        XCTAssertEqual(selected, ["main", "sdk", "subsdk0"])
    }

    func testMissingFixupsAreRejectedBeforeNativeAssembly() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("SwappAssemblyMissing-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let modules = root.appendingPathComponent("modules", isDirectory: true)
        try FileManager.default.createDirectory(at: modules, withIntermediateDirectories: true)
        let host = root.appendingPathComponent("host.dylib")
        try Data([0xCF, 0xFA, 0xED, 0xFE]).write(to: host)
        try Data([0x01]).write(to: modules.appendingPathComponent("main.patched.bin"))
        XCTAssertThrowsError(try NSOMachOAssemblyPipeline.validateInputs(
            hostURL: host,
            rewrittenModulesDirectory: modules,
            modules: ["main"],
            outputURL: root.appendingPathComponent("Game.framework.dylib")
        )) { error in
            XCTAssertEqual(error as? NSOMachOAssemblyPipelineError, .missingFixups("main"))
        }
    }


    func testMissingGateTablesAreRejectedBeforeNativeAssembly() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("SwappAssemblyNoGates-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let modules = root.appendingPathComponent("modules", isDirectory: true)
        try FileManager.default.createDirectory(at: modules, withIntermediateDirectories: true)
        let host = root.appendingPathComponent("host.dylib")
        try Data([0xCF, 0xFA, 0xED, 0xFE]).write(to: host)
        try Data([0x01]).write(to: modules.appendingPathComponent("main.patched.bin"))
        try Data("fixups\n".utf8).write(to: modules.appendingPathComponent("main.fixups.tsv"))
        XCTAssertThrowsError(try NSOMachOAssemblyPipeline.validateInputs(
            hostURL: host,
            rewrittenModulesDirectory: modules,
            modules: ["main"],
            outputURL: root.appendingPathComponent("Game.framework.dylib")
        )) { error in
            XCTAssertEqual(error as? NSOMachOAssemblyPipelineError, .missingGates("main"))
        }
    }

    func testDuplicateModuleNamesAreRejected() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("SwappAssemblyDuplicate-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let modules = root.appendingPathComponent("modules", isDirectory: true)
        try FileManager.default.createDirectory(at: modules, withIntermediateDirectories: true)
        let host = root.appendingPathComponent("host.dylib")
        try Data([0xCF, 0xFA, 0xED, 0xFE]).write(to: host)
        XCTAssertThrowsError(try NSOMachOAssemblyPipeline.validateInputs(
            hostURL: host,
            rewrittenModulesDirectory: modules,
            modules: ["main", "main"],
            outputURL: root.appendingPathComponent("Game.framework.dylib")
        )) { error in
            XCTAssertEqual(error as? NSOMachOAssemblyPipelineError, .duplicateModuleName("main"))
        }
    }
}
