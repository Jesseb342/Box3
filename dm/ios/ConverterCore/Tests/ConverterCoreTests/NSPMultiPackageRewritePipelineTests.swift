import Foundation
import XCTest
@testable import ConverterCore

final class NSPMultiPackageRewritePipelineTests: XCTestCase {
    func testRebasesModuleDirectoryAfterPublishedOutputMove() throws {
        let staging = URL(fileURLWithPath: "/tmp/.game-staging", isDirectory: true)
        let output = URL(fileURLWithPath: "/tmp/game-output", isDirectory: true)
        let original = staging.appendingPathComponent("base/module-sets/0000-section-0/rewritten/modules", isDirectory: true)
        let relocated = try NSPExecutableRewritePipeline.rebased(original, from: staging, to: output)
        XCTAssertEqual(
            relocated.path,
            "/tmp/game-output/base/module-sets/0000-section-0/rewritten/modules"
        )
    }

    func testRejectsModuleDirectoryOutsideStagingRoot() {
        let staging = URL(fileURLWithPath: "/tmp/.game-staging", isDirectory: true)
        let output = URL(fileURLWithPath: "/tmp/game-output", isDirectory: true)
        let outside = URL(fileURLWithPath: "/tmp/other/modules", isDirectory: true)
        XCTAssertThrowsError(try NSPExecutableRewritePipeline.rebased(outside, from: staging, to: output)) { error in
            XCTAssertEqual(error as? NSPExecutableRewritePipelineError, .invalidStagingPath)
        }
    }


    func testRebasesRomFSImageAfterPublishedOutputMove() throws {
        let staging = URL(fileURLWithPath: "/tmp/.game-staging", isDirectory: true)
        let output = URL(fileURLWithPath: "/tmp/game-output", isDirectory: true)
        let original = staging.appendingPathComponent(
            "base/module-sets/0000-section-1/romfs/0000-section-1/RomFS.img"
        )
        let relocated = try NSPExecutableRewritePipeline.rebased(original, from: staging, to: output)
        XCTAssertEqual(
            relocated.path,
            "/tmp/game-output/base/module-sets/0000-section-1/romfs/0000-section-1/RomFS.img"
        )
    }

    func testRejectsRomFSImageOutsideStagingRoot() {
        let staging = URL(fileURLWithPath: "/tmp/.game-staging", isDirectory: true)
        let output = URL(fileURLWithPath: "/tmp/game-output", isDirectory: true)
        let outside = URL(fileURLWithPath: "/tmp/other/RomFS.img")
        XCTAssertThrowsError(try NSPExecutableRewritePipeline.rebased(outside, from: staging, to: output)) { error in
            XCTAssertEqual(error as? NSPExecutableRewritePipelineError, .invalidStagingPath)
        }
    }

    func testOrdersBaseBeforeUpdateAndDLC() throws {
        let inputs = [
            NSPPackageInput(role: .dlc, url: URL(fileURLWithPath: "/tmp/dlc.nsp")),
            NSPPackageInput(role: .update, url: URL(fileURLWithPath: "/tmp/update.nsp")),
            NSPPackageInput(role: .base, url: URL(fileURLWithPath: "/tmp/base.nsp"))
        ]
        let ordered = try NSPMultiPackageRewritePipeline.validateAndOrder(inputs)
        XCTAssertEqual(ordered.map(\.role), [.base, .update, .dlc])
    }

    func testRequiresBasePackage() {
        let inputs = [NSPPackageInput(role: .update, url: URL(fileURLWithPath: "/tmp/update.nsp"))]
        XCTAssertThrowsError(try NSPMultiPackageRewritePipeline.validateAndOrder(inputs)) { error in
            XCTAssertEqual(error as? NSPMultiPackageRewriteError, .missingBasePackage)
        }
    }

    func testRejectsDuplicatePackageRole() {
        let inputs = [
            NSPPackageInput(role: .base, url: URL(fileURLWithPath: "/tmp/base.nsp")),
            NSPPackageInput(role: .base, url: URL(fileURLWithPath: "/tmp/other.nsp"))
        ]
        XCTAssertThrowsError(try NSPMultiPackageRewritePipeline.validateAndOrder(inputs)) { error in
            XCTAssertEqual(error as? NSPMultiPackageRewriteError, .duplicatePackageRole(.base))
        }
    }

    func testRejectsSameFileSelectedForMultipleRoles() {
        let url = URL(fileURLWithPath: "/tmp/shared.nsp")
        let inputs = [
            NSPPackageInput(role: .base, url: url),
            NSPPackageInput(role: .update, url: url)
        ]
        XCTAssertThrowsError(try NSPMultiPackageRewritePipeline.validateAndOrder(inputs)) { error in
            XCTAssertEqual(error as? NSPMultiPackageRewriteError, .duplicatePackageURL)
        }
    }
}
