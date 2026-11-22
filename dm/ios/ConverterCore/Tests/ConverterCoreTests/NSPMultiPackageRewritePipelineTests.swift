import Foundation
import XCTest
@testable import ConverterCore

final class NSPMultiPackageRewritePipelineTests: XCTestCase {
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
