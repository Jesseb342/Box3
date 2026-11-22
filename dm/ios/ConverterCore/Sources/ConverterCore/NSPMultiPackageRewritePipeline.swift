import Foundation

public enum NSPPackageRole: String, Codable, CaseIterable {
    case base
    case update
    case dlc
}

public struct NSPPackageInput {
    public let role: NSPPackageRole
    public let url: URL

    public init(role: NSPPackageRole, url: URL) {
        self.role = role
        self.url = url
    }
}

public enum NSPMultiPackageRewriteError: Error, Equatable {
    case missingBasePackage
    case duplicatePackageRole(NSPPackageRole)
    case duplicatePackageURL
    case invalidPackageURL(NSPPackageRole)
    case couldNotCreateStagingDirectory
}

public struct NSPPackageRewriteSummary {
    public let role: NSPPackageRole
    public let ncaCount: Int
    public let moduleSets: [NSPExecutableRewriteModuleSet]
}

public struct NSPMultiPackageRewriteResult {
    public let gameProfile: String
    public let outputDirectory: URL
    public let packages: [NSPPackageRewriteSummary]
}

/// Orchestrates base, optional update, and optional DLC NSPs as one conversion job.
/// Keys are parsed once and held in memory. The base title ID is used as the
/// shared iBuilder game profile for update and DLC content.
public enum NSPMultiPackageRewritePipeline {
    public static func process(
        packages: [NSPPackageInput],
        prodKeysURL: URL,
        titleKeysURL: URL? = nil,
        gamesDirectory: URL? = nil,
        outputDirectory: URL
    ) throws -> NSPMultiPackageRewriteResult {
        let ordered = try validateAndOrder(packages)
        let keys = try ProdKeys(contentsOf: prodKeysURL)
        let titleKeys = try titleKeysURL.map { try TitleKeys(contentsOf: $0) }

        guard outputDirectory.isFileURL else {
            throw NSPMultiPackageRewriteError.invalidPackageURL(.base)
        }
        let manager = FileManager.default
        guard !manager.fileExists(atPath: outputDirectory.path) else {
            throw NSPExecutableRewritePipelineError.outputAlreadyExists
        }
        let parent = outputDirectory.deletingLastPathComponent()
        try manager.createDirectory(at: parent, withIntermediateDirectories: true)
        let staging = parent.appendingPathComponent(
            ".\(outputDirectory.lastPathComponent).multi-nsp-\(UUID().uuidString)",
            isDirectory: true
        )
        do {
            try manager.createDirectory(at: staging, withIntermediateDirectories: false)
        } catch {
            throw NSPMultiPackageRewriteError.couldNotCreateStagingDirectory
        }

        do {
            var summaries: [NSPPackageRewriteSummary] = []
            var baseGameProfile: String?
            for input in ordered {
                let packageOutput = staging.appendingPathComponent(input.role.rawValue, isDirectory: true)
                let result = try NSPExecutableRewritePipeline.process(
                    nspURL: input.url,
                    keys: keys,
                    titleKeys: titleKeys,
                    gamesDirectory: gamesDirectory,
                    gameProfile: baseGameProfile,
                    outputDirectory: packageOutput
                )
                if input.role == .base {
                    guard let titleID = result.moduleSets.first?.titleID else {
                        throw NSPExecutableRewritePipelineError.noSupportedProgramExeFS
                    }
                    baseGameProfile = titleID
                }
                summaries.append(NSPPackageRewriteSummary(
                    role: input.role,
                    ncaCount: result.ncaCount,
                    moduleSets: result.moduleSets
                ))
            }

            guard let gameProfile = baseGameProfile else {
                throw NSPMultiPackageRewriteError.missingBasePackage
            }
            let manifestData = try JSONEncoder.box3MultiNSPManifest.encode(
                NSPMultiPackageManifest(gameProfile: gameProfile, packages: summaries.map {
                    NSPPackageManifestEntry(
                        role: $0.role,
                        ncaCount: $0.ncaCount,
                        moduleSets: $0.moduleSets.map {
                            NSPModuleSetManifest(
                                ncaFileName: $0.ncaFileName,
                                titleID: $0.titleID,
                                sectionIndex: $0.sectionIndex,
                                verifiedPFS0Blocks: $0.verifiedPFS0Blocks,
                                extractedEntryCount: $0.extractedEntryCount,
                                modules: $0.modules
                            )
                        }
                    )
                })
            )
            try manifestData.write(to: staging.appendingPathComponent("manifest.json"), options: [.atomic])
            try manager.moveItem(at: staging, to: outputDirectory)
            return NSPMultiPackageRewriteResult(
                gameProfile: gameProfile,
                outputDirectory: outputDirectory,
                packages: summaries
            )
        } catch {
            try? manager.removeItem(at: staging)
            throw error
        }
    }

    static func validateAndOrder(_ packages: [NSPPackageInput]) throws -> [NSPPackageInput] {
        var byRole: [NSPPackageRole: NSPPackageInput] = [:]
        var paths = Set<String>()
        for input in packages {
            guard input.url.isFileURL else {
                throw NSPMultiPackageRewriteError.invalidPackageURL(input.role)
            }
            guard byRole[input.role] == nil else {
                throw NSPMultiPackageRewriteError.duplicatePackageRole(input.role)
            }
            guard paths.insert(input.url.standardizedFileURL.path).inserted else {
                throw NSPMultiPackageRewriteError.duplicatePackageURL
            }
            byRole[input.role] = input
        }
        guard byRole[.base] != nil else {
            throw NSPMultiPackageRewriteError.missingBasePackage
        }
        return NSPPackageRole.allCases.compactMap { byRole[$0] }
    }
}

private struct NSPMultiPackageManifest: Codable {
    let gameProfile: String
    let packages: [NSPPackageManifestEntry]
}

private struct NSPPackageManifestEntry: Codable {
    let role: NSPPackageRole
    let ncaCount: Int
    let moduleSets: [NSPModuleSetManifest]
}

private struct NSPModuleSetManifest: Codable {
    let ncaFileName: String
    let titleID: String
    let sectionIndex: Int
    let verifiedPFS0Blocks: UInt64
    let extractedEntryCount: Int
    let modules: [NSORewriteBatchModuleSummary]
}

private extension JSONEncoder {
    static var box3MultiNSPManifest: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }
}
