import Foundation

public enum NSPExecutableRewritePipelineError: Error, Equatable {
    case invalidOutputURL
    case outputAlreadyExists
    case noNCAEntries
    case noSupportedProgramExeFS
    case couldNotCreateStagingDirectory
}

public struct NSPExecutableRewriteModuleSet {
    public let ncaFileName: String
    public let titleID: String
    public let sectionIndex: Int
    public let verifiedPFS0Blocks: UInt64
    public let extractedEntryCount: Int
    public let modules: [NSORewriteBatchModuleSummary]
    public let rewrittenModulesDirectory: URL
}

public struct NSPExecutableRewriteResult {
    public let outputDirectory: URL
    public let ncaCount: Int
    public let moduleSets: [NSPExecutableRewriteModuleSet]
}

/// NSP -> NCA inventory -> program NCA inspection -> ExeFS section decryption,
/// integrity verification, extraction, and NSO rewrite. It deliberately emits
/// intermediate module bundles only; RomFS assets and final Mach-O/IPA packaging
/// are separate pipeline stages.
public enum NSPExecutableRewritePipeline {
    public static func process(
        nspURL: URL,
        keys: ProdKeys,
        titleKeys: TitleKeys? = nil,
        gamesDirectory: URL? = nil,
        gameProfile: String? = nil,
        outputDirectory: URL
    ) throws -> NSPExecutableRewriteResult {
        guard nspURL.isFileURL, outputDirectory.isFileURL else {
            throw NSPExecutableRewritePipelineError.invalidOutputURL
        }
        let archive = try NSPArchive(url: nspURL)
        guard !archive.ncaEntries.isEmpty else {
            throw NSPExecutableRewritePipelineError.noNCAEntries
        }
        let manager = FileManager.default
        guard !manager.fileExists(atPath: outputDirectory.path) else {
            throw NSPExecutableRewritePipelineError.outputAlreadyExists
        }
        let parent = outputDirectory.deletingLastPathComponent()
        try manager.createDirectory(at: parent, withIntermediateDirectories: true)
        let staging = parent.appendingPathComponent(
            ".\(outputDirectory.lastPathComponent).nsp-rewrite-\(UUID().uuidString)",
            isDirectory: true
        )
        do {
            try manager.createDirectory(at: staging, withIntermediateDirectories: false)
        } catch {
            throw NSPExecutableRewritePipelineError.couldNotCreateStagingDirectory
        }

        do {
            let ncaDirectory = staging.appendingPathComponent("nca-input", isDirectory: true)
            let resultDirectory = staging.appendingPathComponent("module-sets", isDirectory: true)
            try manager.createDirectory(at: ncaDirectory, withIntermediateDirectories: true)
            try manager.createDirectory(at: resultDirectory, withIntermediateDirectories: true)
            var moduleSets: [NSPExecutableRewriteModuleSet] = []

            for (index, entry) in archive.ncaEntries.enumerated() {
                let ncaURL = ncaDirectory.appendingPathComponent(String(format: "%04d-%@", index, entry.name))
                try archive.extractNCA(named: entry.name, to: ncaURL)
                let inspection = try NCAFileInspector.inspect(url: ncaURL, keys: keys)
                guard inspection.header.contentType == .program else { continue }

                for section in inspection.header.sections {
                    let fsHeader = try inspection.fileSystemHeader(for: section)
                    guard fsHeader.fileSystemType == .partitionFS else { continue }
                    guard fsHeader.hashType == .hierarchicalSHA256,
                          fsHeader.encryptionType == .aesCTR else {
                        continue
                    }
                    let sectionOutput = resultDirectory.appendingPathComponent(
                        String(format: "%04d-section-%d", index, section.index),
                        isDirectory: true
                    )
                    let rewritten = try NCAExecutableRewritePipeline.process(
                        ncaURL: ncaURL,
                        sectionIndex: section.index,
                        keys: keys,
                        titleKeys: titleKeys,
                        gamesDirectory: gamesDirectory,
                        gameProfile: gameProfile ?? String(format: "%016llx", inspection.header.titleID),
                        outputDirectory: sectionOutput
                    )
                    moduleSets.append(NSPExecutableRewriteModuleSet(
                        ncaFileName: entry.name,
                        titleID: rewritten.titleID,
                        sectionIndex: rewritten.sectionIndex,
                        verifiedPFS0Blocks: rewritten.verifiedPFS0Blocks,
                        extractedEntryCount: rewritten.extractedEntryCount,
                        modules: rewritten.modules,
                        rewrittenModulesDirectory: rewritten.rewrittenModulesDirectory
                    ))
                }
            }

            guard !moduleSets.isEmpty else {
                throw NSPExecutableRewritePipelineError.noSupportedProgramExeFS
            }
            try manager.removeItem(at: ncaDirectory)
            let manifest = try JSONEncoder.box3NSPManifest.encode(moduleSets.map {
                NSPManifestEntry(
                    ncaFileName: $0.ncaFileName,
                    titleID: $0.titleID,
                    sectionIndex: $0.sectionIndex,
                    verifiedPFS0Blocks: $0.verifiedPFS0Blocks,
                    extractedEntryCount: $0.extractedEntryCount,
                    modules: $0.modules
                )
            })
            try manifest.write(to: staging.appendingPathComponent("manifest.json"), options: [.atomic])
            try manager.moveItem(at: staging, to: outputDirectory)
            return NSPExecutableRewriteResult(
                outputDirectory: outputDirectory,
                ncaCount: archive.ncaEntries.count,
                moduleSets: moduleSets
            )
        } catch {
            try? manager.removeItem(at: staging)
            throw error
        }
    }
}

private struct NSPManifestEntry: Codable {
    let ncaFileName: String
    let titleID: String
    let sectionIndex: Int
    let verifiedPFS0Blocks: UInt64
    let extractedEntryCount: Int
    let modules: [NSORewriteBatchModuleSummary]
}

private extension JSONEncoder {
    static var box3NSPManifest: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }
}
