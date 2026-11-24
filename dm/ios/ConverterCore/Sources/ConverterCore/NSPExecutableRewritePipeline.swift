import Foundation

public enum NSPExecutableRewritePipelineError: Error, Equatable {
    case invalidOutputURL
    case outputAlreadyExists
    case noNCAEntries
    case noSupportedProgramExeFS
    case couldNotCreateStagingDirectory
    case invalidStagingPath
    case unsupportedProgramSection(sectionIndex: Int, fileSystemType: NCAFileSystemHeader.FileSystemType, hashType: NCAFileSystemHeader.HashType, encryptionType: NCAFileSystemHeader.EncryptionType)
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

public struct NSPRomFSImageSummary {
    public let ncaFileName: String
    public let titleID: String
    public let sectionIndex: Int
    public let imageURL: URL
    public let relativePath: String
    public let imageSize: UInt64
    public let verifiedBlockCount: UInt64
    public let entryCount: Int
}

public struct NSPExecutableRewriteResult {
    public let outputDirectory: URL
    public let ncaCount: Int
    public let moduleSets: [NSPExecutableRewriteModuleSet]
    public let romFSImages: [NSPRomFSImageSummary]
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
        outputDirectory: URL,
        progress: ((String) -> Void)? = nil
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
            var romFSImages: [NSPRomFSImageSummary] = []

            for (index, entry) in archive.ncaEntries.enumerated() {
                progress?("Package \(nspURL.lastPathComponent): extracting NCA \(index + 1)/\(archive.ncaEntries.count) — \(entry.name)")
                let ncaURL = ncaDirectory.appendingPathComponent(String(format: "%04d-%@", index, entry.name))
                try archive.extractNCA(named: entry.name, to: ncaURL)
                progress?("Inspecting NCA \(entry.name)")
                let inspection = try NCAFileInspector.inspect(url: ncaURL, keys: keys)
                guard inspection.header.contentType == .program else { continue }

                for section in inspection.header.sections {
                    progress?("Processing program NCA \(entry.name), section \(section.index)")
                    let fsHeader = try inspection.fileSystemHeader(for: section)
                    switch fsHeader.fileSystemType {
                    case .partitionFS:
                        guard fsHeader.hashType == .hierarchicalSHA256,
                              fsHeader.encryptionType == .aesCTR else {
                            throw NSPExecutableRewritePipelineError.unsupportedProgramSection(
                                sectionIndex: section.index,
                                fileSystemType: fsHeader.fileSystemType,
                                hashType: fsHeader.hashType,
                                encryptionType: fsHeader.encryptionType
                            )
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
                            outputDirectory: sectionOutput,
                            progress: progress
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
                    case .romFS:
                        guard fsHeader.hashType == .hierarchicalIntegrity,
                              fsHeader.encryptionType == .aesCTR else {
                            throw NSPExecutableRewritePipelineError.unsupportedProgramSection(
                                sectionIndex: section.index,
                                fileSystemType: fsHeader.fileSystemType,
                                hashType: fsHeader.hashType,
                                encryptionType: fsHeader.encryptionType
                            )
                        }
                        let relativePath = String(format: "romfs/%04d-section-%d/RomFS.img", index, section.index)
                        let imageURL = resultDirectory.appendingPathComponent(relativePath)
                        let extracted = try NCASectionRomFSExtractor.extract(
                            inputURL: ncaURL,
                            inspection: inspection,
                            section: section,
                            keys: keys,
                            titleKeys: titleKeys,
                            to: imageURL
                        )
                        romFSImages.append(NSPRomFSImageSummary(
                            ncaFileName: entry.name,
                            titleID: String(format: "%016llx", inspection.header.titleID),
                            sectionIndex: section.index,
                            imageURL: extracted.outputURL,
                            relativePath: relativePath,
                            imageSize: extracted.imageSize,
                            verifiedBlockCount: extracted.verifiedBlockCount,
                            entryCount: extracted.entryCount
                        ))
                    }
                }
            }

            guard !moduleSets.isEmpty else {
                throw NSPExecutableRewritePipelineError.noSupportedProgramExeFS
            }
            try manager.removeItem(at: ncaDirectory)
            let manifest = try JSONEncoder.box3NSPManifest.encode(
                NSPManifest(
                    moduleSets: moduleSets.map {
                        NSPManifestEntry(
                            ncaFileName: $0.ncaFileName,
                            titleID: $0.titleID,
                            sectionIndex: $0.sectionIndex,
                            verifiedPFS0Blocks: $0.verifiedPFS0Blocks,
                            extractedEntryCount: $0.extractedEntryCount,
                            modules: $0.modules
                        )
                    },
                    romFSImages: romFSImages.map {
                        NSPRomFSManifestEntry(
                            ncaFileName: $0.ncaFileName,
                            titleID: $0.titleID,
                            sectionIndex: $0.sectionIndex,
                            relativePath: $0.relativePath,
                            imageSize: $0.imageSize,
                            verifiedBlockCount: $0.verifiedBlockCount,
                            entryCount: $0.entryCount
                        )
                    }
                )
            )
            try manifest.write(to: staging.appendingPathComponent("manifest.json"), options: [.atomic])
            try manager.moveItem(at: staging, to: outputDirectory)
            let publishedModuleSets = try moduleSets.map { moduleSet in
                NSPExecutableRewriteModuleSet(
                    ncaFileName: moduleSet.ncaFileName,
                    titleID: moduleSet.titleID,
                    sectionIndex: moduleSet.sectionIndex,
                    verifiedPFS0Blocks: moduleSet.verifiedPFS0Blocks,
                    extractedEntryCount: moduleSet.extractedEntryCount,
                    modules: moduleSet.modules,
                    rewrittenModulesDirectory: try Self.rebased(
                        moduleSet.rewrittenModulesDirectory, from: staging, to: outputDirectory
                    )
                )
            }
            let publishedRomFSImages = try romFSImages.map { image in
                NSPRomFSImageSummary(
                    ncaFileName: image.ncaFileName,
                    titleID: image.titleID,
                    sectionIndex: image.sectionIndex,
                    imageURL: try Self.rebased(image.imageURL, from: staging, to: outputDirectory),
                    relativePath: image.relativePath,
                    imageSize: image.imageSize,
                    verifiedBlockCount: image.verifiedBlockCount,
                    entryCount: image.entryCount
                )
            }
            return NSPExecutableRewriteResult(
                outputDirectory: outputDirectory,
                ncaCount: archive.ncaEntries.count,
                moduleSets: publishedModuleSets,
                romFSImages: publishedRomFSImages
            )
        } catch {
            try? manager.removeItem(at: staging)
            throw error
        }
    }

    static func rebased(_ url: URL, from staging: URL, to output: URL) throws -> URL {
        let source = staging.standardizedFileURL.path
        let candidate = url.standardizedFileURL.path
        let prefix = source.hasSuffix("/") ? source : source + "/"
        guard candidate.hasPrefix(prefix) else {
            throw NSPExecutableRewritePipelineError.invalidStagingPath
        }
        return output.appendingPathComponent(String(candidate.dropFirst(prefix.count)))
    }
}

private struct NSPManifest: Codable {
    let moduleSets: [NSPManifestEntry]
    let romFSImages: [NSPRomFSManifestEntry]
}

private struct NSPManifestEntry: Codable {
    let ncaFileName: String
    let titleID: String
    let sectionIndex: Int
    let verifiedPFS0Blocks: UInt64
    let extractedEntryCount: Int
    let modules: [NSORewriteBatchModuleSummary]
}

private struct NSPRomFSManifestEntry: Codable {
    let ncaFileName: String
    let titleID: String
    let sectionIndex: Int
    let relativePath: String
    let imageSize: UInt64
    let verifiedBlockCount: UInt64
    let entryCount: Int
}

private extension JSONEncoder {
    static var box3NSPManifest: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }
}
