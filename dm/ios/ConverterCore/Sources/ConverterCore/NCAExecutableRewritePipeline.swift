import Foundation

public enum NCAExecutableRewritePipelineError: Error, Equatable {
    case invalidNCAURL
    case sectionNotFound(Int)
    case sectionIsNotPartitionFS(Int)
    case unsupportedSectionEncryption(Int)
    case outputAlreadyExists
    case couldNotCreateStagingDirectory
}

public struct NCAExecutableRewriteResult {
    public let titleID: String
    public let sectionIndex: Int
    public let verifiedPFS0Blocks: UInt64
    public let extractedEntryCount: Int
    public let modules: [NSORewriteBatchModuleSummary]
    public let outputDirectory: URL
}

/// NCA3 -> AES-CTR decrypted section -> verified PFS0 ExeFS -> rewritten NSO modules.
/// Supports standard CTR-encrypted PartitionFS sections with hierarchical SHA-256.
/// Unsupported NCA storage/encryption modes remain fail-closed.
public enum NCAExecutableRewritePipeline {
    public static func process(
        ncaURL: URL,
        sectionIndex: Int,
        keys: ProdKeys,
        titleKeys: TitleKeys? = nil,
        gamesDirectory: URL? = nil,
        outputDirectory: URL
    ) throws -> NCAExecutableRewriteResult {
        guard ncaURL.isFileURL else { throw NCAExecutableRewritePipelineError.invalidNCAURL }
        let inspection = try NCAFileInspector.inspect(url: ncaURL, keys: keys)
        guard let section = inspection.header.sections.first(where: { $0.index == sectionIndex }) else {
            throw NCAExecutableRewritePipelineError.sectionNotFound(sectionIndex)
        }
        let fsHeader = try inspection.fileSystemHeader(for: section)
        guard fsHeader.fileSystemType == .partitionFS else {
            throw NCAExecutableRewritePipelineError.sectionIsNotPartitionFS(sectionIndex)
        }
        guard fsHeader.encryptionType == .aesCTR else {
            throw NCAExecutableRewritePipelineError.unsupportedSectionEncryption(sectionIndex)
        }

        let manager = FileManager.default
        guard !manager.fileExists(atPath: outputDirectory.path) else {
            throw NCAExecutableRewritePipelineError.outputAlreadyExists
        }
        let parent = outputDirectory.deletingLastPathComponent()
        try manager.createDirectory(at: parent, withIntermediateDirectories: true)
        let staging = parent.appendingPathComponent(
            ".\(outputDirectory.lastPathComponent).nca-rewrite-\(UUID().uuidString)",
            isDirectory: true
        )
        do {
            try manager.createDirectory(at: staging, withIntermediateDirectories: false)
        } catch {
            throw NCAExecutableRewritePipelineError.couldNotCreateStagingDirectory
        }

        do {
            let decryptedURL = staging.appendingPathComponent("decrypted.section")
            _ = try NCASectionStreamDecryptor.decryptSection(
                inputURL: ncaURL,
                outputURL: decryptedURL,
                inspection: inspection,
                section: section,
                keys: keys,
                titleKeys: titleKeys
            )
            let extractedURL = staging.appendingPathComponent("exefs", isDirectory: true)
            let rewrittenURL = staging.appendingPathComponent("rewritten", isDirectory: true)
            let gameID = String(format: "%016llx", inspection.header.titleID)
            let exefs = try NCAExeFSRewritePipeline.extractAndRewrite(
                decryptedSectionURL: decryptedURL,
                sectionSize: section.byteSize,
                fileSystemHeader: fsHeader,
                to: extractedURL,
                rewrittenModulesURL: rewrittenURL,
                gameProfile: gameID,
                gamesDirectory: gamesDirectory
            )
            try manager.removeItem(at: decryptedURL)
            try manager.moveItem(at: staging, to: outputDirectory)
            return NCAExecutableRewriteResult(
                titleID: gameID,
                sectionIndex: sectionIndex,
                verifiedPFS0Blocks: exefs.extraction.verifiedBlockCount,
                extractedEntryCount: exefs.extraction.entryCount,
                modules: exefs.rewrite.modules,
                outputDirectory: outputDirectory
            )
        } catch {
            try? manager.removeItem(at: staging)
            throw error
        }
    }
}
