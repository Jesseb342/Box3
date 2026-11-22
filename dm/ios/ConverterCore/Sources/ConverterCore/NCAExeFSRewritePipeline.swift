import Foundation

public struct NCAExeFSRewriteResult {
    public let extraction: NCASectionPFS0Extractor.Result
    public let rewrite: NSORewriteBatchResult
}

/// Integrity-verifies and extracts an NCA ExeFS PFS0 section, then rewrites its NSO modules.
/// The resulting directory is an intermediate module bundle, not a complete executable or IPA.
public enum NCAExeFSRewritePipeline {
    public static func extractAndRewrite(
        decryptedSectionURL: URL,
        sectionSize: UInt64,
        fileSystemHeader: NCAFileSystemHeader,
        to extractedExeFSURL: URL,
        rewrittenModulesURL: URL,
        gameProfile: String? = nil,
        gamesDirectory: URL? = nil
    ) throws -> NCAExeFSRewriteResult {
        let extraction = try NCASectionPFS0Extractor.extract(
            decryptedSectionURL: decryptedSectionURL,
            sectionSize: sectionSize,
            fileSystemHeader: fileSystemHeader,
            to: extractedExeFSURL
        )
        let rewrite = try NSORewriteBatchProcessor.process(
            exefsDirectory: extractedExeFSURL,
            outputDirectory: rewrittenModulesURL,
            gameProfile: gameProfile,
            gamesDirectory: gamesDirectory
        )
        return NCAExeFSRewriteResult(extraction: extraction, rewrite: rewrite)
    }
}
