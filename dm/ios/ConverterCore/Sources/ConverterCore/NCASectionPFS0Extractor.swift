import Foundation

public enum NCASectionPFS0ExtractorError: Error, Equatable {
    case invalidFileURL
    case destinationAlreadyExists
    case couldNotCreateStagingDirectory
}

/// Verifies a decrypted PartitionFS section's hierarchical SHA-256 layers,
/// then extracts its bounded PFS0 payload into a fresh destination directory.
/// Extraction is staged beside the destination and published only on success.
public enum NCASectionPFS0Extractor {
    public struct Result: Equatable {
        public let entryCount: Int
        public let totalExtractedBytes: UInt64
        public let verifiedBlockCount: UInt64
        public let pfs0Offset: UInt64
        public let pfs0Size: UInt64
    }

    public static func extract(
        decryptedSectionURL: URL,
        sectionSize: UInt64,
        fileSystemHeader: NCAFileSystemHeader,
        to destinationURL: URL
    ) throws -> Result {
        guard decryptedSectionURL.isFileURL, destinationURL.isFileURL else {
            throw NCASectionPFS0ExtractorError.invalidFileURL
        }
        let manager = FileManager.default
        guard !manager.fileExists(atPath: destinationURL.path) else {
            throw NCASectionPFS0ExtractorError.destinationAlreadyExists
        }
        let integrity = try NCASectionIntegrityVerifier.verify(
            decryptedSectionURL: decryptedSectionURL,
            sectionSize: sectionSize,
            fileSystemHeader: fileSystemHeader
        )
        let archive = try PFS0Archive(
            url: decryptedSectionURL, offset: integrity.pfs0Offset, size: integrity.pfs0Size
        )
        let parent = destinationURL.deletingLastPathComponent()
        try manager.createDirectory(at: parent, withIntermediateDirectories: true)
        let stagingURL = parent.appendingPathComponent(
            ".\(destinationURL.lastPathComponent).extract-\(UUID().uuidString)",
            isDirectory: true
        )
        guard manager.createDirectory(at: stagingURL, withIntermediateDirectories: false) != nil else {
            throw NCASectionPFS0ExtractorError.couldNotCreateStagingDirectory
        }
        do {
            try archive.extractAll(to: stagingURL)
            try manager.moveItem(at: stagingURL, to: destinationURL)
        } catch {
            try? manager.removeItem(at: stagingURL)
            throw error
        }
        let total = archive.entries.reduce(UInt64(0)) { partial, entry in
            let (sum, overflow) = partial.addingReportingOverflow(entry.size)
            return overflow ? UInt64.max : sum
        }
        return Result(entryCount: archive.entries.count, totalExtractedBytes: total,
                      verifiedBlockCount: integrity.verifiedBlockCount,
                      pfs0Offset: integrity.pfs0Offset, pfs0Size: integrity.pfs0Size)
    }
}