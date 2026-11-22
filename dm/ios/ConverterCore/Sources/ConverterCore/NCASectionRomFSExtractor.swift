import Foundation

public enum NCASectionRomFSExtractorError: Error, Equatable {
    case invalidFileURL
    case sectionIsNotRomFS
    case unsupportedHashType(NCAFileSystemHeader.HashType)
    case unsupportedEncryptionType(NCAFileSystemHeader.EncryptionType)
    case destinationAlreadyExists
    case sectionOutsideFile
    case truncatedSection
    case couldNotCreateOutput
    case arithmeticOverflow
}

/// Decrypts a standard AES-CTR RomFS section, verifies its complete IVFC tree,
/// and publishes only the verified final-level bytes as a standalone RomFS.img.
public enum NCASectionRomFSExtractor {
    public struct Result: Equatable {
        public let outputURL: URL
        public let imageSize: UInt64
        public let verifiedBlockCount: UInt64
        public let entryCount: Int
    }

    private static let ioChunkSize = 1024 * 1024

    public static func extract(
        inputURL: URL,
        inspection: NCAFileInspection,
        section: NCAHeader.Section,
        keys: ProdKeys,
        titleKeys: TitleKeys? = nil,
        to destinationURL: URL
    ) throws -> Result {
        guard inputURL.isFileURL, destinationURL.isFileURL else {
            throw NCASectionRomFSExtractorError.invalidFileURL
        }
        let verifiedSection = inspection.header.sections.first {
            $0.index == section.index && $0 == section
        }
        guard let verifiedSection else {
            throw NCASectionStreamDecryptorError.sectionNotInInspection(section.index)
        }
        let fsHeader = try inspection.fileSystemHeader(for: verifiedSection)
        guard fsHeader.fileSystemType == .romFS else {
            throw NCASectionRomFSExtractorError.sectionIsNotRomFS
        }
        guard fsHeader.hashType == .hierarchicalIntegrity else {
            throw NCASectionRomFSExtractorError.unsupportedHashType(fsHeader.hashType)
        }
        guard fsHeader.encryptionType == .aesCTR else {
            throw NCASectionRomFSExtractorError.unsupportedEncryptionType(fsHeader.encryptionType)
        }

        let parent = destinationURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        let decryptedURL = parent.appendingPathComponent(
            ".\(destinationURL.lastPathComponent).decrypted-\(UUID().uuidString)"
        )
        defer { try? FileManager.default.removeItem(at: decryptedURL) }

        _ = try NCASectionStreamDecryptor.decryptSection(
            inputURL: inputURL,
            outputURL: decryptedURL,
            inspection: inspection,
            section: verifiedSection,
            keys: keys,
            titleKeys: titleKeys
        )
        return try extract(
            decryptedSectionURL: decryptedURL,
            sectionSize: verifiedSection.byteSize,
            fileSystemHeader: fsHeader,
            to: destinationURL
        )
    }

    public static func extract(
        decryptedSectionURL: URL,
        sectionSize: UInt64,
        fileSystemHeader: NCAFileSystemHeader,
        to destinationURL: URL
    ) throws -> Result {
        guard decryptedSectionURL.isFileURL, destinationURL.isFileURL else {
            throw NCASectionRomFSExtractorError.invalidFileURL
        }
        guard fileSystemHeader.fileSystemType == .romFS else {
            throw NCASectionRomFSExtractorError.sectionIsNotRomFS
        }
        guard fileSystemHeader.hashType == .hierarchicalIntegrity else {
            throw NCASectionRomFSExtractorError.unsupportedHashType(fileSystemHeader.hashType)
        }
        guard fileSystemHeader.encryptionType == .aesCTR else {
            throw NCASectionRomFSExtractorError.unsupportedEncryptionType(fileSystemHeader.encryptionType)
        }
        let manager = FileManager.default
        guard !manager.fileExists(atPath: destinationURL.path) else {
            throw NCASectionRomFSExtractorError.destinationAlreadyExists
        }

        let superblock = try NCAIVFCSuperblock(
            hashData: fileSystemHeader.hashData,
            sectionSize: sectionSize
        )
        let verified = try NCAIVFCVerifier.verify(
            decryptedSectionURL: decryptedSectionURL,
            sectionSize: sectionSize,
            superblock: superblock
        )
        let (end, overflow) = verified.romFSOffset.addingReportingOverflow(verified.romFSSize)
        guard !overflow, end <= sectionSize else {
            throw NCASectionRomFSExtractorError.sectionOutsideFile
        }

        let parent = destinationURL.deletingLastPathComponent()
        try manager.createDirectory(at: parent, withIntermediateDirectories: true)
        let stagingURL = parent.appendingPathComponent(
            ".\(destinationURL.lastPathComponent).ivfc-\(UUID().uuidString)"
        )
        do {
            guard manager.createFile(atPath: stagingURL.path, contents: nil) else {
                throw NCASectionRomFSExtractorError.couldNotCreateOutput
            }
            let input = try FileHandle(forReadingFrom: decryptedSectionURL)
            let output = try FileHandle(forWritingTo: stagingURL)
            do {
                try input.seek(toOffset: verified.romFSOffset)
                var copied: UInt64 = 0
                while copied < verified.romFSSize {
                    let count = Int(min(UInt64(ioChunkSize), verified.romFSSize - copied))
                    guard let bytes = try input.read(upToCount: count), bytes.count == count else {
                        throw NCASectionRomFSExtractorError.truncatedSection
                    }
                    try output.write(contentsOf: bytes)
                    copied += UInt64(count)
                }
                try output.synchronize()
                try input.close()
                try output.close()
            } catch {
                try? input.close()
                try? output.close()
                throw error
            }

            // Structural parsing is an additional check; IVFC verification above
            // remains the cryptographic integrity prerequisite.
            let archive = try RomFSArchive(url: stagingURL)
            try manager.moveItem(at: stagingURL, to: destinationURL)
            return Result(
                outputURL: destinationURL,
                imageSize: verified.romFSSize,
                verifiedBlockCount: verified.verifiedBlockCount,
                entryCount: archive.entries.count
            )
        } catch {
            try? manager.removeItem(at: stagingURL)
            throw error
        }
    }
}
