import Foundation
import Darwin

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
        to destinationURL: URL,
        progress: ((String) -> Void)? = nil
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

        progress?("RomFS: decrypting section \(verifiedSection.index) (\(verifiedSection.byteSize) bytes)")
        _ = try NCASectionStreamDecryptor.decryptSection(
            inputURL: inputURL,
            outputURL: decryptedURL,
            inspection: inspection,
            section: verifiedSection,
            keys: keys,
            titleKeys: titleKeys
        )
        progress?("RomFS: section decryption complete; preparing IVFC verification")
        return try extract(
            decryptedSectionURL: decryptedURL,
            sectionSize: verifiedSection.byteSize,
            fileSystemHeader: fsHeader,
            to: destinationURL,
            progress: progress
        )
    }

    public static func extract(
        decryptedSectionURL: URL,
        sectionSize: UInt64,
        fileSystemHeader: NCAFileSystemHeader,
        to destinationURL: URL,
        progress: ((String) -> Void)? = nil
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

        progress?("RomFS: parsing IVFC superblock")
        let superblock = try NCAIVFCSuperblock(
            hashData: fileSystemHeader.hashData,
            sectionSize: sectionSize
        )
        progress?("RomFS: IVFC superblock parsed; verifying integrity tree (\(superblock.levels.count) levels)")
        let verified = try NCAIVFCVerifier.verify(
            decryptedSectionURL: decryptedSectionURL,
            sectionSize: sectionSize,
            superblock: superblock,
            progress: progress
        )
        progress?("RomFS: IVFC verification complete; \(verified.verifiedBlockCount) blocks verified")
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
                progress?("RomFS: copying verified image (\(verified.romFSSize) bytes)")
            try input.seek(toOffset: verified.romFSOffset)
                var copied: UInt64 = 0
                let diagnosticInterval: UInt64 = 128 * 1024 * 1024
                var nextDiagnostic = diagnosticInterval
                while copied < verified.romFSSize {
                    let count = Int(min(UInt64(ioChunkSize), verified.romFSSize - copied))
                    var chunkError: Error?
                    // Drain Foundation's autorelease pool after every 1 MiB copy.
                    // FileHandle/Data bridging can otherwise retain temporary buffers
                    // throughout this 1.57 GB operation on memory-constrained iPhones.
                    autoreleasepool {
                        do {
                            var bytes = Data()
                            bytes.reserveCapacity(count)
                            while bytes.count < count {
                                guard let part = try input.read(upToCount: count - bytes.count),
                                      !part.isEmpty else {
                                    throw NCASectionRomFSExtractorError.truncatedSection
                                }
                                bytes.append(part)
                            }
                            try output.write(contentsOf: bytes)
                        } catch {
                            chunkError = error
                        }
                    }
                    if let chunkError { throw chunkError }
                    copied += UInt64(count)
                    if copied >= nextDiagnostic || copied == verified.romFSSize {
                        progress?("RomFS: copied \(copied) / \(verified.romFSSize) bytes")
                        nextDiagnostic += diagnosticInterval
                    }
                }
                try output.synchronize()
                progress?("RomFS: verified image copy complete")
                try input.close()
                try output.close()
            } catch {
                try? input.close()
                try? output.close()
                throw error
            }

            // Structural parsing is an additional check; IVFC verification above
            // remains the cryptographic integrity prerequisite.
            progress?("RomFS: validating extracted RomFS structure")
            let archive = try RomFSArchive(url: stagingURL, progress: progress)
            progress?("RomFS: structural validation complete (\(archive.entries.count) entries)")
            // Publish with a same-volume atomic rename. FileManager.moveItem can
            // surface a cleanup error after the destination has already been copied;
            // rename keeps publication atomic and avoids a partially visible image.
            let renameResult = stagingURL.path.withCString { source in
                destinationURL.path.withCString { destination in
                    Darwin.rename(source, destination)
                }
            }
            guard renameResult == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
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
