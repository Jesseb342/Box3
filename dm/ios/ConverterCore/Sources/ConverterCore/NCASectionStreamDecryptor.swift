import Foundation

public enum NCASectionStreamDecryptorError: Error, Equatable {
    case invalidFileURL
    case inputOutputCollision
    case outputAlreadyExists
    case invalidChunkSize(Int)
    case sectionIndexMismatch(expected: Int, actual: Int)
    case unsupportedEncryptionType(NCAFileSystemHeader.EncryptionType)
    case sectionRangeOverflow
    case sectionOutsideFile(offset: UInt64, size: UInt64, fileSize: UInt64)
    case truncatedSection(expected: Int, actual: Int)
    case couldNotCreateOutput
}

/// Bounded-memory AES-CTR decryption for standard NCA3 sections.
///
/// The output contains only the decrypted section bytes. AES-XTS, CTREx,
/// skip-layer-hash, BKTR, sparse storage, and automatic encryption modes are
/// rejected until their storage semantics are implemented independently.
public enum NCASectionStreamDecryptor {
    public static let defaultChunkSize = 1 << 20
    public static let maximumChunkSize = 8 << 20

    /// Decrypts one section to a new output file using an already-resolved
    /// 128- or 256-bit section key. The source NCA is never modified.
    @discardableResult
    public static func decryptSection(
        inputURL: URL,
        outputURL: URL,
        section: NCAHeader.Section,
        fileSystemHeader: NCAFileSystemHeader,
        key: Data,
        chunkSize: Int = defaultChunkSize
    ) throws -> UInt64 {
        guard inputURL.isFileURL, outputURL.isFileURL else {
            throw NCASectionStreamDecryptorError.invalidFileURL
        }
        guard inputURL.standardizedFileURL != outputURL.standardizedFileURL else {
            throw NCASectionStreamDecryptorError.inputOutputCollision
        }
        guard !FileManager.default.fileExists(atPath: outputURL.path) else {
            throw NCASectionStreamDecryptorError.outputAlreadyExists
        }
        guard chunkSize > 0, chunkSize <= maximumChunkSize else {
            throw NCASectionStreamDecryptorError.invalidChunkSize(chunkSize)
        }
        guard fileSystemHeader.sectionIndex == section.index else {
            throw NCASectionStreamDecryptorError.sectionIndexMismatch(
                expected: section.index, actual: fileSystemHeader.sectionIndex
            )
        }
        guard fileSystemHeader.encryptionType == .aesCTR else {
            throw NCASectionStreamDecryptorError.unsupportedEncryptionType(fileSystemHeader.encryptionType)
        }
        guard key.count == 16 || key.count == 32 else {
            throw NCASectionCTRCryptError.invalidAESKeyLength(key.count)
        }

        let sectionOffset = section.byteOffset
        let sectionSize = section.byteSize
        let (sectionEnd, overflow) = sectionOffset.addingReportingOverflow(sectionSize)
        guard !overflow else { throw NCASectionStreamDecryptorError.sectionRangeOverflow }

        let input = try FileHandle(forReadingFrom: inputURL)
        defer { try? input.close() }
        let fileSize = try input.seekToEnd()
        guard sectionEnd <= fileSize else {
            throw NCASectionStreamDecryptorError.sectionOutsideFile(
                offset: sectionOffset, size: sectionSize, fileSize: fileSize
            )
        }
        try input.seek(toOffset: sectionOffset)

        guard FileManager.default.createFile(atPath: outputURL.path, contents: nil) else {
            throw NCASectionStreamDecryptorError.couldNotCreateOutput
        }

        do {
            let output = try FileHandle(forWritingTo: outputURL)
            defer { try? output.close() }

            var offsetWithinSection: UInt64 = 0
            while offsetWithinSection < sectionSize {
                let remaining = sectionSize - offsetWithinSection
                let requested = Int(min(UInt64(chunkSize), remaining))
                let chunk = try Self.readExactly(input, count: requested)
                guard chunk.count == requested else {
                    throw NCASectionStreamDecryptorError.truncatedSection(
                        expected: requested, actual: chunk.count
                    )
                }

                let clear = try NCASectionCTRCrypt.crypt(
                    data: chunk,
                    key: key,
                    sectionCounter: fileSystemHeader.sectionCounter,
                    sectionFileOffset: sectionOffset,
                    offsetWithinSection: offsetWithinSection
                )
                try output.write(contentsOf: clear)
                offsetWithinSection += UInt64(requested)
            }
            try output.synchronize()
        } catch {
            try? FileManager.default.removeItem(at: outputURL)
            throw error
        }

        return sectionSize
    }

    private static func readExactly(_ handle: FileHandle, count: Int) throws -> Data {
        var result = Data()
        result.reserveCapacity(count)
        while result.count < count {
            guard let part = try handle.read(upToCount: count - result.count), !part.isEmpty else {
                break
            }
            result.append(part)
        }
        return result
    }
}
