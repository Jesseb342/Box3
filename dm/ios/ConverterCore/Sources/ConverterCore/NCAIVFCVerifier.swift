import Foundation
import CryptoKit

public enum NCAIVFCVerifierError: Error, Equatable {
    case invalidFileURL
    case sectionOutsideFile
    case truncatedData
    case masterHashMismatch
    case levelHashMismatch(level: Int, block: UInt64)
    case arithmeticOverflow
}

/// Streaming, fail-closed verification of all six NCA RomFS IVFC levels.
/// The input must already be decrypted using the NCA section's AES-CTR context.
public enum NCAIVFCVerifier {
    public struct Result: Equatable {
        public let verifiedBlockCount: UInt64
        public let romFSOffset: UInt64
        public let romFSSize: UInt64
    }

    private static let ioChunkSize = 1024 * 1024

    public static func verify(
        decryptedSectionURL: URL,
        sectionSize: UInt64,
        superblock: NCAIVFCSuperblock,
        progress: ((String) -> Void)? = nil
    ) throws -> Result {
        guard decryptedSectionURL.isFileURL else {
            throw NCAIVFCVerifierError.invalidFileURL
        }
        let handle = try FileHandle(forReadingFrom: decryptedSectionURL)
        defer { try? handle.close() }
        let fileSize = try handle.seekToEnd()
        guard sectionSize <= fileSize else {
            throw NCAIVFCVerifierError.sectionOutsideFile
        }

        var verified: UInt64 = 0
        for index in superblock.levels.indices {
            let level = superblock.levels[index]
            let expectedHashes: Data
            if index == 0 {
                expectedHashes = superblock.masterHash
            } else {
                let parent = superblock.levels[index - 1]
                let count = try NCAIVFCSuperblock.blockCount(
                    size: level.dataSize, blockSize: level.blockSize
                )
                let (length, overflow) = count.multipliedReportingOverflow(by: 0x20)
                guard !overflow else { throw NCAIVFCVerifierError.arithmeticOverflow }
                expectedHashes = try readExactly(handle, offset: parent.logicalOffset, count: Int(length))
            }

            let blockCount = try NCAIVFCSuperblock.blockCount(
                size: level.dataSize, blockSize: level.blockSize
            )
            guard UInt64(expectedHashes.count) == blockCount * 0x20 else {
                throw NCAIVFCVerifierError.truncatedData
            }

            progress?("RomFS: IVFC level \(index + 1)/\(superblock.levels.count), \(blockCount) blocks; loading expected hashes (\(expectedHashes.count) bytes)")
            for blockIndex in 0..<blockCount {
                // Keep progress and persistent diagnostics lightweight on mobile.
                // Level 6 can contain tens of thousands of blocks; emitting a log
                // line every 128 blocks causes repeated disk writes and UI churn.
                if blockIndex == 0 || (blockIndex + 1) % 4096 == 0 || blockIndex + 1 == blockCount {
                    progress?("RomFS: verifying IVFC level \(index + 1), block \(blockIndex + 1)/\(blockCount)")
                }
                let (delta, overflow) = blockIndex.multipliedReportingOverflow(by: level.blockSize)
                let (blockOffset, offsetOverflow) = level.logicalOffset.addingReportingOverflow(delta)
                guard !overflow, !offsetOverflow else {
                    throw NCAIVFCVerifierError.arithmeticOverflow
                }
                let consumed = delta
                let remaining = level.dataSize - consumed
                let actualLength = min(level.blockSize, remaining)
                let actualHash = try paddedBlockDigest(
                    handle: handle, offset: blockOffset,
                    actualLength: actualLength, paddedLength: level.blockSize
                )
                let hashOffset = Int(blockIndex * 0x20)
                let expected = expectedHashes.subdata(in: hashOffset..<(hashOffset + 0x20))
                guard actualHash == expected else {
                    if index == 0 {
                        throw NCAIVFCVerifierError.masterHashMismatch
                    }
                    throw NCAIVFCVerifierError.levelHashMismatch(level: index, block: blockIndex)
                }
                verified += 1
            }
            progress?("RomFS: IVFC level \(index + 1) verified")
        }

        let romFS = superblock.levels[superblock.levels.count - 1]
        return Result(verifiedBlockCount: verified,
                      romFSOffset: romFS.logicalOffset, romFSSize: romFS.dataSize)
    }

    private static func paddedBlockDigest(
        handle: FileHandle, offset: UInt64,
        actualLength: UInt64, paddedLength: UInt64
    ) throws -> Data {
        try handle.seek(toOffset: offset)
        var hasher = SHA256()
        var remaining = actualLength
        while remaining > 0 {
            let count = Int(min(UInt64(ioChunkSize), remaining))
            let bytes = try readExactly(handle, count: count)
            hasher.update(data: bytes)
            remaining -= UInt64(bytes.count)
        }
        if actualLength < paddedLength {
            var padding = Data(repeating: 0, count: Int(min(UInt64(ioChunkSize), paddedLength - actualLength)))
            var left = paddedLength - actualLength
            while left > 0 {
                let count = Int(min(UInt64(padding.count), left))
                hasher.update(data: padding.prefix(count))
                left -= UInt64(count)
            }
            padding.removeAll(keepingCapacity: false)
        }
        return Data(hasher.finalize())
    }

    private static func readExactly(_ handle: FileHandle, offset: UInt64, count: Int) throws -> Data {
        try handle.seek(toOffset: offset)
        return try readExactly(handle, count: count)
    }

    private static func readExactly(_ handle: FileHandle, count: Int) throws -> Data {
        var result = Data()
        result.reserveCapacity(count)
        while result.count < count {
            guard let part = try handle.read(upToCount: count - result.count), !part.isEmpty else {
                throw NCAIVFCVerifierError.truncatedData
            }
            result.append(part)
        }
        return result
    }
}
