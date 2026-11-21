import Foundation
import CryptoKit

public enum NCAHierarchicalSHA256VerifierError: Error, Equatable {
    case sectionOutsideFile
    case truncatedData
    case masterHashMismatch
    case invalidPFS0Magic
    case blockHashMismatch(UInt64)
    case arithmeticOverflow
}

/// Verifies the hierarchical-SHA256 layers of a decrypted PFS0 NCA section.
///
/// The input file is expected to contain the section's plaintext bytes at
/// sectionOffset. This verifier does not decrypt NCA section payloads.
public enum NCAHierarchicalSHA256Verifier {
    public struct Result: Equatable {
        public let verifiedBlockCount: UInt64
        public let pfs0Offset: UInt64
        public let pfs0Size: UInt64
    }

    private static let chunkSize = 1024 * 1024

    public static func verify(
        decryptedSectionURL: URL,
        sectionOffset: UInt64 = 0,
        sectionSize: UInt64,
        superblock: NCAHierarchicalSHA256Superblock
    ) throws -> Result {
        let handle = try FileHandle(forReadingFrom: decryptedSectionURL)
        defer { try? handle.close() }

        let fileSize = try handle.seekToEnd()
        let (sectionEnd, sectionOverflow) = sectionOffset.addingReportingOverflow(sectionSize)
        guard !sectionOverflow, sectionEnd <= fileSize else {
            throw NCAHierarchicalSHA256VerifierError.sectionOutsideFile
        }

        let (hashStart, hashStartOverflow) = sectionOffset.addingReportingOverflow(superblock.hashTableOffset)
        let (pfsStart, pfsStartOverflow) = sectionOffset.addingReportingOverflow(superblock.pfs0Offset)
        guard !hashStartOverflow, !pfsStartOverflow else {
            throw NCAHierarchicalSHA256VerifierError.arithmeticOverflow
        }

        let hashDigest = try digest(
            from: handle,
            offset: hashStart,
            length: superblock.hashTableSize
        )
        guard Data(hashDigest) == superblock.masterHash else {
            throw NCAHierarchicalSHA256VerifierError.masterHashMismatch
        }

        try handle.seek(toOffset: pfsStart)
        let magic = try readExactly(4, from: handle)
        guard magic == Data([0x50, 0x46, 0x53, 0x30]) else {
            throw NCAHierarchicalSHA256VerifierError.invalidPFS0Magic
        }

        let blockSize = UInt64(superblock.blockSize)
        let blockCount = superblock.hashTableSize / 0x20
        for index in 0..<blockCount {
            let (hashDelta, hashDeltaOverflow) = index.multipliedReportingOverflow(by: 0x20)
            let (expectedOffset, expectedOverflow) = hashStart.addingReportingOverflow(hashDelta)
            let (blockDelta, blockDeltaOverflow) = index.multipliedReportingOverflow(by: blockSize)
            let (blockOffset, blockOffsetOverflow) = pfsStart.addingReportingOverflow(blockDelta)
            guard !hashDeltaOverflow, !expectedOverflow, !blockDeltaOverflow, !blockOffsetOverflow else {
                throw NCAHierarchicalSHA256VerifierError.arithmeticOverflow
            }

            try handle.seek(toOffset: expectedOffset)
            let expectedHash = try readExactly(0x20, from: handle)
            let consumed = index * blockSize
            let remaining = superblock.pfs0Size - consumed
            let length = min(blockSize, remaining)
            let actualHash = try digest(from: handle, offset: blockOffset, length: length)
            guard Data(actualHash) == expectedHash else {
                throw NCAHierarchicalSHA256VerifierError.blockHashMismatch(index)
            }
        }

        return Result(
            verifiedBlockCount: blockCount,
            pfs0Offset: superblock.pfs0Offset,
            pfs0Size: superblock.pfs0Size
        )
    }

    private static func digest(from handle: FileHandle, offset: UInt64, length: UInt64) throws -> [UInt8] {
        try handle.seek(toOffset: offset)
        var hasher = SHA256()
        var remaining = length
        while remaining > 0 {
            let amount = Int(min(UInt64(chunkSize), remaining))
            let chunk = try readExactly(amount, from: handle)
            hasher.update(data: chunk)
            remaining -= UInt64(chunk.count)
        }
        return Array(hasher.finalize())
    }

    private static func readExactly(_ count: Int, from handle: FileHandle) throws -> Data {
        var result = Data()
        result.reserveCapacity(count)
        while result.count < count {
            guard let part = try handle.read(upToCount: count - result.count), !part.isEmpty else {
                throw NCAHierarchicalSHA256VerifierError.truncatedData
            }
            result.append(part)
        }
        return result
    }
}
