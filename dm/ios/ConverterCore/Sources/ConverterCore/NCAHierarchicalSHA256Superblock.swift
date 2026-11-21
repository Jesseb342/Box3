import Foundation

public enum NCAHierarchicalSHA256SuperblockError: Error, Equatable {
    case invalidHashDataLength(Int)
    case unsupportedLayerCount(UInt32)
    case invalidBlockSize(UInt32)
    case emptyHashTable
    case emptyPFS0Region
    case hashTableSizeMismatch(expected: UInt64, actual: UInt64)
    case hashTableOutOfBounds
    case pfs0OutOfBounds
    case overlappingRegions
    case arithmeticOverflow
}

/// The two-layer hierarchical-SHA256 descriptor used by a PFS0 NCA section.
/// All offsets are relative to the beginning of the decrypted NCA section.
public struct NCAHierarchicalSHA256Superblock: Equatable {
    public let masterHash: Data
    public let blockSize: UInt32
    public let hashTableOffset: UInt64
    public let hashTableSize: UInt64
    public let pfs0Offset: UInt64
    public let pfs0Size: UInt64

    public init(hashData: Data, sectionSize: UInt64) throws {
        guard hashData.count >= 0x48 else {
            throw NCAHierarchicalSHA256SuperblockError.invalidHashDataLength(hashData.count)
        }

        let masterHash = hashData.subdata(in: 0..<0x20)
        let blockSize = Self.u32(hashData, at: 0x20)
        let layerCount = Self.u32(hashData, at: 0x24)
        let hashTableOffset = Self.u64(hashData, at: 0x28)
        let hashTableSize = Self.u64(hashData, at: 0x30)
        let pfs0Offset = Self.u64(hashData, at: 0x38)
        let pfs0Size = Self.u64(hashData, at: 0x40)

        guard layerCount == 2 else {
            throw NCAHierarchicalSHA256SuperblockError.unsupportedLayerCount(layerCount)
        }
        guard blockSize > 0, blockSize.nonzeroBitCount == 1 else {
            throw NCAHierarchicalSHA256SuperblockError.invalidBlockSize(blockSize)
        }
        guard hashTableSize > 0 else {
            throw NCAHierarchicalSHA256SuperblockError.emptyHashTable
        }
        guard pfs0Size > 0 else {
            throw NCAHierarchicalSHA256SuperblockError.emptyPFS0Region
        }

        let block = UInt64(blockSize)
        let (roundedSize, roundOverflow) = pfs0Size.addingReportingOverflow(block - 1)
        guard !roundOverflow else {
            throw NCAHierarchicalSHA256SuperblockError.arithmeticOverflow
        }
        let blockCount = roundedSize / block
        let (expectedHashSize, hashSizeOverflow) = blockCount.multipliedReportingOverflow(by: 0x20)
        guard !hashSizeOverflow else {
            throw NCAHierarchicalSHA256SuperblockError.arithmeticOverflow
        }
        guard hashTableSize == expectedHashSize else {
            throw NCAHierarchicalSHA256SuperblockError.hashTableSizeMismatch(
                expected: expectedHashSize, actual: hashTableSize
            )
        }

        let (hashEnd, hashOverflow) = hashTableOffset.addingReportingOverflow(hashTableSize)
        guard !hashOverflow else { throw NCAHierarchicalSHA256SuperblockError.arithmeticOverflow }
        let (pfsEnd, pfsOverflow) = pfs0Offset.addingReportingOverflow(pfs0Size)
        guard !pfsOverflow else { throw NCAHierarchicalSHA256SuperblockError.arithmeticOverflow }
        guard hashEnd <= sectionSize else {
            throw NCAHierarchicalSHA256SuperblockError.hashTableOutOfBounds
        }
        guard pfsEnd <= sectionSize else {
            throw NCAHierarchicalSHA256SuperblockError.pfs0OutOfBounds
        }
        guard hashEnd <= pfs0Offset || pfsEnd <= hashTableOffset else {
            throw NCAHierarchicalSHA256SuperblockError.overlappingRegions
        }

        self.masterHash = masterHash
        self.blockSize = blockSize
        self.hashTableOffset = hashTableOffset
        self.hashTableSize = hashTableSize
        self.pfs0Offset = pfs0Offset
        self.pfs0Size = pfs0Size
    }

    private static func u32(_ data: Data, at offset: Int) -> UInt32 {
        UInt32(data[offset]) |
        (UInt32(data[offset + 1]) << 8) |
        (UInt32(data[offset + 2]) << 16) |
        (UInt32(data[offset + 3]) << 24)
    }

    private static func u64(_ data: Data, at offset: Int) -> UInt64 {
        UInt64(u32(data, at: offset)) |
        (UInt64(u32(data, at: offset + 4)) << 32)
    }
}
