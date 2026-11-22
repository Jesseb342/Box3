import Foundation

public enum NCAIVFCSuperblockError: Error, Equatable {
    case invalidHashDataLength(Int)
    case invalidMagic
    case unsupportedVersion(UInt32)
    case unsupportedMasterHashSize(UInt32)
    case unsupportedLayerCount(UInt32)
    case invalidBlockSize(level: Int, exponent: UInt32)
    case emptyLevel(Int)
    case levelOutsideSection(Int)
    case overlappingLevels(Int, Int)
    case invalidMasterHashCoverage
    case insufficientParentHashData(level: Int, required: UInt64, actual: UInt64)
    case arithmeticOverflow
}

public struct NCAIVFCSuperblock: Equatable {
    public struct Level: Equatable {
        public let index: Int
        public let logicalOffset: UInt64
        public let dataSize: UInt64
        public let blockSizeExponent: UInt32
        public let blockSize: UInt64
    }

    public let version: UInt32
    public let masterHashSize: UInt32
    public let masterHash: Data
    public let levels: [Level]

    /// Parses the IVFC IntegrityMetaInfo stored in NCA FS-header HashData.
    /// All level offsets are relative to the beginning of the decrypted NCA section.
    public init(hashData: Data, sectionSize: UInt64) throws {
        guard hashData.count == 0xF8 else {
            throw NCAIVFCSuperblockError.invalidHashDataLength(hashData.count)
        }
        guard Self.u32(hashData, 0) == 0x43465649 else {
            throw NCAIVFCSuperblockError.invalidMagic
        }
        let version = Self.u32(hashData, 4)
        guard version == 0x00020000 else {
            throw NCAIVFCSuperblockError.unsupportedVersion(version)
        }
        let masterHashSize = Self.u32(hashData, 8)
        guard masterHashSize == 0x20 else {
            throw NCAIVFCSuperblockError.unsupportedMasterHashSize(masterHashSize)
        }
        let count = Self.u32(hashData, 0x0C)
        guard count == 6 else {
            throw NCAIVFCSuperblockError.unsupportedLayerCount(count)
        }

        var levels: [Level] = []
        levels.reserveCapacity(Int(count))
        for index in 0..<Int(count) {
            let offset = 0x10 + index * 0x18
            let logicalOffset = Self.u64(hashData, offset)
            let dataSize = Self.u64(hashData, offset + 8)
            let exponent = Self.u32(hashData, offset + 0x10)
            guard exponent >= 5, exponent <= 24 else {
                throw NCAIVFCSuperblockError.invalidBlockSize(level: index, exponent: exponent)
            }
            guard dataSize > 0 else { throw NCAIVFCSuperblockError.emptyLevel(index) }
            let blockSize = UInt64(1) << exponent
            let (end, overflow) = logicalOffset.addingReportingOverflow(dataSize)
            guard !overflow, end <= sectionSize else {
                throw NCAIVFCSuperblockError.levelOutsideSection(index)
            }
            levels.append(Level(index: index, logicalOffset: logicalOffset,
                                dataSize: dataSize, blockSizeExponent: exponent,
                                blockSize: blockSize))
        }

        for i in levels.indices {
            for j in levels.indices where j > i {
                let a = levels[i]
                let b = levels[j]
                let aEnd = a.logicalOffset + a.dataSize
                let bEnd = b.logicalOffset + b.dataSize
                guard aEnd <= b.logicalOffset || bEnd <= a.logicalOffset else {
                    throw NCAIVFCSuperblockError.overlappingLevels(i, j)
                }
            }
        }

        let first = levels[0]
        let firstBlocks = try Self.blockCount(size: first.dataSize, blockSize: first.blockSize)
        guard firstBlocks == 1 else {
            throw NCAIVFCSuperblockError.invalidMasterHashCoverage
        }
        for index in 1..<levels.count {
            let child = levels[index]
            let parent = levels[index - 1]
            let blocks = try Self.blockCount(size: child.dataSize, blockSize: child.blockSize)
            let (required, overflow) = blocks.multipliedReportingOverflow(by: 0x20)
            guard !overflow else { throw NCAIVFCSuperblockError.arithmeticOverflow }
            guard required <= parent.dataSize else {
                throw NCAIVFCSuperblockError.insufficientParentHashData(
                    level: index, required: required, actual: parent.dataSize
                )
            }
        }

        self.version = version
        self.masterHashSize = masterHashSize
        self.masterHash = hashData.subdata(in: 0xC0..<0xE0)
        self.levels = levels
    }

    static func blockCount(size: UInt64, blockSize: UInt64) throws -> UInt64 {
        let (rounded, overflow) = size.addingReportingOverflow(blockSize - 1)
        guard !overflow else { throw NCAIVFCSuperblockError.arithmeticOverflow }
        return rounded / blockSize
    }

    private static func u32(_ data: Data, _ offset: Int) -> UInt32 {
        UInt32(data[offset]) | (UInt32(data[offset + 1]) << 8) |
        (UInt32(data[offset + 2]) << 16) | (UInt32(data[offset + 3]) << 24)
    }

    private static func u64(_ data: Data, _ offset: Int) -> UInt64 {
        UInt64(u32(data, offset)) | (UInt64(u32(data, offset + 4)) << 32)
    }
}
