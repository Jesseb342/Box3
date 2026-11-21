import Foundation

public enum NSOError: Error, Equatable {
    case truncatedHeader
    case invalidMagic
    case unsupportedVersion(UInt32)
    case invalidSegmentRange(Int)
    case overlappingFileSegments(Int, Int)
    case overlappingMemorySegments(Int, Int)
    case invalidCompressedSize(Int)
    case segmentOutsideFile(Int)
    case invalidBuildID
}

/// Validated structural metadata for a Switch NSO module.
/// This is the input-inspection stage; it does not yet decompress or rewrite code.
public struct NSOImage: Equatable {
    public struct Segment: Equatable {
        public let index: Int
        public let fileOffset: UInt32
        public let memoryOffset: UInt32
        public let memorySize: UInt32
        public let storedSize: UInt32

        public var fileRange: Range<UInt64> {
            UInt64(fileOffset)..<(UInt64(fileOffset) + UInt64(storedSize))
        }

        public var memoryRange: Range<UInt64> {
            UInt64(memoryOffset)..<(UInt64(memoryOffset) + UInt64(memorySize))
        }

        public var isCompressed: Bool
    }

    public let version: UInt32
    public let flags: UInt32
    public let segments: [Segment]
    public let bssSize: UInt32
    public let buildID: Data
    public let fileSize: UInt64

    public init(data: Data) throws {
        guard data.count >= 0x70 else { throw NSOError.truncatedHeader }
        guard data.prefix(4) == Data("NSO0".utf8) else { throw NSOError.invalidMagic }

        let version = Self.u32(data, 0x04)
        guard version == 0 else { throw NSOError.unsupportedVersion(version) }

        let flags = Self.u32(data, 0x0c)
        var segments: [Segment] = []
        for index in 0..<3 {
            let descriptor = 0x10 + index * 0x10
            let fileOffset = Self.u32(data, descriptor)
            let memoryOffset = Self.u32(data, descriptor + 4)
            let memorySize = Self.u32(data, descriptor + 8)
            let storedSize = Self.u32(data, 0x60 + index * 4)
            let compressed = (flags & (1 << index)) != 0
            let actualStoredSize = storedSize

            guard memorySize > 0, actualStoredSize > 0 else {
                throw NSOError.invalidSegmentRange(index)
            }
            guard fileOffset >= 0x70,\n                  UInt64(fileOffset) + UInt64(actualStoredSize) <= UInt64(data.count) else {
                throw NSOError.segmentOutsideFile(index)
            }
            if compressed && storedSize == 0 {
                throw NSOError.invalidCompressedSize(index)
            }
            segments.append(Segment(
                index: index,
                fileOffset: fileOffset,
                memoryOffset: memoryOffset,
                memorySize: memorySize,
                storedSize: actualStoredSize,
                isCompressed: compressed
            ))
        }

        for left in 0..<segments.count {
            for right in (left + 1)..<segments.count {
                let a = segments[left], b = segments[right]
                if Self.overlaps(a.fileRange, b.fileRange) {
                    throw NSOError.overlappingFileSegments(left, right)
                }
                if Self.overlaps(a.memoryRange, b.memoryRange) {
                    throw NSOError.overlappingMemorySegments(left, right)
                }
            }
        }

        let buildID = data.subdata(in: 0x40..<0x60)
        guard buildID.contains(where: { $0 != 0 }) else { throw NSOError.invalidBuildID }

        self.version = version
        self.flags = flags
        self.segments = segments
        self.bssSize = Self.u32(data, 0x3c)
        self.buildID = buildID
        self.fileSize = UInt64(data.count)
    }

    public var buildIDHex: String {
        buildID.map { String(format: "%02x", $0) }.joined()
    }

    public var hasCompressedSegments: Bool {
        segments.contains(where: \.isCompressed)
    }

    private static func u32(_ data: Data, _ offset: Int) -> UInt32 {
        UInt32(data[offset]) |
        (UInt32(data[offset + 1]) << 8) |
        (UInt32(data[offset + 2]) << 16) |
        (UInt32(data[offset + 3]) << 24)
    }

    private static func overlaps(_ lhs: Range<UInt64>, _ rhs: Range<UInt64>) -> Bool {
        lhs.lowerBound < rhs.upperBound && rhs.lowerBound < lhs.upperBound
    }
}
