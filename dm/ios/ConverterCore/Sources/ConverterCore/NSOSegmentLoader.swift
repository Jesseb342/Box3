import Foundation

public enum NSOSegmentError: Error, Equatable {
    case uncompressedSizeMismatch(segment: Int, stored: Int, expected: Int)
}

/// Reconstructs the three in-memory NSO segments in text/ro/data order.
/// Compressed segments are raw LZ4 blocks; output is bounded by the declared
/// memory size before allocation. BSS is deliberately not materialized here.
public extension NSOImage {
    func decompressedSegments(from file: Data) throws -> [Data] {
        guard UInt64(file.count) == fileSize else {
            throw NSOError.segmentOutsideFile(0)
        }
        return try segments.map { segment in
            let start = Int(segment.fileOffset)
            let end = start + Int(segment.storedSize)
            let stored = file.subdata(in: start..<end)

            if segment.isCompressed {
                return try LZ4Block.decompress(
                    stored,
                    expectedSize: Int(segment.memorySize)
                )
            }

            guard segment.storedSize == segment.memorySize else {
                throw NSOSegmentError.uncompressedSizeMismatch(
                    segment: segment.index,
                    stored: Int(segment.storedSize),
                    expected: Int(segment.memorySize)
                )
            }
            return stored
        }
    }
}
