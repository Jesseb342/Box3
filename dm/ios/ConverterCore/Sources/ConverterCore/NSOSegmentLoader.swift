import Foundation

public enum NSOSegmentError: Error, Equatable {
    case uncompressedSizeMismatch(segment: Int, stored: Int, expected: Int)
    case imageTooLarge(UInt64)
    case segmentOutsideImage(segment: Int, end: UInt64, imageSize: UInt64)
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


/// Reconstructs the contiguous file-backed module image expected by the batch
/// rewriter. Segment gaps, BSS, and the near-layout key page are zero-filled;
/// far-layout BSS/key-page storage remains outside the file image, matching
/// the desktop rewriter's far-patch convention.
public extension NSOImage {
    func reconstructedImage(from file: Data, layout: NSOPatchLayout) throws -> Data {
        guard layout.fileImageLength <= UInt64(Int.max) else {
            throw NSOSegmentError.imageTooLarge(layout.fileImageLength)
        }
        let segments = try decompressedSegments(from: file)
        guard segments.count == self.segments.count else {
            throw NSOError.invalidSegmentRange(0)
        }

        var image = Data(repeating: 0, count: Int(layout.fileImageLength))
        for (descriptor, bytes) in zip(self.segments, segments) {
            let start = UInt64(descriptor.memoryOffset)
            let end = start.addingReportingOverflow(UInt64(bytes.count))
            guard !end.overflow, end.partialValue <= layout.fileImageLength else {
                throw NSOSegmentError.segmentOutsideImage(
                    segment: descriptor.index,
                    end: end.partialValue,
                    imageSize: layout.fileImageLength
                )
            }
            image.replaceSubrange(Int(start)..<Int(end.partialValue), with: bytes)
        }
        return image
    }
}
