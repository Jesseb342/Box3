import Foundation

public enum NCASectionCTRError: Error, Equatable {
    case invalidSectionCounterLength(Int)
    case arithmeticOverflow
}

/// Constructs the NCA3 AES-CTR counter for an absolute file position.
///
/// The high eight bytes are the section counter seed in reverse byte order;
/// the low eight bytes are the absolute NCA file offset divided by 16,
/// encoded big-endian. This matches the reference NCA counter construction.
public enum NCASectionCTR {
    public static func counter(
        sectionCounter: Data,
        sectionFileOffset: UInt64,
        offsetWithinSection: UInt64 = 0
    ) throws -> Data {
        guard sectionCounter.count == 8 else {
            throw NCASectionCTRError.invalidSectionCounterLength(sectionCounter.count)
        }
        let (absoluteOffset, overflow) = sectionFileOffset.addingReportingOverflow(offsetWithinSection)
        guard !overflow else { throw NCASectionCTRError.arithmeticOverflow }

        var result = Data(repeating: 0, count: 16)
        for index in 0..<8 {
            result[index] = sectionCounter[7 - index]
        }

        var blockIndex = absoluteOffset >> 4
        for index in stride(from: 15, through: 8, by: -1) {
            result[index] = UInt8(blockIndex & 0xFF)
            blockIndex >>= 8
        }
        return result
    }
}
