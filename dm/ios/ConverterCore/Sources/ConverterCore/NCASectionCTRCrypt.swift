import Foundation
import CommonCrypto

public enum NCASectionCTRCryptError: Error, Equatable {
    case invalidAESKeyLength(Int)
    case invalidCounterLength(Int)
    case invalidByteOffset(Int)
    case counterOverflow
    case cryptographicFailure(CCCryptorStatus)
}

/// AES-CTR transform for an already-selected 128- or 256-bit NCA key.
/// Key selection, key derivation, and section storage decoding are separate stages.
public enum NCASectionCTRCrypt {
    /// Applies AES-CTR from an explicit counter. byteOffsetInBlock supports
    /// ranges beginning between AES blocks while retaining the containing counter.
    ///
    /// Counter blocks are encrypted in one CommonCrypto ECB operation per input
    /// buffer. Encrypting each 16-byte counter separately is prohibitively slow
    /// for multi-megabyte RomFS sections on iPhone CPUs.
    public static func crypt(
        data: Data,
        key: Data,
        initialCounter: Data,
        byteOffsetInBlock: Int = 0
    ) throws -> Data {
        guard key.count == 16 || key.count == 32 else {
            throw NCASectionCTRCryptError.invalidAESKeyLength(key.count)
        }
        guard initialCounter.count == 16 else {
            throw NCASectionCTRCryptError.invalidCounterLength(initialCounter.count)
        }
        guard (0..<16).contains(byteOffsetInBlock) else {
            throw NCASectionCTRCryptError.invalidByteOffset(byteOffsetInBlock)
        }
        guard !data.isEmpty else { return Data() }

        let (totalBytes, sizeOverflow) = data.count.addingReportingOverflow(byteOffsetInBlock)
        guard !sizeOverflow else { throw NCASectionCTRCryptError.cryptographicFailure(kCCParamError) }
        let (roundedBytes, roundingOverflow) = totalBytes.addingReportingOverflow(15)
        guard !roundingOverflow else { throw NCASectionCTRCryptError.cryptographicFailure(kCCParamError) }
        let blockCount = roundedBytes / 16
        let (counterByteCount, counterSizeOverflow) = blockCount.multipliedReportingOverflow(by: 16)
        guard !counterSizeOverflow, counterByteCount <= Int(UInt32.max) else {
            throw NCASectionCTRCryptError.cryptographicFailure(kCCParamError)
        }

        var counter = Array(initialCounter)
        var counterBlocks = [UInt8]()
        counterBlocks.reserveCapacity(counterByteCount)
        for block in 0..<blockCount {
            counterBlocks.append(contentsOf: counter)
            if block + 1 < blockCount, !incrementLow64(&counter) {
                throw NCASectionCTRCryptError.counterOverflow
            }
        }

        var keyStream = [UInt8](repeating: 0, count: counterByteCount)
        var moved: size_t = 0
        let status: CCCryptorStatus = key.withUnsafeBytes { keyBytes in
            counterBlocks.withUnsafeBytes { counterBytes in
                keyStream.withUnsafeMutableBytes { outputBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyBytes.baseAddress,
                        key.count,
                        nil,
                        counterBytes.baseAddress,
                        CC_LONG(counterByteCount),
                        outputBytes.baseAddress,
                        CC_LONG(counterByteCount),
                        &moved
                    )
                }
            }
        }
        guard status == kCCSuccess, moved == counterByteCount else {
            throw NCASectionCTRCryptError.cryptographicFailure(status)
        }

        let input = Array(data)
        var output = [UInt8](repeating: 0, count: input.count)
        for index in input.indices {
            output[index] = input[index] ^ keyStream[byteOffsetInBlock + index]
        }
        return Data(output)
    }

    /// Applies AES-CTR at a byte range within an NCA section. The counter is
    /// derived from the absolute NCA file offset; unaligned ranges skip leading keystream.
    public static func crypt(
        data: Data,
        key: Data,
        sectionCounter: Data,
        sectionFileOffset: UInt64,
        offsetWithinSection: UInt64
    ) throws -> Data {
        let (absoluteOffset, overflow) = sectionFileOffset.addingReportingOverflow(offsetWithinSection)
        guard !overflow else { throw NCASectionCTRError.arithmeticOverflow }
        let initialCounter = try NCASectionCTR.counter(
            sectionCounter: sectionCounter,
            sectionFileOffset: sectionFileOffset,
            offsetWithinSection: offsetWithinSection
        )
        return try crypt(
            data: data,
            key: key,
            initialCounter: initialCounter,
            byteOffsetInBlock: Int(absoluteOffset & 0x0F)
        )
    }

    /// Increment only the low 64-bit NCA block index; never carry into the seed.
    private static func incrementLow64(_ counter: inout [UInt8]) -> Bool {
        for index in stride(from: 15, through: 8, by: -1) {
            if counter[index] != 0xFF {
                counter[index] &+= 1
                return true
            }
            counter[index] = 0
        }
        return false
    }
}
