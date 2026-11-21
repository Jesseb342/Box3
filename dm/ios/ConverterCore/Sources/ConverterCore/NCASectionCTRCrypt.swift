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

        var counter = Array(initialCounter)
        let input = Array(data)
        var output = [UInt8](repeating: 0, count: input.count)
        var inputOffset = 0
        var skip = byteOffsetInBlock

        while inputOffset < input.count {
            let stream = Array(try aesEncryptBlock(Data(counter), key: key))
            let count = min(16 - skip, input.count - inputOffset)
            for index in 0..<count {
                output[inputOffset + index] = input[inputOffset + index] ^ stream[skip + index]
            }
            inputOffset += count
            skip = 0
            if inputOffset < input.count {
                guard incrementLow64(&counter) else {
                    throw NCASectionCTRCryptError.counterOverflow
                }
            }
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

    private static func aesEncryptBlock(_ input: Data, key: Data) throws -> Data {
        var output = Data(count: 16)
        var moved: size_t = 0
        let status: CCCryptorStatus = key.withUnsafeBytes { keyBytes in
            input.withUnsafeBytes { inputBytes in
                output.withUnsafeMutableBytes { outputBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyBytes.baseAddress,
                        key.count,
                        nil,
                        inputBytes.baseAddress,
                        16,
                        outputBytes.baseAddress,
                        16,
                        &moved
                    )
                }
            }
        }
        guard status == kCCSuccess, moved == 16 else {
            throw NCASectionCTRCryptError.cryptographicFailure(status)
        }
        return output
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
