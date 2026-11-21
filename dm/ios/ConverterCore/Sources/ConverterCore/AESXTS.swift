import Foundation
import CommonCrypto

public enum AESXTSError: Error, Equatable {
    case invalidCombinedKeyLength
    case invalidTweakLength
    case dataUnitTooShort
    case dataUnitNotBlockAligned
    case cryptographicFailure(CCCryptorStatus)
    case invalidNCAHeaderLength
}

/// AES-XTS for complete AES blocks. The combined key is K1 || K2.
/// This implementation intentionally omits ciphertext stealing: NCA header
/// and section data units are complete 0x200-byte sectors.
public enum AESXTS {
    public static func decrypt(dataUnit: Data, combinedKey: Data, tweak: Data) throws -> Data {
        try transform(dataUnit: dataUnit, combinedKey: combinedKey, tweak: tweak, encrypting: false)
    }

    public static func encrypt(dataUnit: Data, combinedKey: Data, tweak: Data) throws -> Data {
        try transform(dataUnit: dataUnit, combinedKey: combinedKey, tweak: tweak, encrypting: true)
    }

    /// Nintendo NCA XTS uses a 128-bit tweak whose sector number is encoded
    /// as a big-endian integer in the final eight bytes (hactool convention).
    public static func ncaSectorTweak(_ sector: UInt64) -> Data {
        var tweak = Data(repeating: 0, count: 16)
        var value = sector
        for index in stride(from: 15, through: 8, by: -1) {
            tweak[index] = UInt8(value & 0xff)
            value >>= 8
        }
        return tweak
    }

    /// Decrypts the encrypted 0xC00-byte NCA header as six 0x200-byte
    /// XTS data units, starting with sector number zero.
    public static func decryptNCAHeader(_ encryptedHeader: Data, headerKey: Data) throws -> Data {
        guard encryptedHeader.count == 0xC00 else {
            throw AESXTSError.invalidNCAHeaderLength
        }
        var plaintext = Data()
        plaintext.reserveCapacity(encryptedHeader.count)
        for sector in 0..<6 {
            let start = sector * 0x200
            let encryptedSector = encryptedHeader.subdata(in: start..<(start + 0x200))
            let clearSector = try decrypt(
                dataUnit: encryptedSector,
                combinedKey: headerKey,
                tweak: ncaSectorTweak(UInt64(sector))
            )
            plaintext.append(clearSector)
        }
        return plaintext
    }

    private static func transform(
        dataUnit: Data,
        combinedKey: Data,
        tweak: Data,
        encrypting: Bool
    ) throws -> Data {
        guard combinedKey.count == 32 || combinedKey.count == 64 else {
            throw AESXTSError.invalidCombinedKeyLength
        }
        guard tweak.count == 16 else { throw AESXTSError.invalidTweakLength }
        guard dataUnit.count >= 16 else { throw AESXTSError.dataUnitTooShort }
        guard dataUnit.count.isMultiple(of: 16) else {
            throw AESXTSError.dataUnitNotBlockAligned
        }

        let half = combinedKey.count / 2
        let dataKey = combinedKey.prefix(half)
        let tweakKey = combinedKey.suffix(half)
        var mask = Array(try aesBlock(tweak, key: Data(tweakKey), encrypting: true))
        let input = Array(dataUnit)
        var output = [UInt8](repeating: 0, count: input.count)

        for offset in stride(from: 0, to: input.count, by: 16) {
            var block = [UInt8](repeating: 0, count: 16)
            for i in 0..<16 { block[i] = input[offset + i] ^ mask[i] }
            let transformed = try aesBlock(Data(block), key: Data(dataKey), encrypting: encrypting)
            let bytes = Array(transformed)
            for i in 0..<16 { output[offset + i] = bytes[i] ^ mask[i] }
            multiplyByAlpha(&mask)
        }
        return Data(output)
    }

    private static func aesBlock(_ input: Data, key: Data, encrypting: Bool) throws -> Data {
        var output = Data(count: 16)
        var moved: size_t = 0
        let operation = encrypting ? CCOperation(kCCEncrypt) : CCOperation(kCCDecrypt)
        let status: CCCryptorStatus = key.withUnsafeBytes { keyBytes in
            input.withUnsafeBytes { inputBytes in
                output.withUnsafeMutableBytes { outputBytes in
                    CCCrypt(
                        operation,
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
            throw AESXTSError.cryptographicFailure(status)
        }
        return output
    }

    /// XTS multiplication by alpha in GF(2^128), with the IEEE 1619
    /// little-endian polynomial representation.
    private static func multiplyByAlpha(_ value: inout [UInt8]) {
        var carry: UInt8 = 0
        for index in 0..<16 {
            let nextCarry = value[index] >> 7
            value[index] = (value[index] << 1) | carry
            carry = nextCarry
        }
        if carry != 0 { value[0] ^= 0x87 }
    }
}
