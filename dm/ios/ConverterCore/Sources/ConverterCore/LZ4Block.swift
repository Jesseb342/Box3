import Foundation

public enum LZ4BlockError: Error, Equatable {
    case invalidExpectedSize
    case truncatedLiteralLength
    case truncatedLiterals
    case truncatedMatchOffset
    case zeroMatchOffset
    case matchBeforeOutput
    case truncatedMatchLength
    case outputExceedsExpectedSize
    case outputSizeMismatch(expected: Int, actual: Int)
}

/// Decoder for raw LZ4 blocks (not LZ4 frames).
/// NSO compressed segments store raw blocks and provide the expected output size
/// in the NSO segment descriptor.
public enum LZ4Block {
    public static func decompress(_ input: Data, expectedSize: Int) throws -> Data {
        guard expectedSize >= 0 else { throw LZ4BlockError.invalidExpectedSize }
        if expectedSize == 0 {
            guard input.isEmpty else {
                throw LZ4BlockError.outputSizeMismatch(expected: 0, actual: 0)
            }
            return Data()
        }

        let bytes = [UInt8](input)
        var output = [UInt8]()
        output.reserveCapacity(expectedSize)
        var cursor = 0

        func readExtendedLength(base: Int, error: LZ4BlockError) throws -> Int {
            var length = base
            if base == 15 {
                while true {
                    guard cursor < bytes.count else { throw error }
                    let extensionByte = Int(bytes[cursor])
                    cursor += 1
                    let (sum, overflow) = length.addingReportingOverflow(extensionByte)
                    guard !overflow else { throw LZ4BlockError.outputExceedsExpectedSize }
                    length = sum
                    if extensionByte != 255 { break }
                }
            }
            return length
        }

        while cursor < bytes.count {
            let token = bytes[cursor]
            cursor += 1

            let literalLength = try readExtendedLength(
                base: Int(token >> 4),
                error: .truncatedLiteralLength
            )
            guard literalLength <= bytes.count - cursor else {
                throw LZ4BlockError.truncatedLiterals
            }
            guard literalLength <= expectedSize - output.count else {
                throw LZ4BlockError.outputExceedsExpectedSize
            }
            if literalLength > 0 {
                output.append(contentsOf: bytes[cursor..<(cursor + literalLength)])
                cursor += literalLength
            }

            // The final sequence in a raw LZ4 block contains literals only.
            if cursor == bytes.count {
                break
            }

            guard cursor + 2 <= bytes.count else {
                throw LZ4BlockError.truncatedMatchOffset
            }
            let offset = Int(bytes[cursor]) | (Int(bytes[cursor + 1]) << 8)
            cursor += 2
            guard offset != 0 else { throw LZ4BlockError.zeroMatchOffset }
            guard offset <= output.count else { throw LZ4BlockError.matchBeforeOutput }

            let matchNibble = Int(token & 0x0f)
            let encodedMatchLength = try readExtendedLength(
                base: matchNibble,
                error: .truncatedMatchLength
            )
            let matchLength = encodedMatchLength + 4
            guard matchLength <= expectedSize - output.count else {
                throw LZ4BlockError.outputExceedsExpectedSize
            }

            // LZ4 matches may overlap their source; append bytewise so newly
            // emitted bytes can be referenced by the same match.
            for _ in 0..<matchLength {
                output.append(output[output.count - offset])
            }
        }

        guard output.count == expectedSize else {
            throw LZ4BlockError.outputSizeMismatch(
                expected: expectedSize,
                actual: output.count
            )
        }
        return Data(output)
    }
}
