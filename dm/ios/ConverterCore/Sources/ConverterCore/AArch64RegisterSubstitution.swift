import Foundation

public enum AArch64SubstitutionError: Error, Equatable {
    case invalidReplacementRegister(Int)
    case instructionDoesNotMentionX18
    case noEncodingPreservesInstruction
}

/// Rewrites only register fields that actually encode register 18.
/// Candidate words are accepted only when Capstone decodes them to the exact
/// expected mnemonic and operand text after x18/w18 is replaced.
public enum AArch64RegisterSubstitution {
    private static let registerFieldPositions = [0, 5, 10, 16]

    public static func replaceX18(
        in instruction: DecodedAArch64Instruction,
        with replacement: Int,
        decoder: AArch64Disassembler
    ) throws -> UInt32 {
        guard (0...15).contains(replacement) else {
            throw AArch64SubstitutionError.invalidReplacementRegister(replacement)
        }
        guard instruction.mentionsX18 else {
            throw AArch64SubstitutionError.instructionDoesNotMentionX18
        }

        let positions = registerFieldPositions.filter {
            (instruction.word >> $0) & 31 == 18
        }
        guard !positions.isEmpty else {
            throw AArch64SubstitutionError.noEncodingPreservesInstruction
        }

        let expectedOperands = try replacingRegisterTokens(
            instruction.operandString,
            with: replacement
        )
        for mask in 1..<(1 << positions.count) {
            var candidate = instruction.word
            for index in positions.indices where (mask & (1 << index)) != 0 {
                let shift = positions[index]
                candidate = (candidate & ~(UInt32(31) << shift)) |
                    (UInt32(replacement) << shift)
            }

            var bytes = Data()
            var littleEndian = candidate.littleEndian
            withUnsafeBytes(of: &littleEndian) { bytes.append(contentsOf: $0) }
            guard let decoded = try? decoder.disassemble(bytes, at: instruction.address).first,
                  decoded.mnemonic == instruction.mnemonic,
                  decoded.operandString == expectedOperands else {
                continue
            }
            return candidate
        }

        throw AArch64SubstitutionError.noEncodingPreservesInstruction
    }

    private static func replacingRegisterTokens(_ operands: String, with register: Int) throws -> String {
        let expression = try NSRegularExpression(pattern: #"\b([xw])18\b"#)
        let range = NSRange(operands.startIndex..., in: operands)
        guard expression.firstMatch(in: operands, range: range) != nil else {
            throw AArch64SubstitutionError.instructionDoesNotMentionX18
        }
        let matches = expression.matches(in: operands, range: range)
        let source = operands as NSString
        let output = NSMutableString(string: operands)
        for match in matches.reversed() {
            let prefix = source.substring(with: match.range(at: 1))
            output.replaceCharacters(
                in: match.range,
                with: prefix + String(register)
            )
        }
        return output as String
    }
}
