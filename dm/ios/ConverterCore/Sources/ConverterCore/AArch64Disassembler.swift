import Capstone
import Foundation

public enum AArch64DisassemblyError: Error, Equatable {
    case inputNotWordAligned(Int)
    case undecodableInstruction(offset: Int)
    case unexpectedInstructionSize(offset: Int, size: Int)
}

public struct AArch64DisassemblyResult: Equatable {
    public let instructions: [DecodedAArch64Instruction]
    public let undecodableAddresses: [UInt64]
}

public struct DecodedAArch64Instruction: Equatable {
    public let address: UInt64
    public let word: UInt32
    public let mnemonic: String
    public let operandString: String
    public let registersRead: Set<String>
    public let registersWritten: Set<String>
    public let registersMentioned: Set<String>

    public var allRegisters: Set<String> {
        registersRead.union(registersWritten).union(registersMentioned)
    }

    public var mentionsX18: Bool {
        registersMentioned.contains("x18") || registersMentioned.contains("w18") ||
            registersRead.contains("x18") || registersWritten.contains("x18") ||
            registersRead.contains("w18") || registersWritten.contains("w18")
    }
}

/// Strict AArch64 little-endian disassembly adapter.
/// Capstone supplies the full instruction/operand/register detail required by
/// the existing NSO rewriter; this wrapper rejects partial instruction streams
/// and keeps Capstone's types out of ConverterCore's public API.
public final class AArch64Disassembler {
    private let engine: Disassembler

    public init() throws {
        let engine = try Disassembler(
            arch: CS_ARCH_AARCH64,
            mode: CS_MODE_LITTLE_ENDIAN
        )
        engine.detail = true
        self.engine = engine
    }

    private func registerName(_ registerID: UInt16) -> String? {
        engine.registerName(UInt32(registerID))
    }

    private static func registersMentioned(_ operands: String) -> Set<String> {
        let expression = try! NSRegularExpression(pattern: #"\b[wx](?:[0-9]|[12][0-9]|30)\b"#)
        let source = operands as NSString
        let range = NSRange(location: 0, length: source.length)
        return Set(expression.matches(in: operands, range: range).map {
            source.substring(with: $0.range)
        })
    }

    /// Decodes one word at a time and records invalid/trap words instead of
    /// stopping the scan. This matches the desktop rewriter's recovery policy
    /// for functions containing embedded trap instructions.
    public func disassembleRecovering(_ code: Data, at address: UInt64 = 0) throws -> AArch64DisassemblyResult {
        guard code.count % 4 == 0 else {
            throw AArch64DisassemblyError.inputNotWordAligned(code.count)
        }
        var instructions: [DecodedAArch64Instruction] = []
        var gaps: [UInt64] = []
        for offset in stride(from: 0, to: code.count, by: 4) {
            let (pc, overflow) = address.addingReportingOverflow(UInt64(offset))
            guard !overflow else {
                throw AArch64DisassemblyError.undecodableInstruction(offset: offset)
            }
            let word = code.subdata(in: offset..<(offset + 4))
            guard let instruction = engine.disassemble(code: word, address: pc).first,
                  instruction.size == 4,
                  instruction.address == pc,
                  instruction.bytes.count == 4 else {
                gaps.append(pc)
                continue
            }
            let bytes = instruction.bytes
            let rawWord = UInt32(bytes[0]) |
                (UInt32(bytes[1]) << 8) |
                (UInt32(bytes[2]) << 16) |
                (UInt32(bytes[3]) << 24)
            instructions.append(DecodedAArch64Instruction(
                address: pc,
                word: rawWord,
                mnemonic: instruction.mnemonic,
                operandString: instruction.operandString,
                registersRead: Set(instruction.regsRead.compactMap(registerName)),
                registersWritten: Set(instruction.regsWritten.compactMap(registerName)),
                registersMentioned: Self.registersMentioned(instruction.operandString)
            ))
        }
        return AArch64DisassemblyResult(
            instructions: instructions,
            undecodableAddresses: gaps
        )
    }

    public func disassemble(_ code: Data, at address: UInt64 = 0) throws -> [DecodedAArch64Instruction] {
        guard code.count % 4 == 0 else {
            throw AArch64DisassemblyError.inputNotWordAligned(code.count)
        }
        guard !code.isEmpty else { return [] }

        let decoded = engine.disassemble(code: code, address: address)
        var consumed = 0
        var result: [DecodedAArch64Instruction] = []
        result.reserveCapacity(decoded.count)

        for instruction in decoded {
            guard instruction.size == 4 else {
                throw AArch64DisassemblyError.unexpectedInstructionSize(
                    offset: consumed,
                    size: Int(instruction.size)
                )
            }
            let (expectedAddress, overflow) = address.addingReportingOverflow(UInt64(consumed))
            guard !overflow, instruction.address == expectedAddress else {
                throw AArch64DisassemblyError.undecodableInstruction(offset: consumed)
            }
            guard instruction.bytes.count == 4 else {
                throw AArch64DisassemblyError.unexpectedInstructionSize(
                    offset: consumed,
                    size: instruction.bytes.count
                )
            }

            let bytes = instruction.bytes
            let word = UInt32(bytes[0]) |
                (UInt32(bytes[1]) << 8) |
                (UInt32(bytes[2]) << 16) |
                (UInt32(bytes[3]) << 24)
            result.append(DecodedAArch64Instruction(
                address: instruction.address,
                word: word,
                mnemonic: instruction.mnemonic,
                operandString: instruction.operandString,
                registersRead: Set(instruction.regsRead.compactMap(registerName)),
                registersWritten: Set(instruction.regsWritten.compactMap(registerName)),
                registersMentioned: Self.registersMentioned(instruction.operandString)
            ))
            consumed += 4
        }

        guard consumed == code.count else {
            throw AArch64DisassemblyError.undecodableInstruction(offset: consumed)
        }
        return result
    }
}
