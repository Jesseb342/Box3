import Capstone
import Foundation

public enum AArch64DisassemblyError: Error, Equatable {
    case inputNotWordAligned(Int)
    case undecodableInstruction(offset: Int)
    case unexpectedInstructionSize(offset: Int, size: Int)
}

public struct DecodedAArch64Instruction: Equatable {
    public let address: UInt64
    public let word: UInt32
    public let mnemonic: String
    public let operandString: String
    public let registersRead: Set<String>
    public let registersWritten: Set<String>
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
                registersWritten: Set(instruction.regsWritten.compactMap(registerName))
            ))
            consumed += 4
        }

        guard consumed == code.count else {
            throw AArch64DisassemblyError.undecodableInstruction(offset: consumed)
        }
        return result
    }
}
