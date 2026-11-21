import Capstone
import Foundation

public enum AArch64DisassemblyError: Error, Equatable {
    case inputNotWordAligned(Int)
    case undecodableInstruction(offset: Int)
    case unexpectedInstructionSize(offset: Int, size: Int)
}

/// Strict AArch64 little-endian disassembly adapter.
/// Capstone supplies the full instruction/operand/register detail required by
/// the existing NSO rewriter; this wrapper rejects partial decode results.
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

    public func disassemble(_ code: Data, at address: UInt64 = 0) throws -> [Instruction] {
        guard code.count % 4 == 0 else {
            throw AArch64DisassemblyError.inputNotWordAligned(code.count)
        }
        guard !code.isEmpty else { return [] }

        let instructions = engine.disassemble(code: code, address: address)
        var consumed = 0
        for instruction in instructions {
            guard instruction.size == 4 else {
                throw AArch64DisassemblyError.unexpectedInstructionSize(
                    offset: consumed,
                    size: Int(instruction.size)
                )
            }
            guard instruction.address == address + UInt64(consumed) else {
                throw AArch64DisassemblyError.undecodableInstruction(offset: consumed)
            }
            consumed += 4
        }
        guard consumed == code.count else {
            throw AArch64DisassemblyError.undecodableInstruction(offset: consumed)
        }
        return instructions
    }
}
