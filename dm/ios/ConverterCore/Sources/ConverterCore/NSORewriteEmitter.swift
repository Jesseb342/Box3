import Foundation

public enum NSORewriteEmissionError: Error, Equatable {
    case unsupportedSite(NSORewriteSiteKind)
    case stackPointerWritebackNotSupported
    case insufficientScratchRegisters
    case siteInstructionMismatch
    case addressOutOfRange
}

public struct NSORewriteFixup: Equatable {
    public let byteOffset: Int
    public let key: String
}

public struct NSORewriteGate: Equatable {
    public let returnAddress: Int64
    public let kind: String
    public let argument: UInt32
    public let originalAddress: UInt64
}

public struct NSORewriteBlock: Equatable {
    public let siteAddress: UInt64
    public let kind: NSORewriteSiteKind
    public let words: [UInt32]
    public let fixups: [NSORewriteFixup]
    public let siteBranchWord: UInt32
    public let gate: NSORewriteGate?

    public var data: Data {
        var output = Data()
        output.reserveCapacity(words.count * 4)
        for word in words {
            var value = word.littleEndian
            withUnsafeBytes(of: &value) { output.append(contentsOf: $0) }
        }
        return output
    }
}

/// Native emitters for the currently proven subset of patch_nso.py rewrite sites.
/// Unsupported and context-dependent site kinds deliberately have no emitter.
public enum NSORewriteEmitter {
    public static func emitPlainX18(
        _ site: NSORewriteSite,
        patchAddress: Int64,
        keyPageOffset: Int64,
        decoder: AArch64Disassembler
    ) throws -> NSORewriteBlock {
        guard site.kind == .x18Plain else {
            throw NSORewriteEmissionError.unsupportedSite(site.kind)
        }
        guard !writesOrAdjustsStackPointer(site.operands) else {
            throw NSORewriteEmissionError.stackPointerWritebackNotSupported
        }
        guard site.address <= UInt64(Int64.max) else {
            throw NSORewriteEmissionError.addressOutOfRange
        }

        var originalBytes = Data()
        var originalWord = site.instructionWord.littleEndian
        withUnsafeBytes(of: &originalWord) { originalBytes.append(contentsOf: $0) }
        guard let original = try decoder.disassemble(originalBytes, at: site.address).first,
              original.word == site.instructionWord,
              original.mnemonic == site.mnemonic,
              original.operandString == site.operands else {
            throw NSORewriteEmissionError.siteInstructionMismatch
        }

        let used = registers(in: original)
        let scratch = (0..<16).filter { !used.contains($0) }
        guard scratch.count >= 2 else {
            throw NSORewriteEmissionError.insufficientScratchRegisters
        }
        let s = scratch[0]
        let t = scratch[1]
        let substituted = try AArch64RegisterSubstitution.replaceX18(
            in: original,
            with: s,
            decoder: decoder
        )

        var words: [UInt32] = []
        var fixups: [NSORewriteFixup] = []
        func here() throws -> Int64 {
            let delta = Int64(words.count) * 4
            let (address, overflow) = patchAddress.addingReportingOverflow(delta)
            guard !overflow else { throw NSORewriteEmissionError.addressOutOfRange }
            return address
        }
        func emit(_ word: UInt32) { words.append(word) }

        emit(try AArch64Encoder.stp(s, t, base: 31, offset: -16))
        emit(try AArch64Encoder.mrsTPIDRRO(t))
        let keyAddress = try here()
        let fixupOffset = words.count * 4
        emit(try AArch64Encoder.adrp(s, pc: keyAddress, target: keyPageOffset))
        fixups.append(NSORewriteFixup(byteOffset: fixupOffset, key: "K18"))
        emit(try AArch64Encoder.ldrX(s, base: s, immediate12: 0))
        emit(try AArch64Encoder.addRegister(t, source: t, operand: s))
        emit(try AArch64Encoder.ldrX(s, base: t))
        emit(substituted)
        emit(try AArch64Encoder.strX(s, base: t))
        emit(try AArch64Encoder.ldp(s, t, base: 31, offset: -16))
        let branchAddress = try here()
        let (returnAddress, returnOverflow) = Int64(site.address).addingReportingOverflow(4)
        guard !returnOverflow else { throw NSORewriteEmissionError.addressOutOfRange }
        emit(try AArch64Encoder.b(from: branchAddress, to: returnAddress))

        let siteBranch = try AArch64Encoder.b(
            from: Int64(site.address),
            to: patchAddress
        )
        return NSORewriteBlock(
            siteAddress: site.address,
            kind: site.kind,
            words: words,
            fixups: fixups,
            siteBranchWord: siteBranch,
            gate: nil
        )
    }

    public static func emitSystemRegisterRead(
        _ site: NSORewriteSite,
        patchAddress: Int64,
        keyPageOffset: Int64
    ) throws -> NSORewriteBlock {
        let key: String
        let keyIndex: Int
        switch site.kind {
        case .tpidrRead:
            guard site.instructionWord & 0xFFFFFFE0 == 0xD53BD040 else {
                throw NSORewriteEmissionError.siteInstructionMismatch
            }
            key = "KTLS"; keyIndex = 1
        case .tpidrroRead:
            guard site.instructionWord & 0xFFFFFFE0 == 0xD53BD060 else {
                throw NSORewriteEmissionError.siteInstructionMismatch
            }
            key = "KTLR"; keyIndex = 2
        default: throw NSORewriteEmissionError.unsupportedSite(site.kind)
        }
        let destination = Int(site.instructionWord & 31)
        guard destination != 31 else {
            throw NSORewriteEmissionError.insufficientScratchRegisters
        }
        let temporary = destination == 16 ? 17 : 16
        var words: [UInt32] = []
        var fixups: [NSORewriteFixup] = []
        emitWord(try AArch64Encoder.stur(temporary, base: 31, offset: -16), into: &words)
        emitWord(try AArch64Encoder.mrsTPIDRRO(destination), into: &words)
        let keyPC = try patchPC(patchAddress, wordCount: words.count)
        fixups.append(NSORewriteFixup(byteOffset: words.count * 4, key: key))
        emitWord(try AArch64Encoder.adrp(temporary, pc: keyPC, target: keyPageOffset), into: &words)
        emitWord(try AArch64Encoder.ldrX(temporary, base: temporary, immediate12: keyIndex), into: &words)
        emitWord(try AArch64Encoder.addRegister(destination, source: destination, operand: temporary), into: &words)
        emitWord(try AArch64Encoder.ldrX(destination, base: destination), into: &words)
        emitWord(try AArch64Encoder.ldur(temporary, base: 31, offset: -16), into: &words)
        return try finish(
            site: site,
            kind: site.kind,
            words: words,
            fixups: fixups,
            patchAddress: patchAddress
        )
    }

    public static func emitSystemRegisterWrite(
        _ site: NSORewriteSite,
        patchAddress: Int64,
        keyPageOffset: Int64
    ) throws -> NSORewriteBlock {
        guard site.kind == .tpidrWrite else {
            throw NSORewriteEmissionError.unsupportedSite(site.kind)
        }
        guard site.instructionWord & 0xFFFFFFE0 == 0xD51BD040 else {
            throw NSORewriteEmissionError.siteInstructionMismatch
        }
        let source = Int(site.instructionWord & 31)
        guard let scratch = (0..<16).first(where: { $0 != source }),
              let temporary = [16, 17].first(where: { $0 != source && $0 != scratch }) else {
            throw NSORewriteEmissionError.insufficientScratchRegisters
        }
        var words: [UInt32] = []
        var fixups: [NSORewriteFixup] = []
        emitWord(try AArch64Encoder.stur(scratch, base: 31, offset: -16), into: &words)
        emitWord(try AArch64Encoder.stur(temporary, base: 31, offset: -24), into: &words)
        emitWord(try AArch64Encoder.mrsTPIDRRO(scratch), into: &words)
        let keyPC = try patchPC(patchAddress, wordCount: words.count)
        fixups.append(NSORewriteFixup(byteOffset: words.count * 4, key: "KTLS"))
        emitWord(try AArch64Encoder.adrp(temporary, pc: keyPC, target: keyPageOffset), into: &words)
        emitWord(try AArch64Encoder.ldrX(temporary, base: temporary, immediate12: 1), into: &words)
        emitWord(try AArch64Encoder.addRegister(scratch, source: scratch, operand: temporary), into: &words)
        emitWord(try AArch64Encoder.strX(source, base: scratch), into: &words)
        emitWord(try AArch64Encoder.ldur(temporary, base: 31, offset: -24), into: &words)
        emitWord(try AArch64Encoder.ldur(scratch, base: 31, offset: -16), into: &words)
        return try finish(
            site: site,
            kind: site.kind,
            words: words,
            fixups: fixups,
            patchAddress: patchAddress
        )
    }

    public static func emitHostGate(
        _ site: NSORewriteSite,
        patchAddress: Int64,
        keyPageOffset: Int64
    ) throws -> NSORewriteBlock {
        let gateKind: String
        let argument: UInt32
        switch site.kind {
        case .svc:
            guard site.instructionWord & 0xFFE0001F == 0xD4000001 else {
                throw NSORewriteEmissionError.siteInstructionMismatch
            }
            gateKind = "svc"
            argument = (site.instructionWord >> 5) & 0xFFFF
        case .counterPhysicalRead:
            guard site.instructionWord & 0xFFFFFFE0 == 0xD53BE020 else {
                throw NSORewriteEmissionError.siteInstructionMismatch
            }
            gateKind = "cntpct"
            argument = site.instructionWord & 31
        case .counterVirtualRead:
            guard site.instructionWord & 0xFFFFFFE0 == 0xD53BE040 else {
                throw NSORewriteEmissionError.siteInstructionMismatch
            }
            gateKind = "cntvct"
            argument = site.instructionWord & 31
        default:
            throw NSORewriteEmissionError.unsupportedSite(site.kind)
        }

        var words: [UInt32] = []
        let prologue = try AArch64Encoder.stpPre(29, 30, base: 31, offset: -16)
        emitWord(prologue, into: &words)
        emitWord(try AArch64Encoder.mrsTPIDRRO(30), into: &words)
        let keyPC = try patchPC(patchAddress, wordCount: words.count)
        let fixup = NSORewriteFixup(byteOffset: words.count * 4, key: "KGATE")
        emitWord(try AArch64Encoder.adrp(29, pc: keyPC, target: keyPageOffset), into: &words)
        emitWord(try AArch64Encoder.ldrX(29, base: 29, immediate12: 3), into: &words)
        emitWord(try AArch64Encoder.addRegister(30, source: 30, operand: 29), into: &words)
        emitWord(try AArch64Encoder.ldrX(30, base: 30), into: &words)
        emitWord(try AArch64Encoder.ldrX(29, base: 31), into: &words)
        emitWord(try AArch64Encoder.branchLinkRegister(30), into: &words)
        let (returnAddress, overflow) = patchAddress.addingReportingOverflow(Int64(words.count) * 4)
        guard !overflow else { throw NSORewriteEmissionError.addressOutOfRange }
        emitWord(try AArch64Encoder.ldpPost(29, 30, base: 31, offset: 16), into: &words)
        let branchAddress = try patchPC(patchAddress, wordCount: words.count)
        let (resume, resumeOverflow) = Int64(site.address).addingReportingOverflow(4)
        guard !resumeOverflow else { throw NSORewriteEmissionError.addressOutOfRange }
        emitWord(try AArch64Encoder.b(from: branchAddress, to: resume), into: &words)

        return NSORewriteBlock(
            siteAddress: site.address,
            kind: site.kind,
            words: words,
            fixups: [fixup],
            siteBranchWord: try AArch64Encoder.b(from: Int64(site.address), to: patchAddress),
            gate: NSORewriteGate(
                returnAddress: returnAddress,
                kind: gateKind,
                argument: argument,
                originalAddress: site.address
            )
        )
    }

    public static func emitStackAlignment(
        _ site: NSORewriteSite,
        patchAddress: Int64
    ) throws -> NSORewriteBlock {
        guard site.kind == .stackAlignment,
              site.instructionWord & 0xFFE0FFFF == 0xCB2063FF else {
            throw NSORewriteEmissionError.siteInstructionMismatch
        }
        let encodedRegister = (site.instructionWord >> 16) & 31
        guard site.argument == encodedRegister else {
            throw NSORewriteEmissionError.siteInstructionMismatch
        }
        let register = Int(encodedRegister)
        guard (0...30).contains(register), register != 18 else {
            throw NSORewriteEmissionError.insufficientScratchRegisters
        }
        var words = [
            try AArch64Encoder.addImmediate(register, source: register, immediate: 15),
            0x927CEC00 | (UInt32(register) << 5) | UInt32(register),
            site.instructionWord
        ]
        let branchAddress = try patchPC(patchAddress, wordCount: words.count)
        let (resume, overflow) = Int64(site.address).addingReportingOverflow(4)
        guard !overflow else { throw NSORewriteEmissionError.addressOutOfRange }
        words.append(try AArch64Encoder.b(from: branchAddress, to: resume))
        return NSORewriteBlock(
            siteAddress: site.address,
            kind: site.kind,
            words: words,
            fixups: [],
            siteBranchWord: try AArch64Encoder.b(from: Int64(site.address), to: patchAddress),
            gate: nil
        )
    }

    private static func finish(
        site: NSORewriteSite,
        kind: NSORewriteSiteKind,
        words: [UInt32],
        fixups: [NSORewriteFixup],
        patchAddress: Int64
    ) throws -> NSORewriteBlock {
        let (resumeAddress, resumeOverflow) = Int64(site.address).addingReportingOverflow(4)
        guard !resumeOverflow else { throw NSORewriteEmissionError.addressOutOfRange }
        let branchAddress = try patchPC(patchAddress, wordCount: words.count)
        var completedWords = words
        completedWords.append(try AArch64Encoder.b(from: branchAddress, to: resumeAddress))
        let branch = try AArch64Encoder.b(from: Int64(site.address), to: patchAddress)
        return NSORewriteBlock(
            siteAddress: site.address,
            kind: kind,
            words: completedWords,
            fixups: fixups,
            siteBranchWord: branch,
            gate: nil
        )
    }

    private static func patchPC(_ base: Int64, wordCount: Int) throws -> Int64 {
        let (address, overflow) = base.addingReportingOverflow(Int64(wordCount) * 4)
        guard !overflow else { throw NSORewriteEmissionError.addressOutOfRange }
        return address
    }

    private static func emitWord(_ word: UInt32, into words: inout [UInt32]) {
        words.append(word)
    }

    private static func registers(in instruction: DecodedAArch64Instruction) -> Set<Int> {
        Set(instruction.allRegisters.compactMap { name in
            guard let first = name.first, first == "x" || first == "w",
                  let value = Int(name.dropFirst()),
                  (0...15).contains(value) || value == 18 else {
                return nil
            }
            return value
        })
    }

    private static func writesOrAdjustsStackPointer(_ operands: String) -> Bool {
        let first = String(operands.split(separator: ",", maxSplits: 1).first ?? "")
            .trimmingCharacters(in: .whitespaces)
        if first == "sp" || first == "wsp" { return true }
        let pattern = #"\[sp(?:, [^\]]+)?\]!|\[sp\],"#
        return (try? NSRegularExpression(pattern: pattern).firstMatch(
            in: operands,
            range: NSRange(operands.startIndex..., in: operands)
        )) != nil
    }
}
