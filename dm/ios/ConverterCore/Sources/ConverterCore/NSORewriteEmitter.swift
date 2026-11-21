import Foundation

public enum NSORewriteEmissionError: Error, Equatable {
    case unsupportedSite(NSORewriteSiteKind)
    case stackPointerWritebackNotSupported
    case insufficientScratchRegisters
    case addressOutOfRange
}

public struct NSORewriteFixup: Equatable {
    public let byteOffset: Int
    public let key: String
}

public struct NSORewriteBlock: Equatable {
    public let siteAddress: UInt64
    public let kind: NSORewriteSiteKind
    public let words: [UInt32]
    public let fixups: [NSORewriteFixup]

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

/// Emits only the proven, non-stack-adjusting x18 rewrite form from patch_nso.py.
/// Other site kinds remain inventory-only until their dedicated emitters exist.
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

        let used = registers(in: site)
        let scratch = (0..<16).filter { !used.contains($0) }
        guard scratch.count >= 2 else {
            throw NSORewriteEmissionError.insufficientScratchRegisters
        }
        let s = scratch[0]
        let t = scratch[1]
        let original = DecodedAArch64Instruction(
            address: site.address,
            word: site.instructionWord,
            mnemonic: site.mnemonic,
            operandString: site.operands,
            registersRead: [],
            registersWritten: [],
            registersMentioned: used.map { "x\($0)" }.reduce(into: Set<String>()) { $0.insert($1) }
        )
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

        return NSORewriteBlock(
            siteAddress: site.address,
            kind: site.kind,
            words: words,
            fixups: fixups
        )
    }

    private static func registers(in site: NSORewriteSite) -> Set<Int> {
        let expression = try! NSRegularExpression(pattern: #"\b[wx](0|[1-9]|1[0-5]|18)\b"#)
        let source = site.operands as NSString
        let range = NSRange(location: 0, length: source.length)
        return Set(expression.matches(in: site.operands, range: range).compactMap {
            Int(source.substring(with: $0.range).dropFirst())
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
