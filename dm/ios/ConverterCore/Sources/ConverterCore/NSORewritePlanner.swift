import Foundation

public struct NSOCodeRange: Equatable {
    public let start: UInt64
    public let end: UInt64

    public init(start: UInt64, end: UInt64) throws {
        guard start <= end, start % 4 == 0, end % 4 == 0 else {
            throw NSORewritePlanningError.invalidCodeRange
        }
        self.start = start
        self.end = end
    }
}

public enum NSORewritePlanningError: Error, Equatable {
    case invalidCodeRange
    case overlappingCodeRanges
    case instructionOutsideCodeRange(UInt64)
    case duplicateInstructionAddress(UInt64)
    case nonContiguousCodeRange(UInt64)
    case codeRangeOutsideImage(UInt64)
    case unsupportedRewriteSite(UInt64, String)
}

public enum NSORewriteSiteKind: String, Equatable, Hashable {
    case svc
    case tpidrRead
    case tpidrWrite
    case tpidrroRead
    case counterPhysicalRead
    case counterVirtualRead
    case cacheTypeRead
    case stackAlignment
    case x18Plain
    case x18StackPointer
    case x18Conditional
    case x18PCRelative
    case x18IndirectBranch
    case x18IndirectCall
    case x18ExclusiveWindowCandidate
    case x18Unsupported
}

public struct NSORewriteSite: Equatable {
    public let address: UInt64
    public let kind: NSORewriteSiteKind
    public let argument: UInt32?
    public let instructionWord: UInt32
    public let mnemonic: String
    public let operands: String
}

public struct NSORewritePlan: Equatable {
    public let sites: [NSORewriteSite]
    public let counts: [NSORewriteSiteKind: Int]
    public let undecodableAddresses: [UInt64]

    public var unsupportedSites: [NSORewriteSite] {
        sites.filter { $0.kind == .x18Unsupported }
    }
}

/// Conservative first-pass site inventory for the NSO rewriter.
/// It deliberately classifies candidates without emitting executable code.
/// Complex x18 constructs must pass later function/window/jump-table analysis.
public enum NSORewritePlanner {
    public static func plan(
        instructions: [DecodedAArch64Instruction],
        codeRanges: [NSOCodeRange],
        allowUndecodableAddresses: Bool = false
    ) throws -> NSORewritePlan {
        let ranges = codeRanges.sorted { $0.start < $1.start }
        if ranges.count > 1 {
            for i in 1..<ranges.count where ranges[i].start < ranges[i - 1].end {
                throw NSORewritePlanningError.overlappingCodeRanges
            }
        }

        var byAddress: [UInt64: DecodedAArch64Instruction] = [:]
        for instruction in instructions {
            guard byAddress[instruction.address] == nil else {
                throw NSORewritePlanningError.duplicateInstructionAddress(instruction.address)
            }
            byAddress[instruction.address] = instruction
        }

        var sites: [NSORewriteSite] = []
        var undecodable: [UInt64] = []
        for range in ranges {
            var address = range.start
            while address < range.end {
                guard let instruction = byAddress[address] else {
                    guard allowUndecodableAddresses else {
                        throw NSORewritePlanningError.nonContiguousCodeRange(address)
                    }
                    undecodable.append(address)
                    let (next, overflow) = address.addingReportingOverflow(4)
                    guard !overflow else { throw NSORewritePlanningError.invalidCodeRange }
                    address = next
                    continue
                }
                let (next, overflow) = address.addingReportingOverflow(4)
                guard !overflow else { throw NSORewritePlanningError.invalidCodeRange }
                if let site = classify(instruction) { sites.append(site) }
                address = next
            }
        }

        for instruction in instructions where !ranges.contains(where: {
            instruction.address >= $0.start && instruction.address < $0.end
        }) {
            throw NSORewritePlanningError.instructionOutsideCodeRange(instruction.address)
        }

        sites.sort { $0.address < $1.address }
        var counts: [NSORewriteSiteKind: Int] = [:]
        for site in sites { counts[site.kind, default: 0] += 1 }
        return NSORewritePlan(sites: sites, counts: counts, undecodableAddresses: undecodable)
    }

    private static func classify(_ instruction: DecodedAArch64Instruction) -> NSORewriteSite? {
        let word = instruction.word
        let address = instruction.address
        let mnemonic = instruction.mnemonic
        let operands = instruction.operandString

        if word & 0xFFE0001F == 0xD4000001 {
            return site(instruction, .svc, (word >> 5) & 0xFFFF)
        }
        if word & 0xFFFFFFE0 == 0xD53BD040 {
            return site(instruction, .tpidrRead)
        }
        if word & 0xFFFFFFE0 == 0xD51BD040 {
            return site(instruction, .tpidrWrite)
        }
        if word & 0xFFFFFFE0 == 0xD53BD060 {
            return site(instruction, .tpidrroRead)
        }
        if word & 0xFFFFFFE0 == 0xD53BE020 {
            return site(instruction, .counterPhysicalRead, word & 31)
        }
        if word & 0xFFFFFFE0 == 0xD53BE040 {
            return site(instruction, .counterVirtualRead, word & 31)
        }
        if word & 0xFFFFFFE0 == 0xD53B0020 {
            return site(instruction, .cacheTypeRead, word & 31)
        }
        if word & 0xFFE0FFFF == 0xCB2063FF,
           (word >> 16) & 31 != 18 {
            return site(instruction, .stackAlignment, (word >> 16) & 31)
        }

        guard instruction.mentionsX18 else { return nil }

        if isExclusive(mnemonic) {
            return site(instruction, .x18ExclusiveWindowCandidate)
        }
        if mnemonic == "br" && operands == "x18" {
            return site(instruction, .x18IndirectBranch)
        }
        if mnemonic == "blr" && operands == "x18" {
            return site(instruction, .x18IndirectCall)
        }
        if mnemonic == "adr" || mnemonic == "adrp" {
            return site(instruction, .x18PCRelative)
        }
        if ["cbz", "cbnz", "tbz", "tbnz"].contains(mnemonic) || mnemonic.hasPrefix("b.") {
            return site(instruction, .x18Conditional)
        }
        if writesStackPointer(mnemonic: mnemonic, operands: operands) {
            return site(instruction, .x18StackPointer)
        }
        if ["b", "bl", "ret", "br", "blr"].contains(mnemonic) ||
            mnemonic.hasPrefix("ldr") && !operands.contains("[") {
            return site(instruction, .x18Unsupported)
        }
        return site(instruction, .x18Plain)
    }

    private static func site(
        _ instruction: DecodedAArch64Instruction,
        _ kind: NSORewriteSiteKind,
        _ argument: UInt32? = nil
    ) -> NSORewriteSite {
        NSORewriteSite(
            address: instruction.address,
            kind: kind,
            argument: argument,
            instructionWord: instruction.word,
            mnemonic: instruction.mnemonic,
            operands: instruction.operandString
        )
    }

    private static func isExclusive(_ mnemonic: String) -> Bool {
        let prefixes = ["ldxr", "ldaxr", "ldxp", "ldaxp", "stxr", "stlxr", "stxp", "stlxp"]
        return prefixes.contains(where: { mnemonic.hasPrefix($0) })
    }

    private static func writesStackPointer(mnemonic: String, operands: String) -> Bool {
        let first = String(operands.split(separator: ",", maxSplits: 1).first ?? "")
            .trimmingCharacters(in: .whitespaces)
        return first == "sp" || first == "wsp"
    }
}
