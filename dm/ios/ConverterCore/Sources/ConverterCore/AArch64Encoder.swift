import Foundation

public enum AArch64EncodingError: Error, Equatable {
    case invalidRegister(Int)
    case invalidImmediate
    case unalignedBranch
    case branchOutOfRange
    case adrpOutOfRange
}

/// Small, checked AArch64 encoder matching the instruction forms used by
/// Box3's NSO rewriter. Addresses are byte addresses; emitted words are host
/// integers and must be serialized little-endian into the patch stream.
public enum AArch64Encoder {
    private static func reg(_ value: Int) throws -> UInt32 {
        guard (0...31).contains(value) else {
            throw AArch64EncodingError.invalidRegister(value)
        }
        return UInt32(value)
    }

    private static func signed(_ value: Int, bits: Int) -> UInt32? {
        let minimum = -(1 << (bits - 1))
        let maximum = (1 << (bits - 1)) - 1
        guard value >= minimum, value <= maximum else { return nil }
        return UInt32(truncatingIfNeeded: value)
    }

    public static func b(from: Int64, to: Int64) throws -> UInt32 {
        let (delta, overflow) = to.subtractingReportingOverflow(from)
        guard !overflow else { throw AArch64EncodingError.branchOutOfRange }
        guard delta % 4 == 0 else { throw AArch64EncodingError.unalignedBranch }
        guard let immediate = signed(Int(delta / 4), bits: 26) else {
            throw AArch64EncodingError.branchOutOfRange
        }
        return 0x14000000 | (immediate & 0x03ff_ffff)
    }

    public static func beq(from: Int64, to: Int64) throws -> UInt32 {
        let delta = to - from
        guard delta % 4 == 0 else { throw AArch64EncodingError.unalignedBranch }
        guard let immediate = signed(Int(delta / 4), bits: 19) else {
            throw AArch64EncodingError.branchOutOfRange
        }
        return 0x54000000 | ((immediate & 0x7ffff) << 5)
    }

    public static func stp(_ first: Int, _ second: Int, base: Int, offset: Int) throws -> UInt32 {
        try pair(0xA9000000, first, second, base, offset)
    }

    public static func ldp(_ first: Int, _ second: Int, base: Int, offset: Int) throws -> UInt32 {
        try pair(0xA9400000, first, second, base, offset)
    }

    public static func stpPre(_ first: Int, _ second: Int, base: Int, offset: Int) throws -> UInt32 {
        try pair(0xA9800000, first, second, base, offset)
    }

    public static func ldpPost(_ first: Int, _ second: Int, base: Int, offset: Int) throws -> UInt32 {
        try pair(0xA8C00000, first, second, base, offset)
    }

    private static func pair(_ opcode: UInt32, _ first: Int, _ second: Int, _ base: Int, _ offset: Int) throws -> UInt32 {
        guard offset % 8 == 0, let immediate = signed(offset / 8, bits: 7) else {
            throw AArch64EncodingError.invalidImmediate
        }
        return opcode | ((immediate & 0x7f) << 15) |
            (try reg(second) << 10) | (try reg(base) << 5) | (try reg(first))
    }

    public static func stur(_ target: Int, base: Int, offset: Int) throws -> UInt32 {
        try unscaled(0xF8000000, target, base, offset)
    }

    public static func ldur(_ target: Int, base: Int, offset: Int) throws -> UInt32 {
        try unscaled(0xF8400000, target, base, offset)
    }

    private static func unscaled(_ opcode: UInt32, _ target: Int, _ base: Int, _ offset: Int) throws -> UInt32 {
        guard let immediate = signed(offset, bits: 9) else {
            throw AArch64EncodingError.invalidImmediate
        }
        return opcode | ((immediate & 0x1ff) << 12) |
            (try reg(base) << 5) | (try reg(target))
    }

    public static func ldrX(_ target: Int, base: Int, immediate12: Int = 0) throws -> UInt32 {
        try unsignedLoadStore(0xF9400000, target, base, immediate12)
    }

    public static func strX(_ target: Int, base: Int, immediate12: Int = 0) throws -> UInt32 {
        try unsignedLoadStore(0xF9000000, target, base, immediate12)
    }

    private static func unsignedLoadStore(_ opcode: UInt32, _ target: Int, _ base: Int, _ immediate: Int) throws -> UInt32 {
        guard (0...4095).contains(immediate) else {
            throw AArch64EncodingError.invalidImmediate
        }
        return opcode | (UInt32(immediate) << 10) |
            (try reg(base) << 5) | reg(target)
    }

    public static func mrsTPIDRRO(_ target: Int) throws -> UInt32 {
        0xD53BD060 | (try reg(target))
    }

    public static func adrp(_ destination: Int, pc: Int64, target: Int64) throws -> UInt32 {
        let pageDelta = (target >> 12) - (pc >> 12)
        guard let immediate = signed(Int(pageDelta), bits: 21) else {
            throw AArch64EncodingError.adrpOutOfRange
        }
        return 0x90000000 | ((immediate & 0x3) << 29) |
            (((immediate >> 2) & 0x7ffff) << 5) | (try reg(destination))
    }

    public static func addImmediate(_ destination: Int, source: Int, immediate: Int, shift12: Bool = false) throws -> UInt32 {
        try immediateArithmetic(0x91000000, destination, source, immediate, shift12)
    }

    public static func subImmediate(_ destination: Int, source: Int, immediate: Int, shift12: Bool = false) throws -> UInt32 {
        try immediateArithmetic(0xD1000000, destination, source, immediate, shift12)
    }

    private static func immediateArithmetic(_ opcode: UInt32, _ destination: Int, _ source: Int, _ immediate: Int, _ shift12: Bool) throws -> UInt32 {
        guard (0...4095).contains(immediate) else {
            throw AArch64EncodingError.invalidImmediate
        }
        return opcode | (shift12 ? (1 << 22) : 0) |
            (UInt32(immediate) << 10) | (try reg(source) << 5) | (try reg(destination))
    }

    public static func addRegister(_ destination: Int, source: Int, operand: Int) throws -> UInt32 {
        0x8B000000 | (try reg(operand) << 16) |
            (try reg(source) << 5) | reg(destination)
    }

    public static func branchRegister(_ source: Int) throws -> UInt32 {
        0xD61F0000 | (try reg(source) << 5)
    }

    public static func compareRegisters(_ first: Int, _ second: Int) throws -> UInt32 {
        0xEB00001F | (try reg(second) << 16) | (try reg(first) << 5)
    }

    public static func branchLinkRegister(_ source: Int) throws -> UInt32 {
        0xD63F0000 | (try reg(source) << 5)
    }

    public static func brk(_ immediate: Int) throws -> UInt32 {
        guard (0...65535).contains(immediate) else {
            throw AArch64EncodingError.invalidImmediate
        }
        return 0xD4200000 | (UInt32(immediate) << 5)
    }

    public static let nop: UInt32 = 0xD503201F
}
