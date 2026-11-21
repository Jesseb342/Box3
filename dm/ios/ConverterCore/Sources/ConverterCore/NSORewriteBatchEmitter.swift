import Foundation

public enum NSORewriteBatchError: Error, Equatable {
    case baseImageSizeMismatch(expected: UInt64, actual: Int)
    case unsupportedSite(NSORewriteSiteKind, UInt64)
    case siteOutsideImage(UInt64)
    case originalInstructionMismatch(UInt64, expected: UInt32, actual: UInt32)
    case patchAreaDoesNotFit(required: UInt64, available: UInt64)
    case invalidPatchOffset
}

public struct NSORewriteBatchResult {
    public let fileData: Data
    public let patchData: Data
    public let fixups: [NSORewriteFixup]
    public let patchedSiteCount: Int
}

/// Builds a complete file-layout byte stream for modules whose rewrite plan
/// consists exclusively of ordinary x18 sites. Any unimplemented site kind
/// aborts the batch; this prevents silently producing a partially rewritten
/// executable.
public enum NSORewriteBatchEmitter {
    public static func emitPlainX18Sites(
        baseImage: Data,
        plan: NSORewritePlan,
        layout: NSOPatchLayout,
        decoder: AArch64Disassembler
    ) throws -> NSORewriteBatchResult {
        guard UInt64(baseImage.count) == layout.fileImageLength else {
            throw NSORewriteBatchError.baseImageSizeMismatch(
                expected: layout.fileImageLength,
                actual: baseImage.count
            )
        }
        for site in plan.sites where site.kind != .x18Plain {
            throw NSORewriteBatchError.unsupportedSite(site.kind, site.address)
        }

        var image = baseImage
        var patch = Data()
        var fixups: [NSORewriteFixup] = []
        for site in plan.sites.sorted(by: { $0.address < $1.address }) {
            guard site.address <= UInt64(image.count),
                  UInt64(image.count) - site.address >= 4 else {
                throw NSORewriteBatchError.siteOutsideImage(site.address)
            }
            let offset = Int(site.address)
            let actual = readUInt32LE(image, at: offset)
            guard actual == site.instructionWord else {
                throw NSORewriteBatchError.originalInstructionMismatch(
                    site.address,
                    expected: site.instructionWord,
                    actual: actual
                )
            }

            let patchAddress = try currentPatchAddress(
                base: layout.patchOffset,
                byteCount: patch.count
            )
            let block = try NSORewriteEmitter.emitPlainX18(
                site,
                patchAddress: patchAddress,
                keyPageOffset: Int64(layout.keyPageOffset),
                decoder: decoder
            )
            for fixup in block.fixups {
                fixups.append(NSORewriteFixup(
                    byteOffset: patch.count + fixup.byteOffset,
                    key: fixup.key
                ))
            }
            patch.append(block.data)
            writeUInt32LE(block.siteBranchWord, to: &image, at: offset)
        }

        var output = image
        if layout.isFar {
            let front = UInt64(-layout.patchOffset)
            let available = front >= 0x4000 ? front - 0x4000 : 0
            guard UInt64(patch.count) <= available else {
                throw NSORewriteBatchError.patchAreaDoesNotFit(
                    required: UInt64(patch.count),
                    available: available
                )
            }
        } else {
            guard layout.patchOffset >= 0 else {
                throw NSORewriteBatchError.invalidPatchOffset
            }
            let target = UInt64(layout.patchOffset)
            guard target >= UInt64(output.count) else {
                throw NSORewriteBatchError.invalidPatchOffset
            }
            output.append(Data(repeating: 0, count: Int(target - UInt64(output.count))))
        }
        output.append(patch)

        return NSORewriteBatchResult(
            fileData: output,
            patchData: patch,
            fixups: fixups,
            patchedSiteCount: plan.sites.count
        )
    }

    private static func currentPatchAddress(base: Int64, byteCount: Int) throws -> Int64 {
        let (address, overflow) = base.addingReportingOverflow(Int64(byteCount))
        guard !overflow else { throw NSORewriteBatchError.invalidPatchOffset }
        return address
    }

    private static func readUInt32LE(_ data: Data, at offset: Int) -> UInt32 {
        UInt32(data[offset]) |
            (UInt32(data[offset + 1]) << 8) |
            (UInt32(data[offset + 2]) << 16) |
            (UInt32(data[offset + 3]) << 24)
    }

    private static func writeUInt32LE(_ word: UInt32, to data: inout Data, at offset: Int) {
        data[offset] = UInt8(truncatingIfNeeded: word)
        data[offset + 1] = UInt8(truncatingIfNeeded: word >> 8)
        data[offset + 2] = UInt8(truncatingIfNeeded: word >> 16)
        data[offset + 3] = UInt8(truncatingIfNeeded: word >> 24)
    }
}
