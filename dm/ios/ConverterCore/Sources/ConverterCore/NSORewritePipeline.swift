import Foundation

public enum NSORewritePipelineError: Error, Equatable {
    case noCodeRanges
    case codeRangeOutsideText(start: UInt64, end: UInt64, textSize: UInt64)
}

/// Result of the NSO-only conversion stage. The output is the reconstructed
/// module image plus its appended patch area; it is not a complete NCA/NSP/IPA.
public struct NSORewritePipelineResult {
    public let module: NSOImage
    public let layout: NSOPatchLayout
    public let plan: NSORewritePlan
    public let emission: NSORewriteBatchResult

    public var outputData: Data { emission.fileData }
}

/// Coordinates the already-tested NSO primitives into one fail-closed operation.
///
/// Code ranges must come from trusted executable metadata/profile analysis. This
/// pipeline deliberately does not guess that every byte in the text segment is
/// executable: literal pools and embedded data must not be disassembled as code.
public enum NSORewritePipeline {
    public static func process(
        file: Data,
        codeRanges: [NSOCodeRange],
        decoder: AArch64Disassembler? = nil
    ) throws -> NSORewritePipelineResult {
        guard !codeRanges.isEmpty else {
            throw NSORewritePipelineError.noCodeRanges
        }

        let module = try NSOImage(data: file)
        let layout = try NSOPatchLayout.make(
            segments: module.segments,
            bssSize: module.bssSize
        )
        let textSize = UInt64(module.segments[0].memorySize)

        var instructions: [DecodedAArch64Instruction] = []
        var sortedRanges = codeRanges.sorted { $0.start < $1.start }
        for range in sortedRanges {
            guard range.start < range.end, range.end <= textSize else {
                throw NSORewritePipelineError.codeRangeOutsideText(
                    start: range.start,
                    end: range.end,
                    textSize: textSize
                )
            }
        }

        let disassembler = try decoder ?? AArch64Disassembler()
        let image = try module.reconstructedImage(from: file, layout: layout)
        for range in sortedRanges {
            let start = Int(range.start)
            let end = Int(range.end)
            let bytes = image.subdata(in: start..<end)
            let decoded = try disassembler.disassembleRecovering(bytes, at: range.start)
            instructions.append(contentsOf: decoded.instructions)
        }

        let plan = try NSORewritePlanner.plan(
            instructions: instructions,
            codeRanges: sortedRanges,
            allowUndecodableAddresses: true
        )
        let emission = try NSORewriteBatchEmitter.emitSupportedSites(
            baseImage: image,
            plan: plan,
            layout: layout,
            decoder: disassembler
        )
        return NSORewritePipelineResult(
            module: module,
            layout: layout,
            plan: plan,
            emission: emission
        )
    }
}
