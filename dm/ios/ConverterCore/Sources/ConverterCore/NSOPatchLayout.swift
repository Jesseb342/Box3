import Foundation

public enum NSOPatchLayoutError: Error, Equatable {
    case invalidTextSize
    case invalidSegmentLayout
    case arithmeticOverflow
    case frontPatchAreaTooLarge
}

/// Mirrors the near/far patch-area placement policy in dm/tools/patch_nso.py.
/// All offsets are virtual image offsets except patchOffset in far mode, where
/// it is negative relative to the module base.
public struct NSOPatchLayout: Equatable {
    public static let pageAlignment: UInt64 = 0x4000
    public static let patchAlignment: UInt64 = 0x10000
    public static let nearLimit: UInt64 = 0x07000000
    public static let branchReach: UInt64 = 0x08000000
    public static let branchSafetyMargin: UInt64 = 0x00010000
    public static let defaultFront: UInt64 = 0x02000000

    public let isFar: Bool
    public let isBigText: Bool
    public let textSize: UInt64
    public let bssSize: UInt64
    public let fileImageLength: UInt64
    public let keyPageOffset: UInt64
    public let imageSize: UInt64
    public let patchOffset: Int64

    public static func make(
        segments: [NSOImage.Segment],
        bssSize: UInt32,
        frontOverride: UInt64? = nil
    ) throws -> NSOPatchLayout {
        guard segments.count == 3 else { throw NSOPatchLayoutError.invalidSegmentLayout }
        let textSize = UInt64(segments[0].memorySize)
        let roEnd = UInt64(segments[1].memoryOffset) + UInt64(segments[1].memorySize)
        let dataEnd = UInt64(segments[2].memoryOffset) + UInt64(segments[2].memorySize)
        guard textSize > 0,
              UInt64(segments[0].memoryOffset) == 0,
              UInt64(segments[1].memoryOffset) >= textSize,
              UInt64(segments[2].memoryOffset) >= roEnd,
              dataEnd >= UInt64(segments[2].memoryOffset) else {
            throw NSOPatchLayoutError.invalidSegmentLayout
        }

        let bss = UInt64(bssSize)
        let (withBSS, bssOverflow) = dataEnd.addingReportingOverflow(bss)
        guard !bssOverflow else { throw NSOPatchLayoutError.arithmeticOverflow }

        let alignedBSS = try alignUp(withBSS, to: pageAlignment)
        let (nearStart, nearOverflow) = alignedBSS.addingReportingOverflow(pageAlignment)
        guard !nearOverflow else { throw NSOPatchLayoutError.arithmeticOverflow }
        let nearPatch = try alignUp(nearStart, to: patchAlignment)
        let far = nearPatch > nearLimit

        if !far {
            let keyPage = try alignUp(withBSS, to: pageAlignment)
            let (withKeyPage, keyOverflow) = keyPage.addingReportingOverflow(pageAlignment)
            guard !keyOverflow else { throw NSOPatchLayoutError.arithmeticOverflow }
            let patch = try alignUp(withKeyPage, to: patchAlignment)
            guard patch <= UInt64(Int64.max) else { throw NSOPatchLayoutError.arithmeticOverflow }
            return NSOPatchLayout(
                isFar: false,
                isBigText: false,
                textSize: textSize,
                bssSize: bss,
                fileImageLength: withKeyPage,
                keyPageOffset: keyPage,
                imageSize: withKeyPage,
                patchOffset: Int64(patch)
            )
        }

        let fileImageLength = try alignUp(dataEnd, to: pageAlignment)
        let keyPageInput = try adding(dataEnd, bss)
        let keyPage = try alignUp(keyPageInput, to: pageAlignment)
        let (imageSize, imageOverflow) = keyPage.addingReportingOverflow(pageAlignment)
        guard !imageOverflow else { throw NSOPatchLayoutError.arithmeticOverflow }

        guard textSize < Self.branchReach - Self.branchSafetyMargin else {
            throw NSOPatchLayoutError.frontPatchAreaTooLarge
        }
        let maximumFront = Self.branchReach - Self.branchSafetyMargin - textSize
        let isBigText = textSize + Self.defaultFront > Self.branchReach - Self.branchSafetyMargin
        let front: UInt64
        if let frontOverride {
            front = frontOverride
        } else if isBigText {
            front = maximumFront & ~(Self.patchAlignment - 1)
        } else {
            front = Self.defaultFront
        }
        guard front > 0, front <= maximumFront, front <= UInt64(Int64.max) else {
            throw NSOPatchLayoutError.frontPatchAreaTooLarge
        }

        return NSOPatchLayout(
            isFar: true,
            isBigText: isBigText,
            textSize: textSize,
            bssSize: bss,
            fileImageLength: fileImageLength,
            keyPageOffset: keyPage,
            imageSize: imageSize,
            patchOffset: -Int64(front)
        )
    }

    private static func adding(_ lhs: UInt64, _ rhs: UInt64) throws -> UInt64 {
        let (value, overflow) = lhs.addingReportingOverflow(rhs)
        guard !overflow else { throw NSOPatchLayoutError.arithmeticOverflow }
        return value
    }

    private static func alignUp(_ value: UInt64, to alignment: UInt64) throws -> UInt64 {
        let (sum, overflow) = value.addingReportingOverflow(alignment - 1)
        guard !overflow else { throw NSOPatchLayoutError.arithmeticOverflow }
        return sum & ~(alignment - 1)
    }
}
