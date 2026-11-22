import Foundation
import Box3NSOBridge

public struct RustNSORewrite {
    public let image: Data
    public let patch: Data
    public let padTo: Int
    public let fixups: String
    public let gates: String
    public let sites: String
    public let cuts: String
    public let changed: String
    public let observations: String

    /// Reconstructs the on-disk patched module: image, zero padding to padTo, then patch bytes.
    /// This is an NSO-stage artifact, not an NCA/NSP or IPA.
    public func makePatchedData() throws -> Data {
        guard padTo >= image.count, patch.count <= Int.max - padTo else {
            throw RustNSORewriterError.invalidOutput
        }
        var output = image
        if padTo > output.count {
            output.append(Data(repeating: 0, count: padTo - output.count))
        }
        output.append(patch)
        return output
    }
}

public enum RustNSORewriterError: Error, LocalizedError {
    case rejected(String)
    case invalidOutput
    public var errorDescription: String? {
        switch self { case .rejected(let message): return message; case .invalidOutput: return "The Rust NSO rewriter returned invalid output." }
    }
}

/// Calls the pinned iBuilder rewriter through Box3's narrow C ABI. It returns staged bytes and metadata only;
/// it does not assemble a Mach-O executable or package an IPA.
public enum RustNSORewriter {
    public static func rewrite(_ data: Data, moduleName: String, gameProfile: String? = nil, gamesDirectory: URL? = nil) throws -> RustNSORewrite {
        guard !data.isEmpty, !moduleName.isEmpty else { throw RustNSORewriterError.rejected("NSO data and module name are required.") }
        var handle: OpaquePointer?
        var error = [CChar](repeating: 0, count: 2048)
        let status = data.withUnsafeBytes { input in
            error.withUnsafeMutableBufferPointer { err in
                moduleName.withCString { name in
                    let invoke: (UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> Int32 = { profile, directory in
                        box3_rewrite_nso(input.bindMemory(to: UInt8.self).baseAddress, input.count, name, profile, directory, &handle, err.baseAddress, err.count)
                    }
                    if let gamesDirectory {
                        guard gamesDirectory.isFileURL else { return 1 }
                        return gamesDirectory.path.withCString { directory in
                            if let gameProfile {
                                return gameProfile.withCString { profile in invoke(profile, directory) }
                            }
                            return invoke(nil, directory)
                        }
                    }
                    if let gameProfile {
                        return gameProfile.withCString { profile in invoke(profile, nil) }
                    }
                    return invoke(nil, nil)
                }
            }
        }
        guard status == 0, let result = handle else { throw RustNSORewriterError.rejected(String(cString: error)) }
        defer { box3_rewrite_free(result) }
        func dataField(_ getter: (OpaquePointer?, UnsafeMutablePointer<Int>?) -> UnsafePointer<UInt8>?) throws -> Data {
            var length = 0
            guard let pointer = getter(result, &length), length >= 0 else { throw RustNSORewriterError.invalidOutput }
            return Data(bytes: pointer, count: length)
        }
        func stringField(_ getter: (OpaquePointer?, UnsafeMutablePointer<Int>?) -> UnsafePointer<UInt8>?) throws -> String {
            guard let value = String(data: try dataField(getter), encoding: .utf8) else { throw RustNSORewriterError.invalidOutput }
            return value
        }
        let image = try dataField(box3_rewrite_image)
        let patch = try dataField(box3_rewrite_patch)
        let fixups = try stringField(box3_rewrite_fixups)
        let gates = try stringField(box3_rewrite_gates)
        let sites = try stringField(box3_rewrite_sites)
        let cuts = try stringField(box3_rewrite_cuts)
        let changed = try stringField(box3_rewrite_changed)
        let observations = try stringField(box3_rewrite_obs)
        let padTo = box3_rewrite_pad_to(result)
        guard !image.isEmpty, padTo >= image.count else { throw RustNSORewriterError.invalidOutput }
        return RustNSORewrite(image: image, patch: patch, padTo: padTo, fixups: fixups, gates: gates, sites: sites, cuts: cuts, changed: changed, observations: observations)
    }
}
