import Foundation

/// The result of the pinned Rust/iBuilder NSO rewriter, paired with the parsed source module.
/// This is deliberately separate from the experimental Swift code-range planner.
public struct RustNSORewritePipelineResult {
    public let module: NSOImage
    public let rewrite: RustNSORewrite

    /// Fully padded patched module bytes expected by the downstream Mach-O assembly stage.
    public func makePatchedData() throws -> Data {
        try rewrite.makePatchedData()
    }
}

public enum RustNSORewritePipeline {
    /// Runs the iBuilder rewrite engine against one already-decrypted NSO module.
    /// moduleName should be canonical (normally main, rtld, sdk, or subsdk*).
    /// gameProfile is optional; built-in build-ID patches remain available without it.
    public static func process(
        file: Data,
        moduleName: String,
        gameProfile: String? = nil,
        gamesDirectory: URL? = nil
    ) throws -> RustNSORewritePipelineResult {
        let module = try NSOImage(data: file)
        let rewrite = try RustNSORewriter.rewrite(file, moduleName: moduleName, gameProfile: gameProfile, gamesDirectory: gamesDirectory)
        let requiredImageSize = module.segments.map { Int($0.memoryOffset) + Int($0.memorySize) }.max() ?? 0
        guard rewrite.image.count >= requiredImageSize else {
            throw RustNSORewriterError.invalidOutput
        }
        _ = try rewrite.makePatchedData()
        return RustNSORewritePipelineResult(module: module, rewrite: rewrite)
    }
}
