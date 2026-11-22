import Foundation

public enum NSOGameModuleBatchProcessorError: Error, Equatable {
    case invalidSourceDirectory
    case invalidOutputDirectory
    case outputInsideSourceDirectory
    case noRecognizedModules
    case duplicateModuleName(String)
    case moduleTooLarge(String, UInt64)
    case unreadableModule(String)
    case couldNotCreateStagingDirectory
}

public struct NSORewriteBatchModuleSummary: Codable, Equatable {
    public let moduleName: String
    public let sourceFileName: String
    public let buildID: String
    public let sourceBytes: UInt64
    public let patchedBytes: UInt64
    public let patchBytes: UInt64
    public let padTo: UInt64
}

public struct NSOGameModuleBatchResult {
    public let outputDirectory: URL
    public let modules: [NSORewriteBatchModuleSummary]
}

/// Rewrites the recognized executable NSO files from an already integrity-verified ExeFS extraction.
/// Non-module files (NPDM, icons, etc.) are deliberately left untouched in the source directory.
public enum NSORewriteBatchProcessor {
    public static let defaultMaximumModuleSize: UInt64 = 512 * 1024 * 1024

    public static func process(
        exefsDirectory: URL,
        outputDirectory: URL,
        gameProfile: String? = nil,
        gamesDirectory: URL? = nil,
        maximumModuleSize: UInt64 = defaultMaximumModuleSize
    ) throws -> NSOGameModuleBatchResult {
        let manager = FileManager.default
        guard exefsDirectory.isFileURL,
              (try? exefsDirectory.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true else {
            throw NSOGameModuleBatchProcessorError.invalidSourceDirectory
        }
        guard outputDirectory.isFileURL else { throw NSOGameModuleBatchProcessorError.invalidOutputDirectory }
        let sourcePath = exefsDirectory.standardizedFileURL.path
        let outputPath = outputDirectory.standardizedFileURL.path
        guard outputPath != sourcePath, !outputPath.hasPrefix(sourcePath + "/") else {
            throw NSOGameModuleBatchProcessorError.outputInsideSourceDirectory
        }
        guard !manager.fileExists(atPath: outputDirectory.path) else {
            throw NSOGameModuleBatchProcessorError.invalidOutputDirectory
        }

        let candidates = try manager.contentsOfDirectory(
            at: exefsDirectory,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey],
            options: [.skipsHiddenFiles]
        ).sorted { $0.lastPathComponent < $1.lastPathComponent }

        var selected: [(URL, String, UInt64)] = []
        var names = Set<String>()
        for url in candidates {
            guard let name = canonicalModuleName(url.lastPathComponent) else { continue }
            let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true,
                  let size = values.fileSize, size > 0 else {
                throw NSOGameModuleBatchProcessorError.unreadableModule(url.lastPathComponent)
            }
            guard UInt64(size) <= maximumModuleSize else {
                throw NSOGameModuleBatchProcessorError.moduleTooLarge(url.lastPathComponent, UInt64(size))
            }
            guard names.insert(name).inserted else {
                throw NSOGameModuleBatchProcessorError.duplicateModuleName(name)
            }
            selected.append((url, name, UInt64(size)))
        }
        guard !selected.isEmpty else { throw NSOGameModuleBatchProcessorError.noRecognizedModules }

        if let gamesDirectory, !gamesDirectory.isFileURL {
            throw NSOGameModuleBatchProcessorError.invalidSourceDirectory
        }
        let parent = outputDirectory.deletingLastPathComponent()
        try manager.createDirectory(at: parent, withIntermediateDirectories: true)
        let staging = parent.appendingPathComponent(
            ".\(outputDirectory.lastPathComponent).rewrite-\(UUID().uuidString)",
            isDirectory: true
        )
        do {
            try manager.createDirectory(at: staging, withIntermediateDirectories: false)
        } catch {
            throw NSOGameModuleBatchProcessorError.couldNotCreateStagingDirectory
        }

        do {
            let modulesURL = staging.appendingPathComponent("modules", isDirectory: true)
            let reportsURL = staging.appendingPathComponent("reports", isDirectory: true)
            try manager.createDirectory(at: modulesURL, withIntermediateDirectories: true)
            try manager.createDirectory(at: reportsURL, withIntermediateDirectories: true)
            var summaries: [NSORewriteBatchModuleSummary] = []
            for (source, name, sourceSize) in selected {
                let input = try Data(contentsOf: source, options: [.mappedIfSafe])
                let output = try RustNSORewritePipeline.process(
                    file: input,
                    moduleName: name,
                    gameProfile: gameProfile,
                    gamesDirectory: gamesDirectory
                )
                let patched = try output.makePatchedData()
                try patched.write(to: modulesURL.appendingPathComponent("\(name).patched.bin"), options: [.atomic])
                let reportRows: [(String, String)] = [
                    ("fixups.tsv", output.rewrite.fixups),
                    ("gates.tsv", output.rewrite.gates),
                    ("sites.tsv", output.rewrite.sites),
                    ("cuts.tsv", output.rewrite.cuts),
                    ("changed.tsv", output.rewrite.changed),
                    ("obs.tsv", output.rewrite.observations)
                ]
                // iBuilder's assembler and runtime consume the per-module tables beside the
                // patched image. Keep a second reports/ copy for diagnostics/export.
                for (suffix, contents) in reportRows {
                    let data = Data(contents.utf8)
                    try data.write(to: modulesURL.appendingPathComponent("\(name).\(suffix)"), options: [.atomic])
                    try data.write(to: reportsURL.appendingPathComponent("\(name).\(suffix)"), options: [.atomic])
                }
                summaries.append(NSORewriteBatchModuleSummary(
                    moduleName: name,
                    sourceFileName: source.lastPathComponent,
                    buildID: output.module.buildIDHex,
                    sourceBytes: sourceSize,
                    patchedBytes: UInt64(patched.count),
                    patchBytes: UInt64(output.rewrite.patch.count),
                    padTo: UInt64(output.rewrite.padTo)
                ))
            }
            let manifest = try JSONEncoder.box3Manifest.encode(summaries)
            try manifest.write(to: staging.appendingPathComponent("manifest.json"), options: [.atomic])
            try manager.moveItem(at: staging, to: outputDirectory)
            return NSOGameModuleBatchResult(outputDirectory: outputDirectory, modules: summaries)
        } catch {
            try? manager.removeItem(at: staging)
            throw error
        }
    }

    private static func canonicalModuleName(_ filename: String) -> String? {
        let lowered = filename.lowercased()
        let base = lowered.hasSuffix(".nso") ? String(lowered.dropLast(4)) : lowered
        if ["main", "rtld", "sdk"].contains(base) { return base }
        if base.hasPrefix("subsdk"), base.count > 6,
           base.dropFirst(6).allSatisfy(\.isNumber) { return base }
        return nil
    }
}

private extension JSONEncoder {
    static var box3Manifest: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }
}
