import Foundation

public enum NSOMachOAssemblyPipelineError: Error, LocalizedError, Equatable {
    case invalidHost
    case invalidModuleDirectory
    case invalidOutputURL
    case outputAlreadyExists
    case noModules
    case invalidModuleName(String)
    case duplicateModuleName(String)
    case missingPatchedModule(String)
    case missingFixups(String)
    case missingGates(String)

    public var errorDescription: String? {
        switch self {
        case .invalidHost: return "The iOS host dylib is missing or is not a local file."
        case .invalidModuleDirectory: return "The rewritten module directory is missing or is not a directory."
        case .invalidOutputURL: return "The framework output must be a local file URL."
        case .outputAlreadyExists: return "The framework output already exists."
        case .noModules: return "No rewritten modules were selected for assembly."
        case .invalidModuleName(let name): return "Invalid rewritten module name: \(name)."
        case .duplicateModuleName(let name): return "The module list contains a duplicate: \(name)."
        case .missingPatchedModule(let name): return "Missing \(name).patched.bin."
        case .missingFixups(let name): return "Missing \(name).fixups.tsv."
        case .missingGates(let name): return "Missing \\(name).gates.tsv; the iBuilder runtime requires its gate table."
        }
    }
}

public struct NSOMachOAssemblyResult {
    public let frameworkURL: URL
    public let size: UInt64
    public let modules: [String]
}

/// Converts an iBuilder-rewritten module set into one loadable framework dylib
/// using the verified iOS host. This is a framework stage, not an IPA packager:
/// the player app, shader library, RomFS, and other runtime resources are staged later.
public enum NSOMachOAssemblyPipeline {
    public static func assemble(
        hostURL: URL,
        rewrittenModulesDirectory: URL,
        modules: [String],
        outputURL: URL,
        tag: String = ""
    ) throws -> NSOMachOAssemblyResult {
        let normalized = try validateInputs(
            hostURL: hostURL,
            rewrittenModulesDirectory: rewrittenModulesDirectory,
            modules: modules,
            outputURL: outputURL
        )
        let parent = outputURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        let assembly = try MachOFrameworkAssembler.assemble(
            hostURL: hostURL,
            outputURL: outputURL,
            rewrittenModulesDirectory: rewrittenModulesDirectory,
            modules: normalized,
            tag: tag
        )
        return NSOMachOAssemblyResult(
            frameworkURL: assembly.outputURL,
            size: assembly.size,
            modules: normalized
        )
    }

    /// Separates filesystem/input validation from the native assembler so it can be
    /// tested without shipping a host binary or proprietary game files in CI.
    static func validateInputs(
        hostURL: URL,
        rewrittenModulesDirectory: URL,
        modules: [String],
        outputURL: URL
    ) throws -> [String] {
        let manager = FileManager.default
        guard hostURL.isFileURL,
              manager.fileExists(atPath: hostURL.path),
              (try? hostURL.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else {
            throw NSOMachOAssemblyPipelineError.invalidHost
        }
        guard rewrittenModulesDirectory.isFileURL,
              (try? rewrittenModulesDirectory.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true else {
            throw NSOMachOAssemblyPipelineError.invalidModuleDirectory
        }
        guard outputURL.isFileURL else { throw NSOMachOAssemblyPipelineError.invalidOutputURL }
        guard !manager.fileExists(atPath: outputURL.path) else {
            throw NSOMachOAssemblyPipelineError.outputAlreadyExists
        }
        guard !modules.isEmpty else { throw NSOMachOAssemblyPipelineError.noModules }

        var seen = Set<String>()
        for name in modules {
            guard !name.isEmpty,
                  name.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "-") }) else {
                throw NSOMachOAssemblyPipelineError.invalidModuleName(name)
            }
            guard seen.insert(name).inserted else {
                throw NSOMachOAssemblyPipelineError.duplicateModuleName(name)
            }
            let patched = rewrittenModulesDirectory.appendingPathComponent("\(name).patched.bin")
            guard manager.fileExists(atPath: patched.path),
                  (try? patched.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else {
                throw NSOMachOAssemblyPipelineError.missingPatchedModule(name)
            }
            let fixups = rewrittenModulesDirectory.appendingPathComponent("\(name).fixups.tsv")
            guard manager.fileExists(atPath: fixups.path),
                  (try? fixups.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else {
                throw NSOMachOAssemblyPipelineError.missingFixups(name)
            }
            let gates = rewrittenModulesDirectory.appendingPathComponent("\(name).gates.tsv")
            guard manager.fileExists(atPath: gates.path),
                  (try? gates.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else {
                throw NSOMachOAssemblyPipelineError.missingGates(name)
            }
        }
        return modules
    }
}
