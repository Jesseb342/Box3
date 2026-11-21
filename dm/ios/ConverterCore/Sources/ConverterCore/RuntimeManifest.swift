import Foundation
import CryptoKit

public enum RuntimeManifestError: Error, Equatable {
    case unsupportedSchemaVersion(Int)
    case invalidTitleID
    case emptyDisplayName
    case missingMainModule
    case duplicateModuleName(String)
    case duplicatePath(String)
    case invalidRelativePath(String)
    case invalidSHA256(String)
    case missingFile(String)
    case fileHashMismatch(String)
}

/// A portable, game-agnostic description of the runtime payload staged for an IPA.
/// Paths are relative to the manifest's containing directory.
public struct RuntimeManifest: Codable, Equatable {
    public struct Module: Codable, Equatable {
        public let name: String
        public let path: String
        public let sha256: String

        public init(name: String, path: String, sha256: String) {
            self.name = name
            self.path = path
            self.sha256 = sha256.lowercased()
        }
    }

    public struct Resource: Codable, Equatable {
        public let path: String
        public let sha256: String

        public init(path: String, sha256: String) {
            self.path = path
            self.sha256 = sha256.lowercased()
        }
    }

    public let schemaVersion: Int
    public let titleID: String
    public let displayName: String
    public let modules: [Module]
    public let resources: [Resource]
    public let bcFallbackEnabled: Bool

    public init(
        schemaVersion: Int = 1,
        titleID: String,
        displayName: String,
        modules: [Module],
        resources: [Resource] = [],
        bcFallbackEnabled: Bool
    ) {
        self.schemaVersion = schemaVersion
        self.titleID = titleID.lowercased()
        self.displayName = displayName
        self.modules = modules
        self.resources = resources
        self.bcFallbackEnabled = bcFallbackEnabled
    }

    public func validate() throws {
        guard schemaVersion == 1 else {
            throw RuntimeManifestError.unsupportedSchemaVersion(schemaVersion)
        }
        guard titleID.count == 16, titleID.allSatisfy({ $0.isHexDigit }) else {
            throw RuntimeManifestError.invalidTitleID
        }
        guard !displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw RuntimeManifestError.emptyDisplayName
        }
        guard modules.contains(where: { $0.name == "main" }) else {
            throw RuntimeManifestError.missingMainModule
        }

        var names = Set<String>()
        var paths = Set<String>()
        for module in modules {
            guard !module.name.isEmpty, names.insert(module.name).inserted else {
                throw RuntimeManifestError.duplicateModuleName(module.name)
            }
            try Self.validate(path: module.path, sha256: module.sha256)
            guard paths.insert(module.path).inserted else {
                throw RuntimeManifestError.duplicatePath(module.path)
            }
        }
        for resource in resources {
            try Self.validate(path: resource.path, sha256: resource.sha256)
            guard paths.insert(resource.path).inserted else {
                throw RuntimeManifestError.duplicatePath(resource.path)
            }
        }
    }

    /// Validates the manifest and verifies every staged payload file against its SHA-256.
    /// The resolved URL must remain inside the supplied root directory.
    public func verifyFiles(rootURL: URL, fileManager: FileManager = .default) throws {
        try validate()
        let root = rootURL.resolvingSymlinksInPath().standardizedFileURL
        let rootPrefix = root.path.hasSuffix("/") ? root.path : root.path + "/"

        let entries = modules.map { ($0.path, $0.sha256) } +
                      resources.map { ($0.path, $0.sha256) }
        for (relativePath, expectedHash) in entries {
            let candidate = root.appendingPathComponent(relativePath).resolvingSymlinksInPath().standardizedFileURL
            guard candidate.path.hasPrefix(rootPrefix) else {
                throw RuntimeManifestError.invalidRelativePath(relativePath)
            }
            guard fileManager.fileExists(atPath: candidate.path) else {
                throw RuntimeManifestError.missingFile(relativePath)
            }
            let data = try Data(contentsOf: candidate, options: [.mappedIfSafe])
            let actualHash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            guard actualHash == expectedHash else {
                throw RuntimeManifestError.fileHashMismatch(relativePath)
            }
        }
    }

    public func encoded(sortedKeys: Bool = true) throws -> Data {
        try validate()
        let encoder = JSONEncoder()
        if sortedKeys { encoder.outputFormatting = [.prettyPrinted, .sortedKeys] }
        return try encoder.encode(self)
    }

    public static func decode(_ data: Data) throws -> RuntimeManifest {
        let manifest = try JSONDecoder().decode(RuntimeManifest.self, from: data)
        try manifest.validate()
        return manifest
    }

    private static func validate(path: String, sha256: String) throws {
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !path.isEmpty,
              !path.hasPrefix("/"),
              !path.contains("\\"),
              !components.contains(""),
              !components.contains("."),
              !components.contains(".."),
              !path.hasPrefix("~") else {
            throw RuntimeManifestError.invalidRelativePath(path)
        }
        guard sha256.count == 64, sha256.allSatisfy({ $0.isHexDigit }) else {
            throw RuntimeManifestError.invalidSHA256(path)
        }
    }
}
