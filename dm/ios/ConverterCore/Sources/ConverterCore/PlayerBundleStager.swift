import Foundation
import CryptoKit

public enum PlayerBundleStagerError: Error, Equatable, LocalizedError {
    case invalidTitleID
    case emptyDisplayName
    case invalidInput(String)
    case outputAlreadyExists
    case hostHashMismatch
    case missingPlayerExecutable
    case missingFrameworkExecutable
    case missingFrameworkInfoPlist
    case missingRewrittenModules
    case missingShaderFiles
    case emptyRomFS
    case emptyProfile
    case invalidManifest
    case bcFallbackRequired

    public var errorDescription: String? {
        switch self {
        case .invalidTitleID: return "The game title ID must be 16 hexadecimal characters."
        case .emptyDisplayName: return "The game display name cannot be empty."
        case .invalidInput(let value): return "A required player input is missing or invalid: \(value)."
        case .outputAlreadyExists: return "The player app output already exists."
        case .hostHashMismatch: return "The player host does not match the pinned host SHA-256."
        case .missingPlayerExecutable: return "The player template is missing its GameApp executable."
        case .missingFrameworkExecutable: return "The assembled DmGameProbe executable is missing."
        case .missingFrameworkInfoPlist: return "The assembled framework Info.plist is missing."
        case .missingRewrittenModules: return "The rewritten module directory is empty or incomplete."
        case .missingShaderFiles: return "The game's shader directory is empty."
        case .emptyRomFS: return "The complete RomFS.img is missing or empty."
        case .emptyProfile: return "The game's profile.tsv is missing or empty."
        case .invalidManifest: return "The player manifest is empty."
        case .bcFallbackRequired: return "The iPhone 14 player build must select the proven BC fallback."
        }
    }
}

/// All paths are local URLs. The host hash is pinned from the verified template/host provenance manifest,
/// not calculated from the template's signed copy.
public struct PlayerBundleStageRequest {
    public let templateAppURL: URL
    public let hostURL: URL
    public let expectedHostSHA256: String
    public let frameworkURL: URL
    public let rewrittenModulesURL: URL
    public let romFSURL: URL
    public let shadersURL: URL
    public let profileURL: URL
    public let playerManifest: Data
    public let titleID: String
    public let displayName: String
    public let outputAppURL: URL
    public let bcFallbackEnabled: Bool

    public init(
        templateAppURL: URL,
        hostURL: URL,
        expectedHostSHA256: String,
        frameworkURL: URL,
        rewrittenModulesURL: URL,
        romFSURL: URL,
        shadersURL: URL,
        profileURL: URL,
        playerManifest: Data,
        titleID: String,
        displayName: String,
        outputAppURL: URL,
        bcFallbackEnabled: Bool
    ) {
        self.templateAppURL = templateAppURL
        self.hostURL = hostURL
        self.expectedHostSHA256 = expectedHostSHA256.lowercased()
        self.frameworkURL = frameworkURL
        self.rewrittenModulesURL = rewrittenModulesURL
        self.romFSURL = romFSURL
        self.shadersURL = shadersURL
        self.profileURL = profileURL
        self.playerManifest = playerManifest
        self.titleID = titleID.lowercased()
        self.displayName = displayName
        self.outputAppURL = outputAppURL
        self.bcFallbackEnabled = bcFallbackEnabled
    }
}

public struct PlayerBundleStageResult {
    public let appURL: URL
    public let bundleIdentifier: String
    public let titleID: String
    public let copiedRomFSSize: UInt64
    public let hostSHA256: String
}

/// Stages the iBuilder-compatible full player app. This does not ZIP/sign an IPA and does not claim
/// that the selected host has passed an on-device BC runtime test.
public enum PlayerBundleStager {
    public static let playerExecutableName = "GameApp"
    public static let hostFileName = "host-prebuilt.dylib"
    public static let frameworkName = "DmGameProbe.framework"
    public static let frameworkExecutableName = "DmGameProbe"
    public static let exportedGameFolder = "ExportedGame"

    public static func stage(
        _ request: PlayerBundleStageRequest,
        fileManager: FileManager = .default
    ) throws -> PlayerBundleStageResult {
        try validate(request, fileManager: fileManager)

        let hostHash = try sha256(of: request.hostURL)
        guard hostHash == request.expectedHostSHA256 else {
            throw PlayerBundleStagerError.hostHashMismatch
        }

        let output = request.outputAppURL
        try fileManager.createDirectory(
            at: output.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try fileManager.copyItem(at: request.templateAppURL, to: output)

        do {
            try removeCodeSignatures(in: output, fileManager: fileManager)
            let oldGamePayload = output.appendingPathComponent(exportedGameFolder, isDirectory: true)
            if fileManager.fileExists(atPath: oldGamePayload.path) {
                try fileManager.removeItem(at: oldGamePayload)
            }
            let appInfoURL = output.appendingPathComponent("Info.plist")
            let appInfo = try readPropertyList(at: appInfoURL)
            let baseIdentifier = appInfo["CFBundleIdentifier"] as? String ?? "dev.ibuilder.app"
            let bundleIdentifier = exportBundleIdentifier(base: baseIdentifier, titleID: request.titleID)
            var updatedAppInfo = appInfo
            updatedAppInfo["CFBundleIdentifier"] = bundleIdentifier
            updatedAppInfo["CFBundleDisplayName"] = request.displayName
            updatedAppInfo["CFBundleName"] = String(request.displayName.prefix(15))
            try writePropertyList(updatedAppInfo, to: appInfoURL)

            let hostDestination = output.appendingPathComponent(hostFileName)
            if fileManager.fileExists(atPath: hostDestination.path) {
                try fileManager.removeItem(at: hostDestination)
            }
            try fileManager.copyItem(at: request.hostURL, to: hostDestination)

            let frameworkDestination = output
                .appendingPathComponent("Frameworks", isDirectory: true)
                .appendingPathComponent(frameworkName, isDirectory: true)
            if fileManager.fileExists(atPath: frameworkDestination.path) {
                try fileManager.removeItem(at: frameworkDestination)
            }
            try fileManager.createDirectory(
                at: frameworkDestination.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try fileManager.copyItem(at: request.frameworkURL, to: frameworkDestination)
            try removeCodeSignatures(in: frameworkDestination, fileManager: fileManager)

            let frameworkBinary = frameworkDestination.appendingPathComponent(frameworkExecutableName)
            guard fileManager.fileExists(atPath: frameworkBinary.path) else {
                throw PlayerBundleStagerError.missingFrameworkExecutable
            }
            let frameworkInfoURL = frameworkDestination.appendingPathComponent("Info.plist")
            guard fileManager.fileExists(atPath: frameworkInfoURL.path) else {
                throw PlayerBundleStagerError.missingFrameworkInfoPlist
            }
            var frameworkInfo = try readPropertyList(at: frameworkInfoURL)
            frameworkInfo["CFBundleExecutable"] = frameworkExecutableName
            frameworkInfo["CFBundleIdentifier"] = bundleIdentifier + ".DmGameProbe"
            frameworkInfo["CFBundleName"] = frameworkExecutableName
            frameworkInfo["CFBundlePackageType"] = "FMWK"
            frameworkInfo["CFBundleInfoDictionaryVersion"] = "6.0"
            frameworkInfo["CFBundleShortVersionString"] = "1.0"
            frameworkInfo["CFBundleVersion"] = "1"
            try writePropertyList(frameworkInfo, to: frameworkInfoURL)

            let gameRoot = output.appendingPathComponent(exportedGameFolder, isDirectory: true)
            let flatDestination = gameRoot.appendingPathComponent("extract/flat", isDirectory: true)
            let romfsDestination = gameRoot.appendingPathComponent("extract/RomFS.img")
            let shadersDestination = gameRoot.appendingPathComponent("shaders", isDirectory: true)
                .appendingPathComponent(request.titleID, isDirectory: true)
            let documentsDestination = gameRoot.appendingPathComponent("documents", isDirectory: true)
            try fileManager.createDirectory(
                at: flatDestination.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try fileManager.createDirectory(
                at: shadersDestination.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try fileManager.createDirectory(at: documentsDestination, withIntermediateDirectories: true)
            try fileManager.copyItem(at: request.rewrittenModulesURL, to: flatDestination)
            try fileManager.copyItem(at: request.romFSURL, to: romfsDestination)
            try fileManager.copyItem(at: request.shadersURL, to: shadersDestination)
            try fileManager.copyItem(
                at: request.profileURL,
                to: documentsDestination.appendingPathComponent("profile.tsv")
            )
            try request.playerManifest.write(
                to: gameRoot.appendingPathComponent("manifest.tsv"),
                options: [.atomic]
            )

            let stagedRomFSSize = try fileSize(romfsDestination)
            guard stagedRomFSSize > 0 else { throw PlayerBundleStagerError.emptyRomFS }
            return PlayerBundleStageResult(
                appURL: output,
                bundleIdentifier: bundleIdentifier,
                titleID: request.titleID,
                copiedRomFSSize: stagedRomFSSize,
                hostSHA256: hostHash
            )
        } catch {
            try? fileManager.removeItem(at: output)
            throw error
        }
    }

    private static func validate(
        _ request: PlayerBundleStageRequest,
        fileManager: FileManager
    ) throws {
        guard request.titleID.count == 16,
              request.titleID.allSatisfy({ $0.isHexDigit }) else {
            throw PlayerBundleStagerError.invalidTitleID
        }
        guard !request.displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw PlayerBundleStagerError.emptyDisplayName
        }
        guard request.bcFallbackEnabled else {
            throw PlayerBundleStagerError.bcFallbackRequired
        }
        guard request.playerManifest.count > 0 else {
            throw PlayerBundleStagerError.invalidManifest
        }
        guard request.expectedHostSHA256.count == 64,
              request.expectedHostSHA256.allSatisfy({ $0.isHexDigit }) else {
            throw PlayerBundleStagerError.invalidInput("expected host SHA-256")
        }
        guard request.templateAppURL.isFileURL,
              fileManager.fileExists(atPath: request.templateAppURL.appendingPathComponent(playerExecutableName).path),
              fileManager.fileExists(atPath: request.templateAppURL.appendingPathComponent("Info.plist").path),
              fileManager.fileExists(atPath: request.templateAppURL.appendingPathComponent(hostFileName).path) else {
            throw PlayerBundleStagerError.missingPlayerExecutable
        }
        guard request.hostURL.isFileURL,
              fileManager.fileExists(atPath: request.hostURL.path) else {
            throw PlayerBundleStagerError.invalidInput("host-prebuilt.dylib")
        }
        guard request.frameworkURL.isFileURL,
              fileManager.fileExists(atPath: request.frameworkURL.appendingPathComponent(frameworkExecutableName).path) else {
            throw PlayerBundleStagerError.missingFrameworkExecutable
        }
        guard fileManager.fileExists(atPath: request.frameworkURL.appendingPathComponent("Info.plist").path) else {
            throw PlayerBundleStagerError.missingFrameworkInfoPlist
        }
        guard request.rewrittenModulesURL.isFileURL,
              let modules = fileManager.enumerator(at: request.rewrittenModulesURL, includingPropertiesForKeys: nil),
              modules.allObjects.contains(where: { ($0 as? URL)?.lastPathComponent.hasSuffix(".patched.bin") == true }) else {
            throw PlayerBundleStagerError.missingRewrittenModules
        }
        guard request.romFSURL.isFileURL,
              ((try? fileSize(request.romFSURL)) ?? 0) > 0 else {
            throw PlayerBundleStagerError.emptyRomFS
        }
        guard request.shadersURL.isFileURL,
              let shaders = fileManager.enumerator(at: request.shadersURL, includingPropertiesForKeys: nil),
              !shaders.allObjects.isEmpty else {
            throw PlayerBundleStagerError.missingShaderFiles
        }
        guard request.profileURL.isFileURL,
              ((try? fileSize(request.profileURL)) ?? 0) > 0 else {
            throw PlayerBundleStagerError.emptyProfile
        }
        guard request.outputAppURL.isFileURL,
              !fileManager.fileExists(atPath: request.outputAppURL.path) else {
            throw PlayerBundleStagerError.outputAlreadyExists
        }
    }

    private static func removeCodeSignatures(
        in directory: URL,
        fileManager: FileManager
    ) throws {
        guard let enumerator = fileManager.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: []
        ) else { return }
        var removals: [URL] = []
        for case let url as URL in enumerator {
            if url.lastPathComponent == "_CodeSignature" {
                removals.append(url)
                enumerator.skipDescendants()
            }
        }
        for url in removals.sorted(by: { $0.path.count > $1.path.count }) {
            try fileManager.removeItem(at: url)
        }
    }

    private static func readPropertyList(at url: URL) throws -> [String: Any] {
        let data = try Data(contentsOf: url)
        guard let dictionary = try PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: nil
        ) as? [String: Any] else {
            throw PlayerBundleStagerError.invalidInput(url.lastPathComponent)
        }
        return dictionary
    }

    private static func writePropertyList(_ dictionary: [String: Any], to url: URL) throws {
        let data = try PropertyListSerialization.data(
            fromPropertyList: dictionary,
            format: .xml,
            options: 0
        )
        try data.write(to: url, options: [.atomic])
    }

    private static func exportBundleIdentifier(base: String, titleID: String) -> String {
        let safeBase = base.split(separator: ".")
            .map { component in
                String(component.filter { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") })
            }
            .filter { !$0.isEmpty }
            .joined(separator: ".")
        return (safeBase.isEmpty ? "dev.swapp.player" : safeBase) + ".g" + titleID
    }

    private static func sha256(of url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk = try handle.read(upToCount: 1 << 20) ?? Data()
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func fileSize(_ url: URL) throws -> UInt64 {
        let values = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
        guard values.isRegularFile == true, let size = values.fileSize else { return 0 }
        return UInt64(size)
    }
}
