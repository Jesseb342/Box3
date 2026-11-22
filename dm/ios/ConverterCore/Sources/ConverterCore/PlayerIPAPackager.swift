import Foundation
import ZIPFoundation

public enum PlayerIPAPackagerError: Error, Equatable, LocalizedError {
    case invalidAppBundle
    case missingPlayerExecutable
    case missingFramework
    case missingHostRuntime
    case missingPlayerManifest
    case missingRomFS
    case missingProfile
    case missingShaders
    case invalidPlayerManifest
    case invalidBundleIdentity
    case keyMaterialFound(String)
    case profileTitleIDMismatch
    case outputAlreadyExists
    case invalidOutputURL
    case unsafeSymbolicLink(String)
    case unsupportedFileType(String)
    case emptyArchive

    public var errorDescription: String? {
        switch self {
        case .invalidAppBundle: return "The staged player app is missing or is not a directory."
        case .missingPlayerExecutable: return "The staged app is missing its GameApp executable."
        case .missingFramework: return "The staged app is missing DmGameProbe.framework."
        case .missingHostRuntime: return "The staged app is missing its host runtime library."
        case .missingPlayerManifest: return "The staged app is missing ExportedGame/manifest.tsv."
        case .missingRomFS: return "The complete RomFS.img is missing from the app bundle."
        case .missingProfile: return "The staged player profile is missing."
        case .missingShaders: return "The game's shader payload is missing."
        case .invalidPlayerManifest: return "The player manifest is missing required game identity fields."
        case .invalidBundleIdentity: return "The app and framework bundle identifiers do not match the game title ID."
        case .keyMaterialFound(let path): return "Refusing to package Switch key material: \\(path)."
        case .profileTitleIDMismatch: return "The profile and player manifest identify different games."
        case .outputAlreadyExists: return "The IPA output already exists."
        case .invalidOutputURL: return "The IPA output must be a local .ipa file URL."
        case .unsafeSymbolicLink(let path): return "The app contains a symbolic link that resolves outside the app: \(path)."
        case .unsupportedFileType(let path): return "The app contains an unsupported filesystem item: \(path)."
        case .emptyArchive: return "No app files were written to the IPA."
        }
    }
}

public struct PlayerIPAPackagingResult {
    public let ipaURL: URL
    public let entryCount: Int
    public let archiveSize: UInt64
    public let romFSSize: UInt64
    public let titleID: String
}

/// Creates one ZIP64-capable, deflated IPA with the complete player app and RomFS inside Payload.
/// This only packages a staged bundle; it does not sign it or establish runtime/BC compatibility.
public enum PlayerIPAPackager {
    public static func package(
        appURL: URL,
        outputIPAURL: URL,
        fileManager: FileManager = .default
    ) throws -> PlayerIPAPackagingResult {
        let facts = try validate(appURL: appURL, outputIPAURL: outputIPAURL, fileManager: fileManager)
        let temporaryURL = outputIPAURL
            .deletingLastPathComponent()
            .appendingPathComponent("." + outputIPAURL.lastPathComponent + ".partial")

        if fileManager.fileExists(atPath: temporaryURL.path) {
            try fileManager.removeItem(at: temporaryURL)
        }
        do {
            let count = try writeArchive(appURL: appURL, archiveURL: temporaryURL, fileManager: fileManager)
            guard count > 0 else { throw PlayerIPAPackagerError.emptyArchive }
            let archiveSize = try regularFileSize(temporaryURL)
            try fileManager.moveItem(at: temporaryURL, to: outputIPAURL)
            return PlayerIPAPackagingResult(
                ipaURL: outputIPAURL,
                entryCount: count,
                archiveSize: archiveSize,
                romFSSize: facts.romFSSize,
                titleID: facts.titleID
            )
        } catch {
            try? fileManager.removeItem(at: temporaryURL)
            throw error
        }
    }

    private struct ValidatedFacts {
        let titleID: String
        let romFSSize: UInt64
    }

    private static func validate(
        appURL: URL,
        outputIPAURL: URL,
        fileManager: FileManager
    ) throws -> ValidatedFacts {
        guard appURL.isFileURL,
              (try? appURL.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true else {
            throw PlayerIPAPackagerError.invalidAppBundle
        }
        guard outputIPAURL.isFileURL, outputIPAURL.pathExtension.lowercased() == "ipa" else {
            throw PlayerIPAPackagerError.invalidOutputURL
        }
        guard !fileManager.fileExists(atPath: outputIPAURL.path) else {
            throw PlayerIPAPackagerError.outputAlreadyExists
        }

        let player = appURL.appendingPathComponent("GameApp")
        guard isRegularFile(player) else { throw PlayerIPAPackagerError.missingPlayerExecutable }
        let info = appURL.appendingPathComponent("Info.plist")
        guard isRegularFile(info) else { throw PlayerIPAPackagerError.invalidAppBundle }
        let host = appURL.appendingPathComponent("host-prebuilt.dylib")
        guard isRegularFile(host) else { throw PlayerIPAPackagerError.missingHostRuntime }
        let framework = appURL.appendingPathComponent("Frameworks/DmGameProbe.framework/DmGameProbe")
        guard isRegularFile(framework) else { throw PlayerIPAPackagerError.missingFramework }

        let gameRoot = appURL.appendingPathComponent("ExportedGame", isDirectory: true)
        let manifestURL = gameRoot.appendingPathComponent("manifest.tsv")
        guard isRegularFile(manifestURL) else { throw PlayerIPAPackagerError.missingPlayerManifest }
        let manifest = parseTSV(try Data(contentsOf: manifestURL))
        let required = ["title_id", "dump", "name", "app_build", "exported"]
        guard required.allSatisfy({ !(manifest[$0] ?? "").isEmpty }),
              let titleID = manifest["title_id"]?.lowercased(),
              titleID.count == 16,
              titleID.allSatisfy({ $0.isHexDigit }) else {
            throw PlayerIPAPackagerError.invalidPlayerManifest
        }

        let appInfo = try PropertyListSerialization.propertyList(
            from: Data(contentsOf: info), options: [], format: nil
        ) as? [String: Any] ?? [:]
        let expectedBundleSuffix = ".g" + titleID
        guard let appBundleID = appInfo["CFBundleIdentifier"] as? String,
              appBundleID.hasSuffix(expectedBundleSuffix),
              appInfo["CFBundleDisplayName"] as? String == manifest["name"] else {
            throw PlayerIPAPackagerError.invalidBundleIdentity
        }
        let frameworkInfoURL = appURL.appendingPathComponent("Frameworks/DmGameProbe.framework/Info.plist")
        guard isRegularFile(frameworkInfoURL),
              let frameworkInfo = try PropertyListSerialization.propertyList(
                from: Data(contentsOf: frameworkInfoURL), options: [], format: nil
              ) as? [String: Any],
              frameworkInfo["CFBundleIdentifier"] as? String == appBundleID + ".DmGameProbe" else {
            throw PlayerIPAPackagerError.invalidBundleIdentity
        }

        let romFSURL = gameRoot.appendingPathComponent("extract/RomFS.img")
        let romFSSize = (try? regularFileSize(romFSURL)) ?? 0
        guard romFSSize > 0 else { throw PlayerIPAPackagerError.missingRomFS }

        let profileURL = gameRoot.appendingPathComponent("documents/profile.tsv")
        guard isRegularFile(profileURL) else { throw PlayerIPAPackagerError.missingProfile }
        let profile = parseTSV(try Data(contentsOf: profileURL))
        guard profile["title_id"]?.lowercased() == titleID else {
            throw PlayerIPAPackagerError.profileTitleIDMismatch
        }

        let shaderURL = gameRoot.appendingPathComponent("shaders/\(titleID)", isDirectory: true)
        guard (try? shaderURL.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true,
              let enumerator = fileManager.enumerator(at: shaderURL, includingPropertiesForKeys: [.isRegularFileKey]),
              enumerator.allObjects.contains(where: { url in
                  guard let file = url as? URL else { return false }
                  return isRegularFile(file)
              }) else {
            throw PlayerIPAPackagerError.missingShaders
        }

        return ValidatedFacts(titleID: titleID, romFSSize: romFSSize)
    }

    private static func writeArchive(
        appURL: URL,
        archiveURL: URL,
        fileManager: FileManager
    ) throws -> Int {
        let root = appURL.standardizedFileURL
        let rootPrefix = root.path.hasSuffix("/") ? root.path : root.path + "/"
        guard let enumerator = fileManager.enumerator(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey],
            options: []
        ) else {
            throw PlayerIPAPackagerError.invalidAppBundle
        }

        var files: [(URL, String)] = []
        for case let url as URL in enumerator {
            let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey])
            if values.isDirectory == true { continue }
            let lowerName = url.lastPathComponent.lowercased()
            if lowerName == "prod.keys" || lowerName == "title.keys" {
                throw PlayerIPAPackagerError.keyMaterialFound(url.lastPathComponent)
            }
            let relative = String(url.standardizedFileURL.path.dropFirst(rootPrefix.count))
            guard !relative.isEmpty, !relative.hasPrefix("../"), !relative.contains("/../") else {
                throw PlayerIPAPackagerError.unsupportedFileType(url.path)
            }
            if values.isSymbolicLink == true {
                let resolved = url.resolvingSymlinksInPath().standardizedFileURL.path
                guard resolved == root.path || resolved.hasPrefix(rootPrefix) else {
                    throw PlayerIPAPackagerError.unsafeSymbolicLink(url.path)
                }
            } else if values.isRegularFile != true {
                throw PlayerIPAPackagerError.unsupportedFileType(url.path)
            }
            files.append((url, "Payload/\(root.lastPathComponent)/\(relative)"))
        }
        files.sort { $0.1 < $1.1 }

        let archive = try Archive(url: archiveURL, accessMode: .create)
        for (fileURL, entryPath) in files {
            try archive.addEntry(
                with: entryPath,
                fileURL: fileURL,
                compressionMethod: .deflate,
                bufferSize: 1 << 20
            )
        }
        return files.count
    }

    private static func parseTSV(_ data: Data) -> [String: String] {
        guard let text = String(data: data, encoding: .utf8) else { return [:] }
        var values: [String: String] = [:]
        for line in text.split(whereSeparator: { $0.isNewline }) {
            let parts = line.split(separator: "\t", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            values[String(parts[0])] = String(parts[1])
        }
        return values
    }

    private static func isRegularFile(_ url: URL) -> Bool {
        (try? url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true
    }

    private static func regularFileSize(_ url: URL) throws -> UInt64 {
        let values = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
        guard values.isRegularFile == true, let size = values.fileSize else {
            throw PlayerIPAPackagerError.missingRomFS
        }
        return UInt64(size)
    }
}
