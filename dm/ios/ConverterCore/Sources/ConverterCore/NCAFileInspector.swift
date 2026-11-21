import Foundation

public enum NCAFileInspectorError: Error, Equatable {
    case fileTooSmall(UInt64)
    case missingHeaderKey
    case invalidHeaderKeyLength(Int)
    case unsupportedHeaderVersion(String)
}

/// Validated metadata from an NCA whose encrypted header was read from disk.
///
/// This deliberately inspects only the fixed 0xC00-byte header. It does not
/// decrypt section payloads or infer title-key / key-area material.
public struct NCAFileInspection {
    public let header: NCAHeader
    public let fileSize: UInt64
    /// Decrypted fixed-size NCA header, retained so validated section FS headers
    /// can be parsed without reading or decrypting section payloads.
    public let decryptedHeader: Data

    public init(header: NCAHeader, fileSize: UInt64, decryptedHeader: Data) {
        self.header = header
        self.fileSize = fileSize
        self.decryptedHeader = decryptedHeader
    }

    public func fileSystemHeader(for section: NCAHeader.Section) throws -> NCAFileSystemHeader {
        guard header.sections.contains(where: { $0.index == section.index }) else {
            throw NCAFileSystemHeaderError.invalidSectionIndex(section.index)
        }
        return try NCAFileSystemHeader(
            decryptedNCAHeader: decryptedHeader,
            sectionIndex: section.index,
            expectedHash: header.sectionHeaderHashes[section.index]
        )
    }
}

public enum NCAFileInspector {
    public static let encryptedHeaderSize: UInt64 = 0xC00
    public static let headerKeyName = "header_key"

    /// Reads, decrypts, and validates an NCA3 header without loading its payload.
    ///
    /// NCA2 uses a different XTS tweak convention for the four section headers;
    /// it is rejected here rather than silently applying the NCA3 convention.
    public static func inspect(url: URL, keys: ProdKeys) throws -> NCAFileInspection {
        guard let headerKey = keys.value(for: headerKeyName) else {
            throw NCAFileInspectorError.missingHeaderKey
        }
        guard headerKey.count == 32 else {
            throw NCAFileInspectorError.invalidHeaderKeyLength(headerKey.count)
        }

        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }

        let fileSize = try handle.seekToEnd()
        guard fileSize >= encryptedHeaderSize else {
            throw NCAFileInspectorError.fileTooSmall(fileSize)
        }

        try handle.seek(toOffset: 0)
        guard let encryptedHeader = try handle.read(upToCount: Int(encryptedHeaderSize)),
              encryptedHeader.count == Int(encryptedHeaderSize) else {
            throw NCAFileInspectorError.fileTooSmall(fileSize)
        }

        let plaintext = try AESXTS.decryptNCAHeader(encryptedHeader, headerKey: headerKey)
        let header = try NCAHeader(plaintextHeader: plaintext, actualFileSize: fileSize)
        guard header.magic == "NCA3" else {
            throw NCAFileInspectorError.unsupportedHeaderVersion(header.magic)
        }
        return NCAFileInspection(header: header, fileSize: fileSize, decryptedHeader: plaintext)
    }
}
