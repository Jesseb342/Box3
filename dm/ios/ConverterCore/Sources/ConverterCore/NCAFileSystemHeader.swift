import Foundation
import CryptoKit

public enum NCAFileSystemHeaderError: Error, Equatable {
    case invalidHeaderLength(Int)
    case invalidSectionIndex(Int)
    case invalidHeaderHashLength(Int)
    case headerHashMismatch(Int)
    case unsupportedVersion(UInt16)
    case unsupportedFileSystemType(UInt8)
    case unsupportedHashType(UInt8)
    case unsupportedEncryptionType(UInt8)
    case unsupportedMetadataHashType(UInt8)
}

/// Parsed, hash-verified 0x200-byte NCA3 filesystem header.
///
/// The 0x100-byte extension and final 0xC0 bytes are retained as opaque data:
/// BKTR, sparse-storage, and version-specific fields are not interpreted here.
public struct NCAFileSystemHeader: Equatable {
    public enum FileSystemType: UInt8, Equatable {
        case romFS = 0
        case partitionFS = 1
    }

    public enum HashType: UInt8, Equatable {
        case automatic = 0
        case none = 1
        case hierarchicalSHA256 = 2
        case hierarchicalIntegrity = 3
        case automaticSHA3 = 4
        case hierarchicalSHA3_256 = 5
        case hierarchicalIntegritySHA3 = 6
    }

    public enum EncryptionType: UInt8, Equatable {
        case automatic = 0
        case none = 1
        case aesXTS = 2
        case aesCTR = 3
        case aesCTREx = 4
        case aesCTRSkipLayerHash = 5
        case aesCTRExSkipLayerHash = 6
    }

    public let sectionIndex: Int
    public let version: UInt16
    public let fileSystemType: FileSystemType
    public let hashType: HashType
    public let encryptionType: EncryptionType
    public let metadataHashType: UInt8
    public let hashData: Data
    public let extensionData: Data
    /// Eight-byte section CTR seed stored at FS-header offset 0x140.
    public let sectionCounter: Data
    public let trailingData: Data

    /// Interprets the hierarchical-SHA256 hash data for a PFS0 section.
    /// Region offsets are relative to the start of this NCA section.
    public func partitionFSSuperblock(sectionSize: UInt64) throws -> NCAHierarchicalSHA256Superblock {
        guard fileSystemType == .partitionFS, hashType == .hierarchicalSHA256 else {
            throw NCAHierarchicalSHA256SuperblockError.invalidHashDataLength(0)
        }
        return try NCAHierarchicalSHA256Superblock(hashData: hashData, sectionSize: sectionSize)
    }

    /// Parses one section header from the already-decrypted 0xC00-byte NCA3
    /// header. The section index selects both its 0x200-byte FS header and the
    /// corresponding SHA-256 digest in the NCA header.
    public init(decryptedNCAHeader data: Data, sectionIndex: Int, expectedHash: Data) throws {
        guard (0..<4).contains(sectionIndex) else {
            throw NCAFileSystemHeaderError.invalidSectionIndex(sectionIndex)
        }
        guard data.count >= 0xC00 else {
            throw NCAFileSystemHeaderError.invalidHeaderLength(data.count)
        }
        guard expectedHash.count == 0x20 else {
            throw NCAFileSystemHeaderError.invalidHeaderHashLength(expectedHash.count)
        }

        let offset = 0x400 + sectionIndex * 0x200
        let raw = data.subdata(in: offset..<(offset + 0x200))
        let digest = Data(SHA256.hash(data: raw))
        guard digest == expectedHash else {
            throw NCAFileSystemHeaderError.headerHashMismatch(sectionIndex)
        }

        let version = UInt16(raw[0]) | (UInt16(raw[1]) << 8)
        guard version == 2 else {
            throw NCAFileSystemHeaderError.unsupportedVersion(version)
        }
        guard let fileSystemType = FileSystemType(rawValue: raw[2]) else {
            throw NCAFileSystemHeaderError.unsupportedFileSystemType(raw[2])
        }
        guard let hashType = HashType(rawValue: raw[3]) else {
            throw NCAFileSystemHeaderError.unsupportedHashType(raw[3])
        }
        guard let encryptionType = EncryptionType(rawValue: raw[4]) else {
            throw NCAFileSystemHeaderError.unsupportedEncryptionType(raw[4])
        }
        guard raw[5] <= 1 else {
            throw NCAFileSystemHeaderError.unsupportedMetadataHashType(raw[5])
        }

        self.sectionIndex = sectionIndex
        self.version = version
        self.fileSystemType = fileSystemType
        self.hashType = hashType
        self.encryptionType = encryptionType
        self.metadataHashType = raw[5]
        self.hashData = raw.subdata(in: 0x8..<0x100)
        self.extensionData = raw.subdata(in: 0x100..<0x140)
        self.sectionCounter = raw.subdata(in: 0x140..<0x148)
        self.trailingData = raw.subdata(in: 0x148..<0x200)
    }
}
