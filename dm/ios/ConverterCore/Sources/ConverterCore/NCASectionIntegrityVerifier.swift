import Foundation

public enum NCASectionIntegrityVerifierError: Error, Equatable {
    case unsupportedFileSystemType
    case unsupportedHashType
}

/// Bridges a parsed, hash-verified NCA filesystem header to the streaming
/// hierarchical-SHA256 verifier. Only PFS0/PartitionFS with hierarchical
/// SHA-256 is accepted; other layouts fail closed.
public enum NCASectionIntegrityVerifier {
    public static func verify(
        decryptedSectionURL: URL,
        sectionSize: UInt64,
        fileSystemHeader: NCAFileSystemHeader
    ) throws -> NCAHierarchicalSHA256Verifier.Result {
        guard fileSystemHeader.fileSystemType == .partitionFS else {
            throw NCASectionIntegrityVerifierError.unsupportedFileSystemType
        }
        guard fileSystemHeader.hashType == .hierarchicalSHA256 else {
            throw NCASectionIntegrityVerifierError.unsupportedHashType
        }
        let superblock = try fileSystemHeader.partitionFSSuperblock(sectionSize: sectionSize)
        return try NCAHierarchicalSHA256Verifier.verify(
            decryptedSectionURL: decryptedSectionURL,
            sectionSize: sectionSize,
            superblock: superblock
        )
    }
}
