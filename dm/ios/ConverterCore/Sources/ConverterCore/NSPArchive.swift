import Foundation

public enum NSPArchiveError: Error, Equatable {
    case invalidURL
    case noNCAEntries
}

/// Bounded PFS0 view of an NSP package. NCA payloads remain on disk and are copied
/// only when requested; this avoids loading large game packages into memory.
public final class NSPArchive {
    private let archive: PFS0Archive
    public let ncaEntries: [PFS0Archive.Entry]
    public let ticketData: [Data]

    public init(url: URL) throws {
        guard url.isFileURL else { throw NSPArchiveError.invalidURL }
        let archive = try PFS0Archive(url: url)
        self.archive = archive
        self.ncaEntries = archive.entries
            .filter { $0.name.lowercased().hasSuffix(".nca") }
            .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        self.ticketData = try archive.entries
            .filter { $0.name.lowercased().hasSuffix(".tik") }
            .map { try archive.readEntryData(named: $0.name) }
    }

    public func extractNCA(named name: String, to destinationURL: URL) throws {
        guard ncaEntries.contains(where: { $0.name == name }) else {
            throw PFS0Error.entryNotFound(name)
        }
        try archive.copyEntry(named: name, to: destinationURL)
    }
}
