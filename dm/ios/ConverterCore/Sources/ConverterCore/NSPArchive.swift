import Foundation

public enum NSPArchiveError: Error, Equatable {
    case invalidURL
    case noNCAEntries
}

/// Unified game-package view. NSP uses PFS0; XCI uses its secure HFS0 partition.
public final class NSPArchive {
    private let pfs0: PFS0Archive?
    private let xci: XCIArchive?
    public let ncaEntries: [PFS0Archive.Entry]
    public let ticketData: [Data]

    public init(url: URL) throws {
        guard url.isFileURL else { throw NSPArchiveError.invalidURL }
        if url.pathExtension.lowercased() == "xci" {
            let archive = try XCIArchive(url: url)
            self.xci = archive
            self.pfs0 = nil
            self.ncaEntries = archive.ncaEntries
            self.ticketData = archive.ticketData
        } else {
            let archive = try PFS0Archive(url: url)
            self.pfs0 = archive
            self.xci = nil
            self.ncaEntries = archive.entries
                .filter { $0.name.lowercased().hasSuffix(".nca") }
                .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
            self.ticketData = try archive.entries
                .filter { $0.name.lowercased().hasSuffix(".tik") }
                .map { try archive.readEntryData(named: $0.name) }
        }
    }

    public func extractNCA(named name: String, to destinationURL: URL) throws {
        guard ncaEntries.contains(where: { $0.name == name }) else {
            throw PFS0Error.entryNotFound(name)
        }
        if let pfs0 {
            try pfs0.copyEntry(named: name, to: destinationURL)
        } else if let xci {
            try xci.extractNCA(named: name, to: destinationURL)
        } else {
            throw NSPArchiveError.invalidURL
        }
    }
}
