import Foundation

public enum XCIArchiveError: Error, Equatable {
    case invalidURL
    case invalidHeader
    case missingSecurePartition
}

/// Opens the secure HFS0 partition of an XCI game-card image.
public final class XCIArchive {
    private let secure: HFS0Archive
    public let ncaEntries: [PFS0Archive.Entry]
    public let ticketData: [Data]

    public init(url: URL) throws {
        guard url.isFileURL else { throw XCIArchiveError.invalidURL }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let fileSize = try handle.seekToEnd()
        guard fileSize >= 0x200 else { throw XCIArchiveError.invalidHeader }
        try handle.seek(toOffset: 0x100)
        guard try handle.read(upToCount: 4) == Data("HEAD".utf8) else {
            throw XCIArchiveError.invalidHeader
        }
        try handle.seek(toOffset: 0x130)
        let rawOffset = try handle.read(upToCount: 8) ?? Data()
        guard rawOffset.count == 8 else { throw XCIArchiveError.invalidHeader }
        let pageAddress = Self.u64(rawOffset)
        let scaled = pageAddress.multipliedReportingOverflow(by: 0x200)
        guard !scaled.overflow else { throw XCIArchiveError.invalidHeader }
        let partitionOffset = pageAddress == 0 ? UInt64(0x10000) : scaled.partialValue
        guard partitionOffset < fileSize else { throw XCIArchiveError.invalidHeader }

        let root = try HFS0Archive(url: url, offset: partitionOffset, size: fileSize - partitionOffset)
        guard let secureEntry = root.entries.first(where: { $0.name == "secure" }) else {
            throw XCIArchiveError.missingSecurePartition
        }
        let secureArchive = try root.openNestedArchive(named: secureEntry.name)
        let entries = secureArchive.entries
        let programs = entries
            .filter { $0.name.lowercased().hasSuffix(".nca") }
            .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        let tickets = try entries
            .filter { $0.name.lowercased().hasSuffix(".tik") }
            .map { try secureArchive.readEntryData(named: $0.name) }

        self.secure = secureArchive
        self.ncaEntries = programs
        self.ticketData = tickets
    }

    public func extractNCA(named name: String, to destinationURL: URL) throws {
        guard ncaEntries.contains(where: { $0.name == name }) else {
            throw HFS0Error.entryNotFound(name)
        }
        try secure.copyEntry(named: name, to: destinationURL)
    }

    private static func u64(_ data: Data) -> UInt64 {
        (0..<8).reduce(UInt64(0)) { $0 | (UInt64(data[$1]) << (UInt64($1) * 8)) }
    }
}
