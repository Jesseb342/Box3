import Foundation

public enum PFS0Error: Error, Equatable {
    case truncatedData
    case invalidMagic
    case unreasonableEntryCount
    case unreasonableStringTable
    case arithmeticOverflow
    case invalidNameOffset
    case unterminatedName
    case invalidUTF8Name
    case unsafeEntryName(String)
    case duplicateEntryName(String)
    case entryOutsideArchive(String)
    case entryNotFound(String)
    case destinationAlreadyExists(String)
}

/// A bounded, streaming reader for the PFS0 container used by NSP packages.
///
/// Only the PFS0 metadata table is read into memory. Entry payloads are copied
/// in fixed-size chunks, so large NCAs do not need to fit in RAM.
public final class PFS0Archive {
    public struct Entry: Equatable {
        public let name: String
        /// Byte offset relative to the beginning of the PFS0 data region.
        public let offset: UInt64
        public let size: UInt64
    }

    private let sourceURL: URL
    private let dataRegionOffset: UInt64
    private let entriesByName: [String: Entry]
    public let entries: [Entry]

    private static let headerSize: UInt64 = 0x10
    private static let entrySize: UInt64 = 0x18
    private static let maximumEntryCount: UInt32 = 1_000_000
    private static let maximumStringTableSize: UInt32 = 64 * 1024 * 1024
    private static let copyChunkSize = 8 * 1024 * 1024

    /// Reads a PFS0 archive located inside a larger file. `offset` and `size`\n    /// delimit the exact archive region; trailing bytes outside it are ignored.\n    public init(url: URL, offset: UInt64 = 0, size: UInt64? = nil) throws {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }

        let fileSize = try handle.seekToEnd()
        guard offset <= fileSize else { throw PFS0Error.truncatedData }
        let regionSize = size ?? (fileSize - offset)
        let (regionEnd, regionOverflow) = offset.addingReportingOverflow(regionSize)
        guard !regionOverflow, regionEnd <= fileSize, regionSize >= Self.headerSize else {
            throw PFS0Error.truncatedData
        }
        try handle.seek(toOffset: offset)
        let header = try Self.readExactly(Self.headerSize, from: handle)
        guard header.prefix(4) == Data([0x50, 0x46, 0x53, 0x30]) else {
            throw PFS0Error.invalidMagic
        }

        let count = Self.u32(header, at: 4)
        let stringTableSize = Self.u32(header, at: 8)
        guard count <= Self.maximumEntryCount else {
            throw PFS0Error.unreasonableEntryCount
        }
        guard stringTableSize <= Self.maximumStringTableSize else {
            throw PFS0Error.unreasonableStringTable
        }

        let tableBytes = UInt64(count).multipliedReportingOverflow(by: Self.entrySize)
        guard !tableBytes.overflow else { throw PFS0Error.arithmeticOverflow }
        let tableEnd = Self.headerSize.addingReportingOverflow(tableBytes.partialValue)
        guard !tableEnd.overflow else { throw PFS0Error.arithmeticOverflow }
        let dataOffsetResult = tableEnd.partialValue.addingReportingOverflow(UInt64(stringTableSize))
        guard !dataOffsetResult.overflow else { throw PFS0Error.arithmeticOverflow }
        let dataOffsetWithinRegion = dataOffsetResult.partialValue
        guard dataOffsetWithinRegion <= regionSize else { throw PFS0Error.truncatedData }
        let absoluteDataOffset = offset.addingReportingOverflow(dataOffsetWithinRegion)
        guard !absoluteDataOffset.overflow else { throw PFS0Error.arithmeticOverflow }

        let entriesOffset = offset.addingReportingOverflow(Self.headerSize)
        guard !entriesOffset.overflow else { throw PFS0Error.arithmeticOverflow }
        try handle.seek(toOffset: entriesOffset.partialValue)
        let rawEntries = try Self.readExactly(tableBytes.partialValue, from: handle)
        let stringTable = try Self.readExactly(UInt64(stringTableSize), from: handle)

        var parsed: [Entry] = []
        parsed.reserveCapacity(Int(count))
        var byName: [String: Entry] = [:]
        byName.reserveCapacity(Int(count))

        for index in 0..<Int(count) {
            let base = index * Int(Self.entrySize)
            let offset = Self.u64(rawEntries, at: base)
            let size = Self.u64(rawEntries, at: base + 8)
            let nameOffset = Self.u32(rawEntries, at: base + 16)
            guard UInt64(nameOffset) < UInt64(stringTable.count) else {
                throw PFS0Error.invalidNameOffset
            }

            let start = Int(nameOffset)
            guard let terminator = stringTable[start...].firstIndex(of: 0) else {
                throw PFS0Error.unterminatedName
            }
            let nameData = stringTable.subdata(in: start..<terminator)
            guard let name = String(data: nameData, encoding: .utf8), !name.isEmpty else {
                throw PFS0Error.invalidUTF8Name
            }
            guard Self.isSafeFlatName(name) else {
                throw PFS0Error.unsafeEntryName(name)
            }
            guard byName[name] == nil else {
                throw PFS0Error.duplicateEntryName(name)
            }

            let end = offset.addingReportingOverflow(size)
            guard !end.overflow else { throw PFS0Error.arithmeticOverflow }
            let availablePayloadSize = regionSize - dataOffsetWithinRegion
            let absoluteEnd = absoluteDataOffset.partialValue.addingReportingOverflow(end.partialValue)
            guard end.partialValue <= availablePayloadSize,
                  !absoluteEnd.overflow, absoluteEnd.partialValue <= regionEnd else {
                throw PFS0Error.entryOutsideArchive(name)
            }

            let entry = Entry(name: name, offset: offset, size: size)
            parsed.append(entry)
            byName[name] = entry
        }

        self.sourceURL = url
        self.dataRegionOffset = absoluteDataOffset.partialValue
        self.entries = parsed
        self.entriesByName = byName
    }

    public func entry(named name: String) -> Entry? {
        entriesByName[name]
    }

    /// Copies one entry to a new file without loading its payload into memory.
    public func copyEntry(named name: String, to destinationURL: URL) throws {
        guard let entry = entriesByName[name] else {
            throw PFS0Error.entryNotFound(name)
        }

        let manager = FileManager.default
        guard !manager.fileExists(atPath: destinationURL.path) else {
            throw PFS0Error.destinationAlreadyExists(destinationURL.lastPathComponent)
        }
        try manager.createDirectory(
            at: destinationURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        guard manager.createFile(atPath: destinationURL.path, contents: nil) else {
            throw PFS0Error.destinationAlreadyExists(destinationURL.lastPathComponent)
        }

        let input = try FileHandle(forReadingFrom: sourceURL)
        defer { try? input.close() }
        let output = try FileHandle(forWritingTo: destinationURL)
        defer { try? output.close() }

        let absoluteOffset = dataRegionOffset.addingReportingOverflow(entry.offset)
        guard !absoluteOffset.overflow else { throw PFS0Error.arithmeticOverflow }
        try input.seek(toOffset: absoluteOffset.partialValue)

        var remaining = entry.size
        while remaining > 0 {
            let amount = Int(min(UInt64(Self.copyChunkSize), remaining))
            guard let chunk = try input.read(upToCount: amount), !chunk.isEmpty else {
                throw PFS0Error.truncatedData
            }
            try output.write(contentsOf: chunk)
            remaining -= UInt64(chunk.count)
        }
    }

    /// Extracts every flat PFS0 entry into a new directory.
    public func extractAll(to directoryURL: URL) throws {
        try FileManager.default.createDirectory(
            at: directoryURL,
            withIntermediateDirectories: true
        )
        for entry in entries {
            try copyEntry(
                named: entry.name,
                to: directoryURL.appendingPathComponent(entry.name, isDirectory: false)
            )
        }
    }

    private static func isSafeFlatName(_ name: String) -> Bool {
        guard name != ".", name != "..",
              !name.hasPrefix("/"),
              !name.contains("/"),
              !name.contains("\\"),
              !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
        else { return false }
        return true
    }

    private static func readExactly(_ count: UInt64, from handle: FileHandle) throws -> Data {
        guard count <= UInt64(Int.max) else { throw PFS0Error.arithmeticOverflow }
        var result = Data()
        result.reserveCapacity(Int(count))
        var remaining = Int(count)
        while remaining > 0 {
            guard let part = try handle.read(upToCount: remaining), !part.isEmpty else {
                throw PFS0Error.truncatedData
            }
            result.append(part)
            remaining -= part.count
        }
        return result
    }

    private static func u32(_ data: Data, at offset: Int) -> UInt32 {
        UInt32(data[offset]) |
        (UInt32(data[offset + 1]) << 8) |
        (UInt32(data[offset + 2]) << 16) |
        (UInt32(data[offset + 3]) << 24)
    }

    private static func u64(_ data: Data, at offset: Int) -> UInt64 {
        UInt64(u32(data, at: offset)) |
        (UInt64(u32(data, at: offset + 4)) << 32)
    }
}
