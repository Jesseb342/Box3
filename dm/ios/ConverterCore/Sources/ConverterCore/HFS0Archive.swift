import Foundation

public enum HFS0Error: Error, Equatable {
    case invalidURL
    case truncated
    case invalidMagic
    case unreasonableEntryCount
    case invalidName
    case entryOutsideArchive(String)
    case entryNotFound(String)
    case entryTooLarge(String)
    case arithmeticOverflow
}

/// Bounded reader for HFS0 partitions inside XCI game-card images.
public final class HFS0Archive {
    private let sourceURL: URL
    private let dataRegionOffset: UInt64
    private let regionEnd: UInt64
    private let entriesByName: [String: PFS0Archive.Entry]
    public let entries: [PFS0Archive.Entry]

    public init(url: URL, offset: UInt64, size: UInt64) throws {
        guard url.isFileURL else { throw HFS0Error.invalidURL }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let fileSize = try handle.seekToEnd()
        let end = offset.addingReportingOverflow(size)
        guard !end.overflow, end.partialValue <= fileSize, size >= 0x10 else {
            throw HFS0Error.truncated
        }
        try handle.seek(toOffset: offset)
        let header = try Self.readExactly(0x10, from: handle)
        guard header.prefix(4) == Data("HFS0".utf8) else { throw HFS0Error.invalidMagic }
        let count = Self.u32(header, 4)
        let stringSize = Self.u32(header, 8)
        guard count <= 1_000_000, stringSize <= 64 * 1024 * 1024 else {
            throw HFS0Error.unreasonableEntryCount
        }
        let tableBytes = UInt64(count).multipliedReportingOverflow(by: 0x40)
        guard !tableBytes.overflow else { throw HFS0Error.arithmeticOverflow }
        let dataStart = UInt64(0x10).addingReportingOverflow(tableBytes.partialValue)
        guard !dataStart.overflow else { throw HFS0Error.arithmeticOverflow }
        let afterStrings = dataStart.partialValue.addingReportingOverflow(UInt64(stringSize))
        guard !afterStrings.overflow, afterStrings.partialValue <= size else { throw HFS0Error.truncated }
        let absoluteData = offset.addingReportingOverflow(afterStrings.partialValue)
        guard !absoluteData.overflow else { throw HFS0Error.arithmeticOverflow }
        try handle.seek(toOffset: offset + 0x10)
        let raw = try Self.readExactly(tableBytes.partialValue, from: handle)
        let strings = try Self.readExactly(UInt64(stringSize), from: handle)
        let payloadSize = size - afterStrings.partialValue
        var parsed: [PFS0Archive.Entry] = []
        var byName: [String: PFS0Archive.Entry] = [:]
        for i in 0..<Int(count) {
            let base = i * 0x40
            let entryOffset = Self.u64(raw, base)
            let entrySize = Self.u64(raw, base + 8)
            let nameOffset = Self.u32(raw, base + 0x10)
            guard UInt64(nameOffset) < UInt64(strings.count) else { throw HFS0Error.invalidName }
            let start = Int(nameOffset)
            guard let endIndex = strings[start...].firstIndex(of: 0),
                  let name = String(data: strings.subdata(in: start..<endIndex), encoding: .utf8),
                  !name.isEmpty, name != ".", name != "..",
                  !name.contains("/"), !name.contains("\\") else {
                throw HFS0Error.invalidName
            }
            let entryEnd = entryOffset.addingReportingOverflow(entrySize)
            guard !entryEnd.overflow, entryEnd.partialValue <= payloadSize else {
                throw HFS0Error.entryOutsideArchive(name)
            }
            let entry = PFS0Archive.Entry(name: name, offset: entryOffset, size: entrySize)
            guard byName[name] == nil else { throw HFS0Error.invalidName }
            parsed.append(entry)
            byName[name] = entry
        }
        self.sourceURL = url
        self.dataRegionOffset = absoluteData.partialValue
        self.regionEnd = end.partialValue
        self.entries = parsed
        self.entriesByName = byName
    }

    public func readEntryData(named name: String, maximumSize: UInt64 = 1 << 20) throws -> Data {
        guard let entry = entriesByName[name] else { throw HFS0Error.entryNotFound(name) }
        guard entry.size <= maximumSize, entry.size <= UInt64(Int.max) else { throw HFS0Error.entryTooLarge(name) }
        let handle = try FileHandle(forReadingFrom: sourceURL)
        defer { try? handle.close() }
        let absolute = dataRegionOffset.addingReportingOverflow(entry.offset)
        guard !absolute.overflow else { throw HFS0Error.arithmeticOverflow }
        try handle.seek(toOffset: absolute.partialValue)
        return try Self.readExactly(entry.size, from: handle)
    }

    public func copyEntry(named name: String, to destinationURL: URL) throws {
        guard let entry = entriesByName[name] else { throw HFS0Error.entryNotFound(name) }
        guard !FileManager.default.fileExists(atPath: destinationURL.path) else {
            throw PFS0Error.destinationAlreadyExists(destinationURL.lastPathComponent)
        }
        try FileManager.default.createDirectory(at: destinationURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        guard FileManager.default.createFile(atPath: destinationURL.path, contents: nil) else {
            throw PFS0Error.destinationAlreadyExists(destinationURL.lastPathComponent)
        }
        let input = try FileHandle(forReadingFrom: sourceURL)
        defer { try? input.close() }
        let output = try FileHandle(forWritingTo: destinationURL)
        defer { try? output.close() }
        let absolute = dataRegionOffset.addingReportingOverflow(entry.offset)
        guard !absolute.overflow else { throw HFS0Error.arithmeticOverflow }
        try input.seek(toOffset: absolute.partialValue)
        var remaining = entry.size
        while remaining > 0 {
            let amount = Int(min(8 * 1024 * 1024, remaining))
            guard let chunk = try input.read(upToCount: amount), !chunk.isEmpty else { throw HFS0Error.truncated }
            try output.write(contentsOf: chunk)
            remaining -= UInt64(chunk.count)
        }
        try output.synchronize()
    }

    private static func readExactly(_ count: UInt64, from handle: FileHandle) throws -> Data {
        guard count <= UInt64(Int.max) else { throw HFS0Error.arithmeticOverflow }
        var result = Data()
        result.reserveCapacity(Int(count))
        while result.count < Int(count) {
            guard let part = try handle.read(upToCount: Int(count) - result.count), !part.isEmpty else {
                throw HFS0Error.truncated
            }
            result.append(part)
        }
        return result
    }

    private static func u32(_ data: Data, _ offset: Int) -> UInt32 {
        UInt32(data[offset]) | (UInt32(data[offset + 1]) << 8) |
        (UInt32(data[offset + 2]) << 16) | (UInt32(data[offset + 3]) << 24)
    }

    private static func u64(_ data: Data, _ offset: Int) -> UInt64 {
        UInt64(u32(data, offset)) | (UInt64(u32(data, offset + 4)) << 32)
    }
}
