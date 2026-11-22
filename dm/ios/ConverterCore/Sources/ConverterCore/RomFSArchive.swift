import Foundation

public enum RomFSError: Error, Equatable {
    case invalidFileURL
    case truncatedImage
    case invalidHeaderSize(UInt64)
    case invalidRegion(String)
    case overlappingRegions
    case invalidMetadataOffset(String, UInt32)
    case invalidMetadataEntry(String, UInt32)
    case invalidName
    case unsafeName(String)
    case duplicatePath(String)
    case invalidParent(String)
    case cyclicMetadata
    case tooManyEntries
    case fileDataOutOfBounds(String)
    case destinationAlreadyExists
    case couldNotCreateStagingDirectory
}

/// Bounded parser and extractor for the Nintendo Switch 0x50-byte RomFS image.
/// It parses metadata by random-access reads and streams file payloads in chunks.
/// NCA IVFC integrity verification is a separate prerequisite and is not implied
/// by constructing this type.
public final class RomFSArchive {
    public struct Entry: Equatable {
        public let path: String
        public let isDirectory: Bool
        public let dataOffset: UInt64
        public let size: UInt64
    }

    private struct Header {
        let dirHashOffset: UInt64
        let dirHashSize: UInt64
        let dirOffset: UInt64
        let dirSize: UInt64
        let fileHashOffset: UInt64
        let fileHashSize: UInt64
        let fileOffset: UInt64
        let fileSize: UInt64
        let dataOffset: UInt64
    }

    private struct Directory {
        let parent: UInt32
        let sibling: UInt32
        let childDirectory: UInt32
        let childFile: UInt32
        let name: String
    }

    private struct File {
        let parent: UInt32
        let sibling: UInt32
        let dataOffset: UInt64
        let size: UInt64
        let name: String
    }

    private let url: URL
    private let imageOffset: UInt64
    private let imageSize: UInt64
    private let header: Header
    private let directories: [Entry]
    private let files: [Entry]
    public let entries: [Entry]

    private static let none = UInt32.max
    private static let maxEntries = 2_000_000
    private static let maxNameBytes = 1_048_576
    private static let ioChunkSize = 1_048_576

    public init(url: URL, offset: UInt64 = 0, size: UInt64? = nil) throws {
        guard url.isFileURL else { throw RomFSError.invalidFileURL }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let fileSize = try handle.seekToEnd()
        guard offset <= fileSize else { throw RomFSError.truncatedImage }
        let regionSize = size ?? (fileSize - offset)
        let (regionEnd, overflow) = offset.addingReportingOverflow(regionSize)
        guard !overflow, regionEnd <= fileSize, regionSize >= 0x50 else {
            throw RomFSError.truncatedImage
        }

        func read(_ relative: UInt64, _ count: Int) throws -> Data {
            let (absolute, addOverflow) = offset.addingReportingOverflow(relative)
            let (end, endOverflow) = absolute.addingReportingOverflow(UInt64(count))
            guard !addOverflow, !endOverflow, end <= regionEnd else {
                throw RomFSError.truncatedImage
            }
            try handle.seek(toOffset: absolute)
            var result = Data()
            result.reserveCapacity(count)
            while result.count < count {
                guard let chunk = try handle.read(upToCount: count - result.count),
                      !chunk.isEmpty else {
                    throw RomFSError.truncatedImage
                }
                result.append(chunk)
            }
            return result
        }

        let rawHeader = try read(0, 0x50)
        func u64(_ data: Data, _ at: Int) -> UInt64 {
            UInt64(data[at]) | (UInt64(data[at+1]) << 8) |
            (UInt64(data[at+2]) << 16) | (UInt64(data[at+3]) << 24) |
            (UInt64(data[at+4]) << 32) | (UInt64(data[at+5]) << 40) |
            (UInt64(data[at+6]) << 48) | (UInt64(data[at+7]) << 56)
        }
        let headerSize = u64(rawHeader, 0)
        guard headerSize == 0x50 else { throw RomFSError.invalidHeaderSize(headerSize) }
        let parsed = Header(
            dirHashOffset: u64(rawHeader, 8), dirHashSize: u64(rawHeader, 16),
            dirOffset: u64(rawHeader, 24), dirSize: u64(rawHeader, 32),
            fileHashOffset: u64(rawHeader, 40), fileHashSize: u64(rawHeader, 48),
            fileOffset: u64(rawHeader, 56), fileSize: u64(rawHeader, 64),
            dataOffset: u64(rawHeader, 72)
        )

        let regions: [(String, UInt64, UInt64)] = [
            ("directory hash table", parsed.dirHashOffset, parsed.dirHashSize),
            ("directory metadata table", parsed.dirOffset, parsed.dirSize),
            ("file hash table", parsed.fileHashOffset, parsed.fileHashSize),
            ("file metadata table", parsed.fileOffset, parsed.fileSize),
            ("file data", parsed.dataOffset, regionSize - min(parsed.dataOffset, regionSize))
        ]
        var previousEnd: UInt64 = 0x50
        for (name, start, length) in regions {
            let (end, addOverflow) = start.addingReportingOverflow(length)
            guard !addOverflow, start >= 0x50, end <= regionSize else {
                throw RomFSError.invalidRegion(name)
            }
            guard length > 0 || name == "file data" || (name == "file metadata table" && parsed.fileSize == 0) else {
                throw RomFSError.invalidRegion(name)
            }
            if length > 0 {
                guard start >= previousEnd else { throw RomFSError.overlappingRegions }
                previousEnd = end
            }
        }
        guard parsed.dirHashSize % 4 == 0, parsed.fileHashSize % 4 == 0 else {
            throw RomFSError.invalidRegion("hash table alignment")
        }
        guard parsed.dirSize >= 0x18, parsed.fileSize == 0 || parsed.fileSize >= 0x20 else {
            throw RomFSError.invalidRegion("metadata table")
        }

        self.url = url
        self.imageOffset = offset
        self.imageSize = regionSize
        self.header = parsed

        func readMetadata(_ tableOffset: UInt64, _ tableSize: UInt64, _ entryOffset: UInt32,
                          _ kind: String, _ fixed: Int) throws -> (Data, String) {
            guard entryOffset != Self.none, UInt64(entryOffset) % 4 == 0,
                  UInt64(entryOffset) <= tableSize,
                  UInt64(fixed) <= tableSize - UInt64(entryOffset) else {
                throw RomFSError.invalidMetadataOffset(kind, entryOffset)
            }
            let fixedData = try read(tableOffset + UInt64(entryOffset), fixed)
            let nameLength = UInt64(fixedData[fixed - 4]) |
                (UInt64(fixedData[fixed - 3]) << 8) |
                (UInt64(fixedData[fixed - 2]) << 16) |
                (UInt64(fixedData[fixed - 1]) << 24)
            guard nameLength <= UInt64(Self.maxNameBytes),
                  nameLength <= tableSize - UInt64(entryOffset) - UInt64(fixed) else {
                throw RomFSError.invalidMetadataEntry(kind, entryOffset)
            }
            let nameData = try read(tableOffset + UInt64(entryOffset) + UInt64(fixed), Int(nameLength))
            guard let name = String(data: nameData, encoding: .utf8) else {
                throw RomFSError.invalidName
            }
            if !name.isEmpty {
                guard name != ".", name != "..",
                      !name.contains("/"), !name.contains("\\"), !name.contains("\0") else {
                    throw RomFSError.unsafeName(name)
                }
            }
            return (fixedData, name)
        }

        func readDirectory(_ entryOffset: UInt32) throws -> Directory {
            let (raw, name) = try readMetadata(parsed.dirOffset, parsed.dirSize, entryOffset, "directory", 0x18)
            return Directory(parent: Self.readU32(raw, 0), sibling: Self.readU32(raw, 4),
                             childDirectory: Self.readU32(raw, 8), childFile: Self.readU32(raw, 12), name: name)
        }
        func readFile(_ entryOffset: UInt32) throws -> File {
            guard entryOffset != Self.none, UInt64(entryOffset) % 4 == 0,
                  UInt64(entryOffset) <= parsed.fileSize,
                  parsed.fileSize - UInt64(entryOffset) >= 0x20 else {
                throw RomFSError.invalidMetadataOffset("file", entryOffset)
            }
            let raw = try read(parsed.fileOffset + UInt64(entryOffset), 0x20)
            let nameLength = UInt64(Self.readU32(raw, 28))
            guard nameLength <= UInt64(Self.maxNameBytes),
                  nameLength <= parsed.fileSize - UInt64(entryOffset) - 0x20 else {
                throw RomFSError.invalidMetadataEntry("file", entryOffset)
            }
            let nameData = try read(parsed.fileOffset + UInt64(entryOffset) + 0x20, Int(nameLength))
            guard let name = String(data: nameData, encoding: .utf8), !name.isEmpty,
                  name != ".", name != "..", !name.contains("/"),
                  !name.contains("\\"), !name.contains("\0") else {
                throw RomFSError.unsafeName(String(decoding: nameData, as: UTF8.self))
            }
            let dataOffset = Self.readU64(raw, 8)
            let dataLength = Self.readU64(raw, 16)
            let (dataEnd, dataOverflow) = dataOffset.addingReportingOverflow(dataLength)
            let dataRegionSize = regionSize - parsed.dataOffset
            guard !dataOverflow, dataEnd <= dataRegionSize else {
                throw RomFSError.fileDataOutOfBounds(name)
            }
            return File(parent: Self.readU32(raw, 0), sibling: Self.readU32(raw, 4),
                        dataOffset: dataOffset, size: dataLength, name: name)
        }

        var output: [Entry] = [Entry(path: "", isDirectory: true, dataOffset: 0, size: 0)]
        var seenDirectories: Set<UInt32> = [0]
        var seenFiles: Set<UInt32> = []
        var seenPaths: Set<String> = [""]
        var queue: [(UInt32, String)] = [(0, "")]
        var cursor = 0
        while cursor < queue.count {
            guard output.count <= Self.maxEntries else { throw RomFSError.tooManyEntries }
            let (directoryOffset, parentPath) = queue[cursor]
            cursor += 1
            let directory = try readDirectory(directoryOffset)
            if directoryOffset == 0 {
                guard directory.parent == 0, directory.name.isEmpty else {
                    throw RomFSError.invalidParent("root")
                }
            }
            var fileOffset = directory.childFile
            while fileOffset != Self.none {
                guard seenFiles.insert(fileOffset).inserted else { throw RomFSError.cyclicMetadata }
                let file = try readFile(fileOffset)
                guard file.parent == directoryOffset else { throw RomFSError.invalidParent(file.name) }
                let path = parentPath.isEmpty ? file.name : parentPath + "/" + file.name
                guard seenPaths.insert(path).inserted else { throw RomFSError.duplicatePath(path) }
                output.append(Entry(path: path, isDirectory: false,
                                    dataOffset: file.dataOffset, size: file.size))
                fileOffset = file.sibling
                guard output.count <= Self.maxEntries else { throw RomFSError.tooManyEntries }
            }
            var childOffset = directory.childDirectory
            while childOffset != Self.none {
                guard seenDirectories.insert(childOffset).inserted else { throw RomFSError.cyclicMetadata }
                let child = try readDirectory(childOffset)
                guard child.parent == directoryOffset, !child.name.isEmpty else {
                    throw RomFSError.invalidParent(child.name)
                }
                let path = parentPath.isEmpty ? child.name : parentPath + "/" + child.name
                guard seenPaths.insert(path).inserted else { throw RomFSError.duplicatePath(path) }
                output.append(Entry(path: path, isDirectory: true, dataOffset: 0, size: 0))
                queue.append((childOffset, path))
                childOffset = child.sibling
                guard output.count <= Self.maxEntries else { throw RomFSError.tooManyEntries }
            }
        }
        self.entries = output
        self.directories = output.filter(\.isDirectory)
        self.files = output.filter { !$0.isDirectory }
    }

    public func extractAll(to destinationURL: URL, chunkSize: Int = 1_048_576) throws {
        guard destinationURL.isFileURL, chunkSize > 0, chunkSize <= 8 * 1024 * 1024 else {
            throw RomFSError.invalidFileURL
        }
        let manager = FileManager.default
        guard !manager.fileExists(atPath: destinationURL.path) else {
            throw RomFSError.destinationAlreadyExists
        }
        let parent = destinationURL.deletingLastPathComponent()
        try manager.createDirectory(at: parent, withIntermediateDirectories: true)
        let staging = parent.appendingPathComponent(".\(destinationURL.lastPathComponent).romfs-\(UUID().uuidString)", isDirectory: true)
        do { try manager.createDirectory(at: staging, withIntermediateDirectories: false) }
        catch { throw RomFSError.couldNotCreateStagingDirectory }

        let input = try FileHandle(forReadingFrom: url)
        do {
            for entry in directories where !entry.path.isEmpty {
                try manager.createDirectory(at: staging.appendingPathComponent(entry.path, isDirectory: true),
                                            withIntermediateDirectories: true)
            }
            for entry in files {
                let outputURL = staging.appendingPathComponent(entry.path)
                try manager.createDirectory(at: outputURL.deletingLastPathComponent(), withIntermediateDirectories: true)
                guard manager.createFile(atPath: outputURL.path, contents: nil) else {
                    throw RomFSError.invalidRegion("could not create output file")
                }
                let output = try FileHandle(forWritingTo: outputURL)
                do {
                    var copied: UInt64 = 0
                    while copied < entry.size {
                        let count = Int(min(UInt64(chunkSize), entry.size - copied))
                        let absolute = imageOffset + header.dataOffset + entry.dataOffset + copied
                        try input.seek(toOffset: absolute)
                        var bytes = Data()
                        bytes.reserveCapacity(count)
                        while bytes.count < count {
                            guard let chunk = try input.read(upToCount: count - bytes.count),
                                  !chunk.isEmpty else {
                                throw RomFSError.truncatedImage
                            }
                            bytes.append(chunk)
                        }
                        try output.write(contentsOf: bytes)
                        copied += UInt64(count)
                    }
                    try output.close()
                } catch {
                    try? output.close()
                    throw error
                }
            }
            try input.close()
            try manager.moveItem(at: staging, to: destinationURL)
        } catch {
            try? input.close()
            try? manager.removeItem(at: staging)
            throw error
        }
    }

    private static func readU32(_ data: Data, _ offset: Int) -> UInt32 {
        UInt32(data[offset]) | (UInt32(data[offset+1]) << 8) |
        (UInt32(data[offset+2]) << 16) | (UInt32(data[offset+3]) << 24)
    }

    private static func readU64(_ data: Data, _ offset: Int) -> UInt64 {
        UInt64(readU32(data, offset)) | (UInt64(readU32(data, offset + 4)) << 32)
    }
}
