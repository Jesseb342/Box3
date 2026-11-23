import Foundation

public enum TitleKeysError: Error, Equatable {
    case malformedLine(Int)
    case invalidRightsID(Int)
    case invalidTitleKey(Int)
    case duplicateRightsID(Int, String)
    case noKeysFound
    case duplicateTicketRightsID(String)
    case noCommonTickets
}

/// Encrypted title keys indexed by their 16-byte NCA Rights ID.
/// Key material is retained in memory only and must never be logged.
public struct TitleKeys {
    private let values: [String: Data]

    public init(contentsOf url: URL) throws {
        try self.init(text: String(contentsOf: url, encoding: .utf8))
    }

    public init(text: String) throws {
        var parsed: [String: Data] = [:]
        for (index, rawLine) in text.components(separatedBy: .newlines).enumerated() {
            let lineNumber = index + 1
            let line = rawLine.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)[0]
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty { continue }
            guard let separator = line.firstIndex(of: "=") else {
                // hactool-compatible title.keys files may contain non-key lines.
                continue
            }
            let rightsText = line[..<separator].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let keyText = line[line.index(after: separator)...]
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard let rights = Self.decodeHex(rightsText), rights.count == 16 else {
                throw TitleKeysError.invalidRightsID(lineNumber)
            }
            guard let titleKey = Self.decodeHex(keyText), titleKey.count == 16 else {
                throw TitleKeysError.invalidTitleKey(lineNumber)
            }
            let rightsName = rights.map { String(format: "%02x", $0) }.joined()
            guard parsed[rightsName] == nil else {
                throw TitleKeysError.duplicateRightsID(lineNumber, rightsName)
            }
            parsed[rightsName] = titleKey
        }
        guard !parsed.isEmpty else { throw TitleKeysError.noKeysFound }
        self.values = parsed
    }


    public init(ticketData: [Data]) throws {
        var parsed: [String: Data] = [:]
        for data in ticketData {
            let ticket = try Ticket(data: data)
            let name = ticket.rightsID.map { String(format: "%02x", $0) }.joined()
            guard parsed[name] == nil else { throw TitleKeysError.duplicateTicketRightsID(name) }
            parsed[name] = ticket.encryptedTitleKey
        }
        guard !parsed.isEmpty else { throw TitleKeysError.noCommonTickets }
        self.values = parsed
    }

    public func encryptedTitleKey(for rightsID: Data) -> Data? {
        guard rightsID.count == 16 else { return nil }
        let name = rightsID.map { String(format: "%02x", $0) }.joined()
        return values[name]
    }

    private static func decodeHex(_ text: String) -> Data? {
        let bytes = Array(text.utf8)
        guard !bytes.isEmpty, bytes.count.isMultiple(of: 2) else { return nil }
        var result = Data()
        result.reserveCapacity(bytes.count / 2)
        for offset in stride(from: 0, to: bytes.count, by: 2) {
            guard let high = nibble(bytes[offset]), let low = nibble(bytes[offset + 1]) else {
                return nil
            }
            result.append((high << 4) | low)
        }
        return result
    }

    private static func nibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 48...57: return byte - 48
        case 65...70: return byte - 65 + 10
        case 97...102: return byte - 97 + 10
        default: return nil
        }
    }
}
