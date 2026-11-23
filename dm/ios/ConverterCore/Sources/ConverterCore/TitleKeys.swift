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
/// Ticket-derived entries also retain the ticket's master-key revision.
public struct TitleKeys {
    private struct Entry {
        let encryptedKey: Data
        let masterKeyRevision: UInt8?
    }
    private let values: [String: Entry]

    public init(contentsOf url: URL) throws {
        try self.init(text: String(contentsOf: url, encoding: .utf8))
    }

    public init(text: String) throws {
        var parsed: [String: Entry] = [:]
        for (index, rawLine) in text.components(separatedBy: .newlines).enumerated() {
            let lineNumber = index + 1
            let line = rawLine.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)[0]
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty { continue }
            guard let separator = line.firstIndex(of: "=") else { continue }
            let rightsText = line[..<separator].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let keyText = line[line.index(after: separator)...].trimmingCharacters(in: .whitespacesAndNewlines)
            guard let rights = Self.decodeHex(rightsText), rights.count == 16 else {
                throw TitleKeysError.invalidRightsID(lineNumber)
            }
            guard let titleKey = Self.decodeHex(keyText), titleKey.count == 16 else {
                throw TitleKeysError.invalidTitleKey(lineNumber)
            }
            let name = rights.map { String(format: "%02x", $0) }.joined()
            guard parsed[name] == nil else { throw TitleKeysError.duplicateRightsID(lineNumber, name) }
            parsed[name] = Entry(encryptedKey: titleKey, masterKeyRevision: nil)
        }
        guard !parsed.isEmpty else { throw TitleKeysError.noKeysFound }
        self.values = parsed
    }

    public init(ticketData: [Data]) throws {
        var parsed: [String: Entry] = [:]
        for data in ticketData {
            let ticket: Ticket
            do {
                ticket = try Ticket(data: data)
            } catch TicketError.personalizedTicket {
                continue
            }
            let name = ticket.rightsID.map { String(format: "%02x", $0) }.joined()
            let entry = Entry(encryptedKey: ticket.encryptedTitleKey, masterKeyRevision: ticket.masterKeyRevision)
            if let existing = parsed[name] {
                guard existing.encryptedKey == entry.encryptedKey,
                      existing.masterKeyRevision == entry.masterKeyRevision else {
                    throw TitleKeysError.duplicateTicketRightsID(name)
                }
            } else {
                parsed[name] = entry
            }
        }
        guard !parsed.isEmpty else { throw TitleKeysError.noCommonTickets }
        self.values = parsed
    }

    public func encryptedTitleKey(for rightsID: Data) -> Data? {
        guard rightsID.count == 16 else { return nil }
        let name = rightsID.map { String(format: "%02x", $0) }.joined()
        return values[name]?.encryptedKey
    }

    /// Nil for legacy title.keys entries, whose format carries no revision.
    public func masterKeyRevision(for rightsID: Data) -> UInt8? {
        guard rightsID.count == 16 else { return nil }
        let name = rightsID.map { String(format: "%02x", $0) }.joined()
        return values[name]?.masterKeyRevision
    }

    private static func decodeHex(_ text: String) -> Data? {
        let bytes = Array(text.utf8)
        guard !bytes.isEmpty, bytes.count.isMultiple(of: 2) else { return nil }
        var result = Data()
        result.reserveCapacity(bytes.count / 2)
        for offset in stride(from: 0, to: bytes.count, by: 2) {
            guard let high = nibble(bytes[offset]), let low = nibble(bytes[offset + 1]) else { return nil }
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
