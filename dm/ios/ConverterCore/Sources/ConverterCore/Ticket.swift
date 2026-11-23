import Foundation

public enum TicketError: Error, Equatable {
    case truncated
    case unsupportedSignatureType(UInt32)
    case invalidRightsID
    case personalizedTicket(String)
    case noCommonTickets
}

/// Reads the common-ticket fields used by standard NSP title-key crypto.
/// Signature verification is intentionally separate; the ticket is treated as
/// untrusted metadata and its Rights ID must match the NCA header.
public struct Ticket {
    public let rightsID: Data
    public let encryptedTitleKey: Data
    public let masterKeyRevision: UInt8

    public init(data: Data) throws {
        guard data.count >= 4 else { throw TicketError.truncated }
        let signatureType = Self.u32(data, 0)
        let bodyOffset: Int
        switch signatureType {
        case 0x010000: bodyOffset = 0x240
        case 0x010001: bodyOffset = 0x140
        case 0x010002: bodyOffset = 0x80
        case 0x010003: bodyOffset = 0x240
        case 0x010004: bodyOffset = 0x140
        case 0x010005: bodyOffset = 0x80
        case 0x010006: bodyOffset = 0x40
        default: throw TicketError.unsupportedSignatureType(signatureType)
        }
        guard data.count >= bodyOffset + 0x170 else { throw TicketError.truncated }
        let body = data.subdata(in: bodyOffset..<data.count)
        let rights = body.subdata(in: 0x160..<0x170)
        guard rights.contains(where: { $0 != 0 }) else { throw TicketError.invalidRightsID }
        let keyType = body[0x141]
        guard keyType == 0 else {
            let name = rights.map { String(format: "%02x", $0) }.joined()
            throw TicketError.personalizedTicket(name)
        }
        self.rightsID = rights
        self.encryptedTitleKey = body.subdata(in: 0x40..<0x50)
        self.masterKeyRevision = body[0x145]
    }

    private static func u32(_ data: Data, _ offset: Int) -> UInt32 {
        UInt32(data[offset]) | (UInt32(data[offset + 1]) << 8) |
        (UInt32(data[offset + 2]) << 16) | (UInt32(data[offset + 3]) << 24)
    }
}
