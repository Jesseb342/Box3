import Foundation
import XCTest
@testable import ConverterCore

final class TicketTests: XCTestCase {
    func testParsesCommonTicketRightsIDAndEncryptedTitleKey() throws {
        let rights = try bytes("01009bf0072d40000000000000000004")
        let encrypted = try bytes("00112233445566778899aabbccddeeff")
        let ticket = try Ticket(data: fixture(signature: 0x010001, keyType: 0, rights: rights, key: encrypted))
        XCTAssertEqual(ticket.rightsID, rights)
        XCTAssertEqual(ticket.encryptedTitleKey, encrypted)
    }

    func testRejectsPersonalizedTicketWithoutConsolePrivateKey() throws {
        let rights = try bytes("01009bf0072d40000000000000000004")
        XCTAssertThrowsError(try Ticket(data: fixture(signature: 0x010001, keyType: 1, rights: rights, key: Data(repeating: 0, count: 16)))) {
            XCTAssertEqual($0 as? TicketError, .personalizedTicket("01009bf0072d40000000000000000004"))
        }
    }

    func testTitleKeysCanBeBuiltFromTicketData() throws {
        let rights = try bytes("01009bf0072d40000000000000000004")
        let encrypted = try bytes("00112233445566778899aabbccddeeff")
        let keys = try TitleKeys(ticketData: [fixture(signature: 0x010001, keyType: 0, rights: rights, key: encrypted)])
        XCTAssertEqual(keys.encryptedTitleKey(for: rights), encrypted)
    }

    private func fixture(signature: UInt32, keyType: UInt8, rights: Data, key: Data) -> Data {
        let bodyOffset = signature == 0x010001 ? 0x140 : 0x240
        var data = Data(repeating: 0, count: bodyOffset + 0x2c0)
        data[0] = UInt8(signature & 0xff)
        data[1] = UInt8((signature >> 8) & 0xff)
        data[2] = UInt8((signature >> 16) & 0xff)
        data[3] = UInt8((signature >> 24) & 0xff)
        data.replaceSubrange((bodyOffset + 0x40)..<(bodyOffset + 0x50), with: key)
        data[bodyOffset + 0x141] = keyType
        data.replaceSubrange((bodyOffset + 0x160)..<(bodyOffset + 0x170), with: rights)
        return data
    }

    private func bytes(_ hex: String) throws -> Data {
        let chars = Array(hex)
        var output = Data()
        for i in stride(from: 0, to: chars.count, by: 2) {
            guard let byte = UInt8(String(chars[i...i+1]), radix: 16) else {
                throw NSError(domain: "TicketTests", code: 1)
            }
            output.append(byte)
        }
        return output
    }
}
