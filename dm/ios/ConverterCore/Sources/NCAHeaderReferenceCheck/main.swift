import Foundation
import ConverterCore

enum CheckError: Error, CustomStringConvertible {
    case usage
    case missingKey
    case invalidKeyHex
    case wrongHeaderLength(String, Int)

    var description: String {
        switch self {
        case .usage:
            return "Usage: nca-header-reference-check <encrypted-header.bin> <hactool-or-libhac-plaintext-header.bin> (set NCA_HEADER_KEY_HEX in the environment)"
        case .missingKey:
            return "NCA_HEADER_KEY_HEX is not set"
        case .invalidKeyHex:
            return "NCA_HEADER_KEY_HEX must contain an even number of hexadecimal characters"
        case .wrongHeaderLength(let label, let count):
            return "\(label) must be exactly 3072 bytes; got \(count)"
        }
    }
}

func decodeHex(_ value: String) throws -> Data {
    guard value.count.isMultiple(of: 2) else { throw CheckError.invalidKeyHex }
    var bytes = [UInt8]()
    bytes.reserveCapacity(value.count / 2)
    var index = value.startIndex
    while index < value.endIndex {
        let next = value.index(index, offsetBy: 2)
        guard let byte = UInt8(value[index..<next], radix: 16) else {
            throw CheckError.invalidKeyHex
        }
        bytes.append(byte)
        index = next
    }
    return Data(bytes)
}

func run() throws {
    let arguments = Array(CommandLine.arguments.dropFirst())
    guard arguments.count == 2 else { throw CheckError.usage }
    guard let keyText = ProcessInfo.processInfo.environment["NCA_HEADER_KEY_HEX"] else {
        throw CheckError.missingKey
    }

    let encrypted = try Data(contentsOf: URL(fileURLWithPath: arguments[0]))
    let reference = try Data(contentsOf: URL(fileURLWithPath: arguments[1]))
    guard encrypted.count == 0xC00 else {
        throw CheckError.wrongHeaderLength("Encrypted NCA header", encrypted.count)
    }
    guard reference.count == 0xC00 else {
        throw CheckError.wrongHeaderLength("Reference plaintext header", reference.count)
    }

    let key = try decodeHex(keyText)
    let actual = try AESXTS.decryptNCAHeader(encrypted, headerKey: key)
    guard actual == reference else {
        var mismatch = 0
        for index in 0..<actual.count where actual[index] != reference[index] {
            mismatch = index
            break
        }
        let actualByte = actual[mismatch]
        let expectedByte = reference[mismatch]
        fputs(
            String(format: "FAIL: first mismatch at 0x%03X (actual %02X, reference %02X)\n", mismatch, actualByte, expectedByte),
            stderr
        )
        exit(EXIT_FAILURE)
    }

    _ = try NCAHeader(plaintextHeader: actual)
    print("PASS: decrypted 0xC00-byte NCA header matches the independent reference byte-for-byte")
}

do {
    try run()
} catch {
    fputs("ERROR: \(error)\n", stderr)
    exit(EXIT_FAILURE)
}
