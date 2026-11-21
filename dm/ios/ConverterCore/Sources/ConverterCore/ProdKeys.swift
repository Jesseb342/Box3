import Foundation

public enum ProdKeysError: Error, Equatable {
    case malformedLine(Int)
    case invalidKeyName(Int)
    case emptyValue(Int)
    case invalidHex(Int)
    case duplicateKey(Int, String)
    case noKeysFound
}

/// Parsed key material for the current conversion job.
///
/// Values are kept in memory only. Callers must never log or display key bytes.
public struct ProdKeys {
    private let values: [String: Data]

    public var names: [String] {
        values.keys.sorted()
    }

    public init(contentsOf url: URL) throws {
        let text = try String(contentsOf: url, encoding: .utf8)
        try self.init(text: text)
    }

    public init(text: String) throws {
        var parsed: [String: Data] = [:]

        for (zeroBasedLine, rawLine) in text.components(separatedBy: .newlines).enumerated() {
            let lineNumber = zeroBasedLine + 1
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") { continue }

            guard let separator = line.firstIndex(of: "=") else {
                throw ProdKeysError.malformedLine(lineNumber)
            }

            let name = String(line[..<separator]).trimmingCharacters(in: .whitespaces)
            let hex = String(line[line.index(after: separator)...])
                .trimmingCharacters(in: .whitespacesAndNewlines)

            guard Self.isValidName(name) else {
                throw ProdKeysError.invalidKeyName(lineNumber)
            }
            guard !hex.isEmpty else {
                throw ProdKeysError.emptyValue(lineNumber)
            }
            guard parsed[name] == nil else {
                throw ProdKeysError.duplicateKey(lineNumber, name)
            }

            let encoded = Array(hex.utf8)
            guard encoded.count.isMultiple(of: 2) else {
                throw ProdKeysError.invalidHex(lineNumber)
            }

            var bytes: [UInt8] = []
            bytes.reserveCapacity(encoded.count / 2)
            for index in stride(from: 0, to: encoded.count, by: 2) {
                guard let high = Self.hexNibble(encoded[index]),
                      let low = Self.hexNibble(encoded[index + 1]) else {
                    throw ProdKeysError.invalidHex(lineNumber)
                }
                bytes.append((high << 4) | low)
            }
            parsed[name] = Data(bytes)
        }

        guard !parsed.isEmpty else { throw ProdKeysError.noKeysFound }
        self.values = parsed
    }

    public func contains(_ name: String) -> Bool {
        values[name] != nil
    }

    public func value(for name: String) -> Data? {
        values[name]
    }

    private static func isValidName(_ name: String) -> Bool {
        guard !name.isEmpty else { return false }
        return name.utf8.allSatisfy { byte in
            (byte >= 0x30 && byte <= 0x39) ||
            (byte >= 0x41 && byte <= 0x5a) ||
            (byte >= 0x61 && byte <= 0x7a) ||
            byte == 0x5f
        }
    }

    private static func hexNibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: return byte - 0x30
        case 0x41...0x46: return byte - 0x41 + 10
        case 0x61...0x66: return byte - 0x61 + 10
        default: return nil
        }
    }
}
