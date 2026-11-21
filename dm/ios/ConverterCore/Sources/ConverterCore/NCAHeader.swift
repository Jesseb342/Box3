import Foundation

public enum NCAHeaderError: Error, Equatable {
    case truncatedHeader
    case invalidMagic
    case unsupportedContentType(UInt8)
    case invalidDeclaredSize
    case fileSizeMismatch
    case invalidSectionRange(Int)
}

/// Parsed view of the plaintext 0xC00-byte NCA header.
///
/// Raw NCA files store this header encrypted with AES-XTS. This type deliberately
/// accepts plaintext only; decryption is a separate, independently tested stage.
public struct NCAHeader {
    public struct Section: Equatable {
        public let index: Int
        public let mediaStart: UInt32
        public let mediaEnd: UInt32

        public var byteOffset: UInt64 { UInt64(mediaStart) * 0x200 }
        public var byteSize: UInt64 { UInt64(mediaEnd - mediaStart) * 0x200 }
    }

    public enum ContentType: UInt8, Equatable {
        case program = 0
        case meta = 1
        case control = 2
        case manual = 3
        case data = 4
        case publicData = 5
    }

    public let magic: String
    public let contentType: ContentType
    public let distributionType: UInt8
    public let oldKeyGeneration: UInt8
    public let keyAreaKeyIndex: UInt8
    public let declaredSize: UInt64
    public let titleID: UInt64
    public let contentIndex: UInt32
    public let keyGeneration: UInt8
    public let rightsID: Data
    public let sections: [Section]

    public var usesTitleKeyCrypto: Bool {
        rightsID.contains(where: { $0 != 0 })
    }

    public init(plaintextHeader data: Data, actualFileSize: UInt64? = nil) throws {
        guard data.count >= 0xC00 else { throw NCAHeaderError.truncatedHeader }
        let magicData = data.subdata(in: 0x200..<0x204)
        guard let magic = String(data: magicData, encoding: .ascii),
              ["NCA0", "NCA2", "NCA3"].contains(magic) else {
            throw NCAHeaderError.invalidMagic
        }

        guard let contentType = ContentType(rawValue: data[0x205]) else {
            throw NCAHeaderError.unsupportedContentType(data[0x205])
        }

        let declaredSize = Self.u64(data, 0x208)
        guard declaredSize >= 0xC00 else { throw NCAHeaderError.invalidDeclaredSize }
        if let actualFileSize, declaredSize != actualFileSize {
            throw NCAHeaderError.fileSizeMismatch
        }

        var sections: [Section] = []
        for index in 0..<4 {
            let offset = 0x240 + index * 0x10
            let start = Self.u32(data, offset)
            let end = Self.u32(data, offset + 4)
            if start == 0 && end == 0 { continue }
            guard start > 0, end > start,
                  UInt64(end) * 0x200 <= declaredSize else {
                throw NCAHeaderError.invalidSectionRange(index)
            }
            sections.append(Section(index: index, mediaStart: start, mediaEnd: end))
        }

        self.magic = magic
        self.contentType = contentType
        self.distributionType = data[0x204]
        self.oldKeyGeneration = data[0x206]
        self.keyAreaKeyIndex = data[0x207]
        self.declaredSize = declaredSize
        self.titleID = Self.u64(data, 0x210)
        self.contentIndex = Self.u32(data, 0x218)
        self.keyGeneration = data[0x220]
        self.rightsID = data.subdata(in: 0x230..<0x240)
        self.sections = sections
    }

    private static func u32(_ data: Data, _ offset: Int) -> UInt32 {
        UInt32(data[offset]) |
        (UInt32(data[offset + 1]) << 8) |
        (UInt32(data[offset + 2]) << 16) |
        (UInt32(data[offset + 3]) << 24)
    }

    private static func u64(_ data: Data, _ offset: Int) -> UInt64 {
        UInt64(u32(data, offset)) | (UInt64(u32(data, offset + 4)) << 32)
    }
}
