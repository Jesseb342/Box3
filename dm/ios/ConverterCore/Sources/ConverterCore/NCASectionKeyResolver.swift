import Foundation

public enum NCASectionKeyResolverError: Error, Equatable {
    case titleKeyCryptoRequiresTitleKeySupport
    case invalidKeyAreaKeyIndex(UInt8)
    case missingKeyAreaKey(String)
    case invalidKeyAreaKeyLength(Int)
    case invalidEncryptedKeyAreaLength(Int)
}

/// Resolves the section CTR key for standard NCA3 crypto from a user's
/// already-derived prod.keys key-area key. It deliberately does not derive
/// console/master keys or attempt title-key crypto.
public enum NCASectionKeyResolver {
    public enum KeyArea: UInt8, CaseIterable {
        case application = 0
        case ocean = 1
        case system = 2

        fileprivate var keyName: String {
            switch self {
            case .application: return "application"
            case .ocean: return "ocean"
            case .system: return "system"
            }
        }
    }

    /// Decrypts the four 16-byte slots in the NCA key area using the exact
    /// key-area generation and key-area index encoded in the NCA header.
    public static func decryptKeyArea(header: NCAHeader, keys: ProdKeys) throws -> [Data] {
        guard !header.usesTitleKeyCrypto else {
            throw NCASectionKeyResolverError.titleKeyCryptoRequiresTitleKeySupport
        }
        guard let area = KeyArea(rawValue: header.keyAreaKeyIndex) else {
            throw NCASectionKeyResolverError.invalidKeyAreaKeyIndex(header.keyAreaKeyIndex)
        }
        guard header.encryptedKeyArea.count == 0x40 else {
            throw NCASectionKeyResolverError.invalidEncryptedKeyAreaLength(header.encryptedKeyArea.count)
        }
        let name = String(format: "key_area_key_%@_%02x", area.keyName, header.keyAreaGenerationIndex)
        guard let wrappingKey = keys.value(for: name) else {
            throw NCASectionKeyResolverError.missingKeyAreaKey(name)
        }
        guard wrappingKey.count == 16 else {
            throw NCASectionKeyResolverError.invalidKeyAreaKeyLength(wrappingKey.count)
        }
        let clear = try AESXTS.decryptECB(header.encryptedKeyArea, key: wrappingKey)
        return stride(from: 0, to: clear.count, by: 16).map {
            clear.subdata(in: $0..<($0 + 16))
        }
    }

    /// Standard NCA CTR/BKTR sections use key slot 2 (the third 16-byte slot).
    public static func sectionCTRKey(header: NCAHeader, keys: ProdKeys) throws -> Data {
        let slots = try decryptKeyArea(header: header, keys: keys)
        guard slots.count == 4 else {
            throw NCASectionKeyResolverError.invalidEncryptedKeyAreaLength(header.encryptedKeyArea.count)
        }
        return slots[2]
    }
}
