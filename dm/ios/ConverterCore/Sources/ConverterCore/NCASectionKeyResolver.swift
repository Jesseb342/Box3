import Foundation

public enum NCASectionKeyResolverError: Error, Equatable {
    case titleKeyCryptoRequiresTitleKeySupport
    case invalidKeyAreaKeyIndex(UInt8)
    case missingKeyAreaKey(String)
    case invalidKeyAreaKeyLength(Int)
    case invalidEncryptedKeyAreaLength(Int)
    case missingTitleKey(String)
    case missingTitleKek(String)
    case invalidTitleKekLength(Int)
}

/// Resolves standard key-area keys and Rights ID title keys from user-provided key files.
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

    /// Resolves the decrypted title key for an NCA carrying a nonzero Rights ID.
    public static func titleKey(header: NCAHeader, keys: ProdKeys, titleKeys: TitleKeys) throws -> Data {
        guard header.usesTitleKeyCrypto else {
            throw NCASectionKeyResolverError.titleKeyCryptoRequiresTitleKeySupport
        }
        let rightsName = header.rightsID.map { String(format: "%02x", $0) }.joined()
        guard let encryptedTitleKey = titleKeys.encryptedTitleKey(for: header.rightsID) else {
            throw NCASectionKeyResolverError.missingTitleKey(rightsName)
        }
        // The NCA header's crypto_type/crypto_type2 selects the titlekek generation.
        // Ticket master_key_revision is metadata and must not override this value.
        let generation = header.keyAreaGenerationIndex
        let primaryName = String(format: "titlekek_%02x", generation)
        let aliasName = String(format: "ticket_commonkey_%02x", generation)
        guard let titleKek = keys.value(for: primaryName) ?? keys.value(for: aliasName) else {
            throw NCASectionKeyResolverError.missingTitleKek(primaryName)
        }
        guard titleKek.count == 16 else {
            throw NCASectionKeyResolverError.invalidTitleKekLength(titleKek.count)
        }
        return try AESXTS.decryptECB(encryptedTitleKey, key: titleKek)
    }

    /// Standard NCA CTR/BKTR sections use key slot 2 (the third 16-byte slot).
    public static func sectionCTRKey(header: NCAHeader, keys: ProdKeys) throws -> Data {
        let slots = try decryptKeyArea(header: header, keys: keys)
        guard slots.count == 4 else {
            throw NCASectionKeyResolverError.invalidEncryptedKeyAreaLength(header.encryptedKeyArea.count)
        }
        return slots[2]
    }

    /// Selects title-key crypto when the NCA Rights ID is present, otherwise key-area slot 2.
    public static func sectionCTRKey(header: NCAHeader, keys: ProdKeys, titleKeys: TitleKeys) throws -> Data {
        if header.usesTitleKeyCrypto {
            return try titleKey(header: header, keys: keys, titleKeys: titleKeys)
        }
        return try sectionCTRKey(header: header, keys: keys)
    }
}
