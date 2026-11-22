#if os(iOS)
import Foundation
import Box3NSOBridge

public struct RustNSOImage {
    public let image: Data
    public let segments: [(offset: UInt32, size: UInt32)]
    public let bssSize: UInt32
    public let buildID: Data
}

public enum RustNSOLoaderError: Error, LocalizedError {
    case rejected(String)
    case invalidResult

    public var errorDescription: String? {
        switch self {
        case .rejected(let message): return message
        case .invalidResult: return "The Rust NSO loader returned invalid output."
        }
    }
}

/// iOS adapter for iBuilder's validated NSO/NRO loader.
/// The input is borrowed only for the duration of load; returned bytes are copied into Swift-owned Data.
public enum RustNSOLoader {
    public static func load(_ data: Data) throws -> RustNSOImage {
        var handle: OpaquePointer?
        var error = [CChar](repeating: 0, count: 512)
        let status = data.withUnsafeBytes { input in
            error.withUnsafeMutableBufferPointer { errorBuffer in
                box3_nso_load(
                    input.bindMemory(to: UInt8.self).baseAddress,
                    input.count,
                    &handle,
                    errorBuffer.baseAddress,
                    errorBuffer.count
                )
            }
        }
        guard status == 0, let module = handle else {
            throw RustNSOLoaderError.rejected(String(cString: error))
        }
        defer { box3_nso_free(module) }

        var imageLength = 0
        guard let imagePointer = box3_nso_image(module, &imageLength), imageLength > 0 else {
            throw RustNSOLoaderError.invalidResult
        }
        let image = Data(bytes: imagePointer, count: imageLength)

        var rawSegments = [UInt32](repeating: 0, count: 6)
        var bss: UInt32 = 0
        var buildID = [UInt8](repeating: 0, count: 32)
        let metadataStatus = rawSegments.withUnsafeMutableBufferPointer { segments in
            buildID.withUnsafeMutableBufferPointer { build in
                box3_nso_metadata(module, segments.baseAddress, &bss, build.baseAddress)
            }
        }
        guard metadataStatus == 0 else { throw RustNSOLoaderError.invalidResult }

        let segments = stride(from: 0, to: rawSegments.count, by: 2).map {
            (offset: rawSegments[$0], size: rawSegments[$0 + 1])
        }
        return RustNSOImage(
            image: image,
            segments: segments,
            bssSize: bss,
            buildID: Data(buildID)
        )
    }
}
#endif
