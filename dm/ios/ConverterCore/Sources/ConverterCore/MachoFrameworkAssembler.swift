import Foundation
import Box3NSOBridge

/// Calls the pinned iBuilder Mach-O assembler through its narrow C ABI.
/// The host dylib must be a separately built, verified NXNative-compatible iOS host.
public enum MachOFrameworkAssembler {
    public struct Assembly: Sendable {
        public let outputURL: URL
        public let size: UInt64
    }

    public enum AssemblyError: LocalizedError {
        case rejected(String)
        public var errorDescription: String? {
            switch self { case .rejected(let message): return message }
        }
    }

    public static func assemble(hostURL: URL, outputURL: URL,
                                rewrittenModulesDirectory: URL, modules: [String],
                                tag: String = "") throws -> Assembly {
        guard !modules.isEmpty, modules.allSatisfy({
            !$0.isEmpty && $0.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "-") }
        }) else { throw AssemblyError.rejected("At least one valid module name is required.") }
        var size: UInt64 = 0
        var errorBuffer = [CChar](repeating: 0, count: 2048)
        let status = hostURL.path.withCString { host in
            outputURL.path.withCString { output in
                rewrittenModulesDirectory.path.withCString { directory in
                    modules.joined(separator: ",").withCString { moduleList in
                        tag.withCString { tagValue in
                            errorBuffer.withUnsafeMutableBufferPointer { buffer in
                                box3_macho_assemble(host, output, directory, moduleList, tagValue,
                                                    &size, buffer.baseAddress, buffer.count)
                            }
                        }
                    }
                }
            }
        }
        guard status == 0 else {
            let message = errorBuffer.withUnsafeBufferPointer { buffer in
                buffer.baseAddress.map(String.init(cString:)) ?? "Mach-O assembly failed (code \\(status))."
            }
            throw AssemblyError.rejected(message)
        }
        return Assembly(outputURL: outputURL, size: size)
    }
}
