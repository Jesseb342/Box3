import SwiftUI
import UIKit
import UniformTypeIdentifiers
import ConverterCore

@main
struct Box3ConverterApp: App {
    var body: some Scene {
        WindowGroup { ConverterView() }
    }
}

private enum ImportTarget: String {
    case prodKeys, base, update, dlc
    var title: String {
        switch self {
        case .prodKeys: return "prod.keys"
        case .base: return "Base Game (NSP/XCI)"
        case .update: return "Update NSP"
        case .dlc: return "DLC NSP"
        }
    }
}

struct ConverterView: View {
    private let diagnosticBuild = "2026-11-24-aes-ctr-batch"
    @State private var files: [ImportTarget: URL] = [:]
    @State private var activeTarget: ImportTarget?
    @State private var showingImporter = false
    @State private var isRunning = false
    @State private var status = ConversionLogStore.load().isEmpty
        ? "Import your keys and base game NSP to begin."
        : ConversionLogStore.load()
    @State private var outputPath = ""

    private var canRun: Bool { files[.prodKeys] != nil && files[.base] != nil && !isRunning }

    var body: some View {
        NavigationStack {
            Form {
                Section("Required files") {
                    fileRow(.prodKeys)
                    fileRow(.base)
                }
                Section("Optional content") {
                    fileRow(.update)
                    fileRow(.dlc)
                }
                Section("Conversion") {
                    Button {
                        startConversion()
                    } label: {
                        HStack {
                            if isRunning { ProgressView() }
                            Text(isRunning ? "Processing…" : "Extract and rewrite modules")
                        }
                    }
                    .disabled(!canRun)
                    Text("This diagnostic build decrypts and verifies supported program sections, extracts ExeFS, and rewrites NSO modules. It does not yet create the final game IPA.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Section("Status") {
                    Text(status)
                        .textSelection(.enabled)
                    if !outputPath.isEmpty {
                        Text(outputPath).font(.caption2).textSelection(.enabled)
                    }
                    Button {
                        var text = ConversionLogStore.load()
                        if text.isEmpty { text = status }
                        if !outputPath.isEmpty {
                            text += "\nOutput: " + outputPath
                        }
                        UIPasteboard.general.string = text
                    } label: {
                        Label("Copy Output / Error", systemImage: "doc.on.doc")
                    }
                    .disabled(status.isEmpty && outputPath.isEmpty)
                }
            }
            .onAppear {
                let saved = ConversionLogStore.load()
                if !saved.isEmpty { status = saved }
            }
            .navigationTitle("Swapp")
            .fileImporter(
                isPresented: $showingImporter,
                allowedContentTypes: [.data],
                allowsMultipleSelection: false,
                onCompletion: handleImport
            )
        }
    }

    @ViewBuilder
    private func fileRow(_ target: ImportTarget) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text(target.title)
                if let url = files[target] {
                    Text(url.lastPathComponent).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                } else {
                    Text(target == .update || target == .dlc ? "Optional" : "Not selected")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            Button(files[target] == nil ? "Choose" : "Replace") {
                activeTarget = target
                showingImporter = true
            }
        }
    }

    private func handleImport(_ result: Result<[URL], Error>) {
        guard let target = activeTarget else { return }
        activeTarget = nil
        do {
            guard let source = try result.get().first else { return }
            let access = source.startAccessingSecurityScopedResource()
            defer { if access { source.stopAccessingSecurityScopedResource() } }
            let manager = FileManager.default
            let folder = manager.urls(for: .documentDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("Imported", isDirectory: true)
            try manager.createDirectory(at: folder, withIntermediateDirectories: true)
            let ext = source.pathExtension.isEmpty ? "bin" : source.pathExtension
            let destination = folder.appendingPathComponent("\(target.rawValue)-\(UUID().uuidString).\(ext)")
            if manager.fileExists(atPath: destination.path) { try manager.removeItem(at: destination) }
            try manager.copyItem(at: source, to: destination)
            files[target] = destination
            status = "Imported \(target.title)."
        } catch {
            status = "Import failed: \(error.localizedDescription)"
        }
    }

    private func startConversion() {
        guard let keys = files[.prodKeys], let base = files[.base] else { return }
        var packages = [NSPPackageInput(role: .base, url: base)]
        if let update = files[.update] { packages.append(NSPPackageInput(role: .update, url: update)) }
        if let dlc = files[.dlc] { packages.append(NSPPackageInput(role: .dlc, url: dlc)) }
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let output = documents.appendingPathComponent("Swapp-Modules-\(UUID().uuidString)", isDirectory: true)
        isRunning = true
        status = "Starting conversion…"
        outputPath = ""
        ConversionLogStore.clear()
        ConversionLogStore.append("Swapp diagnostic build: \(diagnosticBuild)")
        ConversionLogStore.append("Conversion started. Files: prod.keys and base package; optional update/DLC selected: update=\(files[.update] != nil), DLC=\(files[.dlc] != nil).")
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try NSPMultiPackageRewritePipeline.process(
                    packages: packages,
                    prodKeysURL: keys,
                    outputDirectory: output,
                    progress: { message in
                        ConversionLogStore.append(message)
                        DispatchQueue.main.async { status = message }
                    }
                )
                DispatchQueue.main.async {
                    isRunning = false
                    outputPath = result.outputDirectory.path
                    let modules = result.packages.reduce(0) { $0 + $1.moduleSets.reduce(0) { $0 + $1.modules.count } }
                    let romFSImages = result.packages.reduce(0) { $0 + $1.romFSImages.count }
                    let romFSBytes = result.packages.reduce(UInt64(0)) { total, package in
                        total + package.romFSImages.reduce(UInt64(0)) { $0 + $1.imageSize }
                    }
                    let romFSMegabytes = Double(romFSBytes) / 1_048_576
                    status = String(
                        format: "Completed. %d package(s), %d NCA file(s), %d rewritten module(s), %d verified RomFS image(s) (%.1f MB).",
                        result.packages.count,
                        result.packages.reduce(0) { $0 + $1.ncaCount },
                        modules,
                        romFSImages,
                        romFSMegabytes
                    )
                    ConversionLogStore.append(status)
                }
            } catch {
                DispatchQueue.main.async {
                    isRunning = false
                    let nsError = error as NSError
                    status = "Conversion stopped. \(String(reflecting: error)) [domain: \(nsError.domain), code: \(nsError.code)]"
                    ConversionLogStore.append(status)
                }
            }
        }
    }
}


private enum ConversionLogStore {
    private static let fileName = "Swapp-Last-Conversion.log"
    private static let lock = NSLock()

    private static var logURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent(fileName)
    }

    static func load() -> String {
        lock.lock()
        defer { lock.unlock() }
        return (try? String(contentsOf: logURL, encoding: .utf8)) ?? ""
    }

    static func clear() {
        lock.lock()
        defer { lock.unlock() }
        try? Data().write(to: logURL, options: .atomic)
    }

    static func append(_ message: String) {
        lock.lock()
        defer { lock.unlock() }
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let line = "[\(timestamp)] \(message)\n"
        let manager = FileManager.default
        if !manager.fileExists(atPath: logURL.path) {
            _ = manager.createFile(atPath: logURL.path, contents: nil)
        }
        do {
            let handle = try FileHandle(forWritingTo: logURL)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: Data(line.utf8))
        } catch {
            // Diagnostics must never interrupt conversion.
        }
    }
}
