import SwiftUI
import UniformTypeIdentifiers
import ConverterCore

@main
struct Box3ConverterApp: App {
    var body: some Scene {
        WindowGroup { ConverterView() }
    }
}

private enum ImportTarget: String {
    case prodKeys, titleKeys, base, update, dlc
    var title: String {
        switch self {
        case .prodKeys: return "prod.keys"
        case .titleKeys: return "title.keys"
        case .base: return "Base NSP"
        case .update: return "Update NSP"
        case .dlc: return "DLC NSP"
        }
    }
}

struct ConverterView: View {
    @State private var files: [ImportTarget: URL] = [:]
    @State private var activeTarget: ImportTarget?
    @State private var showingImporter = false
    @State private var isRunning = false
    @State private var status = "Import your keys and base game NSP to begin."
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
                    fileRow(.titleKeys)
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
                    if !outputPath.isEmpty {
                        Text(outputPath).font(.caption2).textSelection(.enabled)
                    }
                }
            }
            .navigationTitle("Box3 Converter")
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
                    Text(target == .titleKeys || target == .update || target == .dlc ? "Optional" : "Not selected")
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
        let titleKeys = files[.titleKeys]
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let output = documents.appendingPathComponent("Box3-Modules-\(UUID().uuidString)", isDirectory: true)
        isRunning = true
        status = "Inspecting NSP files, decrypting supported sections, verifying PFS0, and rewriting modules…"
        outputPath = ""
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try NSPMultiPackageRewritePipeline.process(
                    packages: packages,
                    prodKeysURL: keys,
                    titleKeysURL: titleKeys,
                    outputDirectory: output
                )
                DispatchQueue.main.async {
                    isRunning = false
                    outputPath = result.outputDirectory.path
                    let modules = result.packages.reduce(0) { $0 + $1.moduleSets.reduce(0) { $0 + $1.modules.count } }
                    status = "Completed. \(result.packages.count) package(s), \(result.packages.reduce(0) { $0 + $1.ncaCount }) NCA file(s), \(modules) rewritten module(s)."
                }
            } catch {
                DispatchQueue.main.async {
                    isRunning = false
                    status = "Conversion stopped: \(error.localizedDescription)"
                }
            }
        }
    }
}
