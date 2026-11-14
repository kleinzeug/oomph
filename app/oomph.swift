// oomph — menu bar front-end for the oomph daemon (see ../DESIGN.md).
// Build: ../build-app.sh
import AppKit
import Charts
import SwiftUI

let logDir = ProcessInfo.processInfo.environment["OOMPH_DIR"] ?? "/Library/Logs/oomph"
let agentLabel = "local.oomph.menubar"
let agentPlist = NSHomeDirectory() + "/Library/LaunchAgents/\(agentLabel).plist"

// MARK: - Model

struct Away: Decodable { var idle_s: Int?; var display_on: Bool?; var locked: Bool?; var sleep_preventers: [String]? }
struct Group: Decodable { var name: String; var mb: Int; var n: Int? }
struct Session: Decodable { var pid: Int; var cwd: String?; var mb: Int; var n: Int }
struct Lease: Decodable, Identifiable {
    var id: String; var state: String; var gb: Double; var purpose: String; var project: String?
    var used_gb: Double?; var for_min: Double?; var waiting_min: Double?
}
struct DaemonInfo: Decodable { var pid: Int?; var version: String?; var interval: Double?; var incident: String?; var root: Bool? }

struct Sample: Decodable {
    var t: Double
    var pressure: Int
    var free_pct: Int?
    var ram_gb: Double
    var app_gb: Double
    var wired_gb: Double
    var compressed_gb: Double
    var swap_used_gb: Double
    var swap_total_gb: Double
    var swapfiles: Int?
    var disk_free_gb: Double
    var jetsam_kills: Int?
    var away: Away?
    var groups: [Group]?
    var claude: [Session]?
    var leases: [Lease]?
    var daemon: DaemonInfo?

    var isAway: Bool {
        guard let a = away else { return false }
        return (a.idle_s ?? 0) >= 300 || (a.locked ?? false) || a.display_on == false
    }
}

struct Point: Identifiable {
    let id: Double
    let date: Date
    let wired, app, comp, swap: Double
    let away: Bool
    let kills: Int
}

struct Reason: Decodable { var kind: String; var desc: String }
struct IncidentSummary: Decodable { var jetsam_kills: Int?; var max_swap_used_gb: Double?; var min_disk_free_gb: Double? }
struct Incident: Decodable, Identifiable {
    var id: String
    var start: Double
    var end: Double?
    var open: Bool?
    var reasons: [Reason]
    var summary: IncidentSummary?
    var dir: String = ""
    enum CodingKeys: String, CodingKey { case id, start, end, open, reasons, summary }
}

enum Pressure: Int { case unknown = 0, normal = 1, warn = 2, critical = 4
    var label: String { switch self { case .normal: "Normal"; case .warn: "Warning"; case .critical: "Critical"; default: "–" } }
    var color: Color { switch self { case .warn: .yellow; case .critical: .red; default: .green } }
}

// MARK: - Store

final class Store: ObservableObject {
    @Published var current: Sample?
    @Published var currentAge: Double = .infinity
    @Published var points: [Point] = []
    @Published var incidents: [Incident] = []
    @Published var range: Double = 6 * 3600 { didSet { reloadPoints() } }
    @Published var launchAtLogin = FileManager.default.fileExists(atPath: agentPlist)
    @Published var busy = false

    private var cache: [String: (offset: UInt64, pts: [Point])] = [:]
    private let decoder = JSONDecoder()

    var daemonRunning: Bool {
        guard let c = current else { return false }
        return currentAge < 3 * (c.daemon?.interval ?? 30) + 15
    }
    var installed: Bool { FileManager.default.fileExists(atPath: "/Library/LaunchDaemons/local.oomph.daemon.plist") }

    static func version(at path: String) -> String? {
        guard let s = try? String(contentsOfFile: path, encoding: .utf8),
              let r = s.range(of: #"VERSION = "([^"]+)""#, options: .regularExpression) else { return nil }
        return String(s[r]).replacingOccurrences(of: "VERSION = ", with: "").replacingOccurrences(of: "\"", with: "")
    }
    var installedVersion: String? { Store.version(at: "/usr/local/libexec/oomph/oomph.py") }
    var bundledVersion: String? { Store.version(at: (Bundle.main.resourcePath ?? "") + "/oomph.py") }
    var needsUpdate: Bool { installed && installedVersion != nil && bundledVersion != nil && installedVersion != bundledVersion }

    var lastSeenIncident: String {
        get { UserDefaults.standard.string(forKey: "lastSeenIncident") ?? "" }
        set { UserDefaults.standard.set(newValue, forKey: "lastSeenIncident"); objectWillChange.send() }
    }
    var hasUnseen: Bool { (incidents.first?.id ?? "") > lastSeenIncident }

    func refreshCurrent() {
        let p = logDir + "/current.json"
        guard let d = FileManager.default.contents(atPath: p), let s = try? decoder.decode(Sample.self, from: d) else {
            current = nil; currentAge = .infinity; return
        }
        current = s
        currentAge = Date().timeIntervalSince1970 - s.t
    }

    func refreshAll() {
        refreshCurrent()
        reloadPoints()
        loadIncidents()
    }

    func reloadPoints() {
        let now = Date().timeIntervalSince1970
        let since = now - range
        var days: [String] = []
        let fmt = DateFormatter(); fmt.dateFormat = "yyyy-MM-dd"
        var d = since
        while d <= now + 1 { days.append(fmt.string(from: Date(timeIntervalSince1970: d))); d += 86400 }
        let today = fmt.string(from: Date())
        if !days.contains(today) { days.append(today) }
        var all: [Point] = []
        for day in Array(Set(days)).sorted() { all += loadDay(day, isToday: day == today) }
        let pts = all.filter { $0.id >= since }
        points = downsample(pts, max: 360)
    }

    private func loadDay(_ day: String, isToday: Bool) -> [Point] {
        let plain = "\(logDir)/samples-\(day).jsonl"
        let gz = plain + ".gz"
        let fm = FileManager.default
        if fm.fileExists(atPath: plain) {
            var entry = cache[plain] ?? (0, [])
            guard let fh = FileHandle(forReadingAtPath: plain) else { return entry.pts }
            defer { try? fh.close() }
            let size = (try? fh.seekToEnd()) ?? 0
            if size < entry.offset { entry = (0, []) }
            try? fh.seek(toOffset: entry.offset)
            let data = fh.readDataToEndOfFile()
            if let lastNL = data.lastIndex(of: 0x0A) {
                let chunk = data[data.startIndex...lastNL]
                entry.pts += parse(chunk)
                entry.offset += UInt64(chunk.count)
            }
            cache[plain] = entry
            return entry.pts
        } else if fm.fileExists(atPath: gz) {
            if let c = cache[gz] { return c.pts }
            let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/gzip"); p.arguments = ["-dc", gz]
            let pipe = Pipe(); p.standardOutput = pipe
            do { try p.run() } catch { return [] }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            let pts = parse(data[...])
            cache[gz] = (0, pts)
            return pts
        }
        return []
    }

    private func parse(_ data: Data.SubSequence) -> [Point] {
        var out: [Point] = []
        for line in data.split(separator: 0x0A) {
            guard let s = try? decoder.decode(Sample.self, from: Data(line)) else { continue }
            out.append(Point(id: s.t, date: Date(timeIntervalSince1970: s.t), wired: s.wired_gb, app: s.app_gb,
                             comp: s.compressed_gb, swap: s.swap_used_gb, away: s.isAway, kills: s.jetsam_kills ?? 0))
        }
        return out
    }

    private func downsample(_ pts: [Point], max n: Int) -> [Point] {
        guard pts.count > n else { return pts }
        let step = Double(pts.count) / Double(n)
        var out: [Point] = []
        var i = 0.0
        while Int(i) < pts.count {
            let lo = Int(i), hi = min(pts.count, Int(i + step))
            let slice = pts[lo..<max(hi, lo + 1)]
            // keep the worst point of each bucket so spikes survive
            let worst = slice.max { ($0.app + $0.comp + $0.swap) < ($1.app + $1.comp + $1.swap) }!
            out.append(Point(id: worst.id, date: worst.date, wired: worst.wired, app: worst.app, comp: worst.comp,
                             swap: worst.swap, away: slice.contains { $0.away }, kills: slice.reduce(0) { $0 + $1.kills }))
            i += step
        }
        return out
    }

    func loadIncidents() {
        let dir = logDir + "/incidents"
        let ids = ((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []).sorted(by: >).prefix(30)
        incidents = ids.compactMap { id in
            let p = "\(dir)/\(id)/incident.json"
            guard let d = FileManager.default.contents(atPath: p), var inc = try? decoder.decode(Incident.self, from: d) else { return nil }
            inc.dir = "\(dir)/\(id)"
            return inc
        }
    }

    // MARK: actions
    func runPrivileged(_ script: String, completion: @escaping (String?) -> Void) {
        guard let res = Bundle.main.resourcePath else { return }
        let cmd = "'\(res)/\(script)'"
        busy = true
        DispatchQueue.global().async {
            var err: NSDictionary?
            let src = "do shell script \"\(cmd)\" with prompt \"oomph needs administrator rights to install or remove its memory-logging daemon.\" with administrator privileges"
            let out = NSAppleScript(source: src)?.executeAndReturnError(&err)
            DispatchQueue.main.async {
                self.busy = false
                if let e = err, (e[NSAppleScript.errorNumber] as? Int) != -128 {
                    completion((e[NSAppleScript.errorMessage] as? String) ?? "failed")
                } else { completion(nil) }
                _ = out
                DispatchQueue.main.asyncAfter(deadline: .now() + 3) { self.refreshAll() }
            }
        }
    }

    func setLaunchAtLogin(_ on: Bool) {
        if on {
            let exe = Bundle.main.executablePath ?? ""
            let plist: [String: Any] = ["Label": agentLabel, "ProgramArguments": [exe], "RunAtLoad": true,
                                        "ProcessType": "Interactive", "LimitLoadToSessionType": "Aqua"]
            try? FileManager.default.createDirectory(atPath: NSHomeDirectory() + "/Library/LaunchAgents", withIntermediateDirectories: true)
            (plist as NSDictionary).write(toFile: agentPlist, atomically: true)
        } else {
            try? FileManager.default.removeItem(atPath: agentPlist)
        }
        launchAtLogin = FileManager.default.fileExists(atPath: agentPlist)
    }

    func open(_ inc: Incident) {
        let report = inc.dir + "/report.html"
        if FileManager.default.fileExists(atPath: report) {
            NSWorkspace.shared.open(URL(fileURLWithPath: report))
        } else {
            runCLI(["incident", inc.id, "--html"])
        }
    }

    func runCLI(_ args: [String]) {
        let cli = FileManager.default.fileExists(atPath: "/usr/local/libexec/oomph/oomph.py")
            ? "/usr/local/libexec/oomph/oomph.py" : (Bundle.main.resourcePath ?? "") + "/oomph.py"
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = ["-I", "-B", cli] + args
        try? p.run()
    }
}

// MARK: - Views

struct Stat: View {
    let label: String, value: String
    var warn = false
    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(value).font(.system(size: 13, weight: .semibold)).monospacedDigit().foregroundStyle(warn ? .red : .primary)
            Text(label).font(.system(size: 10)).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct PopoverView: View {
    @ObservedObject var store: Store
    @State private var error: String?
    private let series = ["Wired", "App", "Compressed", "Swap"]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
                .padding(.horizontal, 14).padding(.vertical, 11)
                .frame(maxWidth: .infinity)
                .background(Color.primary.opacity(0.045))
            Divider()
            VStack(alignment: .leading, spacing: 10) {
                if let c = store.current, store.daemonRunning { stats(c) }
                if let ls = store.current?.leases, !ls.isEmpty, store.daemonRunning { leases(ls) }
                chart
                incidentsList
                Divider()
                footer
            }
            .padding(14)
        }
        .frame(width: 428)
        .alert("oomph", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
            Button("OK") { error = nil }
        } message: { Text(error ?? "") }
    }

    var header: some View {
        let live = store.current != nil && store.daemonRunning
        let p = live ? (Pressure(rawValue: store.current!.pressure) ?? .unknown) : .unknown
        let tint: Color = live ? p.color : .secondary
        return HStack(alignment: .center, spacing: 10) {
            Image(systemName: "memorychip")
                .font(.system(size: 16, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 32, height: 32)
                .background(tint.opacity(0.16), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            VStack(alignment: .leading, spacing: 2) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    (Text("oomph").fontWeight(.bold) + Text(": memory monitor").fontWeight(.medium))
                        .font(.system(size: 14))
                    if let v = store.bundledVersion {
                        Text("v" + v).font(.system(size: 10, design: .monospaced)).foregroundStyle(.tertiary)
                            .help(store.needsUpdate ? "Installed logger: v\(store.installedVersion ?? "?")" : "")
                    }
                }
                Text(statusLine).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 8)
            if live {
                Text(p.label).font(.system(size: 11, weight: .semibold))
                    .padding(.horizontal, 10).padding(.vertical, 4)
                    .background(p.color.opacity(0.2), in: Capsule())
                    .foregroundStyle(p == .normal ? .primary : p.color)
            }
        }
    }

    var statusLine: String {
        if !store.installed { return "Logging is off — click Activate" }
        if !store.daemonRunning { return "Daemon installed but not reporting" }
        let d = store.current?.daemon
        var s = "Logging every \(Int(d?.interval ?? 30)) s"
        if let i = d?.incident { s += " · incident \(i) open" }
        return s
    }

    func stats(_ c: Sample) -> some View {
        let idle = c.away?.idle_s ?? 0
        return VStack(spacing: 8) {
            HStack {
                Stat(label: "App memory", value: String(format: "%.1f GB", c.app_gb))
                Stat(label: "Compressed", value: String(format: "%.1f GB", c.compressed_gb))
                Stat(label: "Wired", value: String(format: "%.1f GB", c.wired_gb))
                Stat(label: "RAM", value: String(format: "%.0f GB", c.ram_gb))
            }
            HStack {
                Stat(label: "Swap used / size", value: String(format: "%.1f / %.0f GB", c.swap_used_gb, c.swap_total_gb))
                Stat(label: "Free disk", value: String(format: "%.0f GB", c.disk_free_gb), warn: c.disk_free_gb < 20)
                Stat(label: "Idle", value: idle >= 120 ? "\(idle / 60) min" : "\(idle) s")
                Stat(label: "Top app", value: shortTop(c))
            }
        }
    }

    // Memory Claude sessions have reserved through `oomph reserve` / `oomph run` / the MCP server.
    func leases(_ ls: [Lease]) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("Reserved by sessions").font(.caption).foregroundStyle(.secondary)
            ForEach(ls) { (l: Lease) in
                HStack(spacing: 6) {
                    Circle().fill(l.state == "granted" ? Color.green : Color.orange).frame(width: 6, height: 6)
                    Text(String(format: "%.1fG", l.gb)).font(.system(size: 11, weight: .semibold)).monospacedDigit()
                        .frame(width: 40, alignment: .trailing)
                    Text(l.purpose).font(.system(size: 11)).lineLimit(1)
                    if let p = l.project { Text(p).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1) }
                    Spacer()
                    Text(leaseTail(l)).font(.system(size: 10)).foregroundStyle(.secondary).monospacedDigit()
                }
            }
        }
    }

    func leaseTail(_ l: Lease) -> String {
        if l.state == "granted" { return String(format: "using %.1fG", l.used_gb ?? 0) }
        return "waiting \(Int(l.waiting_min ?? 0)) min"
    }

    func shortTop(_ c: Sample) -> String {
        guard let g = c.groups?.first else { return "–" }
        let n = g.name.count > 9 ? String(g.name.prefix(8)) + "…" : g.name
        return String(format: "%@ %.1fG", n, Double(g.mb) / 1024)
    }

    var chart: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("Memory, GB").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Picker("", selection: $store.range) {
                    Text("1h").tag(3600.0); Text("6h").tag(6 * 3600.0); Text("24h").tag(24 * 3600.0)
                }.pickerStyle(.segmented).frame(width: 140).labelsHidden()
            }
            if store.points.isEmpty {
                Text("No samples yet").font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, minHeight: 140)
            } else {
                Chart {
                    awayMarks
                    stackMarks
                    ramMark
                    incidentMarks
                }
                .chartForegroundStyleScale(domain: series, range: [Color.gray, Color.blue, Color.orange, Color.red])
                .chartLegend(position: .bottom, spacing: 4)
                .frame(height: 160)
                Text("Grey bands = away (idle ≥ 5 min, locked or display off) · red lines = incidents")
                    .font(.system(size: 9)).foregroundStyle(.secondary)
            }
        }
    }

    // Chart content is split into small, explicitly typed pieces: one big Chart { … }
    // expression is too much for the type checker of older Swift toolchains.
    struct Span: Identifiable { let id: Double; let from: Date; let to: Date }
    struct StackEntry: Identifiable { let id: String; let date: Date; let kind: String; let gb: Double }

    var stackEntries: [StackEntry] {
        var out: [StackEntry] = []
        out.reserveCapacity(store.points.count * 4)
        for p in store.points {
            let values: [Double] = [p.wired, p.app, p.comp, p.swap]
            for (i, name) in series.enumerated() {
                out.append(StackEntry(id: "\(p.id)-\(name)", date: p.date, kind: name, gb: values[i]))
            }
        }
        return out
    }

    @ChartContentBuilder var awayMarks: some ChartContent {
        ForEach(awaySpans().map { Span(id: $0.0.timeIntervalSince1970, from: $0.0, to: $0.1) }) { (span: Span) in
            RectangleMark(xStart: .value("from", span.from), xEnd: .value("to", span.to))
                .foregroundStyle(Color.gray.opacity(0.15))
        }
    }

    @ChartContentBuilder var stackMarks: some ChartContent {
        ForEach(stackEntries) { (e: StackEntry) in
            AreaMark(x: .value("time", e.date), y: .value("GB", e.gb))
                .foregroundStyle(by: .value("kind", e.kind))
        }
    }

    @ChartContentBuilder var ramMark: some ChartContent {
        if let ram = store.current?.ram_gb {
            RuleMark(y: .value("RAM", ram))
                .lineStyle(StrokeStyle(lineWidth: 1, dash: [4, 3]))
                .foregroundStyle(Color.primary.opacity(0.6))
        }
    }

    @ChartContentBuilder var incidentMarks: some ChartContent {
        let since: Double = store.points.first?.id ?? 0
        ForEach(store.incidents.filter { $0.start >= since }) { (inc: Incident) in
            RuleMark(x: .value("incident", Date(timeIntervalSince1970: inc.start)))
                .foregroundStyle(Color.red)
        }
    }

    func awaySpans() -> [(Date, Date)] {
        var out: [(Date, Date)] = []
        var start: Date?
        var prev: Date?
        for p in store.points {
            if p.away { if start == nil { start = p.date } } else if let s = start { out.append((s, prev ?? s)); start = nil }
            prev = p.date
        }
        if let s = start, let l = prev { out.append((s, l)) }
        return out
    }

    var incidentsList: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Incidents").font(.caption).foregroundStyle(.secondary)
            if store.incidents.isEmpty {
                Text("None recorded").font(.caption).foregroundStyle(.tertiary)
            } else {
                ScrollView {
                    VStack(spacing: 2) {
                        ForEach(store.incidents) { inc in
                            Button { store.open(inc) } label: { row(inc) }
                                .buttonStyle(.plain)
                                .contextMenu {
                                    Button("Open report") { store.open(inc) }
                                    Button("Copy path") {
                                        NSPasteboard.general.clearContents()
                                        NSPasteboard.general.setString(inc.dir, forType: .string)
                                    }
                                    Button("Reveal in Finder") { NSWorkspace.shared.selectFile(inc.dir + "/incident.json", inFileViewerRootedAtPath: inc.dir) }
                                }
                        }
                    }
                }.frame(maxHeight: 130)
            }
        }
    }

    func row(_ inc: Incident) -> some View {
        let f = DateFormatter(); f.dateFormat = "EEE d MMM HH:mm"
        let kills = inc.summary?.jetsam_kills
        return HStack(alignment: .top, spacing: 6) {
            Circle().fill(inc.open == true ? Color.red : (inc.id > store.lastSeenIncident ? Color.orange : Color.secondary.opacity(0.4)))
                .frame(width: 6, height: 6).padding(.top, 5)
            VStack(alignment: .leading, spacing: 0) {
                Text(f.string(from: Date(timeIntervalSince1970: inc.start)) + (inc.open == true ? " · open" : ""))
                    .font(.system(size: 11, weight: .medium))
                Text(inc.reasons.first?.desc ?? "").font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if let k = kills, k > 0 { Text("\(k) kills").font(.system(size: 10)).foregroundStyle(.red) }
        }
        .padding(.vertical, 3).padding(.horizontal, 4)
        .contentShape(Rectangle())
    }

    var footer: some View {
        HStack {
            if store.needsUpdate {
                Button("Update") {
                    store.runPrivileged("install.sh") { error = $0 }
                }.buttonStyle(.borderedProminent).disabled(store.busy)
                .help("Installed logger is v\(store.installedVersion ?? "?"), this app ships v\(store.bundledVersion ?? "?")")
            }
            if store.installed {
                Button("Deactivate") {
                    store.runPrivileged("uninstall.sh") { error = $0 }
                }.disabled(store.busy)
            } else {
                Button("Activate") {
                    store.runPrivileged("install.sh") { error = $0 }
                }.buttonStyle(.borderedProminent).disabled(store.busy)
            }
            Button("Report") { store.runCLI(["html", "--last", "\(Int(store.range / 3600))h", "--open"]) }
                .help("Open an HTML report for the selected range")
            Spacer()
            Toggle("Launch at login", isOn: Binding(get: { store.launchAtLogin }, set: { store.setLaunchAtLogin($0) }))
                .toggleStyle(.checkbox).font(.caption)
            Button {
                NSApp.terminate(nil)
            } label: { Image(systemName: "power") }.help("Quit oomph")
        }
        .controlSize(.small)
    }
}

// MARK: - App delegate / status item

/// Borderless panel used instead of NSPopover, positioned explicitly below the status item.
final class PopupPanel: NSPanel {
    override var canBecomeKey: Bool { true }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    let store = Store()
    var item: NSStatusItem!
    var panel: PopupPanel!
    var hosting: NSHostingView<PopoverView>!
    var timer: Timer?
    var clickMonitor: Any?
    var lastClose = Date.distantPast

    var isShown: Bool { panel?.isVisible ?? false }

    func applicationDidFinishLaunching(_ n: Notification) {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.target = self
        item.button?.action = #selector(toggle)
        item.button?.imageScaling = .scaleNone

        panel = PopupPanel(contentRect: NSRect(x: 0, y: 0, width: 428, height: 400),
                           styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: true)
        panel.level = .popUpMenu
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]
        panel.delegate = self
        let fx = NSVisualEffectView()
        fx.material = .popover
        fx.blendingMode = .behindWindow
        fx.state = .active
        fx.wantsLayer = true
        fx.layer?.cornerRadius = 10
        fx.layer?.masksToBounds = true
        hosting = NSHostingView(rootView: PopoverView(store: store))
        hosting.translatesAutoresizingMaskIntoConstraints = false
        fx.addSubview(hosting)
        NSLayoutConstraint.activate([
            hosting.leadingAnchor.constraint(equalTo: fx.leadingAnchor), hosting.trailingAnchor.constraint(equalTo: fx.trailingAnchor),
            hosting.topAnchor.constraint(equalTo: fx.topAnchor), hosting.bottomAnchor.constraint(equalTo: fx.bottomAnchor)])
        panel.contentView = fx

        store.refreshCurrent()
        store.loadIncidents()
        updateIcon()
        timer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in self?.tick() }
    }

    func tick() {
        store.refreshCurrent()
        store.loadIncidents()
        if isShown { store.reloadPoints(); DispatchQueue.main.async { self.position() } }
        updateIcon()
    }

    @objc func toggle() {
        if isShown { close(); return }
        // clicking the icon first makes the panel resign key (which closes it); don't reopen on that same click
        if Date().timeIntervalSince(lastClose) < 0.35 { return }
        store.refreshAll()
        position()
        panel.makeKeyAndOrderFront(nil)
        DispatchQueue.main.async { self.position() }  // SwiftUI may settle its size one pass later
        clickMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            self?.close()
        }
    }

    /// Place the panel directly under the status item, top edge just below the menu bar,
    /// clamped to the visible area of the screen the icon is on.
    func position() {
        guard let button = item.button, let win = button.window else { return }
        let r = win.convertToScreen(button.convert(button.bounds, to: nil))
        let screen = win.screen ?? NSScreen.main!
        let vis = screen.visibleFrame
        hosting.layoutSubtreeIfNeeded()
        let size = hosting.fittingSize
        let top = min(r.minY, vis.maxY) - 4
        var x = r.midX - size.width / 2
        x = max(vis.minX + 6, min(x, vis.maxX - size.width - 6))
        let y = max(vis.minY + 6, top - size.height)
        panel.setFrame(NSRect(x: x, y: y, width: size.width, height: min(size.height, top - vis.minY - 6)), display: true)
    }

    func close() {
        guard isShown else { return }
        panel.orderOut(nil)
        lastClose = Date()
        if let m = clickMonitor { NSEvent.removeMonitor(m); clickMonitor = nil }
        if let first = store.incidents.first?.id { store.lastSeenIncident = first }
        updateIcon()
    }

    func windowDidResignKey(_ n: Notification) {
        // a sheet/alert attached to the panel takes key status; don't close for that
        if panel.attachedSheet == nil { close() }
    }

    func updateIcon() {
        let running = store.daemonRunning
        let c = store.current
        let p = Pressure(rawValue: c?.pressure ?? 0) ?? .unknown
        // free physical memory as Activity Monitor shows it: Physical Memory - Memory Used,
        // where Memory Used = App Memory + Wired + Compressed
        let availGB = c.map { max(0, $0.ram_gb - $0.app_gb - $0.wired_gb - $0.compressed_gb) }
        let label = availGB.map { $0 < 9.95 ? String(format: "%.1fG", $0) : String(format: "%.0fG", $0) }
        let img = ChipIcon.make(running: running, pressure: p, label: label)
        item.button?.image = img
        item.button?.toolTip = running
            ? "oomph — \(label ?? "?") physical memory free · pressure \(p.label)"
            : "oomph — logging is OFF (click to activate)"
    }
}

/// Hand-drawn menu bar chip: thick body, 3 thick pins top and bottom, free-memory % on the
/// surface, filled pastel green / yellow / red by pressure; hollow + slashed when logging is off.
enum ChipIcon {
    static let green = NSColor(srgbRed: 0.56, green: 0.86, blue: 0.60, alpha: 1)
    static let yellow = NSColor(srgbRed: 0.99, green: 0.84, blue: 0.35, alpha: 1)
    static let red = NSColor(srgbRed: 0.98, green: 0.45, blue: 0.42, alpha: 1)

    /// The label with a narrow decimal point: tighten the spacing around "." so "4.2G" stays compact.
    static func tightDecimal(_ text: String, _ attrs: [NSAttributedString.Key: Any]) -> NSAttributedString {
        let s = NSMutableAttributedString(string: text, attributes: attrs)
        let ns = text as NSString
        let dot = ns.range(of: ".")
        if dot.location != NSNotFound {
            if dot.location > 0 { s.addAttribute(.kern, value: -0.9, range: NSRange(location: dot.location - 1, length: 1)) }
            s.addAttribute(.kern, value: -0.9, range: dot)
        }
        return s
    }

    static func make(running: Bool, pressure: Pressure, label: String?) -> NSImage {
        let size = NSSize(width: 28, height: 18)
        let img = NSImage(size: size, flipped: false) { rect in
            let fg = NSColor.labelColor
            let line: CGFloat = 1.6
            let body = NSRect(x: 2.5, y: 2.5, width: 23, height: 13)
            // feet: 4 short pins along the top and bottom edges
            let pinW: CGFloat = 2.2, pinH: CGFloat = 2.0
            for i in 0..<4 {
                let x = body.midX - (3 * 4.5 + pinW) / 2 + CGFloat(i) * 4.5
                (running ? fg : fg.withAlphaComponent(0.6)).setFill()
                NSRect(x: x, y: body.minY - pinH, width: pinW, height: pinH).fill()
                NSRect(x: x, y: body.maxY, width: pinW, height: pinH).fill()
            }
            let path = NSBezierPath(roundedRect: body.insetBy(dx: line / 2, dy: line / 2), xRadius: 1.2, yRadius: 1.2)
            path.lineWidth = line
            if running {
                let fill: NSColor = pressure == .critical ? red : (pressure == .warn ? yellow : green)
                // chip with the label punched out (transparent), so the menu bar shows through the digits
                let text = label ?? "–"
                let attrs: [NSAttributedString.Key: Any] = [
                    .font: NSFont.systemFont(ofSize: 8.5, weight: .heavy, width: .condensed),
                    .foregroundColor: NSColor.black]
                let str = tightDecimal(text, attrs)
                let ts = str.size()
                let cg = NSGraphicsContext.current!.cgContext
                cg.beginTransparencyLayer(auxiliaryInfo: nil)
                fill.setFill(); path.fill()
                fg.setStroke(); path.stroke()
                cg.setBlendMode(.destinationOut)
                str.draw(at: NSPoint(x: body.midX - ts.width / 2, y: body.midY - ts.height / 2 + 0.3))
                cg.setBlendMode(.normal)
                cg.endTransparencyLayer()
            } else {
                // deactivated: dimmed hollow chip with an "x" inside
                fg.withAlphaComponent(0.5).setStroke(); path.stroke()
                let c = NSPoint(x: body.midX, y: body.midY), h: CGFloat = 2.1
                let x = NSBezierPath()
                x.move(to: NSPoint(x: c.x - h, y: c.y - h)); x.line(to: NSPoint(x: c.x + h, y: c.y + h))
                x.move(to: NSPoint(x: c.x - h, y: c.y + h)); x.line(to: NSPoint(x: c.x + h, y: c.y - h))
                x.lineWidth = 1.6; x.lineCapStyle = .round
                fg.setStroke(); x.stroke()
            }
            return true
        }
        img.isTemplate = false
        return img
    }
}

@MainActor
func renderPopup(to path: String, dark: Bool) {
    let store = Store()
    store.refreshAll()
    let view = PopoverView(store: store)
        .background(Color(nsColor: .windowBackgroundColor))
        .environment(\.colorScheme, dark ? .dark : .light)
    let r = ImageRenderer(content: view)
    r.scale = 2
    guard let cg = r.cgImage,
          let png = NSBitmapImageRep(cgImage: cg).representation(using: .png, properties: [:]) else { return }
    try? png.write(to: URL(fileURLWithPath: path))
}

@main
struct Main {
    static func main() {
        // Development aid: `oomph --render-popup out.png [--dark]` draws the popup into a PNG and exits.
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "--render-popup"), i + 1 < args.count {
            MainActor.assumeIsolated { renderPopup(to: args[i + 1], dark: args.contains("--dark")) }
            return
        }
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        app.run()
    }
}
