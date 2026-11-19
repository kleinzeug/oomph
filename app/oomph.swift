// oomph — menu bar front-end for the oomph daemon (see ../DESIGN.md).
// Build: ../build-app.sh
import AppKit
import Charts
import Security
import SwiftUI

let logDir = ProcessInfo.processInfo.environment["OOMPH_DIR"] ?? "/Library/Logs/oomph"
let agentLabel = "local.oomph.menubar"
let popupWidth: CGFloat = 480
let statColumn: CGFloat = 96
var renderHoverX: CGFloat?  // --ai hover:X / hoverlog:X renders the hover tooltip at x = X pt
var renderBlend: Double?  // --ai blend:0.5 renders the 24h → ∞ morph halfway
var renderMode = false  // --render-popup: static renders don't draw scroll-view contents
let skillURL = "https://raw.githubusercontent.com/kleinzeug/oomph/main/skills/oomph/SKILL.md"

// MARK: - AI analysis settings

enum AIProvider: String, CaseIterable, Identifiable {
    case claude, openai, ollama
    var id: String { rawValue }
    var title: String { ["claude": "Claude", "openai": "OpenAI Codex", "ollama": "Ollama"][rawValue]! }
    var defaultModel: String { ["claude": "claude-opus-5-5", "openai": "gpt-5-codex", "ollama": ""][rawValue]! }
    var needsToken: Bool { self != .ollama }
    var keyHint: String {
        switch self {
        case .claude: return "API key from platform.claude.com → API keys (sk-ant-…)"
        case .openai: return "API key from platform.openai.com → API keys (sk-…)"
        case .ollama: return "Runs on this Mac — no key needed (optional for a proxied server)"
        }
    }
}

// MARK: - Upgrades from GitHub

enum UpgradeButton: Equatable { case hidden, check, checking, upgrade, upToDate }

struct UpgradeCheck: Decodable {
    var current: String
    var current_commit: String?
    var available: String
    var commit: String
    var newer: Bool
    var behind: Int?
}

struct ChangelogEntry: Decodable, Identifiable {
    var commit, version, date, subject, body, status: String
    var id: String { commit }
}

/// Access tokens live in the login keychain, one item per provider.
enum Keychain {
    static let service = "local.oomph.ai"
    static func base(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
    }
    static func get(_ account: String) -> String? {
        var q = base(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }
    static func set(_ value: String, _ account: String) {
        SecItemDelete(base(account) as CFDictionary)
        guard !value.isEmpty else { return }
        var add = base(account)
        add[kSecValueData as String] = Data(value.utf8)
        SecItemAdd(add as CFDictionary, nil)
    }
}

/// A prompt to paste into a Claude Code session. It downloads the skill verbatim with curl
/// (a web fetch would hand the model a summary, not the file) and has the session follow it.
func skillPrompt(allProjects: Bool) -> String {
    let dir = allProjects ? "~/.claude/skills/oomph" : ".claude/skills/oomph"
    let scope = allProjects ? "for all my projects" : "to this project"
    return "Add the oomph memory skill \(scope): run `mkdir -p \(dir) && curl -fsSL \(skillURL) -o \(dir)/SKILL.md`, "
        + "then read \(dir)/SKILL.md and follow it for the rest of this session."
}
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

struct Gap { let from, to: Double }

/// Just the fields the chart needs: decoding a whole Sample (process groups, sessions…) for two
/// weeks of history is most of the loading time.
struct ChartSample: Decodable {
    var t: Double
    var app_gb: Double
    var wired_gb: Double
    var compressed_gb: Double
    var swap_used_gb: Double
    var jetsam_kills: Int?
    var away: Away?
}

/// One line of events.jsonl, reduced to what the chart's hover tooltip shows.
struct ChartEvent {
    let t: Double
    let kind: String
    let text: String
    var kills = 0
    var top: [String: Int] = [:]
    var seconds = 0.0
    var alarming: Bool { ["jetsam", "stall", "unowned_memory", "disk_low", "pressure_flapping", "daemon_error"].contains(kind) }

    static func pressureName(_ v: Any?) -> String {
        switch (v as? NSNumber)?.intValue { case 1: "normal"; case 2: "warning"; case 4: "critical"; default: "\(v ?? "?")" }
    }

    init?(_ e: [String: Any]) {
        guard let t = (e["t"] as? NSNumber)?.doubleValue, let kind = e["kind"] as? String else { return nil }
        func num(_ k: String) -> Double { (e[k] as? NSNumber)?.doubleValue ?? 0 }
        self.t = t; self.kind = kind
        switch kind {
        case "pressure_change": text = "pressure \(ChartEvent.pressureName(e["old"])) → \(ChartEvent.pressureName(e["new"]))"
        case "pressure_flapping": text = "pressure flapping, \(Int(num("flips"))) flips"
        case "jetsam":
            kills = Int(num("kills")); top = (e["top"] as? [String: Int]) ?? [:]
            text = kills > 0 ? "\(kills) killed by jetsam" : "jetsam report"
        case "sleep_gap": seconds = num("seconds"); text = "asleep " + MemoryChart.duration(seconds)
        case "stall": seconds = num("seconds"); text = "system stalled " + MemoryChart.duration(seconds)
        case "unowned_memory": text = String(format: "%.0f GB unowned memory (leak?)", num("gb"))
        case "unowned_memory_cleared": text = "unowned memory cleared"
        case "disk_low": text = String(format: "disk low: %.1f GB free", num("disk_free_gb"))
        case "daemon_start": text = "logger started" + ((e["version"] as? String).map { " (v\($0))" } ?? "")
        case "daemon_stop": text = "logger stopped"
        case "daemon_error": text = "logger error (\(e["where"] as? String ?? "?"))"
        case "notified": text = "notified: \(e["title"] as? String ?? "")"
        case "log": text = "system log: " + String((e["msg"] as? String ?? "").prefix(60))
        case "incident_open", "incident_close": return nil   // shown from the incidents themselves
        default: text = kind.replacingOccurrences(of: "_", with: " ")
        }
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
    /// All logged history, oldest first, finer near now (see Store.multires): every range draws from it.
    @Published var history: [Point] = []
    /// When `history` was loaded: the chart measures ages from here.
    @Published var historyNow = Date().timeIntervalSince1970
    /// Stretches without samples (asleep, off, logger stopped), found in the raw samples.
    @Published var gaps: [Gap] = []
    /// events.jsonl(.1), oldest first, for the hover tooltip.
    @Published var events: [ChartEvent] = []
    private var eventsStamp = ""
    @Published var incidents: [Incident] = []
    /// The chart's range in seconds; .infinity = all history on a log time axis.
    @Published var range: Double = 24 * 3600
    @Published var launchAtLogin = FileManager.default.fileExists(atPath: agentPlist)
    @Published var busy = false

    // AI reports
    @Published var aiOn = UserDefaults.standard.bool(forKey: "aiOn") { didSet { UserDefaults.standard.set(aiOn, forKey: "aiOn") } }
    @Published var aiProvider = AIProvider(rawValue: UserDefaults.standard.string(forKey: "aiProvider") ?? "") ?? .claude {
        didSet { UserDefaults.standard.set(aiProvider.rawValue, forKey: "aiProvider") }
    }
    @Published var aiRunning = false
    @Published var aiProgress = ""
    @Published var aiError: String?
    private var aiProcess: Process?

    // upgrades ("Upgrade" replaces this app with a newer version; "Update" installs the bundled logger)
    @Published var upgradeButton: UpgradeButton = .hidden
    @Published var upgradeCheckError: String?
    @Published var changelog: [ChangelogEntry] = []
    @Published var showChangelog = false
    @Published var loadingChangelog = false
    @Published var building = false
    @Published var buildProgress = ""
    @Published var buildLines: [String] = []
    @Published var buildError: String?
    @Published var buildVersion = ""
    @Published var alertText: String?
    private var buildProcess: Process?
    private var buildCancelled = false
    private var aiStarted = Date()
    private var aiAborted = false

    // history loading runs on its own queue; the cache and its decoder belong to that queue
    private let loadQueue = DispatchQueue(label: "local.oomph.history", qos: .userInitiated)
    private var cache: [String: (offset: UInt64, pts: [Point])] = [:]
    private let loadDecoder = JSONDecoder()
    private var loading = false, loadAgain = false
    /// False until the history has been loaded once: the chart shows a spinner meanwhile.
    @Published var historyLoaded = false
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

    var allHistory: Bool { range.isInfinite }

    /// Loads every samples file (14 days are kept), so switching ranges never waits for data.
    /// In the background: the popup opens at once and keeps showing the previous history
    /// until the new one is ready (or a spinner, the first time). `sync` is for renders.
    func reloadPoints(sync: Bool = false) {
        if sync {
            let r = loadQueue.sync { loadHistory() }
            apply(r); historyLoaded = true
            return
        }
        if loading { loadAgain = true; return }
        loading = true
        loadQueue.async { [weak self] in
            guard let self else { return }
            let r = self.loadHistory()
            DispatchQueue.main.async {
                self.apply(r)
                if !self.historyLoaded { withAnimation(.easeIn(duration: 0.33)) { self.historyLoaded = true } }
                self.loading = false
                if self.loadAgain { self.loadAgain = false; self.reloadPoints() }
            }
        }
    }

    private struct Loaded { let history: [Point]; let gaps: [Gap]; let now: Double; let events: [ChartEvent]? }

    private func apply(_ r: Loaded) {
        history = r.history
        gaps = r.gaps
        historyNow = r.now
        if let e = r.events { events = e }
    }

    /// On loadQueue only.
    private func loadHistory() -> Loaded {
        let now = Date().timeIntervalSince1970
        let fmt = DateFormatter(); fmt.dateFormat = "yyyy-MM-dd"
        let today = fmt.string(from: Date())
        let files = (try? FileManager.default.contentsOfDirectory(atPath: logDir)) ?? []
        var days = Set(files.compactMap { f -> String? in
            guard f.hasPrefix("samples-"), f.hasSuffix(".jsonl") || f.hasSuffix(".jsonl.gz") else { return nil }
            return String(f.dropFirst("samples-".count).prefix(10))
        })
        days.insert(today)
        var all: [Point] = []
        for day in days.sorted() { all += loadDay(day, isToday: day == today) }
        all.sort { $0.id < $1.id }
        var gaps: [Gap] = []
        for i in all.indices.dropFirst() where all[i].id - all[i - 1].id > Store.gapSeconds {
            gaps.append(Gap(from: all[i - 1].id, to: all[i].id))
        }
        if let last = all.last, now - last.id > Store.gapSeconds { gaps.append(Gap(from: last.id, to: now)) }
        // drop cached files that are gone (a day's plain file once it is gzipped)
        let present = Set(files.map { "\(logDir)/\($0)" })
        for k in cache.keys where !present.contains(k) { cache[k] = nil }
        return Loaded(history: Store.multires(all, now: now), gaps: gaps, now: now, events: loadEvents())
    }

    /// The events, or nil when the files haven't changed since the last load. On loadQueue only.
    private func loadEvents() -> [ChartEvent]? {
        let paths = ["events.jsonl.1", "events.jsonl"].map { "\(logDir)/\($0)" }
        let stamp = paths.map { p -> String in
            let a = try? FileManager.default.attributesOfItem(atPath: p)
            return "\(a?[.size] ?? 0)/\((a?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0)"
        }.joined(separator: ",")
        guard stamp != eventsStamp else { return nil }
        eventsStamp = stamp
        var out: [ChartEvent] = []
        for p in paths {
            guard let d = FileManager.default.contents(atPath: p) else { continue }
            for line in d.split(separator: 0x0A) {
                if let o = (try? JSONSerialization.jsonObject(with: Data(line))) as? [String: Any], let e = ChartEvent(o) {
                    out.append(e)
                }
            }
        }
        return out.sorted { $0.t < $1.t }
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
            guard let s = try? loadDecoder.decode(ChartSample.self, from: Data(line)) else { continue }
            let away = s.away.map { ($0.idle_s ?? 0) >= 300 || ($0.locked ?? false) || $0.display_on == false } ?? false
            out.append(Point(id: s.t, date: Date(timeIntervalSince1970: s.t), wired: s.wired_gb, app: s.app_gb,
                             comp: s.compressed_gb, swap: s.swap_used_gb, away: away, kills: s.jetsam_kills ?? 0))
        }
        return out
    }

    /// Thins the history so its resolution falls with age: buckets max(30 s, age/720) wide, each
    /// keeping its worst point (spikes survive). Fine enough for any linear range at 720 px and
    /// for the log axis, small enough (a few thousand points) to remap on every animation frame.
    /// Longer than this without a sample is a gap (the logger samples every 30 s; the report uses 5 min).
    static let gapSeconds: Double = 300

    static func multires(_ pts: [Point], now: Double) -> [Point] {
        var out: [Point] = []
        var j = pts.count - 1
        while j >= 0 {
            let width = max(30, (now - pts[j].id) / 720)
            var i = j
            // never across a gap: a bucket spanning one would bridge it
            while i > 0 && pts[i - 1].id > pts[j].id - width && pts[i].id - pts[i - 1].id <= gapSeconds { i -= 1 }
            out.append(worst(pts[i...j]))
            j = i - 1
        }
        return out.reversed()
    }

    /// The worst point of a bucket, so spikes survive downsampling.
    static func worst(_ slice: ArraySlice<Point>) -> Point {
        guard slice.count > 1 else { return slice.first! }
        let w = slice.max { ($0.app + $0.comp + $0.swap) < ($1.app + $1.comp + $1.swap) }!
        return Point(id: w.id, date: w.date, wired: w.wired, app: w.app, comp: w.comp,
                     swap: w.swap, away: slice.contains { $0.away }, kills: slice.reduce(0) { $0 + $1.kills })
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
        // always re-render, so old incidents show in the current report design
        runCLI(["incident", inc.id, "--html"])
    }

    // Reports are drawn by the CLI bundled with this app (reading the logs needs no
    // privileges), so they always match the app's version, even before Update.
    var cliPath: String {
        let bundled = (Bundle.main.resourcePath ?? "") + "/oomph.py"
        return FileManager.default.fileExists(atPath: bundled) ? bundled : "/usr/local/libexec/oomph/oomph.py"
    }

    func runCLI(_ args: [String]) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = ["-I", "-B", cliPath] + args
        try? p.run()
    }

    // MARK: Upgrades

    private let defaults = UserDefaults.standard
    var upgradeAuto: Bool {
        get { defaults.object(forKey: "upgradeAuto") as? Bool ?? true }   // on by default
        set { defaults.set(newValue, forKey: "upgradeAuto"); objectWillChange.send() }
    }
    var availableVersion: String { defaults.string(forKey: "upgradeAvailable") ?? "" }
    var availableCommit: String { defaults.string(forKey: "upgradeAvailableCommit") ?? "" }
    var lastUpgradeCheck: Double { defaults.double(forKey: "upgradeLastCheck") }
    var bundleCommit: String { Bundle.main.object(forInfoDictionaryKey: "OOMPHCommit") as? String ?? "" }

    /// A newer version that was found earlier and not skipped (it survives closing the popup).
    var rememberedUpgrade: Bool {
        !availableCommit.isEmpty && availableCommit != defaults.string(forKey: "upgradeSkipped")
            && !bundleCommit.hasPrefix(availableCommit) && availableVersion != bundledVersion
    }

    /// Every time the popup opens: tools once a day, then the button, then the daily check
    /// (no background timer — it only runs while you look).
    func popupOpened() {
        if upgradeButton == .upToDate { upgradeButton = .check }
        let now = Date().timeIntervalSince1970
        if now - defaults.double(forKey: "upgradeToolsChecked") > 86400 {
            runUpgradeCLI(["tools", "--json"]) { [weak self] data, _ in
                guard let self else { return }
                let ok = ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any])?["ok"] as? Bool ?? false
                self.defaults.set(ok, forKey: "upgradeToolsOK")
                self.defaults.set(now, forKey: "upgradeToolsChecked")
                self.continueUpgradeSetup()
            }
        } else {
            continueUpgradeSetup()
        }
    }

    private func continueUpgradeSetup() {
        guard defaults.bool(forKey: "upgradeToolsOK") else { upgradeButton = .hidden; return }
        if upgradeButton == .hidden { upgradeButton = rememberedUpgrade ? .upgrade : .check }
        if upgradeAuto && Date().timeIntervalSince1970 - lastUpgradeCheck > 86400 && upgradeButton != .checking && !building {
            checkForUpgrade(manual: false)
        }
    }

    func checkForUpgrade(manual: Bool) {
        upgradeButton = .checking
        upgradeCheckError = nil
        runUpgradeCLI(["check", "--json"]) { [weak self] data, status in
            guard let self else { return }
            guard status == 0, let r = try? JSONDecoder().decode(UpgradeCheck.self, from: data) else {
                let e = ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any])?["error"] as? String
                self.upgradeCheckError = e ?? "the check failed"
                self.upgradeButton = self.rememberedUpgrade ? .upgrade : .check
                return
            }
            self.defaults.set(Date().timeIntervalSince1970, forKey: "upgradeLastCheck")
            if r.newer {
                self.defaults.set(r.available, forKey: "upgradeAvailable")
                self.defaults.set(r.commit, forKey: "upgradeAvailableCommit")
                // the daily check doesn't offer a skipped version again; pressing Check does
                let skipped = r.commit == self.defaults.string(forKey: "upgradeSkipped")
                self.upgradeButton = (manual || !skipped) ? .upgrade : .check
                if manual && skipped { self.defaults.removeObject(forKey: "upgradeSkipped") }
            } else {
                self.defaults.removeObject(forKey: "upgradeAvailable")
                self.defaults.removeObject(forKey: "upgradeAvailableCommit")
                self.upgradeButton = .upToDate
            }
        }
    }

    func openUpgrade() {
        showChangelog = true
        loadingChangelog = true
        changelog = []
        runUpgradeCLI(["log", "--json"]) { [weak self] data, status in
            guard let self else { return }
            self.loadingChangelog = false
            if status == 0, let entries = try? JSONDecoder().decode([ChangelogEntry].self, from: data) {
                self.changelog = entries
                if let top = entries.first {  // the newest is what will be installed
                    self.defaults.set(top.version, forKey: "upgradeAvailable")
                    self.defaults.set(top.commit, forKey: "upgradeAvailableCommit")
                }
            } else {
                let e = ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any])?["error"] as? String
                self.showChangelog = false
                self.alertText = "Couldn't load the changelog: " + (e ?? "unknown error")
            }
        }
    }

    func skipThisVersion() {
        defaults.set(availableCommit, forKey: "upgradeSkipped")
        showChangelog = false
        upgradeButton = .check
    }

    /// Clone/checkout, build-app.sh into a staging folder (progress streamed), then swap.
    func upgradeNow() {
        showChangelog = false
        building = true
        buildError = nil
        buildLines = []
        buildCancelled = false
        buildVersion = availableVersion
        buildProgress = "Starting"
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = ["-I", "-B", cliPath, "upgrade", "build"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        var buffer = Data()
        var builtApp: String?
        out.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            guard !d.isEmpty else { return }
            buffer.append(d)
            while let nl = buffer.firstIndex(of: 0x0a) {
                let line = buffer.subdata(in: buffer.startIndex..<nl)
                buffer.removeSubrange(buffer.startIndex...nl)
                let j = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any]
                let text = String(data: line, encoding: .utf8) ?? ""
                DispatchQueue.main.async {
                    guard let self else { return }
                    guard let j else { self.buildLines.append(text); return }
                    if let m = j["progress"] as? String { self.buildProgress = m }
                    if let v = j["version"] as? String { self.buildVersion = v }
                    if let l = j["line"] as? String { self.buildLines.append(l) }
                    if let e = j["error"] as? String { self.buildError = e }
                    if let a = j["done"] as? String { builtApp = a }
                    if self.buildLines.count > 400 { self.buildLines.removeFirst(self.buildLines.count - 400) }
                }
            }
        }
        p.terminationHandler = { [weak self] proc in
            DispatchQueue.main.async {
                guard let self else { return }
                out.fileHandleForReading.readabilityHandler = nil
                self.buildProcess = nil
                if self.buildCancelled { self.building = false; return }
                if proc.terminationStatus == 0, let app = builtApp {
                    self.installUpgrade(app)
                } else {
                    self.buildError = self.buildError ?? "The build failed (exit \(proc.terminationStatus))."
                }
            }
        }
        do { try p.run(); buildProcess = p } catch { buildError = "Couldn't start the build: \(error.localizedDescription)" }
    }

    func cancelBuild() {
        buildCancelled = true
        buildProcess?.terminate()
        building = false
    }

    func closeBuild() { building = false; buildError = nil }

    /// Swap the freshly built app in for this one and relaunch it; the new copy closes this one
    /// and goes straight on to the logger update.
    func installUpgrade(_ staged: String) {
        buildProgress = "Replacing the app"
        let fm = FileManager.default
        let current = Bundle.main.bundleURL
        let backup = URL(fileURLWithPath: NSHomeDirectory() + "/Library/Application Support/oomph/previous.app")
        try? fm.removeItem(at: backup)
        do {
            try fm.moveItem(at: current, to: backup)
            do { try fm.moveItem(at: URL(fileURLWithPath: staged), to: current) } catch {
                try? fm.moveItem(at: backup, to: current)
                throw error
            }
        } catch {
            buildError = "Couldn't replace \(current.path): \(error.localizedDescription)"
            return
        }
        buildProgress = "Relaunching"
        defaults.removeObject(forKey: "upgradeAvailable")
        defaults.removeObject(forKey: "upgradeAvailableCommit")
        let cfg = NSWorkspace.OpenConfiguration()
        cfg.arguments = ["--after-upgrade"]
        cfg.createsNewApplicationInstance = true
        NSWorkspace.shared.openApplication(at: current, configuration: cfg) { [weak self] _, err in
            if let err {
                DispatchQueue.main.async {
                    self?.buildError = "Upgraded, but the relaunch failed (\(err.localizedDescription)). Quit oomph and open it again."
                }
            }
        }
    }

    /// Runs `oomph upgrade …` from the bundled CLI off the main thread; hands back stdout.
    func runUpgradeCLI(_ args: [String], done: @escaping (Data, Int32) -> Void) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = ["-I", "-B", cliPath, "upgrade"] + args
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        DispatchQueue.global().async {
            do { try p.run() } catch { DispatchQueue.main.async { done(Data(), -1) }; return }
            let d = out.fileHandleForReading.readDataToEndOfFile()  // read before waiting: no full-pipe stall
            p.waitUntilExit()
            DispatchQueue.main.async { done(d, p.terminationStatus) }
        }
    }

    // MARK: AI settings + report

    func aiModel(_ p: AIProvider) -> String { UserDefaults.standard.string(forKey: "aiModel." + p.rawValue) ?? p.defaultModel }
    func setAIModel(_ m: String, _ p: AIProvider) { UserDefaults.standard.set(m, forKey: "aiModel." + p.rawValue) }
    var ollamaURL: String {
        get { UserDefaults.standard.string(forKey: "ollamaURL") ?? "http://localhost:11434" }
        set { UserDefaults.standard.set(newValue, forKey: "ollamaURL") }
    }
    func hasToken(_ p: AIProvider) -> Bool { (Keychain.get(p.rawValue) ?? "").isEmpty == false }
    func aiConfigured(_ p: AIProvider) -> Bool { !p.needsToken || hasToken(p) }

    var aiSummary: String {
        let m = aiModel(aiProvider)
        return aiProvider.title + (m.isEmpty ? "" : " · " + m)
    }

    func runReport() {
        if aiRunning { return }
        if aiOn && aiConfigured(aiProvider) { runAIReport() } else { runCLI(["html", "--last", "24h", "--open"]) }
    }

    func runAIReport() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        var args = ["-I", "-B", cliPath, "ai-report", "--provider", aiProvider.rawValue, "--last", "24h", "--open"]
        let model = aiModel(aiProvider)
        if !model.isEmpty { args += ["--model", model] }
        if aiProvider == .ollama { args += ["--base-url", ollamaURL] }
        p.arguments = args
        var env = ProcessInfo.processInfo.environment
        env["OOMPH_AI_TOKEN"] = Keychain.get(aiProvider.rawValue) ?? ""  // via the environment, not argv
        p.environment = env
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        var buffer = Data()
        out.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            guard !d.isEmpty else { return }
            buffer.append(d)
            while let nl = buffer.firstIndex(of: 0x0a) {
                let line = buffer.subdata(in: buffer.startIndex..<nl)
                buffer.removeSubrange(buffer.startIndex...nl)
                guard let j = try? JSONSerialization.jsonObject(with: line) as? [String: Any] else { continue }
                DispatchQueue.main.async {
                    guard let self else { return }
                    if let m = j["progress"] as? String { self.aiProgress = m }
                    if let e = j["error"] as? String, !self.aiAborted { self.aiError = "AI report failed: " + e }
                }
            }
        }
        p.terminationHandler = { [weak self] proc in
            DispatchQueue.main.async {
                guard let self else { return }
                out.fileHandleForReading.readabilityHandler = nil
                self.aiRunning = false
                self.aiProcess = nil
                if proc.terminationStatus != 0 && !self.aiAborted && self.aiError == nil {
                    self.aiError = "AI report failed (exit \(proc.terminationStatus))."
                }
            }
        }
        do {
            aiAborted = false
            aiError = nil
            aiStarted = Date()
            aiProgress = "Starting"
            try p.run()
            aiProcess = p
            aiRunning = true
        } catch {
            aiError = "Couldn't start the AI report: \(error.localizedDescription)"
        }
    }

    func abortAI() {
        aiAborted = true
        aiProcess?.terminate()
    }

    var aiTooltip: String {
        let s = Int(Date().timeIntervalSince(aiStarted))
        return "\(aiProgress) · \(s / 60):" + String(format: "%02d", s % 60) + " · \(aiSummary)"
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
        }.frame(width: statColumn, alignment: .leading)  // the 4th column takes the rest (top app)
    }
}

// MARK: - Memory chart

/// The popup's memory chart. One view for every range: x is a blend of a linear axis (the last
/// 10^lgRange seconds) and a log axis over all history (blend 0 → 1), both animatable, so a range
/// switch morphs the chart and every point visibly travels to its new place. Each frame
/// re-buckets the preloaded history into ~360 columns; nothing is reloaded.
struct MemoryChart: View, Animatable {
    var points: [Point]          // oldest first, multi-resolution (Store.multires)
    var gaps: [Gap]
    var now: Double
    var incidents: [Incident]
    var events: [ChartEvent]
    var ram: Double?
    var lgRange: Double          // log10 of the linear range, seconds
    var blend: Double            // 0 = linear, 1 = log
    /// The pointer's x over the chart (overlay coordinates), nil when it isn't hovering.
    @State private var hoverX: CGFloat? = renderHoverX

    var animatableData: AnimatablePair<Double, Double> {
        get { AnimatablePair(lgRange, blend) }
        set { lgRange = newValue.first; blend = newValue.second }
    }

    static let series = ["Wired", "App", "Compressed", "Swap"]
    static let minAge: Double = 300          // ages below this share the right edge of the log axis
    static let columns = 360
    // grid levels, coarse first: a week, a day, 6 h, 1 h, 15 min, 5 min, 1 min (local time)
    static let levels: [Double] = [604800, 86400, 21600, 3600, 900, 300, 60]

    struct Entry: Identifiable { let id: Int; let x: Double; let kind: String; let gb: Double }
    struct Band: Identifiable { let id: Int; let from: Double; let to: Double }
    struct GridLine: Identifiable { let id: Double; let x: Double; let alpha: Double }
    struct Label { let x: Double; let text: String }

    /// Time → x in 0…1 (1 = now) for the current blend.
    func mapper() -> (Double) -> Double {
        let r = pow(10, lgRange), m = MemoryChart.minAge, b = blend, now = now
        let span = log10(max(now - (points.first?.id ?? now), 3600) / m)
        return { t in
            let a = max(now - t, 0)
            return (1 - b) * (1 - a / r) + b * (1 - log10(max(a, m) / m) / span)
        }
    }

    var body: some View {
        GeometryReader { geo in
            let f = mapper()
            let plotW = max(geo.size.width - 30, 50)
            let (entries, away) = columns(f)
            let grid = gridLines(f, plotW: plotW)
            let labels = axisLabels(f, plotW: plotW)
            Chart {
                bandMarks(away, style: AnyShapeStyle(Color.gray.opacity(0.15)))
                gridMarks(grid, color: .primary, scale: 1)
                areaMarks(entries)
                gridMarks(grid, color: .white, scale: 0.45)
                bandMarks(gapBands(f), style: AnyShapeStyle(MemoryChart.hatch))
                ramMark
                incidentMarks(f)
            }
            .chartXScale(domain: 0...1)
            .chartXAxis {
                // ticks here; the labels are drawn centered on them in the overlay (Charts would
                // left-align them to the tick). The blank label keeps the axis's height.
                AxisMarks(values: labels.map(\.x)) { _ in
                    AxisTick(length: 3)
                    AxisValueLabel { Text(" ").font(.system(size: 10)) }
                }
            }
            .chartForegroundStyleScale(domain: MemoryChart.series, range: [Color.gray, Color.blue, Color.orange, Color.red])
            .chartLegend(position: .bottom, spacing: 4)
            .transaction { $0.animation = nil }  // this view animates itself, frame by frame
            .chartOverlay { proxy in
                ZStack(alignment: .topLeading) {
                    axisLabelLayer(proxy, labels: labels)
                    hoverLayer(proxy, mapper: f)
                }
            }
        }
    }

    func axisLabelLayer(_ proxy: ChartProxy, labels: [Label]) -> some View {
        GeometryReader { g in
            let plot = proxy.plotFrame.map { g[$0] } ?? CGRect(origin: .zero, size: g.size)
            ForEach(Array(labels.enumerated()), id: \.offset) { _, l in
                if let x = proxy.position(forX: l.x) {
                    Text(l.text).font(.system(size: 10)).foregroundStyle(.secondary).fixedSize()
                        .position(x: plot.minX + x, y: plot.maxY + 11)
                }
            }
        }
        .allowsHitTesting(false)
    }

    // MARK: hover

    /// A vertical line following the pointer and a live tooltip for the time under it.
    func hoverLayer(_ proxy: ChartProxy, mapper f: @escaping (Double) -> Double) -> some View {
        GeometryReader { g in
            let plot = proxy.plotFrame.map { g[$0] } ?? CGRect(origin: .zero, size: g.size)
            ZStack(alignment: .topLeading) {
                Rectangle().fill(Color.clear).contentShape(Rectangle())
                    .onContinuousHover { phase in
                        switch phase {
                        case .active(let p): hoverX = p.x
                        case .ended: hoverX = nil
                        }
                    }
                if let x = hoverX, x >= plot.minX, x <= plot.maxX,
                   let u = proxy.value(atX: x - plot.minX, as: Double.self) {
                    let info = hoverInfo(u: u, du: 1 / Double(plot.width), mapper: f)
                    Rectangle().fill(Color.primary.opacity(0.55))
                        .frame(width: 1, height: plot.height)
                        .offset(x: x - 0.5, y: plot.minY)
                        .allowsHitTesting(false)
                    HoverCard(info: info)
                        .frame(width: MemoryChart.cardWidth, alignment: .leading)
                        .offset(x: x < plot.midX ? x + 10 : x - 10 - MemoryChart.cardWidth, y: plot.minY + 2)
                        .allowsHitTesting(false)
                }
            }
        }
    }

    static let cardWidth: CGFloat = 230

    struct Reading { let name: String; let lo: Double; let hi: Double }
    struct HoverInfo {
        var when = ""
        var ago = ""
        var samples = 0
        var peak = 0.0                      // the highest stacked total among the readings
        var readings: [Reading] = []
        var away = false
        var noData: String?
        var incidents: [String] = []
        var events: [(String, Bool)] = []   // text, alarming
        var moreEvents = 0
    }

    /// Time for x (the mapper is monotonic, so bisection inverts it).
    func time(at u: Double, _ f: (Double) -> Double) -> Double {
        var lo = (points.first?.id ?? now) - 1, hi = now
        if u >= f(hi) { return hi }
        if u <= f(lo) { return lo }
        for _ in 0..<50 {
            let mid = (lo + hi) / 2
            if f(mid) < u { lo = mid } else { hi = mid }
        }
        return (lo + hi) / 2
    }

    /// Everything under one horizontal pixel, aggregated: on the log axis one pixel can hold hours.
    func hoverInfo(u: Double, du: Double, mapper f: (Double) -> Double) -> HoverInfo {
        var info = HoverInfo()
        let t0 = time(at: max(u - du / 2, 0), f), t1 = time(at: min(u + du / 2, 1), f)
        let tc = (t0 + t1) / 2
        // the time under the pointer
        let day = MemoryChart.dayFmt, clock = MemoryChart.timeFmt
        let d0 = Date(timeIntervalSince1970: t0), d1 = Date(timeIntervalSince1970: t1)
        if t1 - t0 < 90 {
            info.when = day.string(from: Date(timeIntervalSince1970: tc)) + " " + clock.string(from: Date(timeIntervalSince1970: tc))
        } else if Calendar.current.isDate(d0, inSameDayAs: d1) {
            info.when = "\(day.string(from: d0)) \(clock.string(from: d0))–\(clock.string(from: d1))"
        } else {
            info.when = "\(day.string(from: d0)) \(clock.string(from: d0)) – \(day.string(from: d1)) \(clock.string(from: d1))"
        }
        info.ago = now - tc < 90 ? "now" : MemoryChart.duration(now - tc) + " ago"
        // samples in the pixel; on a fine axis the nearest one, unless the pointer is in a gap
        let gapHere = gaps.first { $0.from < tc && $0.to > tc }
        var pts = slice(points, from: t0, to: t1, key: \.id)
        if pts.isEmpty && gapHere == nil, let near = nearest(tc), abs(near.id - tc) <= 60 { pts = [near] }
        info.samples = pts.count
        if !pts.isEmpty {
            let cols: [(String, KeyPath<Point, Double>)] = [("App", \.app), ("Compressed", \.comp), ("Wired", \.wired), ("Swap", \.swap)]
            info.readings = cols.map { (name, k) in
                Reading(name: name, lo: pts.map { $0[keyPath: k] }.min()!, hi: pts.map { $0[keyPath: k] }.max()!)
            }
            info.away = pts.contains { $0.away }
            info.peak = pts.map { $0.wired + $0.app + $0.comp + $0.swap }.max() ?? 0
        }
        let overlapping = gaps.filter { $0.from < t1 && $0.to > t0 }
        if overlapping.count == 1, let g = overlapping.first {
            info.noData = "no data \(clock.string(from: Date(timeIntervalSince1970: g.from)))–\(clock.string(from: Date(timeIntervalSince1970: g.to))) (\(MemoryChart.duration(g.to - g.from)))"
        } else if overlapping.count > 1 {
            info.noData = "\(overlapping.count) stretches without data, \(MemoryChart.duration(overlapping.reduce(0) { $0 + $1.to - $1.from })) in all"
        }
        // incidents and events: catch the ones within a few pixels, they are thin lines
        let e0 = time(at: max(u - 3 * du, 0), f), e1 = time(at: min(u + 3 * du, 1), f)
        info.incidents = incidents.filter { $0.start <= e1 && ($0.end ?? now) >= e0 }.map { inc in
            "incident " + clock.string(from: Date(timeIntervalSince1970: inc.start))
                + (inc.reasons.first.map { ": " + $0.desc } ?? "")
        }
        let evs = slice(events, from: e0, to: e1, key: \.t)
        var lines: [(String, Bool)] = []
        var order: [String] = []
        var byKind: [String: [ChartEvent]] = [:]
        for e in evs { if byKind[e.kind] == nil { order.append(e.kind) }; byKind[e.kind, default: []].append(e) }
        for k in order {
            let es = byKind[k]!
            if es.count == 1 { lines.append((es[0].text, es[0].alarming)); continue }
            switch k {
            case "jetsam":
                let kills = es.reduce(0) { $0 + $1.kills }
                var top: [String: Int] = [:]
                for e in es { top.merge(e.top, uniquingKeysWith: +) }
                let names = top.sorted { $0.value > $1.value }.prefix(2).map { "\($0.key) ×\($0.value)" }.joined(separator: ", ")
                lines.append((kills > 0 ? "\(kills) killed by jetsam" + (names.isEmpty ? "" : " · " + names)
                                        : "\(es.count) jetsam reports", true))
            case "pressure_change":
                lines.append(("pressure changed \(es.count)× · last: " + es.last!.text.replacingOccurrences(of: "pressure ", with: ""), false))
            case "sleep_gap", "stall":
                lines.append(((k == "stall" ? "system stalled" : "asleep") + " \(es.count)×, "
                              + MemoryChart.duration(es.reduce(0) { $0 + $1.seconds }) + " in all", es[0].alarming))
            default:
                lines.append((es.last!.text + " ×\(es.count)", es[0].alarming))
            }
        }
        info.events = Array(lines.prefix(6))
        info.moreEvents = max(lines.count - 6, 0)
        return info
    }

    /// The elements of a sorted array with key in from...to.
    func slice<T>(_ a: [T], from: Double, to: Double, key: KeyPath<T, Double>) -> [T] {
        func lower(_ v: Double) -> Int {
            var lo = 0, hi = a.count
            while lo < hi { let m = (lo + hi) / 2; if a[m][keyPath: key] < v { lo = m + 1 } else { hi = m } }
            return lo
        }
        let i = lower(from), j = lower(to.nextUp)
        return i < j ? Array(a[i..<j]) : []
    }

    func nearest(_ t: Double) -> Point? {
        let after = slice(points, from: t, to: .infinity, key: \.id).first
        let before = slice(points, from: -.infinity, to: t, key: \.id).last
        switch (before, after) {
        case let (b?, a?): return t - b.id <= a.id - t ? b : a
        default: return before ?? after
        }
    }

    static func duration(_ s: Double) -> String {
        let s = Int(s.rounded())
        if s < 90 { return "\(s) s" }
        if s < 3600 { return "\(s / 60) min" }
        if s < 86400 { return s % 3600 / 60 == 0 || s >= 36000 ? "\(s / 3600) h" : "\(s / 3600) h \(s % 3600 / 60) min" }
        let d = s / 86400, h = s % 86400 / 3600
        return h == 0 ? "\(d) d" : "\(d) d \(h) h"
    }

    struct HoverCard: View {
        let info: HoverInfo
        static let colors: [String: Color] = ["App": .blue, "Compressed": .orange, "Wired": .gray, "Swap": .red]

        func gb(_ r: Reading) -> String {
            let lo = String(format: "%.1f", r.lo), hi = String(format: "%.1f", r.hi)
            return lo == hi ? hi + " GB" : "\(lo)–\(hi) GB"
        }

        var body: some View {
            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline) {
                    Text(info.when).font(.system(size: 11, weight: .semibold)).lineLimit(1)
                    Spacer(minLength: 4)
                    Text(info.ago).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
                }
                if info.samples > 1 {
                    Text("\(info.samples) readings in this pixel · range shown")
                        .font(.system(size: 9)).foregroundStyle(.tertiary)
                }
                ForEach(info.readings, id: \.name) { r in
                    HStack(spacing: 5) {
                        Circle().fill(HoverCard.colors[r.name] ?? .gray).frame(width: 6, height: 6)
                        Text(r.name).font(.system(size: 10))
                        Spacer(minLength: 4)
                        Text(gb(r)).font(.system(size: 10, design: .monospaced))
                    }
                }
                if !info.readings.isEmpty {
                    HStack {
                        Text((info.samples > 1 ? "all four, peak" : "all four") + (info.away ? " · away" : ""))
                            .font(.system(size: 10)).foregroundStyle(.secondary)
                        Spacer()
                        Text(String(format: "%.1f GB", info.peak)).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary)
                    }
                }
                if let n = info.noData {
                    SwiftUI.Label(n, systemImage: "slash.circle").font(.system(size: 10)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if !info.incidents.isEmpty || !info.events.isEmpty { Divider().padding(.vertical, 1) }
                ForEach(Array(info.incidents.prefix(2).enumerated()), id: \.offset) { _, t in
                    Text(t).font(.system(size: 10, weight: .medium)).foregroundStyle(.red).lineLimit(3)
                        .fixedSize(horizontal: false, vertical: true)
                }
                ForEach(Array(info.events.enumerated()), id: \.offset) { _, e in
                    Text("• " + e.0).font(.system(size: 10)).foregroundStyle(e.1 ? Color.red : Color.primary).lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if info.moreEvents > 0 {
                    Text("+ \(info.moreEvents) more kinds of events").font(.system(size: 9)).foregroundStyle(.tertiary)
                }
            }
            .padding(8)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Color.primary.opacity(0.12)))
            .shadow(color: .black.opacity(0.18), radius: 6, y: 2)
        }
    }

    /// The history bucketed into screen columns (worst point each), with the area dropping to
    /// zero at both edges of every gap instead of bridging it; plus the away spans.
    func columns(_ f: (Double) -> Double) -> ([Entry], [Band]) {
        var cols: [(x: Double, p: Point)] = []
        var gi = gaps.count - 1
        var bucket: [Point] = [], bucketCol = Int.min, bucketX = 0.0
        var segBreaks: Set<Int> = []                  // indices in cols that start a new segment (older side)
        func flush() {
            if !bucket.isEmpty { cols.append((bucketX, Store.worst(ArraySlice(bucket)))) }
            bucket = []
        }
        var prevT = Double.infinity
        for p in points.reversed() {
            let x = f(p.id)
            // a gap between this point and the newer one?
            var broke = false
            while gi >= 0 && gaps[gi].from >= p.id {
                if gaps[gi].to <= prevT { broke = true }
                gi -= 1
            }
            let col = Int((x * Double(MemoryChart.columns)).rounded(.down))
            if broke || col != bucketCol {
                flush()
                if broke { segBreaks.insert(cols.count) }
                bucketCol = col; bucketX = x
            }
            bucket.append(p)
            prevT = p.id
            if x < 0 { break }                        // one point past the left edge, clamped below
        }
        flush()
        // oldest first, clamped into the plot
        var entries: [Entry] = []
        var away: [Band] = []
        var awayStart: Double?
        var id = 0
        func add(_ x: Double, _ p: Point?) {
            let v: [Double] = p.map { [$0.wired, $0.app, $0.comp, $0.swap] } ?? [0, 0, 0, 0]
            for (k, name) in MemoryChart.series.enumerated() {
                entries.append(Entry(id: id, x: x, kind: name, gb: v[k])); id += 1
            }
        }
        let n = cols.count
        for i in stride(from: n - 1, through: 0, by: -1) {
            let x = min(max(cols[i].x, 0), 1), p = cols[i].p
            let startsSeg = i == n - 1 || segBreaks.contains(i + 1)   // older neighbour is across a gap
            let endsSeg = i == 0 || segBreaks.contains(i)
            if startsSeg && i != n - 1 { add(x - 1e-6, nil) }
            add(x, p)
            if endsSeg && i != 0 { add(x + 1e-6, nil) }
            if p.away { if awayStart == nil { awayStart = x } }
            if (!p.away || endsSeg), let s = awayStart {
                away.append(Band(id: away.count, from: s, to: x)); awayStart = nil
            }
        }
        if let s = awayStart { away.append(Band(id: away.count, from: s, to: 1)) }
        return (entries, away)
    }

    func gapBands(_ f: (Double) -> Double) -> [Band] {
        var out: [Band] = []
        for g in gaps {
            let a = max(f(g.from), 0), b = min(f(g.to), 1)
            if b > a { out.append(Band(id: out.count, from: a, to: b)) }
        }
        return out
    }

    /// Clock-aligned lines at every level, faded by their on-screen spacing: lines closer than a
    /// few pixels vanish, so the log axis shows its decades of grids without turning solid.
    func gridLines(_ f: (Double) -> Double, plotW: Double) -> [GridLine] {
        let tz = Double(TimeZone.current.secondsFromGMT())
        var alpha: [Double: (x: Double, a: Double)] = [:]
        for unit in MemoryChart.levels {
            let offset = unit == 604800 ? 4 * 86400.0 : 0   // weeks start on Monday (1970-01-01 was a Thursday)
            var t = ((now + tz - offset) / unit).rounded(.down) * unit - tz + offset
            var guardN = 0
            while guardN < 400 {
                guardN += 1
                let x = f(t)
                if x < 0 { break }
                let spacing = (x - f(t - unit)) * plotW
                if spacing < 3 { break }                     // only gets denser further left
                let s = min(max((spacing - 3) / 37, 0), 1)   // 3 px → invisible, 40 px → full
                let a = 0.2 * s * s * (3 - 2 * s)
                if a > (alpha[t]?.a ?? 0) { alpha[t] = (x, a) }
                t -= unit
            }
        }
        return alpha.map { GridLine(id: $0.key, x: $0.value.x, alpha: $0.value.a) }.filter { $0.x <= 0.995 }
    }

    /// Labels on grid lines, coarsest first, skipping any that would crowd an earlier one.
    func axisLabels(_ f: (Double) -> Double, plotW: Double) -> [Label] {
        let tz = Double(TimeZone.current.secondsFromGMT())
        let minGap = 46 / plotW
        var out: [Label] = []
        for unit in MemoryChart.levels {
            let offset = unit == 604800 ? 4 * 86400.0 : 0
            var t = ((now + tz - offset) / unit).rounded(.down) * unit - tz + offset
            var guardN = 0
            while guardN < 400 {
                guardN += 1
                let x = f(t)
                if x < 0 { break }
                if (x - f(t - unit)) * plotW < 20 { break }
                if x >= 0.03 && x <= 0.95 && !out.contains(where: { abs($0.x - x) < minGap }) {
                    out.append(Label(x: x, text: MemoryChart.label(t, unit: unit)))
                }
                t -= unit
            }
        }
        return out.sorted { $0.x < $1.x }
    }

    static let dayFmt: DateFormatter = { let f = DateFormatter(); f.dateFormat = "EEE d"; return f }()
    static let timeFmt: DateFormatter = { let f = DateFormatter(); f.dateFormat = "HH:mm"; return f }()
    static func label(_ t: Double, unit: Double) -> String {
        let d = Date(timeIntervalSince1970: t)
        return unit >= 86400 ? dayFmt.string(from: d) : timeFmt.string(from: d)
    }

    /// Diagonal hatching for "no data", visible on either theme.
    static let hatch: ImagePaint = {
        let img = NSImage(size: NSSize(width: 6, height: 6), flipped: false) { r in
            NSColor.gray.withAlphaComponent(0.45).setStroke()
            let p = NSBezierPath(); p.lineWidth = 1
            p.move(to: NSPoint(x: -1, y: -1)); p.line(to: NSPoint(x: 7, y: 7))
            p.move(to: NSPoint(x: -1, y: 5)); p.line(to: NSPoint(x: 1, y: 7))
            p.move(to: NSPoint(x: 5, y: -1)); p.line(to: NSPoint(x: 7, y: 1))
            p.stroke()
            return true
        }
        return ImagePaint(image: Image(nsImage: img))
    }()

    @ChartContentBuilder func bandMarks(_ bands: [Band], style: AnyShapeStyle) -> some ChartContent {
        ForEach(bands) { (b: Band) in
            RectangleMark(xStart: .value("from", b.from), xEnd: .value("to", max(b.to, b.from + 0.002)))
                .foregroundStyle(style)
        }
    }

    @ChartContentBuilder func gridMarks(_ lines: [GridLine], color: Color, scale: Double) -> some ChartContent {
        ForEach(lines) { (l: GridLine) in
            RuleMark(x: .value("grid", l.x))
                .lineStyle(StrokeStyle(lineWidth: 0.5))
                .foregroundStyle(color.opacity(l.alpha * scale))
        }
    }

    @ChartContentBuilder func areaMarks(_ entries: [Entry]) -> some ChartContent {
        ForEach(entries) { (e: Entry) in
            AreaMark(x: .value("time", e.x), y: .value("GB", e.gb))
                .foregroundStyle(by: .value("kind", e.kind))
        }
    }

    @ChartContentBuilder var ramMark: some ChartContent {
        if let ram {
            RuleMark(y: .value("RAM", ram))
                .lineStyle(StrokeStyle(lineWidth: 1, dash: [4, 3]))
                .foregroundStyle(Color.primary.opacity(0.6))
        }
    }

    @ChartContentBuilder func incidentMarks(_ f: (Double) -> Double) -> some ChartContent {
        let xs: [Double] = incidents.map { f($0.start) }.filter { $0 >= 0 && $0 <= 1 }
        ForEach(xs, id: \.self) { (x: Double) in
            RuleMark(x: .value("incident", x)).foregroundStyle(Color.red)
        }
    }
}

struct PopoverView: View {
    @ObservedObject var store: Store
    @State private var error: String?
    @State private var copied = false
    @State var showAI = false
    @State var showTopApps = false
    @State private var draftProvider: AIProvider = .claude
    @State private var draftToken = ""
    @State private var draftModel = ""
    @State private var draftURL = ""
    @State private var ollamaModels: [String] = []
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
                chart.zIndex(1)
                incidentsList
                Divider()
                footer
            }
            .padding(14)
        }
        .frame(width: popupWidth)
        .overlayPreferenceValue(StarAnchorKey.self) { anchor in
            GeometryReader { geo in
                if showAI, let anchor {
                    let r = geo[anchor]
                    let w: CGFloat = 316
                    let left = min(max(8, r.midX - w + 28), geo.size.width - w - 8)
                    aiCallout(arrowX: r.midX - left)
                        .frame(width: w)
                        .padding(.leading, left)
                        .padding(.bottom, geo.size.height - r.minY + 4)
                        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottomLeading)
                        .transition(.opacity.combined(with: .scale(scale: 0.96, anchor: .bottomTrailing)))
                }
            }
        }
        .overlayPreferenceValue(TopAppAnchorKey.self) { anchor in
            GeometryReader { geo in
                if showTopApps, let anchor {
                    let r = geo[anchor]
                    let w: CGFloat = 320
                    let left = min(max(8, r.midX - w + 40), geo.size.width - w - 8)
                    ZStack(alignment: .topLeading) {
                        // a click anywhere outside the bubble closes it
                        Color.black.opacity(0.001)
                            .onTapGesture { withAnimation(.easeOut(duration: 0.15)) { showTopApps = false } }
                        topAppsCallout(arrowX: r.midX - left)
                            .frame(width: w)
                            .padding(.leading, left)
                            .padding(.top, r.maxY + 2)
                            .transition(.opacity.combined(with: .scale(scale: 0.96, anchor: .topTrailing)))
                    }
                }
            }
        }
        .overlay { if store.showChangelog { changelogSheet.transition(.opacity) } }
        .overlay(alignment: .bottom) {
            if store.building || store.buildError != nil { buildDrawer.transition(.move(edge: .bottom)) }
        }
        .animation(.easeOut(duration: 0.2), value: store.showChangelog)
        .animation(.easeOut(duration: 0.25), value: store.building)
        .onExitCommand { withAnimation(.easeOut(duration: 0.15)) { showTopApps = false; showAI = false } }
        .onChange(of: store.alertText) { _, e in
            if let e { error = e; store.alertText = nil }
        }
        .onChange(of: store.aiError) { _, e in
            if let e { error = e; store.aiError = nil }
        }
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
                            .lineLimit(1).truncationMode(.middle)
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
                Stat(label: "RAM total", value: String(format: "%.0f GB", c.ram_gb)).frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack {
                Stat(label: "Swap used / size", value: String(format: "%.1f / %.0f GB", c.swap_used_gb, c.swap_total_gb))
                Stat(label: "Free disk", value: String(format: "%.0f GB", c.disk_free_gb), warn: c.disk_free_gb < 20)
                Stat(label: "Idle", value: idle >= 120 ? "\(idle / 60) min" : "\(idle) s")
                topAppTile(c)
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
                    Text(l.purpose).font(.system(size: 11)).lineLimit(1).help(l.purpose + (l.project.map { " — " + $0 } ?? ""))
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

    // The biggest app: its size as the figure, its name below (shortened in the middle,
    // full name as tooltip). Click for the list of top apps.
    func topAppTile(_ c: Sample) -> some View {
        let g = c.groups?.first
        return Button {
            NSApp.keyWindow?.makeFirstResponder(nil)
            withAnimation(.easeOut(duration: 0.15)) { showTopApps.toggle(); showAI = false }
        } label: {
            VStack(alignment: .leading, spacing: 1) {
                HStack(alignment: .firstTextBaseline, spacing: 5) {
                    Text(g.map { String(format: "%.1f GB", Double($0.mb) / 1024) } ?? "–")
                        .font(.system(size: 13, weight: .semibold)).monospacedDigit()
                    Text("biggest app").font(.system(size: 10)).foregroundStyle(.secondary)
                }
                HStack(spacing: 3) {
                    Text("#1 " + friendlyName(g?.name ?? "–")).lineLimit(1).truncationMode(.middle)
                    Image(systemName: showTopApps ? "chevron.up" : "chevron.down").font(.system(size: 7, weight: .bold))
                }
                .font(.system(size: 10)).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .focusable(false)
        .focusEffectDisabled()
        .help(g.map { "Top app: \($0.name) — \(String(format: "%.1f GB", Double($0.mb) / 1024))\($0.n.map { " in \($0) processes" } ?? "") · click for the top apps" } ?? "")
        .anchorPreference(key: TopAppAnchorKey.self, value: .bounds) { $0 }
    }

    /// "com.apple.WebKit.WebContent" -> "WebKit.WebContent": drop a reverse-DNS prefix so short tiles stay readable.
    func friendlyName(_ n: String) -> String {
        let parts = n.split(separator: ".")
        guard parts.count >= 3, ["com", "org", "net", "io", "de", "app"].contains(parts[0].lowercased()) else { return n }
        return parts.dropFirst(2).joined(separator: ".")
    }

    func topAppsCallout(arrowX: CGFloat) -> some View {
        let gs = Array((store.current?.groups ?? []).prefix(12))
        let maxMB = Double(gs.first?.mb ?? 1)
        let total = Double(gs.reduce(0) { $0 + $1.mb }) / 1024
        return VStack(spacing: 0) {
            CalloutArrow()
                .fill(.regularMaterial)
                .overlay(CalloutArrow().stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
                .frame(width: 16, height: 8)
                .rotationEffect(.degrees(180))
                .offset(x: arrowX - 160)  // centre of a 320-wide bubble
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline) {
                    Text("Biggest apps now").font(.system(size: 13, weight: .semibold))
                    Spacer()
                    Text(String(format: "%.1f GB in these %d", total, gs.count))
                        .font(.system(size: 10)).foregroundStyle(.secondary)
                }
                ForEach(Array(gs.enumerated()), id: \.offset) { i, g in
                    HStack(spacing: 8) {
                        Text("\(i + 1)").font(.system(size: 10)).foregroundStyle(.tertiary).monospacedDigit()
                            .frame(width: 14, alignment: .trailing)
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 4) {
                                Text(g.name).font(.system(size: 11.5)).lineLimit(1).truncationMode(.middle)
                                if let n = g.n, n > 1 {
                                    Text("\(n)").font(.system(size: 9.5)).foregroundStyle(.secondary).monospacedDigit()
                                        .padding(.horizontal, 4).background(Color.primary.opacity(0.08), in: Capsule())
                                        .help("\(n) processes")
                                }
                            }
                            GeometryReader { geo in
                                Capsule().fill(Color.accentColor.opacity(i == 0 ? 0.75 : 0.45))
                                    .frame(width: max(2, geo.size.width * Double(g.mb) / maxMB))
                            }.frame(height: 3)
                        }
                        Text(String(format: "%.1f GB", Double(g.mb) / 1024))
                            .font(.system(size: 11, weight: .medium)).monospacedDigit()
                            .frame(width: 54, alignment: .trailing)
                    }
                    .help(g.name)
                }
                if gs.isEmpty { Text("No data yet").font(.system(size: 11)).foregroundStyle(.secondary) }
                Text("An app counts all its helper processes; sizes are physical footprints like Activity Monitor's Memory column.")
                    .font(.system(size: 9.5)).foregroundStyle(.tertiary).fixedSize(horizontal: false, vertical: true)
            }
            .padding(12)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
        }
        .shadow(color: .black.opacity(0.22), radius: 12, y: 4)
    }

    var chart: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                // ranges animate into each other (0.5 s): the chart morphs, nothing reloads
                Picker("", selection: Binding(get: { store.range }, set: { v in
                    withAnimation(.easeInOut(duration: 0.5)) { store.range = v }
                })) {
                    Image(systemName: "infinity").tag(Double.infinity)
                    Text("24h").tag(24 * 3600.0); Text("6h").tag(6 * 3600.0); Text("1h").tag(3600.0)
                }.pickerStyle(.segmented).frame(width: 180).labelsHidden()
                .focusable(false).focusEffectDisabled()
                if store.needsUpdate {  // the logger is a different version than the one this app ships
                    if store.busy {
                        ProgressView().controlSize(.small).scaleEffect(0.6).frame(width: 16, height: 16)
                    } else {
                        Button { store.runPrivileged("install.sh") { error = $0 } } label: {
                            Image(systemName: "arrow.clockwise").font(.system(size: 12, weight: .semibold))
                                .foregroundStyle(Color.accentColor).frame(width: 16, height: 16).contentShape(Rectangle())
                        }
                        .buttonStyle(.plain).focusable(false)
                        .help("Update the logger: it runs v\(store.installedVersion ?? "?"), this app ships v\(store.bundledVersion ?? "?")")
                    }
                }
                Spacer()
                Text(store.allHistory ? "Memory, GB · log time" : "Memory, GB")
                    .font(.caption).foregroundStyle(.secondary)
            }
            ZStack {
                if !store.historyLoaded {
                    VStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Loading history…").font(.caption).foregroundStyle(.secondary)
                    }
                } else if store.history.isEmpty {
                    Text("No samples yet").font(.caption).foregroundStyle(.secondary)
                } else {
                    MemoryChart(points: store.history, gaps: store.gaps, now: store.historyNow,
                                incidents: store.incidents, events: store.events, ram: store.current?.ram_gb,
                                lgRange: log10(store.allHistory ? 24 * 3600 : store.range),
                                blend: renderBlend ?? (store.allHistory ? 1 : 0))
                        .transition(.opacity)  // fades in (0.33 s) once the history has loaded
                }
            }
            .frame(maxWidth: .infinity)
            .frame(height: 160)
            .zIndex(1)  // the hover tooltip may reach over the caption below
            Text("Grey bands = away (idle, locked or display off) · hatched = no data · red lines = incidents")
                .font(.system(size: 9)).foregroundStyle(.secondary)
        }
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

    // MARK: Upgrade button, changelog dialog, build drawer

    @ViewBuilder var upgradeButtonView: some View {
        let cur = store.bundledVersion ?? "?"
        switch store.upgradeButton {
        case .hidden:
            EmptyView()
        case .checking:  // the Check button, pressed: same size, a spinner instead of the label
            Button {} label: {
                Text("Check").hidden().overlay(ProgressView().controlSize(.small).scaleEffect(0.6))
            }.disabled(true).focusable(false)
                .help("Checking GitHub for a newer oomph…")
        case .check:
            Button("Check") { store.checkForUpgrade(manual: true) }
                .focusable(false)
                .help(store.upgradeCheckError.map { "The last check failed: \($0). Click to try again." }
                      ?? "Check GitHub for a newer oomph (this is \(cur))" + lastChecked)
                .contextMenu { autoCheckToggle }
        case .upgrade:
            Button("Upgrade") { store.openUpgrade() }
                .buttonStyle(.borderedProminent).focusable(false)
                .help("oomph \(cur) is installed — \(store.availableVersion) is available. Click to see what's new.")
                .contextMenu { autoCheckToggle }
        case .upToDate:
            Button("Up to date") {}
                .disabled(true).focusable(false)
                .help("oomph \(cur) is the newest version on GitHub")
        }
    }

    var lastChecked: String {
        let t = store.lastUpgradeCheck
        guard t > 0 else { return "" }
        let f = RelativeDateTimeFormatter()
        return " — last checked " + f.localizedString(for: Date(timeIntervalSince1970: t), relativeTo: Date())
    }

    var autoCheckToggle: some View {
        Toggle("Check once a day when oomph opens", isOn: Binding(get: { store.upgradeAuto }, set: { store.upgradeAuto = $0 }))
    }

    static let isoIn = ISO8601DateFormatter()
    static let dayOut: DateFormatter = { let f = DateFormatter(); f.dateFormat = "d MMM yyyy"; return f }()

    var changelogSheet: some View {
        let cur = store.bundledVersion ?? "?"
        let newCount = store.changelog.filter { $0.status == "new" }.count
        return ZStack {
            Color.black.opacity(0.28).onTapGesture {}
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline) {
                    Image(systemName: "arrow.down.app").foregroundStyle(Color.accentColor)
                    Text("Upgrade oomph").font(.system(size: 14, weight: .semibold))
                    Spacer()
                    Text("\(cur) → \(store.changelog.first?.version ?? store.availableVersion)")
                        .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                }
                Text(store.loadingChangelog ? "Fetching the changelog from GitHub…"
                     : newCount == 1 ? "1 new version since yours. Each commit on main is a release."
                     : "\(newCount) new versions since yours. Each commit on main is a release.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                SwiftUI.Group {
                    if renderMode {
                        changelogList(Array(store.changelog.prefix(4))).frame(maxHeight: .infinity, alignment: .top)
                    } else {
                        ScrollView { changelogList(store.changelog) }
                    }
                }
                .frame(maxHeight: .infinity)
                .background(Color(nsColor: .textBackgroundColor).opacity(0.6), in: RoundedRectangle(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
                .overlay { if store.loadingChangelog { ProgressView().controlSize(.small) } }
                HStack {
                    Button("Cancel") { store.showChangelog = false }.keyboardShortcut(.cancelAction)
                    Spacer()
                    Button("Skip This Version") { store.skipThisVersion() }
                        .help("Don't offer this version again when oomph checks by itself (Check still finds it)")
                    Button("Upgrade Now") { store.upgradeNow() }
                        .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
                        .disabled(store.loadingChangelog || newCount == 0)
                }
                .controlSize(.regular)
            }
            .padding(14)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
            .shadow(color: .black.opacity(0.3), radius: 16, y: 6)
            .padding(.horizontal, 14).padding(.vertical, 18)
        }
    }

    func changelogList(_ entries: [ChangelogEntry]) -> some View {
        LazyVStack(alignment: .leading, spacing: 12) {
            ForEach(entries) { e in changelogEntry(e) }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    func changelogEntry(_ e: ChangelogEntry) -> some View {
        let day = Self.isoIn.date(from: e.date).map { Self.dayOut.string(from: $0) } ?? String(e.date.prefix(10))
        let body = (try? AttributedString(markdown: e.body, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)))
            ?? AttributedString(e.body)
        return VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(e.version).font(.system(size: 11, weight: .semibold, design: .monospaced))
                Text(day).font(.system(size: 10)).foregroundStyle(.secondary)
                Spacer()
                if e.status == "new" {
                    Text("new").font(.system(size: 9, weight: .semibold)).foregroundStyle(.white)
                        .padding(.horizontal, 5).padding(.vertical, 1).background(Color.accentColor, in: Capsule())
                } else if e.status == "installed" {
                    Text("installed").font(.system(size: 9, weight: .semibold)).foregroundStyle(.green)
                        .padding(.horizontal, 5).padding(.vertical, 1).background(Color.green.opacity(0.15), in: Capsule())
                }
            }
            Text(e.subject).font(.system(size: 12, weight: .semibold)).fixedSize(horizontal: false, vertical: true)
            if !e.body.isEmpty {
                Text(body).font(.system(size: 11)).foregroundStyle(.secondary).lineSpacing(1.5)
                    .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
            }
            Divider().padding(.top, 4)
        }
        .opacity(e.status == "new" ? 1 : 0.6)
    }

    var buildDrawer: some View {
        VStack(alignment: .leading, spacing: 8) {
            Capsule().fill(Color.primary.opacity(0.2)).frame(width: 36, height: 4).frame(maxWidth: .infinity)
            HStack(alignment: .firstTextBaseline) {
                Text(store.buildError == nil ? "Upgrading to \(store.buildVersion.isEmpty ? "the newest version" : store.buildVersion)"
                     : "The upgrade didn't finish")
                    .font(.system(size: 13, weight: .semibold))
                Spacer()
                if store.buildError == nil {
                    Button("Cancel") { store.cancelBuild() }.controlSize(.small)
                } else {
                    Button("Close") { store.closeBuild() }.controlSize(.small).keyboardShortcut(.cancelAction)
                }
            }
            if let e = store.buildError {
                Text(e).font(.system(size: 11)).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            } else {
                ProgressView(value: nil as Double?).progressViewStyle(.linear)
                Text(store.buildProgress).font(.system(size: 11)).foregroundStyle(.secondary)
            }
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 1) {
                        ForEach(Array(store.buildLines.enumerated()), id: \.offset) { i, l in
                            Text(l).font(.system(size: 9.5, design: .monospaced)).foregroundStyle(.secondary)
                                .frame(maxWidth: .infinity, alignment: .leading).id(i)
                        }
                    }.padding(6)
                }
                .frame(height: 110)
                .background(Color(nsColor: .textBackgroundColor).opacity(0.5), in: RoundedRectangle(cornerRadius: 5))
                .onChange(of: store.buildLines.count) { _, n in if n > 0 { proxy.scrollTo(n - 1, anchor: .bottom) } }
            }
            Text("When it's built, oomph replaces itself, restarts and updates the logger (one password prompt).")
                .font(.system(size: 10)).foregroundStyle(.tertiary)
        }
        .padding(14)
        .background(.regularMaterial, in: UnevenRoundedRectangle(cornerRadii: .init(topLeading: 12, topTrailing: 12)))
        .overlay(UnevenRoundedRectangle(cornerRadii: .init(topLeading: 12, topTrailing: 12)).stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
        .shadow(color: .black.opacity(0.25), radius: 12, y: -2)
    }

    // MARK: Report + AI pair

    var reportPair: some View {
        let running = store.aiRunning
        let lit = store.aiOn && store.aiConfigured(store.aiProvider)
        let grad = LinearGradient(colors: [Color(red: 0.55, green: 0.36, blue: 0.96), Color(red: 0.23, green: 0.51, blue: 0.96)],
                                  startPoint: .topLeading, endPoint: .bottomTrailing)
        return HStack(spacing: 0) {
            Button { store.runReport() } label: {
                ZStack {
                    Text("Report").opacity(running ? 0 : 1)
                    if running { ProgressView().controlSize(.small).scaleEffect(0.6) }
                }
                .frame(minWidth: 46, minHeight: 20)
                .padding(.horizontal, 8)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .focusable(false)
            .foregroundStyle(running ? .secondary : .primary)
            .help(running ? store.aiTooltip
                  : lit ? "AI report of the last 24 h with \(store.aiSummary)" : "Open an HTML report of the last 24 h")

            Rectangle().fill(Color.primary.opacity(0.15)).frame(width: 1, height: 14)

            Button {
                if running { store.abortAI() }
                else if lit { withAnimation(.easeOut(duration: 0.15)) { store.aiOn = false } }
                else { openAICallout() }
            } label: {
                SwiftUI.Group {
                    if running {
                        Image(systemName: "stop.fill").foregroundStyle(.red)
                    } else if lit {
                        Image(systemName: "sparkles").foregroundStyle(grad)
                    } else {
                        Image(systemName: "sparkles").foregroundStyle(.secondary)
                    }
                }
                .font(.system(size: 11, weight: .semibold))
                .frame(width: 30, height: 20)
                .background(lit && !running ? AnyShapeStyle(grad.opacity(0.22)) : AnyShapeStyle(showAI ? Color.primary.opacity(0.08) : .clear))
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .focusable(false)
            .anchorPreference(key: StarAnchorKey.self, value: .bounds) { $0 }
            .help(running ? "Stop the AI report" : lit ? "AI analysis on (\(store.aiSummary)) — click to turn off"
                  : "Add an AI analysis to reports")

            Rectangle().fill(Color.primary.opacity(0.15)).frame(width: 1, height: 14)

            // the oomph skill for Claude sessions: copy a prompt or the raw link
            Menu {
                Section("Claude skill — paste into a session") {
                    Button("Copy prompt: add to the session's project") { copy(skillPrompt(allProjects: false)) }
                    Button("Copy prompt: add for all projects") { copy(skillPrompt(allProjects: true)) }
                }
                Button("Copy raw SKILL.md link") { copy(skillURL) }
            } label: {
                Image(systemName: copied ? "checkmark" : "link")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(copied ? Color.green : Color.secondary)
                    .frame(width: 30, height: 20)
                    .contentShape(Rectangle())
            }
            .menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden).fixedSize()
            .focusable(false)
            .help(copied ? "Copied — paste it into a Claude Code session" : "Share the oomph skill with a Claude session")
        }
        .font(.system(size: 12))
        .focusEffectDisabled()
        .background(Color.primary.opacity(0.07), in: RoundedRectangle(cornerRadius: 5))
        .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
        .shadow(color: lit && !running ? Color(red: 0.45, green: 0.4, blue: 0.96).opacity(0.35) : .clear, radius: 4)
    }

    func openAICallout() {
        draftProvider = store.aiProvider
        loadDraft(for: draftProvider)
        withAnimation(.easeOut(duration: 0.15)) { showAI = true; showTopApps = false }
    }

    func loadDraft(for p: AIProvider) {
        draftToken = ""
        draftModel = store.aiModel(p)
        draftURL = store.ollamaURL
        if p == .ollama { fetchOllamaModels() }
    }

    func fetchOllamaModels() {
        ollamaModels = []
        guard let url = URL(string: (draftURL.isEmpty ? "http://localhost:11434" : draftURL) + "/api/tags") else { return }
        URLSession.shared.dataTask(with: url) { data, _, _ in
            let names = ((try? JSONSerialization.jsonObject(with: data ?? Data())) as? [String: Any])
                .flatMap { $0["models"] as? [[String: Any]] }?.compactMap { $0["name"] as? String } ?? []
            DispatchQueue.main.async {
                ollamaModels = names
                if draftModel.isEmpty, let first = names.first { draftModel = first }
            }
        }.resume()
    }

    var canApply: Bool { !draftProvider.needsToken || !draftToken.isEmpty || store.hasToken(draftProvider) }

    func applyAI() {
        if !draftToken.isEmpty { Keychain.set(draftToken.trimmingCharacters(in: .whitespacesAndNewlines), draftProvider.rawValue) }
        store.setAIModel(draftModel.trimmingCharacters(in: .whitespaces), draftProvider)
        if draftProvider == .ollama { store.ollamaURL = draftURL.isEmpty ? "http://localhost:11434" : draftURL }
        store.aiProvider = draftProvider
        withAnimation(.easeOut(duration: 0.15)) {
            store.aiOn = store.aiConfigured(draftProvider)
            showAI = false
        }
    }

    func aiCallout(arrowX: CGFloat) -> some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 6) {
                    Image(systemName: "sparkles").foregroundStyle(.purple)
                    Text("AI analysis in reports").font(.system(size: 13, weight: .semibold))
                    Spacer()
                }
                Picker("", selection: $draftProvider) {
                    ForEach(AIProvider.allCases) { Text($0.title).tag($0) }
                }
                .pickerStyle(.segmented).labelsHidden()
                .onChange(of: draftProvider) { _, p in loadDraft(for: p) }

                if draftProvider.needsToken {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            SecureField(store.hasToken(draftProvider) ? "Key saved — paste to replace" : "Paste access token",
                                        text: $draftToken)
                                .textFieldStyle(.roundedBorder)
                            Button("Paste") { draftToken = NSPasteboard.general.string(forType: .string) ?? "" }
                        }
                        Text(draftProvider.keyHint).font(.system(size: 10)).foregroundStyle(.secondary)
                    }
                } else {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            TextField("http://localhost:11434", text: $draftURL).textFieldStyle(.roundedBorder)
                                .onSubmit { fetchOllamaModels() }
                            Button { fetchOllamaModels() } label: { Image(systemName: "arrow.clockwise") }
                                .help("Look for local models")
                        }
                        Text(ollamaModels.isEmpty ? "No Ollama models found at this address yet — is `ollama serve` running?"
                             : "\(ollamaModels.count) local model\(ollamaModels.count == 1 ? "" : "s") found")
                            .font(.system(size: 10)).foregroundStyle(.secondary)
                    }
                }

                HStack(spacing: 6) {
                    Text("Model").font(.system(size: 11)).foregroundStyle(.secondary)
                    if draftProvider == .ollama && !ollamaModels.isEmpty {
                        Picker("", selection: $draftModel) { ForEach(ollamaModels, id: \.self) { Text($0).tag($0) } }
                            .labelsHidden()
                    } else {
                        TextField(draftProvider.defaultModel, text: $draftModel).textFieldStyle(.roundedBorder)
                    }
                }

                Text(draftProvider == .ollama
                     ? "Reports are analysed on this Mac; nothing leaves it."
                     : "AI reports send memory figures, process names and project paths from oomph's logs to \(draftProvider == .claude ? "Anthropic" : "OpenAI"). The key stays in your keychain.")
                    .font(.system(size: 10)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

                HStack {
                    Button("Cancel") { withAnimation(.easeOut(duration: 0.15)) { showAI = false } }
                        .keyboardShortcut(.cancelAction)
                    Spacer()
                    Button("Apply") { applyAI() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(!canApply)
                }
            }
            .padding(12)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(Color.primary.opacity(0.12), lineWidth: 0.5))

            CalloutArrow()
                .fill(.regularMaterial)
                .overlay(CalloutArrow().stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
                .frame(width: 16, height: 8)
                .offset(x: arrowX - 158)  // centre of a 316-wide bubble is 158
        }
        .shadow(color: .black.opacity(0.22), radius: 12, y: 4)
        .controlSize(.small)
    }

    func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) { copied = false }
    }

    var footer: some View {
        HStack {
            if store.installed {
                Button("Deactivate") {
                    store.runPrivileged("uninstall.sh") { error = $0 }
                }.disabled(store.busy)
            } else {
                Button("Activate") {
                    store.runPrivileged("install.sh") { error = $0 }
                }.buttonStyle(.borderedProminent).disabled(store.busy)
            }
            upgradeButtonView
            reportPair
            Spacer()
            Toggle("Launch at login", isOn: Binding(get: { store.launchAtLogin }, set: { store.setLaunchAtLogin($0) }))
                .toggleStyle(.checkbox).font(.caption).lineLimit(1).fixedSize()
            Button {
                NSApp.terminate(nil)
            } label: { Image(systemName: "power") }.help("Quit oomph")
        }
        .controlSize(.small)
    }
}

struct TopAppAnchorKey: PreferenceKey {
    static var defaultValue: Anchor<CGRect>? = nil
    static func reduce(value: inout Anchor<CGRect>?, nextValue: () -> Anchor<CGRect>?) { value = value ?? nextValue() }
}

struct StarAnchorKey: PreferenceKey {
    static var defaultValue: Anchor<CGRect>? = nil
    static func reduce(value: inout Anchor<CGRect>?, nextValue: () -> Anchor<CGRect>?) { value = value ?? nextValue() }
}

/// The little triangle under the AI callout, pointing down at the ✦ button.
struct CalloutArrow: Shape {
    func path(in r: CGRect) -> Path {
        var p = Path()
        p.move(to: CGPoint(x: r.minX, y: r.minY))
        p.addLine(to: CGPoint(x: r.midX, y: r.maxY))
        p.addLine(to: CGPoint(x: r.maxX, y: r.minY))
        return p
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
        store.reloadPoints()  // in the background: the first popup then opens with its chart ready
        item.button?.target = self
        item.button?.action = #selector(toggle)
        item.button?.imageScaling = .scaleNone

        panel = PopupPanel(contentRect: NSRect(x: 0, y: 0, width: popupWidth, height: 400),
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

        // Relaunched by an upgrade: show the popup and go straight on to the logger update.
        if CommandLine.arguments.contains("--after-upgrade") {
            store.upgradeButton = .upToDate
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [weak self] in
                guard let self else { return }
                if !self.isShown { self.toggle() }
                self.store.upgradeButton = .upToDate
                if self.store.installed && self.store.needsUpdate {
                    self.store.runPrivileged("install.sh") { [weak self] e in
                        if let e { self?.store.alertText = "Upgraded to \(self?.store.bundledVersion ?? "the new version"), but the logger update failed: \(e)" }
                    }
                }
            }
        }
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
        store.popupOpened()
        position()
        panel.makeKeyAndOrderFront(nil)
        // nothing focused on open: a focus ring is drawn above everything, callouts included
        DispatchQueue.main.async { self.panel.makeFirstResponder(nil) }
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
func renderPopup(to path: String, dark: Bool, ai: String = "") {
    renderMode = true
    let store = Store()
    store.refreshAll()
    if ai != "loading" { store.reloadPoints(sync: true) }  // `--ai loading` draws the spinner
    // `--ai callout|on|running` draws the AI states (render only; nothing is saved)
    if ai == "on" || ai == "running" { store.aiOn = true; store.aiProvider = .ollama }
    if ai == "running" { store.aiRunning = true; store.aiProgress = "Tracing WebKit.GPU" }
    // `--ai upgrade|changelog|build` draws the upgrade states (render only)
    if ai == "upgrade" { store.upgradeButton = .upgrade }
    if ai == "check" { store.upgradeButton = .check }
    if ai == "checking" { store.upgradeButton = .checking }
    if ai == "uptodate" { store.upgradeButton = .upToDate }
    if ai.hasPrefix("hover:") || ai.hasPrefix("hoverlog:") {
        renderHoverX = Double(ai.split(separator: ":").last ?? "").map { CGFloat($0) }
        if ai.hasPrefix("hoverlog:") { store.range = .infinity }
    }
    if ai.hasPrefix("blend:") { renderBlend = Double(ai.dropFirst(6)) }
    if ai == "log" { store.range = .infinity }  // the ∞ range: all history on a log time axis
    if ai == "changelog" {
        store.upgradeButton = .upgrade
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = ["-I", "-B", store.cliPath, "upgrade", "log", "--json"]
        let out = Pipe(); p.standardOutput = out
        try? p.run()
        let d = out.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        store.changelog = (try? JSONDecoder().decode([ChangelogEntry].self, from: d)) ?? []
        store.showChangelog = true
    }
    if ai == "build" {
        store.building = true; store.buildVersion = "1.5.0"; store.buildProgress = "Compiling oomph 1.5.0"
        store.buildLines = ["==> Compiling oomph 1.5.0", "app/oomph.swift:42: note: building for macOS 14"]
    }
    let view = PopoverView(store: store, showAI: ai == "callout", showTopApps: ai == "top")
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
            let ai = args.firstIndex(of: "--ai").map { args.count > $0 + 1 ? args[$0 + 1] : "" } ?? ""
            MainActor.assumeIsolated { renderPopup(to: args[i + 1], dark: args.contains("--dark"), ai: ai) }
            return
        }
        // One menu-bar icon only: the newest launch wins, so a rebuilt or relaunched app
        // replaces whatever copy is already running (e.g. the one started at login).
        let me = ProcessInfo.processInfo.processIdentifier
        for other in NSRunningApplication.runningApplications(withBundleIdentifier: Bundle.main.bundleIdentifier ?? "")
            where other.processIdentifier != me {
            if !other.terminate() { other.forceTerminate() }
        }
        // Keep the login item pointing at this executable (it went stale after the OOMph → oomph rename).
        if let exe = Bundle.main.executablePath,
           let plist = NSMutableDictionary(contentsOfFile: agentPlist),
           (plist["ProgramArguments"] as? [String])?.first != exe {
            plist["ProgramArguments"] = [exe]
            plist.write(toFile: agentPlist, atomically: true)
        }
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        app.run()
    }
}
