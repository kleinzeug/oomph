// oomph — menu bar front-end for the oomph daemon (see ../DESIGN.md).
// Build: ../build-app.sh
import AppKit
import Charts
import Security
import SwiftUI

let logDir = ProcessInfo.processInfo.environment["OOMPH_DIR"] ?? "/Library/Logs/oomph"
/// The agents' coordination ledger (ledger.json) and its history log (reservations.jsonl).
let ledgerDir = ProcessInfo.processInfo.environment["OOMPH_LEDGER_DIR"] ?? "/Users/Shared/oomph"
let brand = "oomph"  // the product's name in prose and titles (oomph.py's BRAND; tools/brandlint.py)
let descriptor = ": memory monitor"  // what the header says after the name
let agentLabel = "local.oomph.menubar"
let popupWidth: CGFloat = 480
let statColumn: CGFloat = 96
var renderHoverX: CGFloat?  // --ai hover:X / hoverlog:X renders the hover tooltip at x = X pt
var renderBlend: Double?  // --ai blend:0.5 renders the 24h → ∞ morph halfway
var renderMode = false  // --render-popup: static renders don't draw scroll-view contents
var renderStripHover: CGPoint?  // --ai rhover:X:Y renders the reservation strip's tooltip at (X, Y) pt
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

/// The skill installed with the logger and the `oomph` command (install.sh puts it there).
let installedSkill = "/usr/local/libexec/oomph/skills/oomph/SKILL.md"

/// A prompt to paste into a Claude Code session. It copies the skill that was installed with the
/// `oomph` command the session will run, so the two always match (`oomph setup-claude` does the
/// same); only where no logger is installed does it download the one on GitHub's main verbatim
/// with curl (a web fetch would hand the model a summary, not the file). Then the session follows it.
func skillPrompt(allProjects: Bool) -> String {
    let dir = allProjects ? "~/.claude/skills/oomph" : ".claude/skills/oomph"
    let scope = allProjects ? "for all my projects" : "to this project"
    let get = FileManager.default.fileExists(atPath: installedSkill)
        ? "cp \(installedSkill) \(dir)/SKILL.md" : "curl -fsSL \(skillURL) -o \(dir)/SKILL.md"
    return "Add the oomph skill \(scope): run `mkdir -p \(dir) && \(get)`, "
        + "then read \(dir)/SKILL.md and follow it for the rest of this session."
}
let agentPlist = NSHomeDirectory() + "/Library/LaunchAgents/\(agentLabel).plist"

// MARK: - Model

/// Limits for what is read from the shared ledger directory (oomph.py's LIMITS).
let ledgerCap = 4 << 20, historyCap = 8 << 20

/// Reads a file of the shared ledger directory. That directory is world-writable, so anyone can
/// plant a link, a FIFO or an endless or huge file there: this never follows a symbolic link
/// (neither the file nor the directory itself), never blocks on a FIFO, takes only a regular
/// file with a single link, and reads at most `cap` bytes — with `tail`, the last whole lines
/// within `cap` of a bigger file, else nothing.
func readShared(_ path: String, cap: Int, tail: Bool = false) -> Data? {
    let dir = (path as NSString).deletingLastPathComponent, name = (path as NSString).lastPathComponent
    let dfd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard dfd >= 0 else { return nil }
    defer { close(dfd) }
    let fd = openat(dfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard fd >= 0 else { return nil }
    defer { close(fd) }
    var st = stat()
    guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_nlink == 1 else { return nil }
    let size = Int(st.st_size)
    let cut = size > cap
    if cut {
        guard tail, lseek(fd, off_t(size - cap), SEEK_SET) >= 0 else { return nil }
    }
    var data = Data(count: min(size, cap))
    var got = 0
    while got < data.count {
        let n = data.withUnsafeMutableBytes { read(fd, $0.baseAddress! + got, $0.count - got) }
        if n <= 0 { break }
        got += n
    }
    data.count = got
    if cut {  // the first line is a fragment
        data = data.firstIndex(of: 0x0A).map { data.subdata(in: ($0 + 1)..<data.count) } ?? Data()
    }
    return data
}

struct Away: Decodable { var idle_s: Int?; var display_on: Bool?; var locked: Bool?; var sleep_preventers: [String]? }
struct Group: Decodable { var name: String; var mb: Int; var n: Int? }
struct Session: Decodable { var pid: Int; var cwd: String?; var mb: Int; var n: Int }
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

/// One reservation of the agents' memory ledger: live (ledger.json) or finished (reservations.jsonl).
struct Reservation: Identifiable {
    let id: String                       // "r12@1795172655": unique across ledger resets
    let rid: String                      // "r12"
    var purpose: String
    var project: String?
    var holder: String?                  // session / process / run
    var segments: [(t: Double, gb: Double)]  // its size over time (one entry unless edited)
    var requested: Double
    var granted: Double?
    var ended: Double?                   // nil while live
    var outcome: String?
    var peak = 0.0
    var used: Double?
    var expires: Double?

    var live: Bool { ended == nil }
    var gb: Double { segments.last?.gb ?? 0 }
    func gb(at t: Double) -> Double { (segments.last { $0.t <= t } ?? segments.first)?.gb ?? 0 }
    var projectName: String? { project.map { ($0 as NSString).lastPathComponent }.flatMap { $0.isEmpty ? nil : $0 } }

    /// Colours avoid the memory chart's grey, blue, orange and red. The same purpose always gets the
    /// same colour (a stable hash, not Swift's per-launch one), in the blocks and in the list.
    static let palette: [Color] = [.teal, .purple, .pink, .indigo, Color(red: 0.84, green: 0.62, blue: 0.0), .brown, .green]
    var color: Color {
        var h: UInt32 = 5381
        for u in purpose.unicodeScalars { h = (h &* 33) ^ u.value }
        return Reservation.palette[Int(h % UInt32(Reservation.palette.count))]
    }

    /// From a ledger lease, a ledger history entry or a reservations.jsonl record.
    init?(_ o: [String: Any], ended: Double? = nil, outcome: String? = nil) {
        func num(_ k: String) -> Double? { (o[k] as? NSNumber)?.doubleValue }
        guard let rid = o["id"] as? String, let req = num("requested"), let gb = num("gb") else { return nil }
        self.rid = rid
        id = (o["key"] as? String) ?? "\(rid)@\(Int(req))"
        purpose = (o["purpose"] as? String) ?? "?"
        project = o["project"] as? String
        holder = (o["holder"] as? String) ?? ((o["holder"] as? [String: Any])?["kind"] as? String)
        requested = req
        granted = num("granted")
        self.ended = ended ?? num("ended")
        self.outcome = outcome ?? (o["outcome"] as? String)
        peak = num("peak_gb") ?? 0
        used = num("used_gb")
        expires = num("expires")
        let segs = ((o["segments"] as? [[String: Any]]) ?? []).compactMap { x -> (t: Double, gb: Double)? in
            guard let t = (x["t"] as? NSNumber)?.doubleValue, let g = (x["gb"] as? NSNumber)?.doubleValue else { return nil }
            return (t, g)
        }
        segments = segs.isEmpty ? [(req, gb)] : segs
    }
}

/// A reservation laid out on the strip: steps of [a, b) in time with the stacked GB below (lo) and
/// at its top (hi). Reservations overlapping in time stack in lanes, so the top of the stack is the
/// total reserved; lanes are packed first-fit by start time.
struct ResBlock: Identifiable {
    let res: Reservation
    var lane = 0
    var end: Double
    var steps: [(a: Double, b: Double, lo: Double, hi: Double)] = []
    var id: String { res.id }

    static func stack(_ rs: [Reservation], now: Double) -> [ResBlock] {
        var blocks = rs.sorted { $0.requested < $1.requested }
            .map { ResBlock(res: $0, end: max($0.ended ?? now, $0.requested + 1)) }
        var laneEnd: [Double] = []
        for i in blocks.indices {
            if let k = laneEnd.firstIndex(where: { $0 <= blocks[i].res.requested }) {
                blocks[i].lane = k; laneEnd[k] = blocks[i].end
            } else {
                blocks[i].lane = laneEnd.count; laneEnd.append(blocks[i].end)
            }
        }
        var bps = Set<Double>()
        for b in blocks {
            bps.insert(b.res.requested); bps.insert(b.end)
            if let g = b.res.granted, g > b.res.requested, g < b.end { bps.insert(g) }
            for s in b.res.segments where s.t > b.res.requested && s.t < b.end { bps.insert(s.t) }
        }
        let ts = bps.sorted()
        var active: [Int] = []
        var next = 0
        for (i, a) in ts.enumerated().dropLast() {
            let b = ts[i + 1]
            while next < blocks.count && blocks[next].res.requested <= a { active.append(next); next += 1 }
            active.removeAll { blocks[$0].end <= a }
            var acc = 0.0
            for j in active.sorted(by: { blocks[$0].lane < blocks[$1].lane }) {
                let hi = acc + blocks[j].res.gb(at: a)
                if let last = blocks[j].steps.last, last.b == a, last.lo == acc, last.hi == hi,
                   (blocks[j].res.granted ?? .infinity) != a {
                    blocks[j].steps[blocks[j].steps.count - 1].b = b
                } else {
                    blocks[j].steps.append((a, b, acc, hi))
                }
                acc = hi
            }
        }
        return blocks
    }
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
    /// The agents' reservations, live and of the last 14 days, stacked for the strip under the chart.
    @Published var reservations: [ResBlock] = []
    var liveReservations: [Reservation] {
        reservations.map(\.res).filter(\.live).sorted { ($0.granted == nil ? 1 : 0, $0.requested) < ($1.granted == nil ? 1 : 0, $1.requested) }
    }
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
    @Published var aiConnecting = false     // `oomph ai-check` confirming a new connection
    @Published var aiConnectError: String?
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

    private struct Loaded { let history: [Point]; let gaps: [Gap]; let now: Double; let events: [ChartEvent]?
                            let reservations: [ResBlock] }

    private func apply(_ r: Loaded) {
        history = r.history
        gaps = r.gaps
        historyNow = r.now
        if let e = r.events { events = e }
        reservations = r.reservations
    }

    /// Finished reservations from the history log and the ledger's own short history, plus the live
    /// ones. A live lease whose holder is gone, that expired or whose queue place lapsed ends there
    /// (the logger retires it within a sample; an older logger may not have yet). On loadQueue only.
    private func loadReservations(now: Double) -> [ResBlock] {
        var byKey: [String: Reservation] = [:]
        var events: [String: String] = [:]
        if let d = readShared(ledgerDir + "/reservations.jsonl", cap: historyCap, tail: true) {
            for line in d.split(separator: 0x0A) {
                guard let o = (try? JSONSerialization.jsonObject(with: Data(line))) as? [String: Any],
                      let r = Reservation(o) else { continue }
                let ev = (o["event"] as? String) ?? "end"
                if ev == "end" || events[r.id] != "end" { byKey[r.id] = r; events[r.id] = ev }
            }
        }
        let ledger = readShared(ledgerDir + "/ledger.json", cap: ledgerCap)
            .flatMap { (try? JSONSerialization.jsonObject(with: $0)) as? [String: Any] } ?? [:]
        for h in (ledger["history"] as? [[String: Any]]) ?? [] {
            if let r = Reservation(h), byKey[r.id] == nil { byKey[r.id] = r }
        }
        for l in (ledger["leases"] as? [[String: Any]]) ?? [] {
            guard var r = Reservation(l) else { continue }
            let seen = (l["seen"] as? NSNumber)?.doubleValue ?? r.requested
            let pid = ((l["holder"] as? [String: Any])?["pid"] as? NSNumber)?.int32Value ?? 0
            if let e = r.expires, r.granted != nil, e < now { r.ended = e; r.outcome = "expired" }
            else if r.granted == nil, now - seen > 180 { r.ended = seen + 180; r.outcome = "lapsed" }
            else if pid > 0, kill(pid, 0) != 0, errno == ESRCH { r.ended = max(seen, r.granted ?? r.requested); r.outcome = "holder_gone" }
            byKey[r.id] = r
        }
        // an edit record whose reservation neither ended nor is live: the ledger was reset under it
        for (k, ev) in events where ev == "edit" && byKey[k]?.live == true {
            if !((ledger["leases"] as? [[String: Any]]) ?? []).contains(where: { Reservation($0)?.id == k }),
               var r = byKey[k] {
                r.ended = r.segments.last?.t ?? r.requested; r.outcome = "unknown"
                byKey[k] = r
            }
        }
        let keep = now - 14 * 86400
        return ResBlock.stack(byKey.values.filter { ($0.ended ?? now) >= keep }, now: now)
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
        return Loaded(history: Store.multires(all, now: now), gaps: gaps, now: now, events: loadEvents(),
                      reservations: loadReservations(now: now))
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
            let src = "do shell script \"\(cmd)\" with prompt \"\(brand) needs administrator rights to install or remove its memory-logging daemon.\" with administrator privileges"
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
                    self?.buildError = "Upgraded, but the relaunch failed (\(err.localizedDescription)). Quit \(brand) and open it again."
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
    /// Reports include an AI analysis from this provider (the render aid has no keychain).
    var aiConnected: Bool { aiOn && (renderMode || aiConfigured(aiProvider)) }

    /// Connect: confirm the provider takes the token and knows the model (one cheap request
    /// via `oomph ai-check`, no tokens spent), then save the token and switch AI reports on.
    func connectAI(_ p: AIProvider, token: String, model: String, url: String, done: @escaping (Bool) -> Void) {
        aiConnecting = true
        aiConnectError = nil
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        var args = ["-I", "-B", cliPath, "ai-check", "--provider", p.rawValue]
        if !model.isEmpty { args += ["--model", model] }
        if p == .ollama { args += ["--base-url", url] }
        proc.arguments = args
        var env = ProcessInfo.processInfo.environment
        env["OOMPH_AI_TOKEN"] = token  // via the environment, not argv
        proc.environment = env
        let out = Pipe()
        proc.standardOutput = out
        proc.standardError = FileHandle.nullDevice
        DispatchQueue.global().async {
            var reply: [String: Any] = [:]
            do {
                try proc.run()
                let d = out.fileHandleForReading.readDataToEndOfFile()
                proc.waitUntilExit()
                let last = String(decoding: d, as: UTF8.self).split(separator: "\n").last.map(String.init) ?? ""
                reply = (try? JSONSerialization.jsonObject(with: Data(last.utf8)) as? [String: Any]) ?? [:]
            } catch {
                reply = ["error": "couldn't run the check: \(error.localizedDescription)"]
            }
            DispatchQueue.main.async {
                self.aiConnecting = false
                guard reply["ok"] as? Bool == true else {
                    self.aiConnectError = (reply["error"] as? String) ?? "the connection check failed"
                    done(false)
                    return
                }
                if p.needsToken { Keychain.set(token, p.rawValue) }
                self.setAIModel(model.isEmpty ? (reply["model"] as? String ?? "") : model, p)
                if p == .ollama { self.ollamaURL = url }
                self.aiProvider = p
                self.aiOn = true
                done(true)
            }
        }
    }

    /// Disconnect: reports go back to plain HTML. The token stays in the keychain for a reconnect.
    func disconnectAI() {
        aiOn = false
        aiConnectError = nil
    }

    var aiSummary: String {
        let m = aiModel(aiProvider)
        return aiProvider.title + (m.isEmpty ? "" : " · " + m)
    }

    func runReport() {
        if aiRunning { return }
        if aiConnected { runAIReport() } else { runCLI(["html", "--last", "24h", "--open"]) }
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
    /// The agents' reservations, drawn as a strip of blocks under the chart on the same time axis.
    var reservations: [ResBlock] = []
    var stripHeight: CGFloat = 0 // 0 = no strip
    /// The pointer's x over the chart (overlay coordinates), nil when it isn't hovering.
    @State private var hoverX: CGFloat? = renderHoverX
    /// The pointer over the reservation strip (strip coordinates).
    @State private var stripHover: CGPoint? = renderStripHover

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
        MemoryChart.mapper(now: now, first: points.first?.id ?? now, lgRange: lgRange, blend: blend)
    }

    /// Linear: the last 10^lgRange s. Log: all history, ages under minAge at the right edge.
    static func mapper(now: Double, first: Double, lgRange: Double, blend b: Double) -> (Double) -> Double {
        let r = pow(10, lgRange), m = MemoryChart.minAge
        let span = log10(max(now - first, 3600) / m)
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
            let gaps = gapBands(f)
            let grid = gridLines(f, plotW: plotW)
            let labels = axisLabels(f, plotW: plotW)
            VStack(spacing: MemoryChart.stripGap) {
                Chart {
                    gridMarks(grid, color: .primary, scale: 1)
                    areaMarks(entries)
                    gridMarks(grid, color: .white, scale: 0.45)
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
                .chartForegroundStyleScale(domain: MemoryChart.series, range: MemoryChart.seriesColors)
                .chartLegend(.hidden)  // the compact legend sits in the header row (ChartLegend)
                .transaction { $0.animation = nil }  // this view animates itself, frame by frame
                .chartBackground { proxy in bandLayer(proxy, away: away, gaps: gaps) }
                .chartOverlay { proxy in
                    ZStack(alignment: .topLeading) {
                        axisLabelLayer(proxy, labels: labels)
                        hoverTracker(proxy)
                    }
                }
                if stripHeight > 0 {
                    Color.clear.frame(height: stripHeight).tourAnchor("strip")
                }
            }
            // drawn over both: the strip needs the chart's plot frame, and the tooltips reach over
            // the other part (the chart's tooltip over the strip, the strip's over the chart)
            .overlayPreferenceValue(PlotRectKey.self) { plot in
                ZStack(alignment: .topLeading) {
                    if let plot {
                        if stripHeight > 0 { stripLayer(plot: plot, top: geo.size.height - stripHeight, mapper: f, grid: grid) }
                        hoverLayer(plot: plot, mapper: f, stripTop: geo.size.height - stripHeight)
                        if stripHeight > 0 { stripCard(plot: plot, top: geo.size.height - stripHeight, width: geo.size.width, mapper: f) }
                    }
                }
                .frame(width: geo.size.width, height: geo.size.height, alignment: .topLeading)
            }
        }
    }

    static let seriesColors: [Color] = [.gray, .blue, .orange, .red]
    static let stripGap: CGFloat = 4

    // MARK: away bands and no-data hatching

    /// Away bands and no-data stretches, drawn behind the series in one Canvas: stretches closer
    /// than 2 px merge (a Mac that keeps dozing off reads as one calm band, not a grey comb), and
    /// one hatch pattern, anchored to the plot, shows through all no-data stretches.
    func bandLayer(_ proxy: ChartProxy, away: [Band], gaps: [Band]) -> some View {
        GeometryReader { g in
            let plot = proxy.plotFrame.map { g[$0] } ?? CGRect(origin: .zero, size: g.size)
            Canvas { ctx, size in
                let W = Double(size.width)
                let (grey, hatched) = MemoryChart.calmBands(away: away.map { ($0.from * W, $0.to * W) },
                                                            gaps: gaps.map { ($0.from * W, $0.to * W) }, tolerance: 2)
                var greyPath = Path(), hatchPath = Path()
                for (a, b) in grey { greyPath.addRect(CGRect(x: a, y: 0, width: max(b - a, 1), height: size.height)) }
                for (a, b) in hatched { hatchPath.addRect(CGRect(x: a, y: 0, width: max(b - a, 1), height: size.height)) }
                ctx.fill(greyPath, with: .color(.gray.opacity(0.15)))
                ctx.fill(hatchPath, with: .color(.gray.opacity(0.06)))
                var c = ctx
                c.clip(to: hatchPath)
                c.stroke(MemoryChart.hatchLines(in: CGRect(origin: .zero, size: size)), with: .color(.gray.opacity(0.45)), lineWidth: 1)
            }
            .frame(width: plot.width, height: plot.height)
            .offset(x: plot.minX, y: plot.minY)
        }
        .allowsHitTesting(false)
    }

    /// Merges spans (in px) closer than `tolerance`. Grey: away spans, bridged by no-data stretches
    /// that touch them (asleep while away); a no-data stretch with nobody away near it stays white.
    static func calmBands(away: [(Double, Double)], gaps: [(Double, Double)], tolerance: Double)
        -> (grey: [(Double, Double)], hatched: [(Double, Double)]) {
        func merge(_ spans: [(Double, Double, Bool)]) -> [(Double, Double, Bool)] {
            var out: [(Double, Double, Bool)] = []
            for s in spans.sorted(by: { $0.0 < $1.0 }) {
                if let l = out.last, s.0 - l.1 <= tolerance {
                    out[out.count - 1] = (l.0, max(l.1, s.1), l.2 || s.2)
                } else {
                    out.append(s)
                }
            }
            return out
        }
        let grey = merge(away.map { ($0.0, $0.1, true) } + gaps.map { ($0.0, $0.1, false) }).filter(\.2).map { ($0.0, $0.1) }
        return (grey, merge(gaps.map { ($0.0, $0.1, true) }).map { ($0.0, $0.1) })
    }

    /// Diagonal hatch lines over `r`, on a grid anchored at the origin: clipped to several shapes,
    /// they form one continuous pattern.
    static func hatchLines(in r: CGRect, spacing: CGFloat = 6) -> Path {
        var p = Path()
        var c = ((r.minX + r.minY) / spacing).rounded(.down) * spacing
        while c <= r.maxX + r.maxY {
            p.move(to: CGPoint(x: c - r.maxY, y: r.maxY))
            p.addLine(to: CGPoint(x: c - r.minY, y: r.minY))
            c += spacing
        }
        return p
    }

    // MARK: reservation strip

    /// Every reservation as blocks on the chart's time axis: height ∝ GB, stacked where they
    /// overlap, solid while granted, hatched while queued. The scale's top is a round figure above
    /// the highest stack in view.
    func stripRects(_ f: (Double) -> Double, W: CGFloat, H: CGFloat) -> (rects: [(i: Int, r: CGRect, queued: Bool)], top: Double) {
        var vis = 0.0
        for b in reservations where f(b.end) >= 0 {
            for st in b.steps where f(st.b) >= 0 { vis = max(vis, st.hi) }
        }
        let top = [2.0, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256].first { $0 >= vis } ?? vis
        let usable = H - 4
        var out: [(i: Int, r: CGRect, queued: Bool)] = []
        for (i, b) in reservations.enumerated() {
            let bx0 = f(b.res.requested) * W, bx1 = f(b.end) * W
            guard bx1 >= 0, bx0 <= W else { continue }
            let widen = max(0, 1.5 - (bx1 - bx0))  // even a 10-second reservation stays visible
            for (k, st) in b.steps.enumerated() {
                let x0 = max(f(st.a) * W, 0), x1 = min(f(st.b) * W + (k == b.steps.count - 1 ? widen : 0), W)
                guard x1 > x0 else { continue }
                let y0 = H - CGFloat(st.hi / top) * usable, y1 = H - CGFloat(st.lo / top) * usable
                let queued = b.res.granted.map { st.a < $0 } ?? true
                // half a point off top and bottom: stacked blocks get a hairline between them
                out.append((i, CGRect(x: x0, y: y0 + 0.5, width: x1 - x0, height: max(y1 - y0 - 1, 0.75)), queued))
            }
        }
        return (out, top)
    }

    func stripLayer(plot: CGRect, top: CGFloat, mapper f: @escaping (Double) -> Double, grid: [GridLine]) -> some View {
        let W = plot.width, H = stripHeight
        let (rects, scaleTop) = stripRects(f, W: W, H: H)
        let blocks = reservations, now = now
        return ZStack(alignment: .topLeading) {
            Canvas { ctx, size in
                let usable = H - 4
                for l in grid {
                    ctx.fill(Path(CGRect(x: l.x * W - 0.25, y: 0, width: 0.5, height: H)), with: .color(.primary.opacity(l.alpha)))
                }
                ctx.fill(Path(CGRect(x: 0, y: H - 0.5, width: W, height: 0.5)), with: .color(.primary.opacity(0.25)))
                var topLine = Path()
                topLine.move(to: CGPoint(x: 0, y: H - usable)); topLine.addLine(to: CGPoint(x: W, y: H - usable))
                ctx.stroke(topLine, with: .color(.primary.opacity(0.12)), style: StrokeStyle(lineWidth: 0.5, dash: [2, 2]))
                var plotCtx = ctx
                plotCtx.clip(to: Path(CGRect(x: 0, y: 0, width: W, height: H)))
                var solid: [Int: Path] = [:], waiting: [Int: Path] = [:]
                for x in rects {
                    if x.queued { waiting[x.i, default: Path()].addRect(x.r) } else { solid[x.i, default: Path()].addRect(x.r) }
                }
                for (i, p) in solid { plotCtx.fill(p, with: .color(blocks[i].res.color.opacity(0.8))) }
                for (i, p) in waiting {
                    let c = blocks[i].res.color
                    plotCtx.fill(p, with: .color(c.opacity(0.12)))
                    var h = plotCtx
                    h.clip(to: p)
                    h.stroke(MemoryChart.hatchLines(in: p.boundingRect, spacing: 4), with: .color(c.opacity(0.75)), lineWidth: 1)
                }
                // purpose labels on the widest granted part of each block, when it fits
                var best: [Int: CGRect] = [:]
                for x in rects where !x.queued && x.r.height >= 9 && x.r.width > (best[x.i]?.width ?? 0) { best[x.i] = x.r }
                for (i, r) in best where r.width >= 24 {
                    let purpose = blocks[i].res.purpose
                    var n = purpose.count
                    while n >= 4 {
                        let s = n == purpose.count ? purpose : String(purpose.prefix(n)) + "…"
                        let t = plotCtx.resolve(Text(s).font(.system(size: 8.5, weight: .medium)).foregroundColor(.white))
                        if t.measure(in: CGSize(width: 1000, height: 20)).width <= r.width - 6 {
                            plotCtx.draw(t, at: CGPoint(x: r.minX + 3, y: r.midY), anchor: .leading)
                            break
                        }
                        n = n > 24 ? 24 : n - 3
                    }
                }
                // right of the plot: the scale, and how long each live grant has left
                var used: [CGFloat] = []
                for x in rects where blocks[x.i].res.live && !x.queued && x.r.maxX >= W - 0.5 {
                    guard let e = blocks[x.i].res.expires, !used.contains(where: { abs($0 - x.r.midY) < 9 }) else { continue }
                    used.append(x.r.midY)
                    ctx.draw(Text(MemoryChart.shortDuration(e - now)).font(.system(size: 8.5)).foregroundColor(.secondary),
                             at: CGPoint(x: W + 4, y: x.r.midY), anchor: .leading)
                }
                if !used.contains(where: { abs($0 - (H - usable)) < 9 }) {
                    ctx.draw(Text(String(format: "%.0fG", scaleTop)).font(.system(size: 8.5)).foregroundColor(.secondary),
                             at: CGPoint(x: W + 4, y: H - usable), anchor: .leading)
                }
                if rects.isEmpty {
                    ctx.draw(Text("No reservations in this range").font(.system(size: 9)).foregroundColor(.secondary),
                             at: CGPoint(x: W / 2, y: H / 2), anchor: .center)
                }
            }
            .frame(width: W + 40, height: H)
            .allowsHitTesting(false)
            Rectangle().fill(Color.clear).contentShape(Rectangle())
                .frame(width: W, height: H)
                .onContinuousHover { phase in
                    switch phase {
                    case .active(let p): stripHover = p
                    case .ended: stripHover = nil
                    }
                }
                .help(stripHover.flatMap { stripHit($0, f, W: W) } != nil ? "" : "Memory reserved by agents (Claude sessions, oomph run), one block per reservation: height = GB reserved, hatched while queued, stacked where they overlap. Hover a block for details.")
        }
        .offset(x: plot.minX, y: top)
    }

    /// The reservation under the pointer on the strip, if any.
    func stripHit(_ p: CGPoint, _ f: (Double) -> Double, W: CGFloat) -> (block: ResBlock, rect: CGRect)? {
        let (rects, _) = stripRects(f, W: W, H: stripHeight)
        let hit = rects.last { $0.r.insetBy(dx: -2, dy: -1).contains(p) }
            ?? rects.filter { p.x >= $0.r.minX - 2 && p.x <= $0.r.maxX + 2 }.min { abs($0.r.midY - p.y) < abs($1.r.midY - p.y) }
        return hit.map { (reservations[$0.i], $0.r) }
    }

    @ViewBuilder func stripCard(plot: CGRect, top: CGFloat, width: CGFloat, mapper f: (Double) -> Double) -> some View {
        if let p = stripHover, let (b, r) = stripHit(p, f, W: plot.width) {
            let x = plot.minX + p.x
            let w = MemoryChart.cardWidth
            Rectangle().strokeBorder(Color.primary.opacity(0.7), lineWidth: 1)
                .frame(width: max(r.width, 1.5) + 2, height: r.height + 2)
                .offset(x: plot.minX + r.minX - 1, y: top + r.minY - 1)
                .allowsHitTesting(false)
            ReservationCard(res: b.res, now: now)
                .frame(width: w, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
                .frame(width: w, height: max(top - 6, 1), alignment: .bottom)  // above the strip, over the chart
                .offset(x: min(max(x - w / 2, 0), width - w))
                .allowsHitTesting(false)
        }
    }

    static func shortDuration(_ s: Double) -> String {
        let m = max(Int((s / 60).rounded()), 0)
        return m < 60 ? "\(m)m" : (m % 60 == 0 || m >= 600 ? "\(m / 60)h" : "\(m / 60)h\(String(format: "%02d", m % 60))")
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

    /// Follows the pointer over the chart, and hands the plot's frame to the layers drawn over
    /// the chart and the strip.
    func hoverTracker(_ proxy: ChartProxy) -> some View {
        GeometryReader { g in
            let plot = proxy.plotFrame.map { g[$0] } ?? CGRect(origin: .zero, size: g.size)
            Rectangle().fill(Color.clear).contentShape(Rectangle())
                .onContinuousHover { phase in
                    switch phase {
                    case .active(let p): hoverX = p.x
                    case .ended: hoverX = nil
                    }
                }
                .preference(key: PlotRectKey.self, value: plot)
        }
    }

    /// A vertical line following the pointer and a live tooltip for the time under it.
    @ViewBuilder func hoverLayer(plot: CGRect, mapper f: @escaping (Double) -> Double, stripTop: CGFloat) -> some View {
        if let x = hoverX, x >= plot.minX, x <= plot.maxX {
            let info = hoverInfo(u: Double((x - plot.minX) / plot.width), du: 1 / Double(plot.width), mapper: f)
            Rectangle().fill(Color.primary.opacity(0.55))
                .frame(width: 1, height: plot.height)
                .offset(x: x - 0.5, y: plot.minY)
                .allowsHitTesting(false)
            if stripHeight > 0 {  // the same moment on the reservation strip
                Rectangle().fill(Color.primary.opacity(0.4))
                    .frame(width: 1, height: stripHeight)
                    .offset(x: x - 0.5, y: stripTop)
                    .allowsHitTesting(false)
            }
            HoverCard(info: info)
                .frame(width: MemoryChart.cardWidth, alignment: .leading)
                .offset(x: x < plot.midX ? x + 10 : x - 10 - MemoryChart.cardWidth, y: plot.minY + 2)
                .allowsHitTesting(false)
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
        var reserved: [(String, Color)] = []  // reservations active under the pointer
        var moreReserved = 0
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
        let res = reservations.filter { $0.res.requested <= t1 && $0.end >= t0 }
        info.reserved = res.prefix(4).map { b in
            let queued = (b.res.granted ?? .infinity) > tc
            return (String(format: "%.1f GB ", b.res.gb(at: min(max(tc, b.res.requested), b.end))) + b.res.purpose
                    + (queued ? " (queued)" : ""), b.res.color)
        }
        info.moreReserved = max(res.count - 4, 0)
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
                if !info.reserved.isEmpty {
                    Divider().padding(.vertical, 1)
                    Text("Reserved by agents").font(.system(size: 9)).foregroundStyle(.secondary)
                    ForEach(Array(info.reserved.enumerated()), id: \.offset) { _, r in
                        HStack(spacing: 5) {
                            RoundedRectangle(cornerRadius: 1.5).fill(r.1.opacity(0.8)).frame(width: 7, height: 7)
                            Text(r.0).font(.system(size: 10)).lineLimit(1).truncationMode(.tail)
                        }
                    }
                    if info.moreReserved > 0 {
                        Text("+ \(info.moreReserved) more").font(.system(size: 9)).foregroundStyle(.tertiary)
                    }
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

/// The plot's frame inside the memory chart, for the layers drawn over the chart and the strip.
struct PlotRectKey: PreferenceKey {
    static var defaultValue: CGRect? = nil
    static func reduce(value: inout CGRect?, nextValue: () -> CGRect?) { value = value ?? nextValue() }
}

/// A reservation's details, for the strip's tooltip.
struct ReservationCard: View {
    let res: Reservation
    let now: Double

    static let clock: DateFormatter = { let f = DateFormatter(); f.dateFormat = "HH:mm"; return f }()
    static let dayClock: DateFormatter = { let f = DateFormatter(); f.dateFormat = "EEE d HH:mm"; return f }()
    func at(_ t: Double) -> String {
        let d = Date(timeIntervalSince1970: t)
        return Calendar.current.isDateInToday(d) ? ReservationCard.clock.string(from: d) : ReservationCard.dayClock.string(from: d)
    }
    static let outcomes = ["released": "released", "expired": "expired (not released in time)",
                           "holder_gone": "ended: its session or process exited", "lapsed": "lapsed: stopped waiting in the queue",
                           "cancelled": "cancelled while queued", "unknown": "ended (the ledger was reset)"]

    func row(_ k: String, _ v: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(k).font(.system(size: 10)).foregroundStyle(.secondary).frame(width: 58, alignment: .leading)
            Text(v).font(.system(size: 10)).fixedSize(horizontal: false, vertical: true)
        }
    }

    var body: some View {
        let gbs = res.segments.map { String(format: "%.1f", $0.gb) }.joined(separator: " → ") + " GB"
        let edits = res.segments.count > 1 ? " (changed " + res.segments.dropFirst().map { at($0.t) }.joined(separator: ", ") + ")" : ""
        VStack(alignment: .leading, spacing: 3) {
            HStack(alignment: .firstTextBaseline, spacing: 5) {
                RoundedRectangle(cornerRadius: 2).fill(res.color.opacity(0.85)).frame(width: 8, height: 8)
                Text(res.purpose).font(.system(size: 11, weight: .semibold)).lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 4)
                Text(res.rid).font(.system(size: 9, design: .monospaced)).foregroundStyle(.tertiary)
            }
            if res.projectName != nil || res.holder != nil {
                Text([res.projectName, res.holder.map { $0 == "run" ? "oomph run" : $0 }].compactMap { $0 }.joined(separator: " · "))
                    .font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
            }
            Divider().padding(.vertical, 1)
            row("Reserved", gbs + edits)
            row("Peak used", res.live && res.granted != nil
                ? String(format: "%.1f GB so far (%.1f GB now)", res.peak, res.used ?? 0)
                : String(format: "%.1f GB", res.peak))
            if let g = res.granted {
                row("Granted", at(g) + (g - res.requested >= 60 ? " · waited " + MemoryChart.duration(g - res.requested) : ""))
            } else {
                row("Requested", at(res.requested) + " · waited " + MemoryChart.duration((res.ended ?? now) - res.requested))
            }
            if let e = res.ended {
                row("Ended", at(e) + " · " + (ReservationCard.outcomes[res.outcome ?? ""] ?? (res.outcome ?? "")))
                if let g = res.granted { row("Held", MemoryChart.duration(e - g)) }
            } else if res.granted == nil {
                row("Now", "queued, waiting for room")
            } else {
                row("Now", "active for " + MemoryChart.duration(now - (res.granted ?? now))
                    + (res.expires.map { " · expires in " + MemoryChart.duration(max($0 - now, 0)) } ?? ""))
            }
        }
        .padding(8)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Color.primary.opacity(0.12)))
        .shadow(color: .black.opacity(0.18), radius: 6, y: 2)
    }
}

/// The chart's legend, two tiny rows next to the range buttons; every entry explains itself on hover.
struct ChartLegend: View {
    struct Item { let name: String; let help: String; let kind: Int }  // 0 swatch, 1 away, 2 hatch, 3 incident
    static let rows: [[Item]] = [
        [Item(name: "Wired", help: "Wired: memory the kernel and drivers hold in RAM. It is never compressed or swapped out.", kind: 0),
         Item(name: "App", help: "App memory: what apps and processes use — Activity Monitor's App Memory.", kind: 0),
         Item(name: "Compressed", help: "Compressed: memory macOS squeezed to make room instead of swapping it out. It grows when RAM gets tight.", kind: 0),
         Item(name: "Swap", help: "Swap: memory written out to disk. Lasting swap means the work needs more RAM than the Mac has.", kind: 0)],
        [Item(name: "away", help: "Grey band: you were away — idle for 5 minutes or more, the screen locked or the display off. Stretches close together merge into one band.", kind: 1),
         Item(name: "no data", help: "Hatched: no samples — the Mac was asleep or off, or the logger wasn't running.", kind: 2),
         Item(name: "incident", help: "Red line: an incident starts — high memory pressure, apps killed for memory, or a stall. Each one is listed under Incidents with its report.", kind: 3)],
    ]

    @ViewBuilder func swatch(_ it: Item, _ color: Color) -> some View {
        switch it.kind {
        case 0: RoundedRectangle(cornerRadius: 1.5).fill(color).frame(width: 7, height: 7)
        case 1: RoundedRectangle(cornerRadius: 1.5).fill(Color.gray.opacity(0.3)).frame(width: 9, height: 7)
        case 2:
            Canvas { ctx, size in
                let r = CGRect(origin: .zero, size: size)
                ctx.fill(Path(r), with: .color(.gray.opacity(0.08)))
                ctx.clip(to: Path(r))
                ctx.stroke(MemoryChart.hatchLines(in: r, spacing: 3.5), with: .color(.gray.opacity(0.75)), lineWidth: 1)
            }
            .frame(width: 9, height: 7)
        default: Rectangle().fill(Color.red).frame(width: 1.5, height: 8).frame(width: 5)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(Array(ChartLegend.rows.enumerated()), id: \.offset) { r, row in
                HStack(spacing: 7) {
                    ForEach(Array(row.enumerated()), id: \.offset) { i, it in
                        HStack(spacing: 3) {
                            swatch(it, r == 0 ? MemoryChart.seriesColors[i] : .clear)
                            Text(it.name)
                        }
                        .contentShape(Rectangle())
                        .help(it.help)
                    }
                }
            }
        }
        .font(.system(size: 9))
        .foregroundStyle(.secondary)
        .fixedSize()
    }
}

struct PopoverView: View {
    @ObservedObject var store: Store
    @State private var error: String?
    @State private var copied = false
    @State var showAI = false
    @State var showTopApps = false
    @State var tourStep: Int? = nil  // the guided tour (the chip turns into a ? on hover)
    @State private var chipHover = false
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
                .tourAnchor("header")
            Divider()
            VStack(alignment: .leading, spacing: 10) {
                if let c = store.current, store.daemonRunning { stats(c).tourAnchor("stats") }
                chart.tourAnchor("chart").zIndex(1)
                if !store.reservations.isEmpty { reservedList(store.liveReservations).tourAnchor("leases") }
                incidentsList.tourAnchor("incidents")
                Divider()
                footer.tourAnchor("footer")
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
        .overlayPreferenceValue(TourAnchorKey.self) { anchors in
            GeometryReader { geo in
                if let step = tourStep {
                    tourLayer(step: step, rects: anchors.mapValues { geo[$0] }, size: geo.size)
                        .transition(.opacity)
                }
            }
        }
        .overlay { if store.showChangelog { changelogSheet.transition(.opacity) } }
        .overlay(alignment: .bottom) {
            if store.building || store.buildError != nil { buildDrawer.transition(.move(edge: .bottom)) }
        }
        .animation(.easeOut(duration: 0.2), value: store.showChangelog)
        .animation(.easeOut(duration: 0.25), value: store.building)
        .onExitCommand { withAnimation(.easeOut(duration: 0.15)) { showTopApps = false; showAI = false; tourStep = nil } }
        .onChange(of: store.alertText) { _, e in
            if let e { error = e; store.alertText = nil }
        }
        .onChange(of: store.aiError) { _, e in
            if let e { error = e; store.aiError = nil }
        }
        .alert(brand, isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
            Button("OK") { error = nil }
        } message: { Text(error ?? "") }
    }

    var header: some View {
        let live = store.current != nil && store.daemonRunning
        let p = live ? (Pressure(rawValue: store.current!.pressure) ?? .unknown) : .unknown
        let tint: Color = live ? p.color : .secondary
        return HStack(alignment: .center, spacing: 10) {
            // hover: the chip turns into a ?, a click starts the guided tour
            Button { startTour() } label: {
                Image(systemName: chipHover ? "questionmark" : "memorychip")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(chipHover ? Color.accentColor : tint)
                    .frame(width: 32, height: 32)
                    .background((chipHover ? Color.accentColor : tint).opacity(0.16),
                                in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain).focusable(false)
            .onHover { h in withAnimation(.easeOut(duration: 0.12)) { chipHover = h } }
            .help("Take a quick tour of the dashboard")
            .tourAnchor("chip")
            VStack(alignment: .leading, spacing: 2) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    (Text(brand).fontWeight(.bold) + Text(descriptor).fontWeight(.medium))
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

    // Memory Claude sessions and other agents reserved through `oomph reserve` / `oomph run` / the
    // MCP server, in the colours of their blocks on the strip above.
    func reservedList(_ live: [Reservation]) -> some View {
        let now = Date().timeIntervalSince1970
        let day = store.reservations.filter { ($0.res.ended ?? now) >= now - 86400 }.count
        return VStack(alignment: .leading, spacing: 3) {
            HStack(alignment: .firstTextBaseline) {
                Text("Reserved by agents").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Text(live.isEmpty ? "\(day) in the last 24 h"
                     : String(format: "%.1f GB reserved · %d in the last 24 h", live.filter { $0.granted != nil }.reduce(0) { $0 + $1.gb }, day))
                    .font(.system(size: 10)).foregroundStyle(.tertiary)
            }
            if live.isEmpty {
                Text("Nothing reserved right now").font(.caption).foregroundStyle(.tertiary)
            }
            ForEach(live) { (r: Reservation) in
                HStack(spacing: 6) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 2).fill(r.color.opacity(r.granted == nil ? 0.15 : 0.8))
                        if r.granted == nil {
                            RoundedRectangle(cornerRadius: 2).strokeBorder(r.color.opacity(0.8), lineWidth: 1)
                        }
                    }
                    .frame(width: 8, height: 8)
                    Text(String(format: "%.1fG", r.gb)).font(.system(size: 11, weight: .semibold)).monospacedDigit()
                        .frame(width: 40, alignment: .trailing)
                    Text(r.purpose).font(.system(size: 11)).lineLimit(1)
                    if let p = r.projectName { Text(p).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1) }
                    Spacer(minLength: 4)
                    Text(reservationTail(r, now: now)).font(.system(size: 10)).foregroundStyle(.secondary).monospacedDigit()
                        .lineLimit(1).fixedSize()
                }
                .help("\(r.rid): \(r.purpose)" + (r.project.map { " — " + $0 } ?? "")
                      + String(format: " · reserved %.1f GB, peak %.1f GB so far", r.gb, r.peak))
            }
        }
    }

    func reservationTail(_ r: Reservation, now: Double) -> String {
        guard r.granted != nil else { return "waiting " + MemoryChart.duration(now - r.requested) }
        return String(format: "using %.1fG", r.used ?? 0) + (r.expires.map { " · " + MemoryChart.shortDuration($0 - now) + " left" } ?? "")
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
        .tourAnchor("topapp")
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
                RangeSegments(selection: Binding(get: { store.range }, set: { v in
                    withAnimation(.easeInOut(duration: 0.5)) { store.range = v }
                }))
                .tourAnchor("picker")
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
                Spacer(minLength: 6)
                ChartLegend()
                Text("GB").font(.caption).foregroundStyle(.secondary)
                    .help("Memory in GB; the dashed line is the Mac's RAM. " + (store.allHistory
                          ? "∞: all history on a logarithmic time axis — the last hours wide, older days squeezed."
                          : "Time runs left to right up to now."))
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
                                blend: renderBlend ?? (store.allHistory ? 1 : 0),
                                reservations: store.reservations, stripHeight: stripHeight)
                        .transition(.opacity)  // fades in (0.33 s) once the history has loaded
                }
            }
            .frame(maxWidth: .infinity)
            .frame(height: 160 + (stripHeight > 0 ? MemoryChart.stripGap + stripHeight : 0))
            .tourAnchor("plot")
            .zIndex(1)  // the hover tooltips may reach over what follows
        }
    }

    /// The reservation strip under the chart: there once any agent reserved memory (14 days kept).
    var stripHeight: CGFloat {
        store.historyLoaded && !store.history.isEmpty && !store.reservations.isEmpty ? 46 : 0
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

    // MARK: Guided tour (click the chip's ? in the header)

    static let tourSteps = ["Right now", "History", "Incidents", "Actions"]

    func startTour() {
        NSApp.keyWindow?.makeFirstResponder(nil)
        chipHover = false
        withAnimation(.easeOut(duration: 0.2)) { showAI = false; showTopApps = false; tourStep = 0 }
    }

    func goTour(_ step: Int?) {
        withAnimation(.easeInOut(duration: 0.35)) { tourStep = step }
    }

    /// One explanation bubble: its text, where it sits, and the point its stem reaches.
    struct TourNote {
        var title: String, text: String
        var left: CGFloat, width: CGFloat
        var above: Bool           // the bubble sits above its targets (stems downwards) or below them
        var xs: [CGFloat]         // one stem per target; the dots sit on line y
        var y: CGFloat
        var reach: CGFloat = 12   // stem length between bubble and dots
    }

    /// The step's zone (lit up, everything else dimmed) and its bubbles, laid out from the
    /// measured positions of the dashboard's parts.
    func tourPlan(_ step: Int, _ r: [String: CGRect], _ size: CGSize) -> (zone: CGRect, notes: [TourNote]) {
        let W = size.width, m: CGFloat = 12
        func union(_ ids: [String]) -> CGRect {
            ids.compactMap { r[$0] }.reduce(CGRect.null) { $0.union($1) }
        }
        switch step {
        case 0:
            let zone = union(["header", "stats"])
            let chip = r["chip"] ?? .zero, top = r["topapp"] ?? CGRect(x: W - 120, y: zone.maxY - 30, width: 100, height: 30)
            let half = (W - 2 * m - 8) / 2
            return (zone, [
                TourNote(title: "Memory pressure",
                         text: "The chip's colour is macOS memory pressure, and the badge on the right names it. The figure in the menu bar is free memory. Hover the chip to come back to this tour.",
                         left: m, width: half, above: false,
                         xs: [chip.midX], y: chip.maxY + 3, reach: zone.maxY - chip.maxY + 10),
                TourNote(title: "Live readings",
                         text: "Updated every 30 seconds: the same figures as Activity Monitor. Click the biggest app for the twelve largest.",
                         left: m + half + 8, width: half, above: false,
                         xs: [top.midX], y: top.maxY + 3, reach: zone.maxY - top.maxY + 10),
            ])
        case 1:
            let zone = union(["chart", "leases"])
            let picker = r["picker"] ?? .zero, plot = r["plot"] ?? zone
            let half = (W - 2 * m - 8) / 2
            let timeRange = TourNote(title: "Time range",
                                     text: "∞ shows all history on a logarithmic time axis: the last hours wide, older days and weeks squeezed. 24h, 6h and 1h are linear. A blue ↻ beside it means the logger needs an update.",
                                     left: m, width: half, above: true,
                                     xs: [picker.minX + 30], y: picker.minY - 3)
            // below the zone: above it, the right half belongs to the tour's bar
            guard let strip = r["strip"] else {
                return (zone, [timeRange,
                    TourNote(title: "Memory over time",
                             text: "Hover to read the values and events under the cursor; try it now. The legend above the chart explains the colours: hover an entry for more.",
                             left: W * 0.36, width: W * 0.64 - m, above: false,
                             xs: [plot.midX + 70], y: zone.maxY + 7, reach: 10)])
            }
            let chartBottom = strip.minY - 22
            return (zone, [timeRange,
                TourNote(title: "Memory over time",
                         text: "Hover to read the values and events under the cursor; try it now. The legend above the chart explains the colours: hover an entry for more.",
                         left: m, width: half, above: false,
                         xs: [plot.minX + 90], y: chartBottom, reach: zone.maxY - chartBottom + 10),
                TourNote(title: "Reserved by agents",
                         text: "Claude sessions and other agents reserve memory before heavy work and take turns (the oomph skill). One block per reservation: its height the GB, hatched while it waited, stacked where they overlap. Hover a block for its peak and how it ended.",
                         left: m + half + 8, width: half, above: false,
                         xs: [strip.midX + 60], y: strip.maxY + 2, reach: zone.maxY - strip.maxY + 11),
            ])
        case 2:
            let zone = union(["incidents"])
            return (zone, [
                TourNote(title: "Incidents",
                         text: "Each stretch of high memory pressure, with the apps macOS killed to free memory. Red: still open. Orange: new since you last looked. Click one for its report; right-click to copy its path or show it in Finder.",
                         left: m, width: W * 0.62, above: true,
                         xs: [zone.minX + 40], y: zone.minY - 7),
            ])
        default:
            let zone = union(["footer"])
            let acts = r["actions"] ?? .zero, rep = r["report"] ?? .zero, login = r["login"] ?? .zero
            return (zone, [
                TourNote(title: "Actions",
                         text: """
                         **Deactivate** stops the background logger, **Activate** starts it; both ask for your password. **Check** asks GitHub for a newer \(brand), and **Upgrade** builds and installs it.
                         **Report** opens an HTML report of the last 24 hours; **✦** adds an AI analysis to it. The **link** copies the oomph skill, so Claude sessions can check memory before heavy work.
                         **Launch at login** and **Quit** concern only this menu-bar app: the logger keeps recording.
                         """,
                         left: m, width: W - 2 * m, above: true,
                         xs: [acts.minX + 30, rep.midX, login.midX], y: zone.minY - 7, reach: 14),
            ])
        }
    }

    func tourLayer(step: Int, rects: [String: CGRect], size: CGSize) -> some View {
        let plan = tourPlan(step, rects, size)
        let hole = plan.zone.isNull ? CGRect(x: size.width / 2, y: size.height / 2, width: 0, height: 0)
                                    : plan.zone.insetBy(dx: -4, dy: -4)
        let spot = TourSpotlight(hole: hole)
        let header = rects["header"] ?? CGRect(x: 0, y: 0, width: size.width, height: 54)
        return ZStack(alignment: .topLeading) {
            // the dim catches clicks; the lit zone stays live (hover the chart, click an incident)
            spot.fill(Color.black.opacity(0.42), style: FillStyle(eoFill: true))
                .contentShape(spot, eoFill: true)
                .onTapGesture {}
            TourSpotlight(hole: hole, frameOnly: true).stroke(Color.white.opacity(0.55), lineWidth: 1)
                .allowsHitTesting(false)
            ZStack(alignment: .topLeading) {
                ForEach(Array(plan.notes.enumerated()), id: \.offset) { _, n in tourBubble(n, size: size) }
            }
            .id(step)
            .transition(.opacity)
            tourBar(step)
                .padding(.top, header.maxY - 13)
                .padding(.trailing, 12)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topTrailing)
        }
        .frame(width: size.width, height: size.height)
    }

    func tourBubble(_ n: TourNote, size: CGSize) -> some View {
        let stem = VStack(spacing: 0) {
            if !n.above { Circle().fill(Color.white).frame(width: 6, height: 6) }
            Rectangle().fill(Color.white.opacity(0.85)).frame(width: 1.5, height: n.reach)
            if n.above { Circle().fill(Color.white).frame(width: 6, height: 6) }
        }
        .frame(width: 6)
        .shadow(color: .black.opacity(0.4), radius: 1.5)
        let stems = ZStack(alignment: .topLeading) {
            ForEach(Array(n.xs.enumerated()), id: \.offset) { _, x in
                stem.offset(x: min(max(x - n.left, 14), n.width - 14) - 3)
            }
        }
        .frame(width: n.width, height: n.reach + 6, alignment: .topLeading)
        let paragraphs = n.text.split(separator: "\n").map {
            (try? AttributedString(markdown: String($0))) ?? AttributedString(String($0))
        }
        let bubble = VStack(alignment: .leading, spacing: 4) {
            Text(n.title).font(.system(size: 12, weight: .semibold))
            ForEach(Array(paragraphs.enumerated()), id: \.offset) { _, t in
                Text(t).font(.system(size: 11)).foregroundStyle(.secondary).lineSpacing(1.5)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(10)
        .frame(width: n.width, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
        .shadow(color: .black.opacity(0.25), radius: 10, y: 3)
        return VStack(alignment: .leading, spacing: 0) {
            if n.above { bubble; stems } else { stems; bubble }
        }
        .padding(.leading, n.left)
        // the dots sit on line y: measured from the bottom when the bubble is above, from the top when below
        .padding(n.above ? .bottom : .top, n.above ? size.height - n.y - 3 : n.y - 3)
        .frame(width: size.width, height: size.height, alignment: n.above ? .bottomLeading : .topLeading)
    }

    func tourBar(_ step: Int) -> some View {
        let last = Self.tourSteps.count - 1
        return HStack(spacing: 2) {
            Button { goTour(step - 1) } label: {
                Image(systemName: "chevron.left").frame(width: 24, height: 22).contentShape(Rectangle())
            }
            .disabled(step == 0).keyboardShortcut(.leftArrow, modifiers: []).help("Previous")
            VStack(spacing: 0) {
                Text(Self.tourSteps[step]).font(.system(size: 11, weight: .semibold))
                Text("\(step + 1) of \(last + 1)").font(.system(size: 9)).foregroundStyle(.secondary).monospacedDigit()
            }
            .frame(width: 70)
            if step < last {
                Button { goTour(step + 1) } label: {
                    Image(systemName: "chevron.right").frame(width: 24, height: 22).contentShape(Rectangle())
                }
                .keyboardShortcut(.rightArrow, modifiers: []).help("Next")
            } else {
                Button { goTour(nil) } label: {
                    Text("Done").font(.system(size: 11, weight: .semibold)).foregroundStyle(Color.accentColor)
                        .frame(width: 40, height: 22).contentShape(Rectangle())
                }
                .keyboardShortcut(.defaultAction).help("End the tour")
            }
            Rectangle().fill(Color.primary.opacity(0.15)).frame(width: 1, height: 16).padding(.horizontal, 2)
            Button { goTour(nil) } label: {
                Image(systemName: "xmark").frame(width: 22, height: 22).contentShape(Rectangle())
            }
            .help("Close the tour (Esc)")
        }
        .font(.system(size: 11, weight: .semibold))
        .buttonStyle(.plain).focusable(false).focusEffectDisabled()
        .padding(.horizontal, 6).padding(.vertical, 2)
        .background(.regularMaterial, in: Capsule())
        .overlay(Capsule().stroke(Color.primary.opacity(0.15), lineWidth: 0.5))
        .shadow(color: .black.opacity(0.3), radius: 8, y: 2)
        .transaction { $0.animation = nil }  // the bar stays put while the spotlight moves
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
                .help("Checking GitHub for a newer \(brand)…")
        case .check:
            Button("Check") { store.checkForUpgrade(manual: true) }
                .focusable(false)
                .help(store.upgradeCheckError.map { "The last check failed: \($0). Click to try again." }
                      ?? "Check GitHub for a newer \(brand) (this is \(cur))" + lastChecked)
                .contextMenu { autoCheckToggle }
        case .upgrade:
            Button("Upgrade") { store.openUpgrade() }
                .buttonStyle(.borderedProminent).focusable(false)
                .help("\(brand) \(cur) is installed — \(store.availableVersion) is available. Click to see what's new.")
                .contextMenu { autoCheckToggle }
        case .upToDate:
            Button("Up to date") {}
                .disabled(true).focusable(false)
                .help("\(brand) \(cur) is the newest version on GitHub")
        }
    }

    var lastChecked: String {
        let t = store.lastUpgradeCheck
        guard t > 0 else { return "" }
        let f = RelativeDateTimeFormatter()
        return " — last checked " + f.localizedString(for: Date(timeIntervalSince1970: t), relativeTo: Date())
    }

    var autoCheckToggle: some View {
        Toggle("Check once a day when \(brand) opens", isOn: Binding(get: { store.upgradeAuto }, set: { store.upgradeAuto = $0 }))
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
                    Text("Upgrade \(brand)").font(.system(size: 14, weight: .semibold))
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
                        .help("Don't offer this version again when \(brand) checks by itself (Check still finds it)")
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
            Text("When it's built, \(brand) replaces itself, restarts and updates the logger (one password prompt).")
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
        let lit = store.aiConnected
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

            // ✦ when not connected; a spinner while a connection is confirmed; then the provider's
            // mark. A click always opens the dialog, which shows (and changes) the connection.
            Button {
                if running { store.abortAI() } else { openAICallout() }
            } label: {
                SwiftUI.Group {
                    if running {
                        Image(systemName: "stop.fill").foregroundStyle(.red)
                    } else if store.aiConnecting {
                        ProgressView().controlSize(.small).scaleEffect(0.55)
                    } else if lit {
                        AIProviderMark(provider: store.aiProvider)
                    } else {
                        Image(systemName: "sparkles").foregroundStyle(.secondary)
                    }
                }
                .font(.system(size: 11, weight: .semibold))
                .frame(width: 30, height: 20)
                .background(showAI ? Color.primary.opacity(0.08) : .clear)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .focusable(false)
            .anchorPreference(key: StarAnchorKey.self, value: .bounds) { $0 }
            .help(running ? "Stop the AI report"
                  : store.aiConnecting ? "Checking the connection to \(store.aiProvider.title)…"
                  : lit ? "Reports include an AI analysis by \(store.aiSummary). Click to see or disconnect."
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
    }

    func openAICallout() {
        draftProvider = store.aiProvider
        loadDraft(for: draftProvider)
        withAnimation(.easeOut(duration: 0.15)) { showAI = true; showTopApps = false }
    }

    func loadDraft(for p: AIProvider) {
        // the saved token comes back into the field: reconnecting never needs a new one
        draftToken = p.needsToken ? (Keychain.get(p.rawValue) ?? "") : ""
        store.aiConnectError = nil
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

    var canConnect: Bool { !draftProvider.needsToken || !draftToken.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

    func connectAI() {
        let p = draftProvider
        store.connectAI(p, token: p.needsToken ? draftToken.trimmingCharacters(in: .whitespacesAndNewlines) : "",
                        model: draftModel.trimmingCharacters(in: .whitespaces),
                        url: draftURL.isEmpty ? "http://localhost:11434" : draftURL) { ok in
            if ok { withAnimation(.easeOut(duration: 0.15)) { showAI = false } }
        }
    }

    func aiCalloutHeader(connected: Bool, busy: Bool) -> some View {
        HStack(spacing: 6) {
            if connected { AIProviderMark(provider: store.aiProvider) } else {
                Image(systemName: "sparkles").foregroundStyle(.purple)
            }
            Text("AI analysis in reports").font(.system(size: 13, weight: .semibold))
            Spacer()
            if connected {
                HStack(spacing: 4) {
                    Circle().fill(Color.green).frame(width: 6, height: 6)
                    Text("Connected").font(.system(size: 10, weight: .medium)).foregroundStyle(.secondary)
                }
            } else if busy {
                Text("Connecting…").font(.system(size: 10, weight: .medium)).foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder func aiCalloutFields(connected: Bool, busy: Bool) -> some View {
        if draftProvider.needsToken {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    SecureField("Paste access token", text: $draftToken)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit { if canConnect && !connected && !busy { connectAI() } }
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
    }

    @ViewBuilder func aiCalloutNote(connected: Bool) -> some View {
        if let e = store.aiConnectError {
            SwiftUI.Label(e, systemImage: "exclamationmark.triangle.fill")
                .font(.system(size: 10)).foregroundStyle(.red)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        } else if connected {
            Text("Reports include an analysis by \(store.aiSummary). Disconnect to switch provider or key; the key stays saved for a reconnect.")
                .font(.system(size: 10)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        } else {
            Text(draftProvider == .ollama
                 ? "Reports are analysed on this Mac; nothing leaves it."
                 : "AI reports send memory figures, process names and project paths from \(brand)'s logs to \(draftProvider == .claude ? "Anthropic" : "OpenAI"). The key stays in your keychain.")
                .font(.system(size: 10)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    func aiCalloutButtons(connected: Bool, busy: Bool) -> some View {
        HStack {
            Button(connected ? "Close" : "Cancel") { withAnimation(.easeOut(duration: 0.15)) { showAI = false } }
                .keyboardShortcut(.cancelAction)
            Spacer()
            Button("Disconnect") { withAnimation(.easeOut(duration: 0.15)) { store.disconnectAI() } }
                .disabled(!connected)
                .help(connected ? "Stop adding an AI analysis to reports. The key stays saved." : "Not connected")
            Button { connectAI() } label: { Text(busy ? "Connecting…" : "Connect") }
                .keyboardShortcut(.defaultAction)
                .disabled(connected || busy || !canConnect)
                .help("Check that \(draftProvider.title) accepts the key and knows the model (no tokens spent), then use it for reports")
        }
    }

    func aiCallout(arrowX: CGFloat) -> some View {
        // connected: the provider's tab is fixed, the fields are read-only, only Disconnect works
        let connected = store.aiConnected
        let busy = store.aiConnecting
        return VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 10) {
                aiCalloutHeader(connected: connected, busy: busy)
                Picker("", selection: $draftProvider) {
                    ForEach(AIProvider.allCases) { Text($0.title).tag($0) }
                }
                .pickerStyle(.segmented).labelsHidden()
                .disabled(connected || busy)
                .onChange(of: draftProvider) { _, p in loadDraft(for: p) }
                aiCalloutFields(connected: connected, busy: busy)
                    .disabled(connected || busy)
                aiCalloutNote(connected: connected)
                aiCalloutButtons(connected: connected, busy: busy)
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
            HStack {
                if store.installed {
                    Button("Deactivate") {
                        store.runPrivileged("uninstall.sh") { error = $0 }
                    }.disabled(store.busy)
                    .help("Stop and remove the background logger (asks for your password). The logs are kept.")
                } else {
                    Button("Activate") {
                        store.runPrivileged("install.sh") { error = $0 }
                    }.buttonStyle(.borderedProminent).disabled(store.busy)
                    .help("Install and start the background logger that records memory every 30 s (asks for your password)")
                }
                upgradeButtonView
            }.tourAnchor("actions")
            reportPair.tourAnchor("report")
            Spacer()
            Toggle("Launch at login", isOn: Binding(get: { store.launchAtLogin }, set: { store.setLaunchAtLogin($0) }))
                .toggleStyle(.checkbox).font(.caption).lineLimit(1).fixedSize()
                .help("Open \(brand) in the menu bar when you log in. The logger records either way.")
                .tourAnchor("login")
            Button {
                NSApp.terminate(nil)
            } label: { Image(systemName: "power") }
            .help("Quit oomph. The background logger keeps recording.")
        }
        .controlSize(.small)
    }
}

/// The connected provider's mark on the ✦ button: Claude's orange burst, OpenAI's aperture,
/// Ollama's llama. Drawn here (no bundled brand artwork).
struct AIProviderMark: View {
    let provider: AIProvider
    var body: some View {
        switch provider {
        case .claude:
            ClaudeBurst().fill(Color(red: 0.85, green: 0.47, blue: 0.34)).frame(width: 14, height: 14)
        case .openai:
            Image(systemName: "camera.aperture").font(.system(size: 12, weight: .semibold)).foregroundStyle(.primary)
        case .ollama:
            Text("🦙").font(.system(size: 12))
        }
    }
}

/// A burst of tapered rays of slightly varying length, after Claude's mark.
struct ClaudeBurst: Shape {
    func path(in r: CGRect) -> Path {
        var p = Path()
        let c = CGPoint(x: r.midX, y: r.midY), R = min(r.width, r.height) / 2
        let n = 12
        for i in 0..<n {
            // Everything CGFloat: older compilers find `cos` ambiguous with mixed Double/CGFloat.
            let a: CGFloat = CGFloat(i) / CGFloat(n) * 2 * .pi - .pi / 2
            let len: CGFloat = R * (i % 2 == 0 ? 1.0 : 0.84)
            let w: CGFloat = 0.26  // half the ray's angular width at its base
            let tip = CGPoint(x: c.x + cos(a) * len, y: c.y + sin(a) * len)
            let l = CGPoint(x: c.x + cos(a - w) * R * 0.3, y: c.y + sin(a - w) * R * 0.3)
            let rr = CGPoint(x: c.x + cos(a + w) * R * 0.3, y: c.y + sin(a + w) * R * 0.3)
            p.move(to: c); p.addLine(to: l); p.addLine(to: tip); p.addLine(to: rr); p.closeSubpath()
        }
        p.addEllipse(in: CGRect(x: c.x - R * 0.3, y: c.y - R * 0.3, width: R * 0.6, height: R * 0.6))
        return p
    }
}

struct TopAppAnchorKey: PreferenceKey {
    static var defaultValue: Anchor<CGRect>? = nil
    static func reduce(value: inout Anchor<CGRect>?, nextValue: () -> Anchor<CGRect>?) { value = value ?? nextValue() }
}

/// The chart's time ranges as a segmented control drawn in SwiftUI. Every segment has a fixed
/// width, so nothing gets re-measured: the native NSSegmentedControl re-measured itself right
/// after the popup opened and briefly changed width.
struct RangeSegments: View {
    @Binding var selection: Double
    @Environment(\.colorScheme) private var scheme
    static let options: [(symbol: String?, label: String, value: Double, help: String)] = [
        ("infinity", "", .infinity, "All history, on a logarithmic time axis"),
        (nil, "24h", 24 * 3600, "The last 24 hours"),
        (nil, "6h", 6 * 3600, "The last 6 hours"),
        (nil, "1h", 3600, "The last hour"),
    ]
    let segment: CGFloat = 45, height: CGFloat = 22

    var body: some View {
        let opts = Self.options
        let idx = opts.firstIndex { $0.value == selection } ?? 0
        ZStack(alignment: .leading) {
            RoundedRectangle(cornerRadius: 6, style: .continuous).fill(Color.primary.opacity(0.07))
            // separators between neighbours that aren't next to the selected segment
            ForEach(1..<opts.count, id: \.self) { i in
                Rectangle().fill(Color.primary.opacity(i == idx || i == idx + 1 ? 0 : 0.15))
                    .frame(width: 1, height: 12)
                    .offset(x: CGFloat(i) * segment - 0.5)
            }
            RoundedRectangle(cornerRadius: 5, style: .continuous)
                .fill(scheme == .dark ? Color.white.opacity(0.25) : Color.white)
                .shadow(color: .black.opacity(0.2), radius: 0.5, y: 0.5)
                .frame(width: segment - 4, height: height - 4)
                .offset(x: CGFloat(idx) * segment + 2)
                .animation(.easeOut(duration: 0.2), value: idx)
            HStack(spacing: 0) {
                ForEach(opts.indices, id: \.self) { i in
                    Button { if opts[i].value != selection { selection = opts[i].value } } label: {
                        SwiftUI.Group {
                            if let sym = opts[i].symbol { Image(systemName: sym).font(.system(size: 12, weight: .semibold)) }
                            else { Text(opts[i].label).font(.system(size: 12, weight: .medium)) }
                        }
                        .foregroundStyle(i == idx ? Color.primary : Color.primary.opacity(0.75))
                        .frame(width: segment, height: height)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain).focusable(false)
                    .help(opts[i].help)
                }
            }
        }
        .frame(width: segment * CGFloat(opts.count), height: height)
        .focusEffectDisabled()
    }
}

/// Where the dashboard's parts are, for the guided tour's spotlight and bubbles.
struct TourAnchorKey: PreferenceKey {
    static var defaultValue: [String: Anchor<CGRect>] = [:]
    static func reduce(value: inout [String: Anchor<CGRect>], nextValue: () -> [String: Anchor<CGRect>]) {
        value.merge(nextValue()) { a, _ in a }
    }
}

extension View {
    func tourAnchor(_ id: String) -> some View {
        // transform, not set: a part inside another part (the chip in the header) keeps its own entry
        transformAnchorPreference(key: TourAnchorKey.self, value: .bounds) { $0[id] = $1 }
    }
}

/// The tour's dim: the whole panel minus a rounded hole, which glides from zone to zone.
struct TourSpotlight: Shape {
    var hole: CGRect
    var frameOnly = false
    var animatableData: AnimatablePair<AnimatablePair<CGFloat, CGFloat>, AnimatablePair<CGFloat, CGFloat>> {
        get { .init(.init(hole.minX, hole.minY), .init(hole.width, hole.height)) }
        set { hole = CGRect(x: newValue.first.first, y: newValue.first.second, width: newValue.second.first, height: newValue.second.second) }
    }
    func path(in r: CGRect) -> Path {
        var p = Path()
        if !frameOnly { p.addRect(r.insetBy(dx: -2, dy: -2)) }
        p.addRoundedRect(in: hole, cornerSize: CGSize(width: 8, height: 8), style: .continuous)
        return p
    }
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
            ? "\(brand) — \(label ?? "?") physical memory free · pressure \(p.label)"
            : "\(brand) — logging is OFF (click to activate)"
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
    // `--ai connected:claude|openai|ollama`, `connecting`, `dialog-connected`, `dialog-error` (render only)
    if ai.hasPrefix("connected:") { store.aiOn = true; store.aiProvider = AIProvider(rawValue: String(ai.dropFirst(10))) ?? .claude }
    if ai == "connecting" { store.aiConnecting = true }
    if ai == "dialog-connected" { store.aiOn = true; store.aiProvider = .claude }
    if ai == "dialog-error" { store.aiConnectError = "api.anthropic.com returned 401: invalid x-api-key" }
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
    if ai.hasPrefix("rhover:") {  // rhover:X:Y — the reservation strip's tooltip at (X, Y) in strip points
        let v = ai.split(separator: ":").dropFirst().compactMap { Double($0) }
        if v.count >= 2 { renderStripHover = CGPoint(x: v[0], y: v[1]) }
    }
    if ai == "log" { store.range = .infinity }  // the ∞ range: all history on a log time axis
    if ai == "6h" || ai.hasSuffix(":6h") { store.range = 6 * 3600 }    // e.g. `--ai 6h`, `--ai rhover:200:20:6h`
    if ai == "1h" || ai.hasSuffix(":1h") { store.range = 3600 }
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
        store.building = true; store.buildVersion = "1.5.0"; store.buildProgress = "Compiling \(brand) 1.5.0"
        store.buildLines = ["==> Compiling \(brand) 1.5.0", "app/oomph.swift:42: note: building for macOS 14"]
    }
    // `--ai tour:N` draws step N of the guided tour (1-based)
    let tour = ai.hasPrefix("tour:") ? Int(ai.dropFirst(5)).map { $0 - 1 } : nil
    let view = PopoverView(store: store, showAI: ["callout", "dialog-connected", "dialog-error"].contains(ai), showTopApps: ai == "top", tourStep: tour)
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
