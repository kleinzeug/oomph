// oomph — menu bar front-end for the oomph daemon (see ../DESIGN.md).
// Build: ../build-app.sh
import AppKit
import Charts
import Combine
import Network
import Security
import SwiftUI

let logDir = ProcessInfo.processInfo.environment["OOMPH_DIR"] ?? "/Library/Logs/oomph"
/// The agents' coordination ledger (ledger.json) and its history log (reservations.jsonl).
let ledgerDir = ProcessInfo.processInfo.environment["OOMPH_LEDGER_DIR"] ?? "/Users/Shared/oomph"
/// Where `oomph remote` keeps the machines this Mac watches: machines.json and one mirror per machine.
let machinesDir = ProcessInfo.processInfo.environment["OOMPH_MACHINES_DIR"]
    ?? (NSHomeDirectory() + "/Library/Application Support/oomph/machines")
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

/// Access tokens live in the login keychain, one item per provider, and are read only when a
/// connection needs one (a report): never when the app starts or the dialog opens.
///
/// Why macOS asks: a keychain item's access list trusts the app that made it by its designated
/// requirement, and an ad hoc signed app's is `cdhash H"…"`, the hash of that very build. Every
/// rebuild (every upgrade) is a different app to the keychain, so reading the token asks once per
/// build ("Always Allow" lasts until the next upgrade). Up to 1.9.8 the popup read it on every
/// launch just to know that one existed, so every first launch after an upgrade asked. Without a
/// developer certificate no build can be trusted ahead of time, so the read waits until it is needed.
/// An earlier build's item can't be deleted or replaced by this one either (errSecInvalidOwnerEdit,
/// no prompt): a new token then goes into an item of its own, and the provider's account name in
/// the defaults says which item is current.
enum Keychain {
    static let service = "local.oomph.ai"
    static func base(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
    }
    /// The item that holds a provider's token: `claude`, or `claude.<8 hex>` once a later build saved one.
    static func account(_ provider: String) -> String {
        UserDefaults.standard.string(forKey: "aiTokenAccount." + provider) ?? provider
    }
    /// The token, or the keychain's status: errSecItemNotFound (none saved), errSecUserCanceled or
    /// errSecAuthFailed (the prompt was declined). The one call that may ask for access.
    static func get(_ provider: String) -> (String?, OSStatus) {
        var q = base(account(provider))
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        guard st == errSecSuccess, let d = out as? Data else { return (nil, st == errSecSuccess ? errSecDecode : st) }
        return (String(data: d, encoding: .utf8), st)
    }
    /// Saves a token as this build's item, which this build then reads without asking.
    static func set(_ value: String, _ provider: String) {
        forget(provider)
        guard !value.isEmpty else { return }
        var acct = account(provider)
        var add = base(acct)
        add[kSecValueData as String] = Data(value.utf8)
        if SecItemAdd(add as CFDictionary, nil) == errSecDuplicateItem {   // an earlier build's, kept from this one
            acct = provider + "." + String(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(8)).lowercased()
            add = base(acct)
            add[kSecValueData as String] = Data(value.utf8)
            guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else { return }
        }
        UserDefaults.standard.set(acct, forKey: "aiTokenAccount." + provider)
    }
    /// Deletes the current item, never asking: an earlier build's item stays (the keychain allows
    /// that only to a build the user trusted with "Always Allow").
    static func forget(_ provider: String) {
        quietly { SecItemDelete(base(account(provider)) as CFDictionary) }
    }
    /// `body` with the keychain's prompts off: what would ask fails instead. The switch is the old
    /// keychain's own (SecKeychainSetUserInteractionAllowed), looked up by name: it has no successor
    /// for this keychain, and its deprecation would be the build's only warning.
    @discardableResult static func quietly(_ body: () -> OSStatus) -> OSStatus {
        typealias Get = @convention(c) (UnsafeMutablePointer<UInt8>) -> OSStatus
        typealias Set = @convention(c) (UInt8) -> OSStatus
        let h = dlopen(nil, RTLD_NOW)
        guard let g = dlsym(h, "SecKeychainGetUserInteractionAllowed"),
              let s = dlsym(h, "SecKeychainSetUserInteractionAllowed") else { return errSecUnimplemented }
        let get = unsafeBitCast(g, to: Get.self), set = unsafeBitCast(s, to: Set.self)
        var was: UInt8 = 1
        _ = get(&was)
        guard set(0) == errSecSuccess else { return errSecInteractionRequired }  // never delete where it could ask
        defer { _ = set(was) }
        return body()
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

/// What a stretch without samples is: the machine logged nothing (hatched), or, for another
/// machine's mirror, this dashboard has not received it (dotted), not since the link dropped, or
/// never will (that machine keeps 14 days).
enum GapKind { case noData, notReceived, notConnected, gone }

struct Gap { let from, to: Double; var kind: GapKind = .noData }

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
    var alarming: Bool { ["jetsam", "stall", "unowned_memory", "disk_low", "disk_filling", "pressure_flapping", "daemon_error"].contains(kind) }
    static let thermal = [0: "nominal", 1: "moderate", 2: "heavy", 3: "trapping", 4: "sleeping"]
    static let volumeWord = ["mounted": "mounted", "unmounted": "unmounted", "watched": "watched", "unwatched": "no longer watched"]

    static func pressureName(_ v: Any?) -> String {
        switch (v as? NSNumber)?.intValue { case 1: "normal"; case 2: "warning"; case 4: "critical"; default: "\(v ?? "?")" }
    }

    /// The disk an event is about: its name, else where it is mounted, else its pool id.
    static func volume(_ e: [String: Any]) -> String {
        for k in ["name", "mount", "pool"] { if let v = e[k] as? String, !v.isEmpty { return v } }
        return "?"
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
        case "disk_low":
            if let name = e["name"] as? String, e["free_gb"] is NSNumber {
                text = "disk low: \(name) " + String(format: "%.1f GB free", num("free_gb"))
            } else {
                text = String(format: "disk low: %.1f GB free", num("disk_free_gb"))
            }
        case "disk_filling":
            text = "disk filling: \(ChartEvent.volume(e)), " + String(format: "full in %.0f min at %.1f GB/min", num("eta_min"), num("rate_gb_min"))
        case "volume": text = "disk \(ChartEvent.volumeWord[e["what"] as? String ?? ""] ?? "changed"): \(ChartEvent.volume(e))"
        case "thermal":
            text = "thermal \(ChartEvent.thermal[(e["old"] as? NSNumber)?.intValue ?? -1] ?? "?") → \(ChartEvent.thermal[(e["new"] as? NSNumber)?.intValue ?? -1] ?? "?")"
        case "cpu_saturated": text = String(format: "cores saturated: %.1f of %.0f busy for %.0f min", num("busy"), num("n"), num("minutes"))
        case "cpu_saturated_cleared": text = String(format: "cores no longer saturated, after %.0f min", num("minutes"))
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
    var queue: Int?                      // its place in ledger.json's list of leases: the queue's order

    var live: Bool { ended == nil }
    var gb: Double { segments.last?.gb ?? 0 }
    func gb(at t: Double) -> Double { (segments.last { $0.t <= t } ?? segments.first)?.gb ?? 0 }
    var projectName: String? { project.map { ($0 as NSString).lastPathComponent }.flatMap { $0.isEmpty ? nil : $0 } }

    /// Colours avoid the memory chart's grey, blue, orange and red. The same purpose always gets the
    /// same colour (a stable hash, not Swift's per-launch one), in the blocks and in the list.
    static let palette: [Color] = [.teal, .purple, .pink, .indigo, Color(red: 0.84, green: 0.62, blue: 0.0), .brown, .green]
    var color: Color { Reservation.palette[Reservation.colorIndex(purpose)] }
    /// The palette index of a purpose. Shared with `oomph top` (tools/vectors/chart.json).
    static func colorIndex(_ purpose: String) -> Int {
        var h: UInt32 = 5381
        for u in purpose.unicodeScalars { h = (h &* 33) ^ u.value }
        return Int(h % UInt32(Reservation.palette.count))
    }

    /// The order of the reservation list (roadmap C13, 02 §3.4.6), the same in `oomph top`
    /// (tools/vectors/chart.json): waiting first, in queue order (the ledger's: a queued request that
    /// grows moves to the back; by request time where the place is unknown); then grants by time left,
    /// the one that ends soonest first, a grant without a ttl last. With a cap, the rows that explain
    /// why an agent waits are the ones that stay.
    static func listOrder(_ live: [Reservation]) -> [Reservation] {
        let waiting = live.filter { $0.granted == nil }.sorted { a, b in
            let ka: (Int, Int, Double, String) = (a.queue == nil ? 1 : 0, a.queue ?? 0, a.requested, a.id)
            let kb: (Int, Int, Double, String) = (b.queue == nil ? 1 : 0, b.queue ?? 0, b.requested, b.id)
            return ka < kb
        }
        let granted = live.filter { $0.granted != nil }.sorted { a, b in
            let ka: (Int, Double, Double, String) = (a.expires == nil ? 1 : 0, a.expires ?? 0, a.requested, a.id)
            let kb: (Int, Double, Double, String) = (b.expires == nil ? 1 : 0, b.expires ?? 0, b.requested, b.id)
            return ka < kb
        }
        return waiting + granted
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
/// total reserved; lanes are packed first-fit by start time. Shared with `oomph top` (tools/vectors/chart.json).
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

// MARK: - One machine

/// A mirror's status.json: the state of the link to that machine (roadmap 01 §5.7).
struct LinkStatus: Decodable {
    var state: String?
    var was: String?
    var since: Double?
    var last_contact: Double?
    var error: String?
    var detail: String?
    /// The connection failed at once (the engine's word for "maybe macOS's Local Network privacy").
    var fast: Bool?
    var pid: Int32?
    var updated: Double?
    /// How long the last connection took to its first frame: the opening grace (roadmap 01 §3.6).
    var connect_ms: Double?
    /// When the engine tries again after a failure (backoff, §6.2).
    var next_try: Double?
    var transport: String?
}

/// A mirror's sync.json: the coverage map (`have`: stretches of the remote's time received whole,
/// `gone`: stretches it no longer keeps), which lists have had their first sync, the clock offset.
struct SyncState: Decodable {
    struct Synced: Decodable { var ledger: Bool?; var reservations: Bool?; var incidents: Bool? }
    var have: [[Double]]?
    var gone: [[Double]]?
    var synced: Synced?
    var offset_s: Double?
    var spans: [(Double, Double)] { (have ?? []).compactMap { $0.count == 2 && $0[0] <= $0[1] ? ($0[0], $0[1]) : nil } }
    var goneSpans: [(Double, Double)] { (gone ?? []).compactMap { $0.count == 2 && $0[0] <= $0[1] ? ($0[0], $0[1]) : nil } }
}

/// A mirror's machine.json: what the machine said about itself when it was last reached.
struct MachineInfo: Decodable {
    var id: String?
    var name: String?
    var os: String?
    var os_version: String?
    var kind: String?
    var version: String?
    var oldest: Double?
    /// What it serves; "ai" when its owner allows AI analysis of its data (D7, off by default).
    var caps: [String]?
}

/// A machine of machines.json (roadmap 01 §5.6), as `oomph remote` writes it. The app reads it and
/// never writes it: every change goes through the engine.
struct MachineEntry: Decodable {
    var mid: String
    var label: String?
    var name: String?
    var host: String?
    var transport: String?
    var user: String?
    var port: Int?
    var version: String?
    var pinned: Bool?
    var order: Double?
    var caps: [String]?
    var os: String?
    var os_version: String?
    var ram_gb: Double?
    var addrs: [String]?
    var last_connected: Double?

    /// The pinned machines (tabs), in the order they were added; entries whose mirror name is not of
    /// the fixed pattern are skipped, since that name becomes a path. Only Macs (or a machine not yet
    /// reached): the app does not know Linux's words until 1.13, so a Linux machine is watched from
    /// the terminal for now (roadmap G5, the LG row; 01 §4.3: an unknown os is not drawn).
    static func load(_ dir: String) -> [MachineEntry] {
        loadAll(dir).filter { $0.pinned == true }.sorted { ($0.order ?? 0) < ($1.order ?? 0) }
    }

    /// Every machine this Mac knows (tabs and Recents), under the same rules as `load`.
    static func loadAll(_ dir: String) -> [MachineEntry] {
        struct File: Decodable { var machines: [MachineEntry]? }
        guard let d = readShared(dir + "/machines.json", cap: 4 << 20),
              let f = try? JSONDecoder().decode(File.self, from: d) else { return [] }
        return (f.machines ?? []).filter { e in
            (e.os == nil || e.os == "macos")
                && e.mid.range(of: #"^m-[0-9a-f]{16}(-[0-9a-f]{8})?$"#, options: .regularExpression) != nil
        }
    }

    /// Recents (roadmap 01 §3.7): every machine that is not a tab now, the one connected last first.
    static func recents(_ dir: String) -> [MachineEntry] {
        loadAll(dir).filter { $0.pinned != true }.sorted { ($0.last_connected ?? 0) > ($1.last_connected ?? 0) }
    }
    /// The tab's name as the popover shows it before a store exists.
    var title: String { label ?? name ?? host ?? mid }
    var address: String {
        let h = host ?? "?"
        if transport == "ssh" { return (user.map { $0 + "@" } ?? "") + h }
        return port.map { $0 == 6674 ? h : "\(h):\($0)" } ?? h
    }
}

/// One machine's data, as the popup draws it: this Mac from its own directories, or another
/// machine from its mirror (…/machines/<mid>/: log/, ledger/, status.json, sync.json,
/// machine.json, written by `oomph remote sync`). Everything per machine lives here; the app's
/// own state (AI, upgrades, the range) stays in Store. Until tabs exist the popup shows This
/// Mac; `--render-popup … --mirror DIR` draws a mirror.
final class MachineStore: ObservableObject {
    let logDir: String
    let ledgerDir: String
    /// The mirror's directory; nil for this Mac.
    let mirror: String?
    var isLocal: Bool { mirror == nil }

    @Published var current: Sample?
    @Published var currentAge: Double = .infinity
    /// All logged history, oldest first, finer near now (see Store.multires): every range draws from it.
    @Published var history: [Point] = []
    /// When `history` was loaded: the chart measures ages from here (for a mirror, on its clock).
    @Published var historyNow = Date().timeIntervalSince1970
    /// Stretches without samples (asleep, off, logger stopped), found in the raw samples; for a
    /// mirror also the stretches it has not received (Gap.kind).
    @Published var gaps: [Gap] = []
    /// events.jsonl(.1), oldest first, for the hover tooltip.
    @Published var events: [ChartEvent] = []
    /// The agents' reservations, live and of the last 14 days, stacked for the strip under the chart.
    @Published var reservations: [ResBlock] = []
    var liveReservations: [Reservation] { Reservation.listOrder(reservations.map(\.res).filter(\.live)) }
    private var eventsStamp = ""
    @Published var incidents: [Incident] = []
    /// A mirror's link, coverage and machine (nil for this Mac).
    @Published var link: LinkStatus?
    @Published var sync: SyncState?
    @Published var info: MachineInfo?

    // history loading runs on its own queue; the cache and its decoder belong to that queue
    private let loadQueue = DispatchQueue(label: "local.oomph.history", qos: .userInitiated)
    /// Per file: its identity (a mirror replaces whole files by renaming), how far it was read, its points.
    private var cache: [String: (ino: UInt64, offset: UInt64, pts: [Point])] = [:]
    private let loadDecoder = JSONDecoder()
    private var loading = false, loadAgain = false
    /// False until the history has been loaded once: the chart shows a spinner meanwhile.
    @Published var historyLoaded = false
    private let decoder = JSONDecoder()

    init(logDir: String, ledgerDir: String, mirror: String? = nil) {
        self.logDir = logDir; self.ledgerDir = ledgerDir; self.mirror = mirror
    }

    convenience init(mirror dir: String) {
        self.init(logDir: dir + "/log", ledgerDir: dir + "/ledger", mirror: dir)
    }

    var daemonRunning: Bool {
        guard let c = current else { return false }
        return currentAge < 3 * (c.daemon?.interval ?? 30) + 15
    }

    /// The machine's clock: a mirror's times are the remote's own, corrected by the offset measured
    /// at the handshake (roadmap 01 §4.6).
    var now: Double { Date().timeIntervalSince1970 + (isLocal ? 0 : sync?.offset_s ?? 0) }

    /// A mirror is live while its engine says so and has rewritten status.json within the last 10 s
    /// from a process that still exists; in every other case it is drawn stale, so a crashed engine
    /// can never leave a pane looking live (roadmap 01 §4.4).
    var linkLive: Bool {
        guard let l = link, l.state == "live" || l.state == "catching_up", let u = l.updated, let pid = l.pid, pid > 0
        else { return false }
        return Date().timeIntervalSince1970 - u < 10 && (kill(pid, 0) == 0 || errno == EPERM)
    }
    /// Another machine that is not live: what claims to be now is drawn grey (roadmap 01 §3.5),
    /// except during the grace of an opening.
    var stale: Bool { !isLocal && !linkLive && !inGrace }

    /// When the popup last opened, and whether this machine's link was live when it closed: the
    /// three opening steps of roadmap 01 §3.6 (grace, Connecting…, the verdict). Every opening is a
    /// reconnect (D8), so a machine that was fine is not called "Not connected" while it reconnects.
    var openedAt: Double?
    var openedLive = false
    enum Opening { case none, grace, connecting }

    func markOpened(at t: Double = Date().timeIntervalSince1970) {
        openedAt = t
        openedLive = !isLocal && ((link?.state == "idle" && link?.was == "live") || linkLive)
        guard openedLive, !renderMode else { return }
        // the steps change with time alone: draw again then (after the grace the chart shows what
        // was not received, unless the link is live by then)
        DispatchQueue.main.asyncAfter(deadline: .now() + grace + 0.05) { [weak self] in
            guard let self, self.openedAt == t else { return }
            if !self.linkLive { self.reloadPoints() }
            self.objectWillChange.send()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + openTimeout + 0.05) { [weak self] in
            if let self, self.openedAt == t { self.objectWillChange.send() }
        }
    }
    var isSSH: Bool { (link?.transport ?? entry?.transport) == "ssh" }
    /// Twice what the last connection took, at least 0.8 s and at most 3 s (ssh 1.5 s and 6 s).
    var grace: Double {
        let ms: Double = link?.connect_ms ?? 0
        let lo: Double = isSSH ? 1.5 : 0.8, hi: Double = isSSH ? 6 : 3
        return min(hi, max(lo, 2 * ms / 1000))
    }
    var openTimeout: Double { isSSH ? 20 : 8 }
    /// The step of this opening: none once live, for a machine that was not live at the last close,
    /// and after a definite failure or the timeout (the verdict).
    var opening: Opening {
        guard !isLocal, openedLive, let t = openedAt, !linkLive else { return .none }
        if link?.state == "offline" || link?.state == "needs_attention" || link?.error == "local_network_denied" || probeDenied {
            return .none
        }
        let age: Double = Date().timeIntervalSince1970 - t
        return age < grace ? .grace : age < openTimeout ? .connecting : .none
    }
    var inGrace: Bool { opening == .grace }
    var connecting: Bool { opening == .connecting }
    /// Where this dashboard's knowledge of the machine ends: the end of a mirror's coverage.
    var knownUntil: Double? { sync?.spans.last?.1 ?? history.last?.id }
    /// The stat tiles: this Mac's while its logger reports; a mirror's whenever it has a reading.
    var showsStats: Bool { isLocal ? daemonRunning : current != nil }
    /// A mirror's list that has not had its first sync says "fetching…", never "nothing".
    var fetchingLedger: Bool { !isLocal && sync?.synced?.ledger != true }
    var fetchingIncidents: Bool { !isLocal && sync?.synced?.incidents != true }

    /// The mirror's name (…/machines/<mid>); "local" for this Mac.
    var mid: String { mirror.map { ($0 as NSString).lastPathComponent } ?? "local" }
    /// Its line in machines.json (nil for this Mac).
    var entry: MachineEntry?
    /// The tab's name: "This Mac", or the label someone gave it, or what it calls itself.
    var title: String { isLocal ? "This Mac" : (entry?.label ?? info?.name ?? entry?.name ?? entry?.host ?? mid) }
    /// Whether its data may go to an AI model: this Mac's always (the person chose a provider), another's
    /// only when its owner allows it there (`oomph share ai on`; D7).
    var allowsAI: Bool { isLocal || (info?.caps ?? entry?.caps ?? []).contains("ai") }
    /// Pressure as a tab shows it: critical only while live.
    var critical: Bool { (isLocal ? daemonRunning : linkLive) && current?.pressure == 4 }
    /// An incident open there now (the red badge).
    var incidentOpen: Bool { current?.daemon?.incident != nil || incidents.first?.open == true }

    var lastSeenKey: String { isLocal ? "lastSeenIncident" : "lastSeenIncident." + (info?.id ?? (mirror! as NSString).lastPathComponent) }
    var lastSeenIncident: String {
        get { UserDefaults.standard.string(forKey: lastSeenKey) ?? "" }
        set { UserDefaults.standard.set(newValue, forKey: lastSeenKey); objectWillChange.send() }
    }
    var hasUnseen: Bool { (incidents.first?.id ?? "") > lastSeenIncident }

    /// The app's own answer to "is macOS blocking this?" (roadmap 01 §7.6), from the probe below.
    @Published var probeDenied = false
    private var probe: NWConnection?
    private var probedAt: Double = 0
    /// Blocked by macOS: the engine said so (a fixture) or the probe found `localNetworkDenied`.
    var blocked: Bool { !isLocal && !linkLive && (link?.error == "local_network_denied" || probeDenied) }

    /// When the engine reports a connection that failed at once, the app opens one NWConnection to
    /// the same host and port (it sends nothing; cancelled within 5 s) and reads the path: only
    /// `localNetworkDenied` is "Blocked by macOS", anything else stays "No answer". From the app's own
    /// long-lived process, the one the system's alert names. At most every 30 s per machine; the only
    /// networking the Swift side does.
    func probeLocalNetwork() {
        guard !renderMode, probe == nil, let e = entry, e.transport != "ssh", let host = e.host, !host.isEmpty,
              Date().timeIntervalSince1970 - probedAt > 30,
              let port = NWEndpoint.Port(rawValue: UInt16(clamping: e.port ?? 6674)) else { return }
        probedAt = Date().timeIntervalSince1970
        let c = NWConnection(host: NWEndpoint.Host(host), port: port, using: .tcp)
        probe = c
        c.stateUpdateHandler = { [weak self] st in
            DispatchQueue.main.async {
                guard let self, self.probe === c else { return }
                switch st {
                case .waiting, .failed:
                    self.probeDenied = c.currentPath?.unsatisfiedReason == .localNetworkDenied
                    self.endProbe()
                case .ready:
                    self.probeDenied = false
                    self.endProbe()
                default: break
                }
            }
        }
        c.start(queue: .main)
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
            if let self, self.probe === c { self.endProbe() }
        }
    }

    private func endProbe() {
        probe?.stateUpdateHandler = nil
        probe?.cancel()
        probe = nil
    }

    func refreshCurrent() {
        if let m = mirror {
            link = FileManager.default.contents(atPath: m + "/status.json").flatMap { try? decoder.decode(LinkStatus.self, from: $0) }
            if linkLive { probeDenied = false } else if link?.state == "offline" && link?.fast == true { probeLocalNetwork() }
            info = FileManager.default.contents(atPath: m + "/machine.json").flatMap { try? decoder.decode(MachineInfo.self, from: $0) }
            sync = FileManager.default.contents(atPath: m + "/sync.json").flatMap { try? decoder.decode(SyncState.self, from: $0) }
        }
        let p = logDir + "/current.json"
        guard let d = FileManager.default.contents(atPath: p), let s = try? decoder.decode(Sample.self, from: d) else {
            current = nil; currentAge = .infinity; return
        }
        current = s
        currentAge = now - s.t
    }

    func refreshAll() {
        refreshCurrent()
        reloadPoints()
        loadIncidents()
    }

    /// Loads every samples file (14 days are kept), so switching ranges never waits for data.
    /// In the background: the popup opens at once and keeps showing the previous history
    /// until the new one is ready (or a spinner, the first time). `sync` is for renders.
    func reloadPoints(sync: Bool = false) {
        let state = self.sync, down = stale, grace = inGrace, oldest = info?.oldest
        if sync {
            let r = loadQueue.sync { loadHistory(state, down: down, grace: grace, oldest: oldest) }
            apply(r); historyLoaded = true
            return
        }
        if loading { loadAgain = true; return }
        loading = true
        loadQueue.async { [weak self] in
            guard let self else { return }
            let r = self.loadHistory(state, down: down, grace: grace, oldest: oldest)
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
    /// ones, stacked for the strip. On loadQueue only. A mirror's pids are another machine's: its
    /// logger retires leases itself, and while it is not connected the blocks end where knowledge
    /// ends instead of running on to now.
    private func loadReservations(now: Double) -> [ResBlock] {
        let records = readShared(ledgerDir + "/reservations.jsonl", cap: historyCap, tail: true)
        let ledger = readShared(ledgerDir + "/ledger.json", cap: ledgerCap)
            .flatMap { (try? JSONSerialization.jsonObject(with: $0)) as? [String: Any] } ?? [:]
        let local = isLocal
        let rs = Store.mergeReservations(records: records, ledger: ledger, now: now,
                                         holderGone: { pid in local && kill(pid, 0) != 0 && errno == ESRCH })
        return ResBlock.stack(rs, now: now)
    }

    /// On loadQueue only. For a mirror: its coverage, whether its link is down (or in the grace of
    /// an opening: the stretch from its last data to now is then left blank), its oldest sample.
    private func loadHistory(_ state: SyncState?, down: Bool, grace: Bool = false, oldest: Double?) -> Loaded {
        let now = Date().timeIntervalSince1970 + (isLocal ? 0 : state?.offset_s ?? 0)
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
        var gaps = Store.findGaps(all, now: now)
        var known = now
        if !isLocal, let st = state {
            gaps = MachineStore.mirrorGaps(gaps, have: st.spans, gone: st.goneSpans, oldest: oldest, now: now, down: down)
            if down || grace { known = st.spans.last?.1 ?? all.last?.id ?? now }
            if grace { gaps.removeAll { $0.kind == .notReceived && $0.to >= now - 1 } }
        }
        // drop cached files that are gone (a day's plain file once it is gzipped)
        let present = Set(files.map { "\(logDir)/\($0)" })
        for k in cache.keys where !present.contains(k) { cache[k] = nil }
        return Loaded(history: Store.multires(all, now: now), gaps: gaps, now: now, events: loadEvents(),
                      reservations: loadReservations(now: known))
    }

    /// A mirror's gaps (roadmap 01 §3.5, §5.7): inside the coverage map, the stretches without
    /// samples stay *no data* (the machine logged nothing); outside it, from the remote's oldest
    /// sample (or the first covered moment) to now, a stretch the remote no longer keeps is
    /// *gone*, the one that reaches now while the link is down is *not connected*, every other one
    /// *not received*. While the link is up, the youngest stretch is not drawn until it is longer
    /// than a local chart's gap (the remote's logger vouches for its samples a little later).
    static func mirrorGaps(_ noData: [Gap], have: [(Double, Double)], gone: [(Double, Double)], oldest: Double?,
                           now: Double, down: Bool) -> [Gap] {
        var out: [Gap] = []
        for g in noData {
            for (a, b) in have where b > g.from && a < g.to {
                out.append(Gap(from: max(a, g.from), to: min(b, g.to), kind: .noData))
            }
        }
        guard let first = (have.first?.0).map({ min($0, gone.first?.0 ?? $0, oldest ?? $0) }) else {
            return [Gap(from: oldest ?? now - 14 * 86400, to: now, kind: down ? .notConnected : .notReceived)]
        }
        var at = first
        var holes: [(Double, Double)] = []
        for (a, b) in have {
            if a > at { holes.append((at, a)) }
            at = max(at, b)
        }
        if now - at > (down ? 0 : Store.gapSeconds) { holes.append((at, now)) }
        for (a, b) in holes {
            var x = a
            for (ga, gb) in gone where gb > x && ga < b {
                if ga > x { out.append(Gap(from: x, to: ga, kind: .notReceived)) }
                out.append(Gap(from: max(ga, x), to: min(gb, b), kind: .gone))
                x = min(gb, b)
            }
            if b > x { out.append(Gap(from: x, to: b, kind: down && b >= now - 1 ? .notConnected : .notReceived)) }
        }
        return out.sorted { $0.from < $1.from }
    }

    /// The events, or nil when the files haven't changed since the last load. On loadQueue only.
    private func loadEvents() -> [ChartEvent]? {
        let paths = ["events.jsonl.1", "events.jsonl"].map { "\(logDir)/\($0)" }
        let stamp = paths.map { p -> String in
            let a = try? FileManager.default.attributesOfItem(atPath: p)
            return "\(a?[.size] ?? 0)/\((a?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0)/\(a?[.systemFileNumber] ?? 0)"
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

    /// A file's identity: the cache keys on it, because a mirror replaces whole files by renaming.
    private func inode(_ path: String) -> UInt64 {
        var st = stat()
        return lstat(path, &st) == 0 ? UInt64(st.st_ino) : 0
    }

    private func loadDay(_ day: String, isToday: Bool) -> [Point] {
        let plain = "\(logDir)/samples-\(day).jsonl"
        let gz = plain + ".gz"
        let fm = FileManager.default
        if fm.fileExists(atPath: plain) {
            let ino = inode(plain)
            var entry = cache[plain] ?? (ino, 0, [])
            if entry.ino != ino { entry = (ino, 0, []) }
            guard let fh = FileHandle(forReadingAtPath: plain) else { return entry.pts }
            defer { try? fh.close() }
            let size = (try? fh.seekToEnd()) ?? 0
            if size < entry.offset { entry = (ino, 0, []) }
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
            let ino = inode(gz)
            if let c = cache[gz], c.ino == ino { return c.pts }
            let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/gzip"); p.arguments = ["-dc", gz]
            let pipe = Pipe(); p.standardOutput = pipe
            do { try p.run() } catch { return [] }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            let pts = parse(data[...])
            cache[gz] = (ino, 0, pts)
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
}

// MARK: - Store

final class Store: ObservableObject {
    /// The chart's range in seconds; .infinity = all history on a log time axis.
    @Published var range: Double = 24 * 3600
    @Published var launchAtLogin = FileManager.default.fileExists(atPath: agentPlist)
    @Published var busy = false

    /// The machines: This Mac first. Mirrors join with tabs (roadmap 01, R1a); until then only a
    /// render shows one. The popup draws `machine`, the menu-bar chip is always `local`.
    @Published var machines: [MachineStore] = [MachineStore(logDir: logDir, ledgerDir: ledgerDir)] { didSet { watchMachines() } }
    @Published var selected = 0
    var machine: MachineStore { machines[min(max(selected, 0), machines.count - 1)] }
    var local: MachineStore { machines[0] }
    private var watching: [AnyCancellable] = []

    init() { watchMachines() }

    /// A change in a machine is a change of the popup.
    private func watchMachines() {
        watching = machines.map { m in m.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() } }
    }

    // MARK: machines (roadmap 01 R1a): tabs for the machines added with `oomph remote add`

    /// Tabs for other machines, behind a default until the Local Network question is settled on a
    /// second Mac: `defaults write local.oomph.menubar machinesUI -bool YES`.
    var machinesUI: Bool { UserDefaults.standard.bool(forKey: "machinesUI") }
    /// The machine whose pane was on screen during this opening: only their incidents become seen.
    var shownThisOpening = Set<String>()
    /// When each machine's tab was last chosen: who goes behind » first.
    var lastSelected: [String: Double] = [:]
    /// A tab just closed with its ×: one click brings it back for six seconds.
    @Published var undoUnpin: (mid: String, title: String)?
    // the + (R1b): the connect popover, its draft, Share this Mac (roadmap 01 §3.7–§3.10)
    /// The connect popover is up (an NSPopover on the +; a sheet on the popup with `connectSheet`).
    @Published var connectShown = false
    /// What the popover holds: in memory only, kept 15 minutes after the last edit (§3.8 rule 2).
    let draft = ConnectDraft()
    /// Every machine of machines.json (tabs and Recents), as the popover lists and completes them.
    @Published var known: [MachineEntry] = []
    /// `oomph share status --json` as it was last read (public files, no prompt).
    @Published var share: ShareStatus?
    /// The code made in this session, kept until it is spent or expires (§3.8 rule 6).
    @Published var shareCode: ShareCode?
    /// A fresh code waits for the other machine: the panel stays where it is (§3.8 rule 3).
    @Published var shareWaiting = false
    @Published var sharePaired: String?
    @Published var shareError: String?
    /// The tab to select once machines.json names it (a Recents row, a pairing just made).
    var pendingSelect: String?
    /// Where the + is, in the popup's coordinates (top left): the popover points at it, also when it
    /// moves from the line into the strip of tabs (a pairing just made).
    var plusRect: CGRect = .zero { didSet { if plusRect != oldValue { onPlusMoved?() } } }
    var onPlusMoved: (() -> Void)?
    var addProcess: Process?
    var addIn: FileHandle?
    var addBuf = Data()
    var addOpen = 0
    var addResult: [String: Any]?
    /// The panel's height follows its content (the tour's strip): AppDelegate places it again.
    var onResize: (() -> Void)?
    /// The panel stays up (under the administrator prompt, while a code waits; §3.8 rule 3).
    var holdsPanel: Bool { machinesUI && (busy || shareWaiting) }
    private var engine: Process?
    private var engineIn: FileHandle?
    private var engineBuf = Data()
    private var engineTries = 0
    var engineRunning: Bool { engine != nil }
    var popupOpen = false

    /// The tabs: This Mac, then every pinned machine of machines.json (at most twelve). Stores are
    /// kept across reloads, so a mirror is not read from scratch again.
    func reloadMachines() {
        guard machinesUI else {
            if machines.count > 1 { machines = [local]; selected = 0 }
            return
        }
        let was = machine.mid
        known = MachineEntry.loadAll(machinesDir)
        var next: [MachineStore] = [local]
        for e in MachineEntry.load(machinesDir).prefix(12) {
            let dir = machinesDir + "/" + e.mid
            let m = machines.first { $0.mirror == dir } ?? MachineStore(mirror: dir)
            m.entry = e
            next.append(m)
        }
        if next.map(\.mid) != machines.map(\.mid) { machines = next }
        selected = machines.firstIndex { $0.mid == was } ?? 0
        if let p = pendingSelect, let i = machines.firstIndex(where: { $0.mid == p }) {
            pendingSelect = nil
            select(i)
        }
    }

    /// This Mac has something to say (D9): critical pressure, an open or unseen incident, or a logger
    /// that is installed but silent. Warning, a low disk and the like show on its tile and tab only.
    var localHasSay: Bool {
        guard installed else { return false }
        let l = local
        return !l.daemonRunning || l.current?.pressure == 4 || l.incidentOpen || l.hasUnseen
    }

    /// The opening rule (roadmap 01 §3.3 rule 4, D9): the tab the popup was closed on, unless This Mac
    /// has something to say. Opening on This Mac then does not change which tab is remembered.
    func applyOpeningRule() {
        reloadMachines()
        let remembered = UserDefaults.standard.string(forKey: "selectedMachine") ?? "local"
        selected = localHasSay ? 0 : (machines.firstIndex { $0.mid == remembered } ?? 0)
        shownThisOpening = [machine.mid]
    }

    /// A tab chosen by a click: remembered for the next opening, and backfilled first.
    func select(_ i: Int) {
        guard machines.indices.contains(i) else { return }
        selected = i
        let m = machines[i]
        UserDefaults.standard.set(m.mid, forKey: "selectedMachine")
        lastSelected[m.mid] = Date().timeIntervalSince1970
        shownThisOpening.insert(m.mid)
        m.refreshAll()
        sendWatch()
    }

    /// The tab's ×: the engine unpins it (it stays in Recents), and Undo can pin it again.
    func unpin(_ i: Int) {
        guard machines.indices.contains(i), i > 0 else { return }
        let m = machines[i]
        sendEngine(["cmd": "unpin", "id": m.mid])
        if selected == i { selected = 0 } else if selected > i { selected -= 1 }
        machines.remove(at: i)
        undoUnpin = (m.mid, m.title)
        let mid = m.mid
        DispatchQueue.main.asyncAfter(deadline: .now() + 6) { [weak self] in
            if self?.undoUnpin?.mid == mid { self?.undoUnpin = nil }
        }
        sendWatch()
    }

    func undoLastUnpin() {
        guard let u = undoUnpin else { return }
        sendEngine(["cmd": "pin", "id": u.mid])
        undoUnpin = nil
    }

    /// The tab's context menu: try now instead of waiting out the backoff.
    func reconnect(_ i: Int) {
        guard machines.indices.contains(i), i > 0 else { return }
        sendEngine(["cmd": "retry", "id": machines[i].mid])
    }

    /// The tab's context menu: a label of its own (empty: the name the machine gives itself again).
    func rename(_ i: Int) {
        guard machines.indices.contains(i), i > 0 else { return }
        let m = machines[i]
        let a = NSAlert()
        a.messageText = "Rename \(m.title)"
        a.informativeText = "The tab's name on this Mac. Leave it empty for the name the machine gives itself."
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 240, height: 22))
        field.stringValue = m.entry?.label ?? ""
        field.placeholderString = m.info?.name ?? m.entry?.name ?? m.mid
        a.accessoryView = field
        a.addButton(withTitle: "Rename")
        a.addButton(withTitle: "Cancel")
        a.window.initialFirstResponder = field
        let done: (NSApplication.ModalResponse) -> Void = { [weak self] r in
            guard r == .alertFirstButtonReturn else { return }
            self?.sendEngine(["cmd": "rename", "id": m.mid, "label": String(field.stringValue.prefix(64))])
        }
        // a sheet on the popup: it stays open (it closes when another window takes the keyboard)
        if let w = NSApp.keyWindow { a.beginSheetModal(for: w, completionHandler: done) } else { done(a.runModal()) }
    }

    /// Forget… on a tab (roadmap 01 §3.9): one confirmation, then mirror, key and token go.
    func confirmForget(_ i: Int) {
        guard machines.indices.contains(i), i > 0 else { return }
        let m = machines[i]
        let a = NSAlert()
        a.messageText = "Forget \(m.title)?"
        a.informativeText = "Its history on this Mac is deleted and you'll need a new pairing code to connect again."
        a.addButton(withTitle: "Forget")
        a.addButton(withTitle: "Cancel")
        let done: (NSApplication.ModalResponse) -> Void = { [weak self] r in
            guard let self, r == .alertFirstButtonReturn else { return }
            if let j = self.machines.firstIndex(where: { $0.mid == m.mid }) {
                if self.selected == j { self.selected = 0 } else if self.selected > j { self.selected -= 1 }
                self.machines.remove(at: j)
            }
            self.forget(m.mid)
            self.sendWatch()
        }
        if let w = NSApp.keyWindow { a.beginSheetModal(for: w, completionHandler: done) } else { done(a.runModal()) }
    }

    static func openLocalNetworkSettings() {
        if let u = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_LocalNetwork") {
            NSWorkspace.shared.open(u)
        }
    }

    /// Keys while the popup is open and tabs are on (roadmap 01 §3.2): ⌘1…⌘9 choose a tab, ⌃⇥ and
    /// ⌃⇧⇥ the next and previous one. True when the key was taken.
    func machineKey(_ e: NSEvent) -> Bool {
        guard machinesUI, e.type == .keyDown else { return false }
        let mods = e.modifierFlags.intersection(.deviceIndependentFlagsMask)
        if mods == .command, e.charactersIgnoringModifiers == "n" { toggleConnect(); return true }  // ⌘N: the + (R1b)
        guard machines.count > 1 else { return false }
        if mods == .command, let c = e.charactersIgnoringModifiers, let n = Int(c), (1...9).contains(n) {
            if machines.indices.contains(n - 1) { select(n - 1) }
            return true
        }
        if e.keyCode == 48 && mods.contains(.control) {  // ⇥
            let step = mods.contains(.shift) ? machines.count - 1 : 1
            select((selected + step) % machines.count)
            return true
        }
        return false
    }

    /// Opening the popup: machines connect only now, and until a minute after it closed (D8).
    func machinesOpened() {
        popupOpen = true
        if machinesUI { refreshShare() }  // "shared with 2 machines" in the status line
        guard machinesUI, machines.count > 1 else { return }
        for m in machines.dropFirst() { m.refreshCurrent(); m.markOpened(); m.reloadPoints(); m.loadIncidents() }
        startEngine()
    }

    /// Closing it: incidents become seen only on the panes that were on screen; the engine is told
    /// to go idle (it disconnects a minute later).
    func machinesClosed() {
        popupOpen = false
        for m in machines where shownThisOpening.contains(m.mid) {
            if let first = m.incidents.first?.id { m.lastSeenIncident = first }
        }
        sendEngine(["cmd": "idle"])
    }

    /// The engine, started if it is not running (a pin from Recents, a pairing made in the popover).
    func ensureEngine() { startEngine() }

    /// An edit of machines.json (pin, forget, rename): the engine makes it, so it is started for it.
    func engineCommand(_ obj: [String: Any]) {
        if engine == nil { startEngine() }
        sendEngine(obj)
    }

    /// `oomph remote sync --json`, the bundled CLI: the only thing here that talks to other
    /// machines. It writes the mirrors; the app reads them when it says what changed.
    private func startEngine() {
        if engine != nil { sendWatch(); return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = ["-I", "-B", cliPath, "remote", "sync", "--json"]
        let inp = Pipe(), out = Pipe()
        p.standardInput = inp
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        let rd = out.fileHandleForReading
        rd.readabilityHandler = { [weak self] h in
            let d = h.availableData
            // at the end of output the handler fires again and again with nothing: it goes now
            if d.isEmpty { h.readabilityHandler = nil; return }
            DispatchQueue.main.async { self?.engineData(d) }
        }
        p.terminationHandler = { [weak self] _ in
            rd.readabilityHandler = nil
            DispatchQueue.main.async { self?.engineEnded() }
        }
        do { try p.run() } catch { return }
        engine = p
        engineIn = inp.fileHandleForWriting
        sendWatch()
    }

    private func sendEngine(_ obj: [String: Any]) {
        guard let h = engineIn, var d = try? JSONSerialization.data(withJSONObject: obj) else { return }
        d.append(0x0A)
        try? h.write(contentsOf: d)
    }

    func sendWatch() {
        sendEngine(["cmd": "watch", "ids": machines.dropFirst().map(\.mid),
                    "focus": machine.isLocal ? NSNull() as Any : machine.mid as Any])
    }

    private func engineData(_ d: Data) {
        guard !d.isEmpty else { return }
        engineBuf.append(d)
        if engineBuf.count > 1 << 20 { engineBuf.removeAll() }
        while let i = engineBuf.firstIndex(of: 0x0A) {
            let line = engineBuf.subdata(in: engineBuf.startIndex..<i)
            engineBuf.removeSubrange(engineBuf.startIndex...i)
            guard let o = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else { continue }
            let id = o["id"] as? String
            switch o["ev"] as? String {
            case "state":
                engineTries = 0
                machines.first { $0.mid == id }?.refreshCurrent()
            case "changed":
                if let m = machines.first(where: { $0.mid == id }) {
                    m.refreshCurrent()
                    let what = (o["what"] as? [String]) ?? []
                    if what.contains("samples") || what.contains("ledger") || what.contains("events") { m.reloadPoints() }
                    if what.contains("incidents") { m.loadIncidents() }
                }
            case "machines":
                reloadMachines()
                sendWatch()
            default: break
            }
        }
    }

    /// The engine ended: on its own after the idle minute, or it died. While the popup is open it is
    /// started again, after 1, 2, 4 … at most 60 s.
    private func engineEnded() {
        engine = nil
        engineIn = nil
        engineBuf.removeAll()
        for m in machines.dropFirst() { m.refreshCurrent() }
        guard popupOpen, machines.count > 1 else { engineTries = 0; return }
        engineTries += 1
        let wait = min(60.0, pow(2.0, Double(engineTries - 1)))
        DispatchQueue.main.asyncAfter(deadline: .now() + wait) { [weak self] in
            if let self, self.popupOpen, self.engine == nil { self.startEngine() }
        }
    }

    /// Which tabs fit the strip (roadmap 01 §3.2, simplified): This Mac and the selected tab always;
    /// then the others, most recently chosen first, at least 92 pt each; the rest go behind ».
    func fitTabs(width: CGFloat = 426) -> (visible: [Int], hidden: [Int]) {
        let font = NSFont.systemFont(ofSize: 11.5)
        func natural(_ i: Int) -> CGFloat {
            let w: CGFloat = (machines[i].title as NSString).size(withAttributes: [.font: font]).width
            let cap: CGFloat = i == selected ? 180 : 150
            return min(cap, w + (i == 0 ? 33 : 38))
        }
        let all = Array(machines.indices)
        let total: CGFloat = all.reduce(CGFloat(0)) { $0 + natural($1) + 2 }
        if total <= width { return (all, []) }
        var budget: CGFloat = width - 47 - natural(0) - 2
        if selected != 0 { budget -= max(92, min(natural(selected), 120)) + 2 }
        let others = all.filter { $0 != 0 && $0 != selected }
            .sorted { (lastSelected[machines[$0].mid] ?? -Double($0)) > (lastSelected[machines[$1].mid] ?? -Double($1)) }
        var shown: [Int] = []
        for i in others where budget >= 94 {
            shown.append(i)
            budget -= 94
        }
        let visible = all.filter { $0 == 0 || $0 == selected || shown.contains($0) }
        return (visible, all.filter { !visible.contains($0) })
    }

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
    /// Tokens read or pasted in this session: the keychain is asked at most once per launch.
    private var sessionTokens: [AIProvider: String] = [:]

    // upgrades ("Upgrade" replaces this app with a newer version; "Update" installs the bundled logger)
    @Published var upgradeButton: UpgradeButton = .hidden
    @Published var upgradeCheckError: String?
    @Published var changelog: [ChangelogEntry] = []
    @Published var showChangelog = false
    @Published var optionHeld = false     // ⌥ down while the popup is up: Check becomes a forced Upgrade
    @Published var forceUpgrade = false   // the changelog was opened with ⌥: rebuild main even if it isn't newer
    private var flagsMonitor: Any?
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

    var installed: Bool { FileManager.default.fileExists(atPath: "/Library/LaunchDaemons/local.oomph.daemon.plist") }

    static func version(at path: String) -> String? {
        guard let s = try? String(contentsOfFile: path, encoding: .utf8),
              let r = s.range(of: #"VERSION = "([^"]+)""#, options: .regularExpression) else { return nil }
        return String(s[r]).replacingOccurrences(of: "VERSION = ", with: "").replacingOccurrences(of: "\"", with: "")
    }
    var installedVersion: String? { Store.version(at: "/usr/local/libexec/oomph/oomph.py") }
    var bundledVersion: String? { Store.version(at: (Bundle.main.resourcePath ?? "") + "/oomph.py") }
    var needsUpdate: Bool { installed && installedVersion != nil && bundledVersion != nil && installedVersion != bundledVersion }


    var allHistory: Bool { range.isInfinite }


    /// What a later history record's null does not undo (oomph.MERGE_KEEP).
    static let mergeKeep: Set<String> = ["res", "peak", "v", "agent", "user"]

    /// The merge behind loadReservations, without files or the kernel: the records of the history log
    /// merged per key (a later record overrides the fields it has, a null not those of mergeKeep; an
    /// "end" is never undone by a later record of another kind, an "edit" or a newer writer's "grant"),
    /// the ledger's own short history, then the live leases. A live lease whose holder is gone, that
    /// expired or whose queue place lapsed ends there (the logger retires it within a sample; an older
    /// logger may not have yet). A holder in another pid namespace (`holder.ns`, Linux) is not looked
    /// up: its pid means something else here.
    /// `oomph top` does the same (oomph_view.merge_reservations; tools/vectors/chart.json).
    static func mergeReservations(records: Data?, ledger: [String: Any], now: Double,
                                  holderGone: (Int32) -> Bool) -> [Reservation] {
        var byKey: [String: Reservation] = [:]
        var events: [String: String] = [:]
        if let d = records {
            var merged: [String: [String: Any]] = [:]
            var order: [String] = []
            for line in d.split(separator: 0x0A) {
                guard let o = (try? JSONSerialization.jsonObject(with: Data(line))) as? [String: Any],
                      let r = Reservation(o) else { continue }
                let ev = (o["event"] as? String) ?? "end"
                if var m = merged[r.id] {
                    if ev == "end" || events[r.id] != "end" {
                        for (f, x) in o where !(x is NSNull && mergeKeep.contains(f)) { m[f] = x }
                        merged[r.id] = m
                        events[r.id] = ev
                    }
                } else {
                    merged[r.id] = o; events[r.id] = ev; order.append(r.id)
                }
            }
            for k in order { if let o = merged[k], let r = Reservation(o) { byKey[k] = r } }
        }
        for h in (ledger["history"] as? [[String: Any]]) ?? [] {
            if let r = Reservation(h), byKey[r.id] == nil { byKey[r.id] = r }
        }
        for (pos, l) in ((ledger["leases"] as? [[String: Any]]) ?? []).enumerated() {
            guard var r = Reservation(l) else { continue }
            r.queue = pos
            let seen = (l["seen"] as? NSNumber)?.doubleValue ?? r.requested
            let h = l["holder"] as? [String: Any]
            let ns: Any? = h?["ns"]
            let pid: Int32 = (ns == nil || ns is NSNull) ? ((h?["pid"] as? NSNumber)?.int32Value ?? 0) : 0
            if let e = r.expires, r.granted != nil, e < now { r.ended = e; r.outcome = "expired" }
            else if r.granted == nil, now - seen > 180 { r.ended = seen + 180; r.outcome = "lapsed" }
            else if pid > 0, holderGone(pid) { r.ended = max(seen, r.granted ?? r.requested); r.outcome = "holder_gone" }
            byKey[r.id] = r
        }
        // an edit record whose reservation neither ended nor is live: the ledger was reset under it
        for (k, ev) in events where ev != "end" && byKey[k]?.live == true {
            if !((ledger["leases"] as? [[String: Any]]) ?? []).contains(where: { Reservation($0)?.id == k }),
               var r = byKey[k] {
                r.ended = r.segments.last?.t ?? r.requested; r.outcome = "unknown"
                byKey[k] = r
            }
        }
        let keep = now - 14 * 86400
        return byKey.values.filter { ($0.ended ?? now) >= keep }
    }


    /// Thins the history so its resolution falls with age: buckets max(30 s, age/720) wide, each
    /// keeping its worst point (spikes survive). Fine enough for any linear range at 720 px and
    /// for the log axis, small enough (a few thousand points) to remap on every animation frame.
    /// Longer than this without a sample is a gap (the logger samples every 30 s; the report uses 5 min).
    static let gapSeconds: Double = 300

    /// Stretches without samples in the history as logged (before thinning), and from the last
    /// sample to now. Shared with `oomph top` (tools/vectors/chart.json).
    static func findGaps(_ all: [Point], now: Double) -> [Gap] {
        var gaps: [Gap] = []
        for i in all.indices.dropFirst() where all[i].id - all[i - 1].id > Store.gapSeconds {
            gaps.append(Gap(from: all[i - 1].id, to: all[i].id))
        }
        if let last = all.last, now - last.id > Store.gapSeconds { gaps.append(Gap(from: last.id, to: now)) }
        return gaps
    }

    /// Shared with `oomph top`, like worst (tools/vectors/chart.json).
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
                DispatchQueue.main.asyncAfter(deadline: .now() + 3) { self.local.refreshAll() }
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
    /// Newer than this app, not just different: an app built or installed another way (build-app.sh,
    /// a copy) must not offer the version an older app had found as an "upgrade".
    var rememberedUpgrade: Bool {
        !availableCommit.isEmpty && availableCommit != defaults.string(forKey: "upgradeSkipped")
            && !bundleCommit.hasPrefix(availableCommit) && availableVersion != bundledVersion
            && Store.isNewer(availableVersion, than: bundledVersion ?? "")
    }

    /// "1.9.6" → [1, 9, 6, 0]; "1.9.6-3-gabc1234" → [1, 9, 6, 3]; "-dirty" ignored. nil when it isn't one.
    static func versionKey(_ v: String) -> [Int]? {
        var parts: [Substring] = v.split(separator: "-")
        if parts.last == "dirty" { parts.removeLast() }
        guard let head = parts.first else { return nil }
        let nums: [Int] = head.split(separator: ".").compactMap { Int($0) }
        guard nums.count == 3, nums.count == head.split(separator: ".").count else { return nil }
        let ahead: Int = parts.count >= 3 ? (Int(parts[1]) ?? 0) : 0
        return nums + [ahead]
    }

    /// Whether version `a` comes after `b`; when either isn't a version, whether they differ (as before).
    static func isNewer(_ a: String, than b: String) -> Bool {
        guard let x = versionKey(a), let y = versionKey(b) else { return a != b }
        return x.lexicographicallyPrecedes(y) == false && x != y
    }

    /// Forget a remembered "upgrade" that isn't newer than this app.
    private func dropStaleUpgrade() {
        if !availableCommit.isEmpty && !rememberedUpgrade && availableCommit != defaults.string(forKey: "upgradeSkipped") {
            defaults.removeObject(forKey: "upgradeAvailable")
            defaults.removeObject(forKey: "upgradeAvailableCommit")
        }
    }

    /// Every time the popup opens: tools once a day, then the button, then the daily check
    /// (no background timer — it only runs while you look).
    func popupOpened() {
        if upgradeButton == .upToDate { upgradeButton = .check }
        watchOption()
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
        dropStaleUpgrade()
        if upgradeButton == .hidden || (upgradeButton == .upgrade && !rememberedUpgrade) {
            upgradeButton = rememberedUpgrade ? .upgrade : .check
        }
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

    /// Follow the ⌥ key while the app is active (the popup is its key window).
    func watchOption() {
        optionHeld = NSEvent.modifierFlags.contains(.option)
        guard flagsMonitor == nil else { return }
        flagsMonitor = NSEvent.addLocalMonitorForEvents(matching: .flagsChanged) { [weak self] e in
            let down: Bool = e.modifierFlags.contains(.option)
            if self?.optionHeld != down { self?.optionHeld = down }
            return e
        }
    }

    func openUpgrade(force: Bool = false) {
        forceUpgrade = force
        showChangelog = true
        loadingChangelog = true
        changelog = []
        runUpgradeCLI(["log", "--json"]) { [weak self] data, status in
            guard let self else { return }
            self.loadingChangelog = false
            if status == 0, let entries = try? JSONDecoder().decode([ChangelogEntry].self, from: data) {
                if entries.isEmpty && !self.forceUpgrade {  // nothing newer after all: say so instead of an empty changelog
                    self.showChangelog = false
                    self.defaults.removeObject(forKey: "upgradeAvailable")
                    self.defaults.removeObject(forKey: "upgradeAvailableCommit")
                    self.upgradeButton = .upToDate
                    return
                }
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
    /// Reports include an AI analysis from this provider. Connect switches it on only once the token
    /// is saved, so this needs no look into the keychain (which would ask for access, 1.9.9).
    var aiConnected: Bool { aiOn }

    /// The token for a report: this session's, else the keychain's (the one read that may ask, once
    /// per launch; "Always Allow" makes it once per build). nil: aiError says why.
    func reportToken(_ p: AIProvider) -> String? {
        if !p.needsToken { return "" }
        if let t = sessionTokens[p], !t.isEmpty { return t }
        let (t, st) = Keychain.get(p.rawValue)
        if let t, !t.isEmpty {
            sessionTokens[p] = t
            return t
        }
        if st == errSecItemNotFound || st == errSecSuccess || st == errSecDecode {
            aiOn = false   // nothing to report with: connected no more, the dialog asks for the key
            aiError = "The \(p.title) key is no longer in your keychain, so this report has no AI analysis. "
                + "Connect again with the key."
        } else {
            aiError = "The keychain didn't hand over the \(p.title) key. Try Report again and allow access, "
                + "or disconnect and connect again with the key."
        }
        return nil
    }

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
                if p.needsToken {
                    Keychain.set(token, p.rawValue)
                    self.sessionTokens[p] = token
                }
                self.setAIModel(model.isEmpty ? (reply["model"] as? String ?? "") : model, p)
                if p == .ollama { self.ollamaURL = url }
                self.aiProvider = p
                self.aiOn = true
                done(true)
            }
        }
    }

    /// Disconnect: reports go back to plain HTML, and the token is forgotten (here and in the
    /// keychain): a reconnect takes it pasted again, as Update takes the password only when used.
    /// Only this build's item can be deleted without a prompt (Keychain.forget): an earlier build's
    /// stays in the login keychain until the user deletes it in Keychain Access.
    func disconnectAI() {
        aiOn = false
        aiConnectError = nil
        for p in AIProvider.allCases where p.needsToken {
            sessionTokens[p] = nil
            if !renderMode { Keychain.forget(p.rawValue) }
        }
    }

    var aiSummary: String {
        let m = aiModel(aiProvider)
        return aiProvider.title + (m.isEmpty ? "" : " · " + m)
    }

    func runReport() {
        if aiRunning || !machine.isLocal { return }  // another machine's reports come in R2 (1.10.3)
        if aiConnected { runAIReport() } else { runCLI(["html", "--last", "24h", "--open"]) }
    }

    func runAIReport() {
        aiError = nil   // a second identical failure is news again
        guard let token = reportToken(aiProvider) else {
            if !aiOn { runCLI(["html", "--last", "24h", "--open"]) }  // the key is gone: the plain report still opens
            return
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        var args = ["-I", "-B", cliPath, "ai-report", "--provider", aiProvider.rawValue, "--last", "24h", "--open"]
        let model = aiModel(aiProvider)
        if !model.isEmpty { args += ["--model", model] }
        if aiProvider == .ollama { args += ["--base-url", ollamaURL] }
        p.arguments = args
        var env = ProcessInfo.processInfo.environment
        env["OOMPH_AI_TOKEN"] = token  // via the environment, not argv
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
    /// Another machine's oldest sample as it reported it: the ∞ axis spans back to it, so it does
    /// not rescale while history arrives (roadmap 01 §3.5). nil: from the oldest point loaded.
    var oldest: Double? = nil
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
        MemoryChart.mapper(now: now, first: firstT, lgRange: lgRange, blend: blend)
    }

    /// Where the ∞ axis begins.
    var firstT: Double {
        guard let o = oldest else { return points.first?.id ?? now }
        return min(o, points.first?.id ?? o)
    }

    /// Linear: the last 10^lgRange s. Log: all history, ages under minAge at the right edge.
    /// Shared with `oomph top` (tools/vectors/chart.json).
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
            let missing = gapBands(f, missing: true)
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
                .chartBackground { proxy in bandLayer(proxy, away: away, gaps: gaps, missing: missing) }
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
                        if stripHeight > 0 { stripLayer(plot: plot, top: geo.size.height - stripHeight, mapper: f, grid: grid, missing: missing) }
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
    func bandLayer(_ proxy: ChartProxy, away: [Band], gaps: [Band], missing: [Band]) -> some View {
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
                if !missing.isEmpty { MemoryChart.drawMissing(ctx, missing.map { ($0.from * W, $0.to * W) }, height: size.height) }
            }
            .frame(width: plot.width, height: plot.height)
            .offset(x: plot.minX, y: plot.minY)
        }
        .allowsHitTesting(false)
    }

    /// Merges spans (in px) closer than `tolerance`. Grey: away spans, bridged by no-data stretches
    /// that touch them (asleep while away); a no-data stretch with nobody away near it stays white.
    /// Shared with `oomph top` (tools/vectors/chart.json).
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

    /// Stretches this dashboard has not received from another machine: a dotted field between
    /// dashed edges, distinct from the hatch of *no data* (roadmap 01 §3.5).
    static func drawMissing(_ ctx: GraphicsContext, _ spans: [(Double, Double)], height: CGFloat) {
        var field = Path(), edges = Path()
        for (a, b) in spans where b > a {
            let x0 = CGFloat(a), x1 = CGFloat(b)
            field.addRect(CGRect(x: x0, y: 0, width: max(x1 - x0, 1), height: height))
            for x in [x0, x1] { edges.move(to: CGPoint(x: x, y: 0)); edges.addLine(to: CGPoint(x: x, y: height)) }
        }
        ctx.fill(field, with: .color(.gray.opacity(0.05)))
        var c = ctx
        c.clip(to: field)
        c.fill(MemoryChart.dots(in: field.boundingRect, spacing: 4), with: .color(.gray.opacity(0.55)))
        ctx.stroke(edges, with: .color(.gray.opacity(0.5)), style: StrokeStyle(lineWidth: 0.75, dash: [2, 2]))
    }

    /// Small dots on a grid anchored at the origin, over `r`.
    static func dots(in r: CGRect, spacing: CGFloat) -> Path {
        var p = Path()
        let d: CGFloat = spacing > 3.5 ? 1.2 : 1.0
        var y: CGFloat = (r.minY / spacing).rounded(.down) * spacing + spacing / 2
        while y < r.maxY {
            var x: CGFloat = (r.minX / spacing).rounded(.down) * spacing + spacing / 2
            while x < r.maxX {
                p.addEllipse(in: CGRect(x: x - d / 2, y: y - d / 2, width: d, height: d))
                x += spacing
            }
            y += spacing
        }
        return p
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
        let top = MemoryChart.stripTop(vis)
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

    /// The strip's scale: the first round figure at or above the tallest stack in view. Shared with
    /// `oomph top` (tools/vectors/chart.json).
    static func stripTop(_ vis: Double) -> Double {
        [2.0, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256].first { $0 >= vis } ?? vis
    }

    func stripLayer(plot: CGRect, top: CGFloat, mapper f: @escaping (Double) -> Double, grid: [GridLine],
                    missing: [Band] = []) -> some View {
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
                if !missing.isEmpty {
                    let w = Double(W)
                    MemoryChart.drawMissing(plotCtx, missing.map { ($0.from * w, $0.to * w) }, height: H)
                }
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
        var noDataIcon = "slash.circle"
        var incidents: [String] = []
        var events: [(String, Bool)] = []   // text, alarming
        var moreEvents = 0
        var reserved: [(String, Color)] = []  // reservations active under the pointer
        var moreReserved = 0
    }

    /// Time for x (the mapper is monotonic, so bisection inverts it).
    func time(at u: Double, _ f: (Double) -> Double) -> Double {
        var lo = firstT - 1, hi = now
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
        let kinds = Set(overlapping.map(\.kind))
        if kinds.count == 1, let g = overlapping.first, g.kind != .noData {
            // another machine's stretch this dashboard has not received: which kind, and whether it fills in
            let span = "\(MemoryChart.when(overlapping.map(\.from).min()!))–\(clock.string(from: Date(timeIntervalSince1970: overlapping.map(\.to).max()!)))"
            info.noDataIcon = "circle.dotted"
            switch g.kind {
            case .notConnected: info.noData = "not connected since \(MemoryChart.when(g.from)): nothing is known after that; this fills in when the machine is back"
            case .gone: info.noData = "no longer available, before \(MemoryChart.when(g.to)): never received, and that machine keeps 14 days"
            default: info.noData = "not received \(span): not connected then and not fetched yet; it fills in when the machine is back"
            }
        } else if overlapping.count == 1, let g = overlapping.first {
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
                    SwiftUI.Label(n, systemImage: info.noDataIcon).font(.system(size: 10)).foregroundStyle(.secondary)
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

    /// The no-data stretches on screen, or with `missing` the ones not received from another machine.
    func gapBands(_ f: (Double) -> Double, missing: Bool = false) -> [Band] {
        var out: [Band] = []
        for g in gaps where (g.kind != .noData) == missing {
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
    /// "06:36" today, "Tue 4 Nov 06:36" before.
    static func when(_ t: Double) -> String {
        let d = Date(timeIntervalSince1970: t)
        if Calendar.current.isDateInToday(d) { return timeFmt.string(from: d) }
        let f = DateFormatter(); f.dateFormat = "EEE d MMM HH:mm"
        return f.string(from: d)
    }
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
    /// Another machine's chart with a stretch it has not received in view: the dots get an entry.
    var missing = false
    struct Item { let name: String; let help: String; let kind: Int }  // 0 swatch, 1 away, 2 hatch, 3 incident, 4 dots
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
        case 4:
            Canvas { ctx, size in
                let r = CGRect(origin: .zero, size: size)
                ctx.fill(Path(r), with: .color(.gray.opacity(0.06)))
                ctx.fill(MemoryChart.dots(in: r, spacing: 3), with: .color(.gray.opacity(0.75)))
            }
            .frame(width: 9, height: 7)
        default: Rectangle().fill(Color.red).frame(width: 1.5, height: 8).frame(width: 5)
        }
    }

    static let notReceived = Item(name: "not received", help: "Dotted: this Mac has not received this stretch from that machine — it was not connected then. It fills in when the machine is back; a stretch older than what it keeps never will.", kind: 4)

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(Array((missing ? [ChartLegend.rows[0], ChartLegend.rows[1] + [ChartLegend.notReceived]] : ChartLegend.rows).enumerated()), id: \.offset) { r, row in
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
    @State var showAllReservations = false  // the callout behind "+N more"
    private let series = ["Wired", "App", "Compressed", "Swap"]
    /// The machine on screen.
    var m: MachineStore { store.machine }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SwiftUI.Group { if m.isLocal { header } else { mirrorHeader } }
                .padding(.horizontal, 14).padding(.vertical, 11)
                .frame(maxWidth: .infinity)
                .background(Color.primary.opacity(0.045))
                .tourAnchor("header")
            if store.machinesUI && store.machines.count > 1 {
                machineTabs
            } else if store.machinesUI {
                // one machine: the + on the hairline (roadmap 01 §3.1); it adds no height
                Divider()
                    .overlay(alignment: .trailing) { PlusButton(store: store).padding(.trailing, 14) }
                    .tourAnchor("machines")
                    .zIndex(2)
            } else {
                Divider()
            }
            VStack(alignment: .leading, spacing: 10) {
                if let c = m.current, m.showsStats {
                    if m.stale { stats(c).grayscale(1).opacity(0.5).tourAnchor("stats") } else { stats(c).opacity(m.inGrace ? 0.6 : 1).tourAnchor("stats") }
                }
                chart.tourAnchor("chart").zIndex(1)
                if !m.reservations.isEmpty || m.fetchingLedger { reservedList(m.liveReservations).tourAnchor("leases") }
                incidentsList.tourAnchor("incidents")
                Divider()
                footer.tourAnchor("footer")
            }
            .padding(14)
            // the tour's bar has a strip of its own under the footer once the + sits where it floated (§3.12)
            if tourStep != nil && store.machinesUI { Color.clear.frame(height: 34) }
        }
        .frame(width: popupWidth)
        .onChange(of: tourStep == nil) { _, _ in store.onResize?() }
        .sheet(isPresented: Binding(get: { store.connectShown && connectAsSheet && !renderMode },
                                    set: { if !$0 { store.connectShown = false } })) {
            ConnectView(store: store, draft: store.draft)
        }
        .overlayPreferenceValue(PlusAnchorKey.self) { anchor in
            // a render draws the popover where it opens, under the + (an NSPopover is a window of its own)
            GeometryReader { geo in
                if renderMode, store.connectShown, let anchor {
                    let r = geo[anchor]
                    let w: CGFloat = store.draft.step == .share ? 316 : 304
                    let left = min(max(6, r.midX - w + 34), geo.size.width - w - 6)
                    VStack(spacing: 0) {
                        CalloutArrow().rotation(Angle(degrees: 180)).fill(Color(nsColor: .windowBackgroundColor))
                            .frame(width: 18, height: 8).padding(.leading, r.midX - left - 9)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        ConnectView(store: store, draft: store.draft)
                            .background(Color(nsColor: .windowBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
                            .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.primary.opacity(0.15), lineWidth: 0.5))
                    }
                    .frame(width: w)
                    .compositingGroup()
                    .shadow(color: .black.opacity(0.3), radius: 12, y: 4)
                    .padding(.leading, left)
                    .padding(.top, r.maxY + 1)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                }
            }
        }
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
        .overlayPreferenceValue(MoreAnchorKey.self) { anchor in
            GeometryReader { geo in
                if showAllReservations, let anchor {
                    let r = geo[anchor]
                    let w: CGFloat = 360
                    let left = min(max(8, r.minX + 40 - w / 2), geo.size.width - w - 8)
                    ZStack(alignment: .topLeading) {
                        Color.black.opacity(0.001)
                            .onTapGesture { withAnimation(.easeOut(duration: 0.15)) { showAllReservations = false } }
                        allReservationsCallout(arrowX: r.minX + 40 - left)
                            .frame(width: w)
                            .padding(.leading, left)
                            .padding(.bottom, geo.size.height - r.minY + 2)
                            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottomLeading)
                            .transition(.opacity.combined(with: .scale(scale: 0.96, anchor: .bottom)))
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
        .onExitCommand { withAnimation(.easeOut(duration: 0.15)) { showTopApps = false; showAI = false; showAllReservations = false; tourStep = nil } }
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
        let live = m.current != nil && m.daemonRunning
        let p = live ? (Pressure(rawValue: m.current!.pressure) ?? .unknown) : .unknown
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
                    .onTapGesture { if store.machinesUI && store.share?.shared == true { store.openConnect(share: true) } }
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

    /// The header of another machine (roadmap 01 §3.3, §3.5): its name, its kind's tile tinted by
    /// its pressure, its state in the status line and the capsule. Not connected: the tile and
    /// the capsule's fill are grey, the capsule's words stay in the primary colour.
    var mirrorHeader: some View {
        let live = !m.stale && m.current != nil
        let p = live ? (Pressure(rawValue: m.current!.pressure) ?? .unknown) : .unknown
        let tint: Color = live ? p.color : .secondary
        let icon = ["laptop": "laptopcomputer", "server": "server.rack", "container": "shippingbox"][m.info?.kind ?? ""] ?? "desktopcomputer"
        let attention = m.link?.state == "needs_attention" || m.link?.was == "needs_attention"
        return HStack(alignment: .center, spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 32, height: 32)
                .background(tint.opacity(0.16), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .opacity(m.inGrace ? 0.6 : 1)
                .tourAnchor("chip")
            VStack(alignment: .leading, spacing: 2) {
                (Text(brand).fontWeight(.bold) + Text(": " + m.title).fontWeight(.medium))
                    .font(.system(size: 14)).lineLimit(1).truncationMode(.tail)
                if m.link?.next_try != nil, m.link?.state == "offline", store.engineRunning, !renderMode {
                    TimelineView(.periodic(from: .now, by: 1)) { _ in  // the countdown of "next try in 40 s"
                        Text(mirrorStatusLine).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
                    }
                } else {
                    Text(mirrorStatusLine).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer(minLength: 8)
            SwiftUI.Group {
                if live {
                    Text(p.label).background(p.color.opacity(0.2), in: Capsule()).foregroundStyle(p == .normal ? .primary : p.color)
                } else if m.blocked {
                    Button { Store.openLocalNetworkSettings() } label: {
                        Text("Local Network settings…").padding(.horizontal, 10).padding(.vertical, 4)
                            .background(Color.orange.opacity(0.22), in: Capsule()).foregroundStyle(.primary)
                    }
                    .buttonStyle(.plain).padding(.horizontal, -10).padding(.vertical, -4)
                    .help("macOS does not let \(brand) reach the local network: allow it in System Settings › Privacy & Security › Local Network")
                } else if attention {
                    Text("Needs attention").background(Color.orange.opacity(0.22), in: Capsule()).foregroundStyle(.primary)
                } else if m.connecting {
                    HStack(spacing: 5) {
                        ProgressView().controlSize(.mini).scaleEffect(0.8).frame(width: 10, height: 10)
                        Text("Connecting…")
                    }
                    .background(Color.gray.opacity(0.22), in: Capsule()).foregroundStyle(.primary)
                } else {
                    Text("Not connected").background(Color.gray.opacity(0.22), in: Capsule()).foregroundStyle(.primary)
                }
            }
            .opacity(m.inGrace ? 0.6 : 1)
            .font(.system(size: 11, weight: .semibold))
            .padding(.horizontal, 10).padding(.vertical, 4)
            .fixedSize()
        }
    }

    /// The line under the header becomes a strip of tabs once another machine is watched (roadmap 01
    /// §3.2): This Mac first, then each machine added with `oomph remote add`; » holds what does not
    /// fit. The header and everything below the strip belong to the selected tab.
    var machineTabs: some View {
        let fit = store.fitTabs()
        return HStack(alignment: .bottom, spacing: 2) {
            ForEach(fit.visible, id: \.self) { i in
                MachineTab(store: store, index: i)
            }
            if !fit.hidden.isEmpty && renderMode {
                Text("» \(fit.hidden.count)").font(.system(size: 11.5)).foregroundStyle(.secondary)
                    .frame(height: 24).padding(.horizontal, 6)
            } else if !fit.hidden.isEmpty {
                Menu {
                    ForEach(fit.hidden, id: \.self) { i in
                        Button(store.machines[i].title) { store.select(i) }
                    }
                } label: {
                    Text("» \(fit.hidden.count)").font(.system(size: 11.5)).foregroundStyle(.secondary)
                }
                .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
                .frame(height: 24).padding(.horizontal, 6)
                .help("\(fit.hidden.count) more machine\(fit.hidden.count == 1 ? "" : "s")")
            }
            Spacer(minLength: 0)
            if let u = store.undoUnpin {
                Button("Undo") { store.undoLastUnpin() }
                    .buttonStyle(.link).font(.system(size: 11)).frame(height: 24)
                    .help("Watch \(u.title) again")
            }
            PlusButton(store: store).frame(height: 24).padding(.leading, 4)
        }
        .padding(.horizontal, 10)
        .frame(maxWidth: .infinity, minHeight: 27, maxHeight: 27, alignment: .bottomLeading)
        .background(Color.primary.opacity(0.045))
        .overlay(alignment: .bottom) { Divider() }
        .tourAnchor("machines")
    }

    var mirrorStatusLine: String {
        let last = m.knownUntil.map { MemoryChart.when($0) } ?? "never"
        if !m.stale {
            if m.link?.state == "catching_up" { return "Catching up: fetching missed history…" }
            var s = "Logging every \(Int(m.current?.daemon?.interval ?? 30)) s"
            if let i = m.current?.daemon?.incident { s += " · incident \(i) open" }
            return s
        }
        if m.connecting { return "Last data " + last }
        let was = m.link?.state == "idle" ? m.link?.was : m.link?.state
        if was == "catching_up" { return "Fetching history…" }
        var s: String
        if m.blocked { return "Blocked by macOS · last data " + last }
        switch was {
        case "offline":
            s = "No answer since " + MemoryChart.when(m.link?.last_contact ?? m.knownUntil ?? 0)
            let left: Double = (m.link?.next_try ?? 0) - Date().timeIntervalSince1970
            if m.link?.state == "offline", store.engineRunning, left >= 0.5 { s += " · next try in \(Int(left.rounded())) s" }
        case "needs_attention":
            let why = ["identity_changed": "Its key changed", "revoked": "Access revoked", "ssh": "SSH can't sign in",
                       "incompatible": "Its version can't talk to this one"][m.link?.error ?? ""] ?? "Needs attention"
            s = why + " · last data " + last
        default: s = "Last data " + last
        }
        if let c = m.current, c.pressure != 1, let p = Pressure(rawValue: c.pressure) { s += " · pressure was " + p.label.lowercased() }
        return s
    }

    /// Whether the visible range holds a stretch this dashboard has not received: the legend
    /// then explains the dots (only then: it adds no row).
    var missingInView: Bool {
        guard !m.isLocal else { return false }
        let from = store.allHistory ? -Double.infinity : m.historyNow - store.range
        return m.gaps.contains { $0.kind != .noData && $0.to > from }
    }

    var statusLine: String {
        if !store.installed { return "Logging is off — click Activate" }
        if !m.daemonRunning { return "Daemon installed but not reporting" }
        let d = m.current?.daemon
        var s = "Logging every \(Int(d?.interval ?? 30)) s"
        if let i = d?.incident { s += " · incident \(i) open" }
        // a machine that listens says so where its owner looks (roadmap 01 §3.10)
        if store.machinesUI, let sh = store.share, sh.shared {
            let n = sh.clients?.count ?? 0
            s += n == 1 ? " · shared with 1 machine" : " · shared with \(n) machines"
        }
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
    /// The height contract for one machine (roadmap 01 §3.11): at most this many lines of
    /// reservations; with more, the last line is "+N more", which lists them all in a callout.
    static let reservationLines = 5

    func reservedList(_ live: [Reservation]) -> some View {
        // a machine that is not connected is shown as of the moment knowledge of it ends
        let now = m.isLocal ? Date().timeIntervalSince1970 : m.stale || m.inGrace ? (m.knownUntil ?? m.now) : m.now
        let day = m.reservations.filter { ($0.res.ended ?? now) >= now - 86400 }.count
        let capped = live.count > PopoverView.reservationLines
        let shown = capped ? Array(live.prefix(PopoverView.reservationLines - 1)) : live
        let reserved = live.filter { $0.granted != nil }.reduce(0) { $0 + $1.gb }
        var summary = live.isEmpty ? "\(day) in the last 24 h" : String(format: "%.1f GB reserved · %d in the last 24 h", reserved, day)
        if m.stale && !live.isEmpty { summary = "as of " + MemoryChart.when(now) + String(format: ": %.1f GB reserved", reserved) }
        return VStack(alignment: .leading, spacing: 3) {
            HStack(alignment: .firstTextBaseline) {
                Text("Reserved by agents").font(.caption).foregroundStyle(.secondary)
                Spacer()
                if !m.fetchingLedger {
                    Text(summary)
                        .font(.system(size: 10)).foregroundStyle(.tertiary)
                }
            }
            if m.fetchingLedger {
                Text("fetching…").font(.caption).foregroundStyle(.tertiary)
            } else if live.isEmpty {
                Text("Nothing reserved right now").font(.caption).foregroundStyle(.tertiary)
            }
            ForEach(shown) { (r: Reservation) in
                if m.stale { reservationRow(r, now: now).grayscale(1).opacity(0.6) } else { reservationRow(r, now: now) }
            }
            if capped { moreLine(Array(live.dropFirst(shown.count))) }
        }
    }

    func reservationRow(_ r: Reservation, now: Double) -> some View {
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

    /// The fifth line when there are more: "+3 more · 5.0 GB reserved · 1 waiting" (of the ones
    /// not listed); a click lists them all.
    func moreLine(_ rest: [Reservation]) -> some View {
        let gb = rest.filter { $0.granted != nil }.reduce(0) { $0 + $1.gb }
        let waiting = rest.filter { $0.granted == nil }.count
        var text = "+\(rest.count) more"
        if gb > 0 { text += String(format: " · %.1f GB reserved", gb) }
        if waiting > 0 { text += " · \(waiting) waiting" }
        return Button {
            NSApp.keyWindow?.makeFirstResponder(nil)
            withAnimation(.easeOut(duration: 0.15)) { showAllReservations.toggle(); showTopApps = false; showAI = false }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "ellipsis").font(.system(size: 8, weight: .bold)).foregroundStyle(.secondary)
                    .frame(width: 8, height: 8)
                Text(text).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
                Image(systemName: showAllReservations ? "chevron.down" : "chevron.up").font(.system(size: 7, weight: .bold))
                    .foregroundStyle(.secondary)
                Spacer(minLength: 4)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain).focusable(false).focusEffectDisabled()
        .help("Every reservation, in a list")
        .anchorPreference(key: MoreAnchorKey.self, value: .bounds) { $0 }
    }

    /// Every live reservation, above the "+N more" line.
    func allReservationsCallout(arrowX: CGFloat) -> some View {
        let live = m.liveReservations
        let now = m.isLocal ? Date().timeIntervalSince1970 : m.stale || m.inGrace ? (m.knownUntil ?? m.now) : m.now
        let reserved = live.filter { $0.granted != nil }.reduce(0) { $0 + $1.gb }
        let rows = renderMode ? Array(live.prefix(14)) : live
        return VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline) {
                    Text("Reserved by agents").font(.system(size: 13, weight: .semibold))
                    Spacer()
                    Text(String(format: "%d · %.1f GB reserved", live.count, reserved)).font(.system(size: 10)).foregroundStyle(.secondary)
                }
                .padding(.bottom, 3)
                if rows.count > 14 {
                    ScrollView { VStack(alignment: .leading, spacing: 3) { ForEach(rows) { reservationRow($0, now: now) } } }
                        .frame(maxHeight: 14 * 17)
                } else {
                    ForEach(rows) { reservationRow($0, now: now) }
                }
            }
            .padding(12)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
            CalloutArrow()
                .fill(.regularMaterial)
                .overlay(CalloutArrow().stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
                .frame(width: 16, height: 8)
                .offset(x: arrowX - 180)  // centre of a 360-wide bubble
        }
        .shadow(color: .black.opacity(0.22), radius: 12, y: 4)
    }

    func reservationTail(_ r: Reservation, now: Double) -> String {
        if m.stale { return r.granted == nil ? "was waiting" : String(format: "was using %.1fG", r.used ?? 0) }
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
        let gs = Array((m.current?.groups ?? []).prefix(12))
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
                if store.needsUpdate && m.isLocal {  // the logger is a different version than the one this app ships
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
                ChartLegend(missing: missingInView)
                Text("GB").font(.caption).foregroundStyle(.secondary)
                    .help("Memory in GB; the dashed line is the Mac's RAM. " + (store.allHistory
                          ? "∞: all history on a logarithmic time axis — the last hours wide, older days squeezed."
                          : "Time runs left to right up to now."))
            }
            ZStack {
                if !m.historyLoaded {
                    VStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Loading history…").font(.caption).foregroundStyle(.secondary)
                    }
                } else if m.history.isEmpty && m.isLocal {
                    Text("No samples yet").font(.caption).foregroundStyle(.secondary)
                } else {
                    MemoryChart(points: m.history, gaps: m.gaps, now: m.historyNow,
                                incidents: m.incidents, events: m.events, ram: m.current?.ram_gb,
                                lgRange: log10(store.allHistory ? 24 * 3600 : store.range),
                                blend: renderBlend ?? (store.allHistory ? 1 : 0),
                                reservations: m.reservations, stripHeight: stripHeight,
                                oldest: m.isLocal ? nil : m.info?.oldest)
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
        m.historyLoaded && (!m.history.isEmpty || !m.isLocal) && !m.reservations.isEmpty ? 46 : 0
    }

    var incidentsList: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Incidents").font(.caption).foregroundStyle(.secondary)
            if m.fetchingIncidents {
                Text("fetching…").font(.caption).foregroundStyle(.tertiary)
            } else if m.incidents.isEmpty {
                Text("None recorded").font(.caption).foregroundStyle(.tertiary)
            } else {
                ScrollView {
                    VStack(spacing: 2) {
                        ForEach(m.incidents) { inc in
                            // another machine's report is rendered there, not here (R2): no click yet
                            Button { if m.isLocal { store.open(inc) } } label: { row(inc) }
                                .buttonStyle(.plain)
                                .contextMenu {
                                    if m.isLocal { Button("Open report") { store.open(inc) } }
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
            Circle().fill(inc.open == true ? Color.red : (inc.id > m.lastSeenIncident ? Color.orange : Color.secondary.opacity(0.4)))
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

    /// The tour's steps; with the + (machinesUI) Machines is the fourth of five (roadmap 01 §3.12).
    var tourSteps: [String] {
        store.machinesUI ? ["Right now", "History", "Incidents", "Machines", "Actions"] : ["Right now", "History", "Incidents", "Actions"]
    }

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
        switch tourSteps[min(max(step, 0), tourSteps.count - 1)] {
        case "Right now":
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
        case "History":
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
        case "Incidents":
            let zone = union(["incidents"])
            return (zone, [
                TourNote(title: "Incidents",
                         text: "Each stretch of high memory pressure, with the apps macOS killed to free memory. Red: still open. Orange: new since you last looked. Click one for its report; right-click to copy its path or show it in Finder.",
                         left: m, width: W * 0.62, above: true,
                         xs: [zone.minX + 40], y: zone.minY - 7),
            ])
        case "Machines":
            // the line and nothing but the line: the strip with tabs; with one machine a band around the
            // hairline plus a disc around the + (tourLayer draws it as one shape)
            let line = r["machines"] ?? .zero, plus = r["plus"] ?? .zero
            let tabs = store.machines.count > 1
            let zone = tabs ? line : CGRect(x: line.minX, y: line.midY - 4, width: line.width, height: 8)
            let wide: CGFloat = min(W * 0.62, 300)
            let underPlus = TourNote(title: tabs ? "Connect or share" : "More machines",
                                     text: tabs ? "The + connects another machine or shares this one. Point at a tab for × to disconnect it; it stays in Recents under the +."
                                                : "The + connects another Mac, and each gets a tab on this line. The other side is here too: + › Share this Mac hands out a one-time pairing code.",
                                     left: W - m - wide, width: wide, above: false,
                                     xs: [plus.midX], y: (tabs ? line.maxY : plus.maxY + 4) + 3, reach: tabs ? 12 : 10)
            guard tabs else { return (zone, [underPlus]) }
            let half = (W - 2 * m - 8) / 2
            return (zone, [
                TourNote(title: "A tab per machine",
                         text: "The dot is that machine's memory pressure; a slashed circle means not connected, an orange triangle that it needs you. Everything under the line belongs to the selected tab.",
                         left: m, width: half, above: false,
                         xs: [line.minX + 130], y: line.maxY + 3, reach: 12),
                TourNote(title: underPlus.title, text: underPlus.text, left: m + half + 8, width: half, above: false,
                         xs: [plus.midX], y: line.maxY + 3, reach: 12),
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
        let machines = tourSteps[min(step, tourSteps.count - 1)] == "Machines"
        let hole = plan.zone.isNull ? CGRect(x: size.width / 2, y: size.height / 2, width: 0, height: 0)
                                    : machines ? plan.zone : plan.zone.insetBy(dx: -4, dy: -4)
        // with one machine the lit zone is the hairline's band plus a disc around the +
        let disc = machines && store.machines.count <= 1 ? rects["plus"].map { $0.insetBy(dx: -5, dy: -5) } : nil
        let spot = TourSpotlight(hole: hole, disc: disc)
        let header = rects["header"] ?? CGRect(x: 0, y: 0, width: size.width, height: 54)
        return ZStack(alignment: .topLeading) {
            // the dim catches clicks; the lit zone stays live (hover the chart, click an incident)
            spot.fill(Color.black.opacity(0.42), style: FillStyle(eoFill: true))
                .contentShape(spot, eoFill: true)
                .onTapGesture {}
            TourSpotlight(hole: hole, disc: disc, frameOnly: true).stroke(Color.white.opacity(0.55), lineWidth: 1)
                .allowsHitTesting(false)
            ZStack(alignment: .topLeading) {
                ForEach(Array(plan.notes.enumerated()), id: \.offset) { _, n in tourBubble(n, size: size) }
            }
            .id(step)
            .transition(.opacity)
            if store.machinesUI {
                // the + sits where the bar floated: the bar has its own strip under the footer (§3.12)
                tourBar(step)
                    .padding(.bottom, 5)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottom)
            } else {
                tourBar(step)
                    .padding(.top, header.maxY - 13)
                    .padding(.trailing, 12)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topTrailing)
            }
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
        let last = tourSteps.count - 1
        return HStack(spacing: 2) {
            Button { goTour(step - 1) } label: {
                Image(systemName: "chevron.left").frame(width: 24, height: 22).contentShape(Rectangle())
            }
            .disabled(step == 0).keyboardShortcut(.leftArrow, modifiers: []).help("Previous")
            VStack(spacing: 0) {
                Text(tourSteps[min(step, last)]).font(.system(size: 11, weight: .semibold))
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
        case .check where store.optionHeld, .upToDate where store.optionHeld:
            forcedUpgradeButton(cur)
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

    /// ⌥ held over Check or "Up to date": rebuild and reinstall GitHub's main even if it isn't newer.
    func forcedUpgradeButton(_ cur: String) -> some View {
        Button("Upgrade") { store.openUpgrade(force: true) }
            .buttonStyle(.borderedProminent).focusable(false)
            .help("Rebuild and reinstall the newest \(brand) from GitHub's main, even if it is \(cur) already")
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
                     : newCount == 0 && store.forceUpgrade ? "Nothing newer than yours. Upgrade Now rebuilds GitHub's main and installs it again."
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
                    if newCount > 0 {
                        Button("Skip This Version") { store.skipThisVersion() }
                            .help("Don't offer this version again when \(brand) checks by itself (Check still finds it)")
                    }
                    Button("Upgrade Now") { store.upgradeNow() }
                        .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
                        .disabled(store.loadingChangelog || (newCount == 0 && !store.forceUpgrade))
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

    /// A commit body as the popup should wrap it: git's hard line breaks inside a paragraph or a list
    /// item are joined (else each wrapped line breaks again in the narrow sheet, a comb); blank lines
    /// and the start of a list item ("- ", "* ", "1. ") keep their line break.
    static func unwrap(_ body: String) -> String {
        var out: [String] = []
        for raw in body.components(separatedBy: "\n") {
            let line: String = raw.trimmingCharacters(in: .whitespaces)
            let item: Bool = line.hasPrefix("- ") || line.hasPrefix("* ") || line.hasPrefix("• ")
                || (line.first?.isNumber == true && line.contains(". ") && line.prefix(4).contains("."))
            if line.isEmpty {
                if out.last != "" { out.append("") }
            } else if item || out.isEmpty || out.last == "" || Self.isHeading(out[out.count - 1]) {
                let indent: String = String(raw.prefix(while: { $0 == " " }))
                out.append((item ? indent : "") + line)
            } else {
                out[out.count - 1] += " " + line
            }
        }
        while out.last == "" { out.removeLast() }
        return out.joined(separator: "\n")
    }

    /// A line that stands alone: all bold ("**Per file**"), or short and ending in a colon ("Per file:";
    /// a long one is a sentence that git wrapped after its colon).
    static func isHeading(_ line: String) -> Bool {
        let t: String = line.trimmingCharacters(in: .whitespaces)
        return (t.hasPrefix("**") && t.hasSuffix("**") && t.count > 4) || (t.hasSuffix(":") && t.count <= 40)
    }

    func changelogEntry(_ e: ChangelogEntry) -> some View {
        let day = Self.isoIn.date(from: e.date).map { Self.dayOut.string(from: $0) } ?? String(e.date.prefix(10))
        let text: String = Self.unwrap(e.body)
        let body = (try? AttributedString(markdown: text, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)))
            ?? AttributedString(text)
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
        // never from the keychain (reading it asks for access): pasted on each connect
        draftToken = ""
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
                    // connected: dots in place of the key, which is not read just to fill the field
                    SecureField("Paste access token", text: connected ? .constant(String(repeating: "•", count: 24)) : $draftToken)
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
            Text("Reports include an analysis by \(store.aiSummary). Disconnect to switch provider or key.")
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
                .help(connected ? "Stop adding an AI analysis to reports, and forget the key. A key an earlier version of "
                      + "\(brand) saved can stay in your keychain (“\(Keychain.service)” in Keychain Access) until you delete it there."
                      : "Not connected")
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
            if !m.isLocal {
                // another machine's pane: read-only, its own version and system, nothing of this Mac's
                Text(["Read-only", m.info?.version.map { brand + " " + $0 }, m.info?.os_version].compactMap { $0 }.joined(separator: " · "))
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
                    .tourAnchor("actions")
                upgradeButtonView
            } else {
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
            }
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

/// One tab of the strip (roadmap 01 §3.2): the link's state as a glyph whose colour is the
/// machine's pressure, its name, and a 16 pt slot at the end that holds its badge (a red ! for an
/// open incident, an orange ring for an unseen one) or, under the pointer, the × that stops
/// watching it. This Mac has no ×. A tab at critical pressure that is not selected is tinted red.
struct MachineTab: View {
    @ObservedObject var store: Store
    let index: Int
    @State private var hover = false

    var body: some View {
        let m = store.machines[index]
        let sel = index == store.selected
        let alarm = m.critical && !sel
        return HStack(spacing: 6) {
            glyph(m)
            Text(m.title)
                .font(.system(size: 11.5, weight: sel ? .semibold : .regular))
                .italic(!m.isLocal && m.stale)
                .lineLimit(1).truncationMode(m.entry?.label == nil ? .middle : .tail)
                .foregroundStyle(alarm ? Color.red : sel ? Color.primary : Color.secondary)
                .frame(width: nameWidth(m.title, sel), alignment: .leading)
            if alarm && store.machines.count <= 4 { Text("critical").font(.system(size: 10)).foregroundStyle(.red) }
            if !m.isLocal || (!sel && (m.incidentOpen || m.hasUnseen)) {
                ZStack {
                    if hover && !m.isLocal {
                        Button { store.unpin(index) } label: {
                            Image(systemName: "xmark").font(.system(size: 8, weight: .bold)).foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                        .help("Disconnect \(m.title) · it stays in Recents under +")
                    } else if !sel && m.incidentOpen {
                        Text("!").font(.system(size: 11, weight: .heavy)).foregroundStyle(.red)
                    } else if !sel && m.hasUnseen {
                        Circle().stroke(Color.orange, lineWidth: 1.5).frame(width: 7, height: 7)
                    }
                }
                .frame(width: 16, height: 16)
            }
        }
        .padding(.leading, 9).padding(.trailing, m.isLocal && !(!sel && (m.incidentOpen || m.hasUnseen)) ? 11 : 3)
        .frame(height: 24)
        .background(alarm ? Color.red.opacity(0.12) : sel ? Color(nsColor: .windowBackgroundColor) : Color.clear,
                    in: UnevenRoundedRectangle(topLeadingRadius: 7, topTrailingRadius: 7, style: .continuous))
        .contentShape(Rectangle())
        .onTapGesture { store.select(index) }
        .onHover { hover = $0 }
        .help(tooltip(m))
        .contextMenu {
            if m.isLocal {
                Button("Share this Mac…") { store.openConnect(share: true) }
            }
            if !m.isLocal {
                Button("Rename…") { store.rename(index) }
                Button("Reconnect") { store.reconnect(index) }
                Button("Copy address") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(m.entry?.address ?? m.mid, forType: .string)
                }
                if m.blocked { Button("Open Local Network settings") { Store.openLocalNetworkSettings() } }
                Divider()
                Button("Disconnect") { store.unpin(index) }
                Button("Forget…") { store.confirmForget(index) }
            }
        }
    }

    /// A filled dot: live, coloured by pressure (grey while that machine's logger is silent); a
    /// dotted circle while connecting; a slashed circle when not connected; an orange triangle
    /// when waiting will not help (its key changed, access revoked, ssh can't sign in, too old).
    @ViewBuilder func glyph(_ m: MachineStore) -> some View {
        let state = m.link?.state == "idle" ? m.link?.was : m.link?.state
        if !m.isLocal && (state == "needs_attention") {
            Image(systemName: "exclamationmark.triangle.fill").font(.system(size: 9)).foregroundStyle(.orange)
        } else if m.blocked {
            Image(systemName: "hand.raised.fill").font(.system(size: 9)).foregroundStyle(.orange)
        } else if !m.isLocal && (m.connecting || m.stale && (state == "connecting" || state == "catching_up") && m.link?.state != "idle") {
            Image(systemName: "circle.dotted").font(.system(size: 9)).foregroundStyle(.secondary)
        } else if !m.isLocal && m.stale {
            Image(systemName: "circle.slash").font(.system(size: 10)).foregroundStyle(.secondary)
        } else {
            let p = Pressure(rawValue: m.current?.pressure ?? 0) ?? .unknown
            let reporting = m.isLocal ? m.daemonRunning : m.inGrace || (m.current.map { m.now - $0.t < 3 * ($0.daemon?.interval ?? 30) + 15 } ?? false)
            Circle().fill(reporting ? p.color : Color.gray).frame(width: 7, height: 7).opacity(m.inGrace ? 0.6 : 1)
        }
    }

    /// The name's width: as wide as it is, at most 112 pt (142 when selected; roadmap 01 §3.2 caps a
    /// tab at 150 and 180 pt); a longer one is cut in the middle (a host name) or at the end (a label).
    func nameWidth(_ s: String, _ sel: Bool) -> CGFloat {
        let font = NSFont.systemFont(ofSize: 11.5, weight: sel ? .semibold : .regular)
        let w: CGFloat = ceil((s as NSString).size(withAttributes: [.font: font]).width) + 1
        return min(w, sel ? 142 : 112)
    }

    func tooltip(_ m: MachineStore) -> String {
        if m.isLocal { return "This Mac" }
        var parts = [m.title]
        if let e = m.entry { parts.append(e.address + (e.transport == "ssh" ? " (ssh)" : "")) }
        if let v = m.info?.os_version { parts.append((m.info?.os == "linux" ? "Linux " : "macOS ") + v) }
        if let v = m.info?.version { parts.append(brand + " " + v) }
        parts.append(m.allowsAI ? "AI analysis allowed there" : "AI analysis not allowed there")
        if m.linkLive { parts.append("connected") } else if let t = m.link?.last_contact {
            parts.append("last contact " + MemoryChart.when(t))
        }
        if m.blocked {
            parts.append("Blocked by macOS: allow \(brand) in System Settings › Privacy & Security › Local Network")
        } else if !m.linkLive, let d = m.link?.detail, !d.isEmpty {
            parts.append(d)
        }
        return parts.joined(separator: " · ")
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

struct MoreAnchorKey: PreferenceKey {
    static var defaultValue: Anchor<CGRect>? = nil
    static func reduce(value: inout Anchor<CGRect>?, nextValue: () -> Anchor<CGRect>?) { value = value ?? nextValue() }
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
    /// A disc joined to the hole (the + on the hairline, roadmap 01 §3.12): one outline, no seam.
    var disc: CGRect? = nil
    var frameOnly = false
    var animatableData: AnimatablePair<AnimatablePair<CGFloat, CGFloat>, AnimatablePair<CGFloat, CGFloat>> {
        get { .init(.init(hole.minX, hole.minY), .init(hole.width, hole.height)) }
        set { hole = CGRect(x: newValue.first.first, y: newValue.first.second, width: newValue.second.first, height: newValue.second.second) }
    }
    func path(in r: CGRect) -> Path {
        var p = Path()
        if !frameOnly { p.addRect(r.insetBy(dx: -2, dy: -2)) }
        guard let d = disc, d.width > 0, d.minY < hole.minY, d.maxY > hole.maxY else {
            p.addRoundedRect(in: hole, cornerSize: CGSize(width: 8, height: 8), style: .continuous)
            return p
        }
        // the band, interrupted by the disc's arcs above and below it
        let rad: CGFloat = d.width / 2, c = CGPoint(x: d.midX, y: d.midY)
        let up: CGFloat = c.y - hole.minY, down: CGFloat = hole.maxY - c.y
        let a1: CGFloat = asin(min(1, up / rad)), a2: CGFloat = asin(min(1, down / rad))
        p.move(to: CGPoint(x: hole.minX, y: hole.minY))
        p.addLine(to: CGPoint(x: c.x - rad * cos(a1), y: hole.minY))
        p.addArc(center: c, radius: rad, startAngle: .radians(Double.pi + Double(a1)), endAngle: .radians(-Double(a1)), clockwise: false)
        p.addLine(to: CGPoint(x: hole.maxX, y: hole.minY))
        p.addLine(to: CGPoint(x: hole.maxX, y: hole.maxY))
        p.addLine(to: CGPoint(x: c.x + rad * cos(a2), y: hole.maxY))
        p.addArc(center: c, radius: rad, startAngle: .radians(Double(a2)), endAngle: .radians(Double.pi - Double(a2)), clockwise: false)
        p.addLine(to: CGPoint(x: hole.minX, y: hole.maxY))
        p.closeSubpath()
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

// MARK: - Connecting and sharing (roadmap 01 §3.7–§3.10, R1b; behind machinesUI)

/// What the popover's field holds, and the words it says (roadmap 01 §3.7). Pure, so that
/// tools/vectors/connect.json can hold it to the CLI's reading of the same text
/// (oomph_sync.parse_link, parse_target, oomph_net.norm_code) and to fixed words.
enum ConnectInput {
    static let alphabet = Set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    /// The pairing link's scheme (an identifier, like the command).
    static let scheme = "oomph://"

    static func groups(_ pattern: String, _ s: String) -> [String]? {
        guard let re = try? NSRegularExpression(pattern: pattern),
              let m = re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) else { return nil }
        return (0..<m.numberOfRanges).map { i in Range(m.range(at: i), in: s).map { String(s[$0]) } ?? "" }
    }

    /// A code as someone typed it (any case, dashes and spaces, O for 0, I or L for 1): its 12 characters.
    static func normCode(_ s: String) -> String? {
        guard s.count <= 64 else { return nil }
        let c = String(s.uppercased().filter { $0 != "-" && !$0.isWhitespace }
            .map { $0 == "O" ? "0" : $0 == "I" || $0 == "L" ? "1" : $0 })
        return c.count == 12 && c.allSatisfy({ alphabet.contains($0) }) ? c : nil
    }

    static func showCode(_ c: String) -> String {
        let a = Array(c)
        return a.count == 12 ? String(a[0..<4]) + "-" + String(a[4..<8]) + "-" + String(a[8..<12]) : c
    }

    /// HOST[:PORT] or [IPv6]:PORT as a shared Mac's address (no user, no options): the CLI checks it again.
    static func tcpTarget(_ s: String) -> Bool {
        func port(_ p: String) -> Bool { p.isEmpty || (Int(p).map { $0 > 0 && $0 < 65536 } ?? false) && p.count <= 5 }
        func v6(_ a: String) -> Bool {
            let parts = a.split(separator: "%", maxSplits: 1).map(String.init)
            guard let addr = parts.first, addr.count <= 45 else { return false }
            if parts.count == 2, groups(#"^[A-Za-z0-9._-]{1,16}$"#, parts[1]) == nil { return false }
            var buf = in6_addr()
            return inet_pton(AF_INET6, addr, &buf) == 1
        }
        if let g = groups(#"^\[([^\]]+)\](?::(\d{1,5}))?$"#, s) { return v6(g[1]) && port(g[2]) }
        if s.filter({ $0 == ":" }).count >= 2 { return v6(s) }
        let hp = s.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
        guard groups(#"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$"#, hp[0]) != nil, !hp[0].hasSuffix("..") else { return false }
        return hp.count == 1 || port(hp[1])  // "studio:" is the default port, as the CLI reads it
    }

    /// A pairing link, `oomph://K7QF-2M9X-D4TR@studio.local:6674`: (the target HOST[:PORT], the code's
    /// 12 characters), or nil. A link only fills the popover in: Pair still has to be clicked.
    static func link(_ raw: String) -> (target: String, code: String)? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard s.hasPrefix(scheme), let g = groups(#"^([A-Za-z0-9 -]{12,24})@([^/@\s]{1,300})/?$"#, String(s.dropFirst(scheme.count))),
              let code = normCode(g[1]), tcpTarget(g[2]) else { return nil }
        return (g[2], code)
    }

    /// Which way the text goes: "link", "ssh" (user@host, ssh://…), "tcp" (a shared Mac), "" (nothing).
    static func kind(_ raw: String) -> String {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { return "" }
        if s.hasPrefix(scheme) { return "link" }
        return s.hasPrefix("ssh://") || s.contains("@") ? "ssh" : "tcp"
    }

    /// (user, host, port) of an ssh target; the user is this account's when none is given.
    static func sshParts(_ raw: String) -> (user: String, host: String, port: String) {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix("ssh://") { s = String(s.dropFirst(6)); while s.hasSuffix("/") { s.removeLast() } }
        var user = NSUserName()
        if let at = s.lastIndex(of: "@") { user = String(s[..<at]); s = String(s[s.index(after: at)...]) }
        if let g = groups(#"^\[([^\]]+)\](?::(\d{1,5}))?$"#, s) { return (user, g[1], g[2]) }
        if s.filter({ $0 == ":" }).count == 1, let c = s.firstIndex(of: ":") {
            return (user, String(s[..<c]), String(s[s.index(after: c)...]))
        }
        return (user, s, "")
    }

    /// The command the SSH step shows before Connect (roadmap 01 §8: the consent is seeing it).
    static func sshCommand(_ target: String) -> String {
        let p = sshParts(target)
        return "ssh -l \(p.user)" + (p.port.isEmpty ? "" : " -p \(p.port)") + " -- \(p.host) oomph serve --stdio"
    }

    /// The host as the popover names it: no user, port or brackets.
    static func host(_ target: String) -> String {
        if kind(target) == "ssh" { return sshParts(target).host }
        if let g = groups(#"^\[([^\]]+)\](?::\d{1,5})?$"#, target) { return g[1] }
        if target.filter({ $0 == ":" }).count == 1, let c = target.firstIndex(of: ":") { return String(target[..<c]) }
        return target
    }

    /// The port named in a shared Mac's target, 6674 without one.
    static func port(_ target: String) -> Int {
        if let g = groups(#"^\[[^\]]+\]:(\d{1,5})$"#, target) { return Int(g[1]) ?? 6674 }
        if target.filter({ $0 == ":" }).count == 1, let c = target.firstIndex(of: ":") {
            return Int(target[target.index(after: c)...]) ?? 6674
        }
        return 6674
    }

    /// When a machine was last connected, as a row says it: "just now", "12 min ago", "3 h ago", "2 days ago".
    static func ago(_ t: Double, now: Double) -> String {
        let s: Double = max(0, now - t)
        if s < 120 { return "just now" }
        if s < 3600 { return "\(Int(s / 60)) min ago" }
        if s < 86400 { return "\(Int(s / 3600)) h ago" }
        let d = Int(s / 86400)
        return d == 1 ? "yesterday" : "\(d) days ago"
    }

    /// A machine's short name: a host name without .local, an address as it is.
    static func shortName(_ host: String) -> String {
        host.hasSuffix(".local") ? String(host.dropLast(6)) : host
    }

    /// Completion (roadmap 01 §3.7): the known machines whose name, host name or any remembered
    /// address starts with the text (ignoring case), each with what matched, in the order given.
    static func matches(_ raw: String, _ known: [(mid: String, names: [String])]) -> [(mid: String, matched: String)] {
        let t = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !t.isEmpty else { return [] }
        return known.compactMap { k in
            k.names.first { $0.lowercased().hasPrefix(t) }.map { (k.mid, $0) }
        }
    }

    /// The popover's words for what `oomph remote add --json` answered (roadmap 01 §3.7's table). No
    /// message names a release: too old or too new is what the two ends negotiated.
    static func message(_ code: String, target: String, detail: String = "", side: String? = nil) -> String {
        let h = host(target), n = shortName(h)
        switch code {
        case "refused":
            return "\(h) answered, but sharing is off there. On \(n): + › Share this Mac, or `sudo oomph share on`. This step is kept while you do that."
        case "turned_away":
            return "\(h) closed the connection right away. Sharing there is limited to the networks it was turned on for: if \(n) moved, run `sudo oomph share on` there. (It also does this when too many machines knock at once.)"
        case "local_network_denied":
            return "macOS is not letting \(brand) reach your local network. Turn \(brand) on in System Settings › Privacy & Security › Local Network, then try again."
        case "timeout":
            return "No answer from \(h). Is it awake and on this network?"
        case "dns":
            return "Can't find “\(h)”."
        case "not_oomph":
            if kind(target) == "ssh" {
                return detail.contains("not installed") ? "\(brand) is not installed on \(h). Install it there, then try again."
                    : "The \(brand) on \(h) is too old for remote access. Update it there."
            }
            return "Something answers on port \(port(target)) there, but it isn't oomph."
        case "pair_failed":
            return "That code wasn't accepted. Codes work once, for 10 minutes, and five wrong tries void them. Get a new one there."
        case "incompatible":
            return side == "old" ? "\(n)'s \(brand) is too old for remote access. Update it there."
                : side == "new" ? "\(n)'s \(brand) is newer than this app understands. Upgrade \(brand) on this Mac."
                : "\(n)'s \(brand) and this app can't talk to each other. Update the older one."
        case "too_many":
            return "Twelve machines are connected. Disconnect one to add another."
        case "busy":
            return "\(n) has as many viewers as it serves at once. Try again in a minute."
        case "ssh":
            return "ssh could not sign in to \(h) without asking for something, and \(brand) never types a password. Try it in a terminal: ssh \(target)"
        case "identity_changed":
            return "\(h) answered with another key than the one shown: nothing was sent. Try again, and compare the key with `oomph share status` there."
        case "revoked":
            return "\(n) no longer knows this Mac: its access was revoked, or sharing was reset there. Pair again with a new code."
        case "bad_address":
            return "That isn't an address. Type a host name, host:port or user@host, or paste a pairing link."
        case "ask":
            return "Nothing was added. The pairing made just now was given back there and its code is used up: get a new one there to try again."
        default:
            return detail.isEmpty ? "Connecting to \(h) failed." : detail
        }
    }
}

/// The connect popover's state (roadmap 01 §3.8 rule 2): in the app's memory only, never on disk,
/// kept for 15 minutes after the last edit; Cancel, success and time discard it.
final class ConnectDraft: ObservableObject {
    enum Step: String { case start, connecting, code, ssh, ask, paired, share }
    @Published var step: Step = .start { didSet { touch() } }
    @Published var text = "" { didSet { touch() } }
    @Published var code = "" { didSet { touch() } }
    /// What Connect and Pair run: HOST[:PORT], USER@HOST or ssh://…
    @Published var target = ""
    /// The step an error goes back to.
    var from: Step = .start
    /// The key the code step showed (sha256:…): Pair binds the pairing to it (`--fp`).
    @Published var fp: String?
    @Published var fpShort = ""
    @Published var error: String?
    @Published var errorCode: String?
    /// macOS denies the local network (the app's own probe): the error offers the settings.
    @Published var blocked = false
    /// The pairing there was revoked, or sharing reset: a new code is needed.
    @Published var revoked = false
    @Published var askMid = ""
    @Published var askLabel = ""
    @Published var pairedMid = ""
    @Published var pairedName = ""
    @Published var pairedAbout = ""
    /// Added, but not a Mac (Linux over ssh): no tab until 1.13, the terminal watches it.
    @Published var pairedOther = false
    @Published var tabName = "" { didSet { touch() } }
    @Published var started: Date?
    /// A Recents row asking "Forget …?".
    @Published var forgetting: String?
    var edited = Date.distantPast

    func touch() { edited = Date() }
    var alive: Bool { Date().timeIntervalSince(edited) < 15 * 60 }
    var host: String { ConnectInput.host(target) }

    func reset() {
        step = .start; text = ""; code = ""; target = ""; from = .start; fp = nil; fpShort = ""
        error = nil; errorCode = nil; blocked = false; revoked = false; askMid = ""; askLabel = ""
        pairedMid = ""; pairedName = ""; pairedAbout = ""; pairedOther = false; tabName = ""; started = nil; forgetting = nil
        edited = .distantPast
    }
}

/// `oomph share status --json`, read as this user (public files; roadmap 01 §5.9).
struct ShareStatus: Decodable {
    struct Net: Decodable {
        var iface: String?
        var net: String?
        var router: String?
        enum CodingKeys: String, CodingKey { case iface = "if", net, router }
    }
    struct Client: Decodable, Identifiable {
        var id: String
        var name: String?
        var paired: Double?
        var last_seen: Double?
        var last_addr: String?
    }
    struct Reading: Decodable { var client: String; var peer: String?; var since: Double? }
    struct Pairing: Decodable { var active: Bool?; var expires: Double?; var left: Int? }
    var on: Bool
    var port: Int?
    var networks: [Net]?
    var any_network: Bool?
    var clients: [Client]?
    var reading: [Reading]?
    var pairing: Pairing?
    var fp: String?
    var host: String?
    var service: Bool?
    var more: Int?
    var shared: Bool { on && service != false }
}

/// A pairing code made in this session (§3.8 rule 6): shown until it is spent or expires.
struct ShareCode {
    var code: String
    var link: String
    var expires: Double
    /// The viewers paired before it was made, and when it was made: a viewer paired since used it.
    var before: Set<String>
    var made: Double = Date().timeIntervalSince1970
}

/// What the app asks root to do for sharing: a closed set, run by the installed, root-owned CLI
/// (roadmap 01 §4.4); an id only after it matched its pattern, and then quoted.
enum ShareAction {
    case on, off, pair, revoke(String, String)
    var args: [String]? {
        switch self {
        case .on: return ["share", "on", "--pair", "--json"]
        case .off: return ["share", "off"]
        case .pair: return ["share", "pair", "--json"]
        case .revoke(let id, _):
            return id.range(of: #"^c-[0-9a-f]{8}$"#, options: .regularExpression) != nil ? ["share", "revoke", id] : nil
        }
    }
    var prompt: String {
        switch self {
        case .on: return "\(brand) needs administrator rights to share this Mac with other machines and make a pairing code."
        case .off: return "\(brand) needs administrator rights to stop sharing this Mac."
        case .pair: return "\(brand) needs administrator rights to make a pairing code for another machine."
        case .revoke(_, let name):
            // the name goes into AppleScript's source: letters, digits and . _ - only
            let safe = String(name.filter { $0.isASCII && ($0.isLetter || $0.isNumber || "._- ".contains($0)) }.prefix(40))
            return "\(brand) needs administrator rights to end the access of \(safe.isEmpty ? "a viewer" : safe) to this Mac."
        }
    }
}

extension Store {
    /// The share switch and its codes run the installed CLI as root: never the bundle's copy.
    static let installedCLI = "/usr/local/libexec/oomph/oomph.py"

    /// The + (and ⌘N): the popover, at the step the draft is at. `share` opens Share this Mac.
    func openConnect(share: Bool = false) {
        guard machinesUI else { return }
        if !draft.alive { endAdd(); draft.reset() }
        known = MachineEntry.loadAll(machinesDir)
        if share || draft.step == .share { showShare() }
        connectShown = true
    }

    /// Share this Mac: a code that is still good is shown again, and waited for again (§3.8 rule 6).
    func showShare() {
        draft.step = .share
        if shareCodeValid, !renderMode { shareWaiting = true }
        refreshShare { [weak self] in self?.pollShare() }
    }

    /// The code this app made is still good (not used, not expired).
    var shareCodeValid: Bool { shareCode.map { Date().timeIntervalSince1970 < $0.expires } ?? false }

    func toggleConnect() {
        if connectShown { connectShown = false } else { openConnect() }
    }

    /// Cancel, Esc, success: the draft goes (and a connection still under way is ended).
    func closeConnect(discard: Bool) {
        if discard {
            endAdd()
            shareWaiting = false
            draft.reset()
        }
        connectShown = false
    }

    /// A `remote add` still under way is ended and let go of at once, so a retry starts straight
    /// away (its late end is not read). At the question the pairing is made already: "no" gives it
    /// back there; anywhere else the attempt stops.
    func endAdd() {
        guard let p = addProcess else { return }
        if draft.step == .ask { try? addIn?.write(contentsOf: Data("\n".utf8)) } else { p.terminate() }
        try? addIn?.close()
        addProcess = nil; addIn = nil; addBuf = Data(); addResult = nil; addOpen = 0
    }

    /// A `remote add` lives no longer than its draft (§3.8 rule 4): one still waiting (at the
    /// question, the popup closed and nobody back) when the draft expires is ended.
    private func expireAdd(_ id: ObjectIdentifier) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 60) { [weak self] in
            guard let self, self.addProcess.map(ObjectIdentifier.init) == id else { return }
            if self.draft.alive { self.expireAdd(id); return }
            self.endAdd()
            self.draft.reset()
            self.connectShown = false
        }
    }

    /// The machines of machines.json the field can complete to: their names and addresses.
    var completions: [(mid: String, names: [String])] {
        known.map { e in (e.mid, [e.label, e.name, e.host].compactMap { $0 } + (e.addrs ?? [])) }
    }

    /// ↵, "Connect to … as typed", a link pasted: what the text names. A machine this Mac knows by that
    /// name or address is its tab, or comes back from Recents; a link and an address are reached
    /// (nothing is paired yet); user@host shows the SSH step first.
    func connectTyped() {
        let t = draft.text.trimmingCharacters(in: .whitespacesAndNewlines)
        draft.error = nil; draft.errorCode = nil; draft.blocked = false
        guard !t.isEmpty else { return }
        if let e = known.first(where: { e in
            [e.label, e.name, e.host].compactMap { $0?.lowercased() }.contains(t.lowercased()) || (e.addrs ?? []).contains(t)
        }) {
            useKnown(e)
            return
        }
        switch ConnectInput.kind(t) {
        case "link":
            // a link only fills in the code step: nothing is sent until Pair (01 §3.7, §7.3), whose
            // proof over the key presented keeps a machine in between out
            guard let l = ConnectInput.link(t) else { fail("bad_address"); return }
            draft.target = l.target
            draft.code = ConnectInput.showCode(l.code)
            draft.fp = nil; draft.fpShort = ""; draft.revoked = false
            draft.from = .start
            draft.step = .code
        case "ssh":
            draft.target = t
            draft.step = .ssh
        default:
            guard ConnectInput.tcpTarget(t) else { fail("bad_address"); return }
            draft.target = t
            draft.code = ""
            runAdd(code: nil)
        }
    }

    private func fail(_ code: String, detail: String = "", side: String? = nil) {
        draft.errorCode = code
        draft.error = ConnectInput.message(code, target: draft.target.isEmpty ? draft.text : draft.target, detail: detail, side: side)
    }

    /// A remembered machine always becomes a tab, reachable or not (§3.7); a tab is just selected.
    func useKnown(_ e: MachineEntry) {
        if e.pinned == true, let i = machines.firstIndex(where: { $0.mid == e.mid }) {
            select(i)
        } else {
            pendingSelect = e.mid
            engineCommand(["cmd": "pin", "id": e.mid])
        }
        closeConnect(discard: true)
    }

    /// Forget (the trash of a Recents row, after its question): mirror, key and token go, and the
    /// machine is told to drop this viewer when it can be reached.
    func forget(_ mid: String) {
        engineCommand(["cmd": "forget", "id": mid])
        known.removeAll { $0.mid == mid }
        draft.forgetting = nil
    }

    /// `oomph remote add TARGET --json --no-mirror --ask`, the bundled CLI as this user: reaches the
    /// machine, and pairs with the code (on stdin, never in an argument other users could read) bound
    /// to the key the code step showed. The tab fills live afterwards (no first sync here). The
    /// identity question comes as a line and is answered on stdin.
    func runAdd(code: String?) {
        guard addProcess == nil else { return }
        draft.from = draft.step == .connecting ? draft.from : (draft.step == .ask ? .code : draft.step)
        var args = ["-I", "-B", cliPath, "remote", "add", draft.target, "--json", "--no-mirror", "--ask"]
        if code != nil { args += ["--code", "-"] }
        if code != nil, let fp = draft.fp { args += ["--fp", fp] }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = args
        let inp = Pipe(), out = Pipe()
        p.standardInput = inp
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        addBuf = Data()
        addResult = nil
        addOpen = 2  // its output and the process: the answer is read when both have ended
        let id = ObjectIdentifier(p)  // a run let go of (Cancel, a retry) is no longer listened to
        out.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            if d.isEmpty { h.readabilityHandler = nil; DispatchQueue.main.async { self?.addEnded(id) }; return }
            DispatchQueue.main.async { self?.addData(d, id) }
        }
        p.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async { self?.addEnded(id) }
        }
        draft.error = nil; draft.errorCode = nil; draft.blocked = false
        draft.step = .connecting
        draft.started = Date()
        do { try p.run() } catch { draft.step = draft.from; fail("", detail: "can't start the `oomph` command"); return }
        addProcess = p
        addIn = inp.fileHandleForWriting
        if let c = code { try? addIn?.write(contentsOf: Data((c + "\n").utf8)) }
        expireAdd(id)
    }

    /// The identity question answered: "new", "replace:MID", or "" (cancel).
    func answerAsk(_ a: String) {
        if a.isEmpty { closeConnect(discard: true); return }
        try? addIn?.write(contentsOf: Data((a + "\n").utf8))
        draft.step = .connecting
    }

    private func addData(_ d: Data, _ id: ObjectIdentifier) {
        guard addProcess.map(ObjectIdentifier.init) == id else { return }
        addBuf.append(d)
        if addBuf.count > 1 << 20 { addBuf.removeAll() }
        while let i = addBuf.firstIndex(of: 0x0A) {
            let line = addBuf.subdata(in: addBuf.startIndex..<i)
            addBuf.removeSubrange(addBuf.startIndex...i)
            guard let o = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else { continue }
            if o["ev"] as? String == "ask", let k = o["known"] as? [String: Any], let mid = k["mid"] as? String {
                draft.askMid = mid
                draft.askLabel = (k["label"] as? String) ?? mid
                draft.step = .ask
            } else {
                addResult = o
            }
        }
    }

    private func addEnded(_ id: ObjectIdentifier) {
        guard addProcess.map(ObjectIdentifier.init) == id else { return }
        addOpen -= 1
        guard addOpen <= 0 else { return }
        addProcess = nil
        try? addIn?.close()
        addIn = nil
        let o = addResult ?? [:]
        addResult = nil
        guard draft.step == .connecting else { return }
        if o["ok"] as? Bool == true, let m = o["machine"] as? [String: Any], let mid = m["mid"] as? String {
            // a machine that is not a Mac (Linux over ssh) is watched from the terminal until 1.13: no tab yet
            let other = (m["os"] as? String).map { $0 != "macos" } ?? false
            if !other { machineAdded(mid) }
            if o["new"] as? Bool == true || other {
                let name = (m["name"] as? String) ?? draft.host
                draft.pairedOther = other
                draft.pairedMid = mid
                draft.pairedName = name
                var about: [String] = []
                if let v = m["os_version"] as? String { about.append(v) }
                if let r = (m["ram_gb"] as? NSNumber)?.doubleValue { about.append(String(format: "%.0f GB", r)) }
                if let v = m["version"] as? String { about.append(brand + " " + v) }
                draft.pairedAbout = about.joined(separator: " · ")
                draft.tabName = ConnectInput.shortName(name)
                draft.step = .paired
            } else {
                closeConnect(discard: true)
            }
            return
        }
        let code = (o["error"] as? String) ?? "", detail = (o["detail"] as? String) ?? ""
        switch code {
        case "needs_code":
            draft.fp = o["fp"] as? String
            draft.fpShort = (o["fp_short"] as? String) ?? ""
            draft.revoked = o["revoked"] as? Bool == true
            draft.step = .code
        case "revoked":
            draft.fp = o["fp"] as? String
            draft.fpShort = (o["fp_short"] as? String) ?? ""
            draft.revoked = true
            draft.step = .code
        case "identity_changed" where draft.from == .code && o["fp"] is String:
            // Pair met another key than the one shown: the key it presented now is shown, and the
            // next Pair binds to that one (not again to the stale one)
            draft.fp = o["fp"] as? String
            draft.fpShort = (o["fp_short"] as? String) ?? ""
            draft.step = .code
            fail(code, detail: detail)
        default:
            draft.step = draft.from
            fail(code, detail: detail, side: o["side"] as? String)
            if o["fast"] as? Bool == true, ConnectInput.kind(draft.target) != "ssh" { probeLocalNetwork() }
        }
    }

    /// A connection that failed at once: is it macOS (Local Network privacy)? The app's own probe,
    /// as for a tab (roadmap 01 §7.6): only `localNetworkDenied` says so.
    private func probeLocalNetwork() {
        guard !renderMode, let port = NWEndpoint.Port(rawValue: UInt16(clamping: ConnectInput.port(draft.target))) else { return }
        let c = NWConnection(host: NWEndpoint.Host(draft.host), port: port, using: .tcp)
        let target = draft.target
        c.stateUpdateHandler = { [weak self] st in
            DispatchQueue.main.async {
                guard let self else { c.cancel(); return }
                switch st {
                case .waiting, .failed:
                    if c.currentPath?.unsatisfiedReason == .localNetworkDenied, self.draft.target == target {
                        self.draft.blocked = true
                        self.fail("local_network_denied")
                    }
                    c.stateUpdateHandler = nil; c.cancel()
                case .ready:
                    c.stateUpdateHandler = nil; c.cancel()
                default: break
                }
            }
        }
        c.start(queue: .main)
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { c.cancel() }
    }

    /// Pair (the code step): the code typed or from the link, bound to the key shown.
    func pair() {
        guard let c = ConnectInput.normCode(draft.code) else { return }
        draft.step = .code
        runAdd(code: c)
    }

    /// The last step of pairing: the tab's name (a label of its own only when it differs).
    func addTab() {
        let name = draft.tabName.trimmingCharacters(in: .whitespacesAndNewlines)
        if !name.isEmpty, name != ConnectInput.shortName(draft.pairedName), name != draft.pairedName {
            engineCommand(["cmd": "rename", "id": draft.pairedMid, "label": String(name.prefix(64))])
        }
        closeConnect(discard: true)
    }

    /// A machine was added from the popover: it becomes a tab, selected, and the engine connects it.
    func machineAdded(_ mid: String) {
        pendingSelect = mid
        reloadMachines()
        if machines.count > 1 { ensureEngine() }
    }

    // MARK: Share this Mac

    /// `share status --json` as this user, in the background (no prompt).
    func refreshShare(then: (() -> Void)? = nil) {
        guard !renderMode else { return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = ["-I", "-B", cliPath, "share", "status", "--json"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard (try? p.run()) != nil else { return }
            let d = out.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            let st = try? JSONDecoder().decode(ShareStatus.self, from: d)
            DispatchQueue.main.async {
                guard let self else { return }
                self.share = st
                self.checkCode()
                then?()
            }
        }
    }

    /// Whether the code on screen was used (a viewer that was not there when it was made) or expired.
    private func checkCode() {
        guard let c = shareCode else { return }
        if let new = (share?.clients ?? []).first(where: { !c.before.contains($0.id) && ($0.paired ?? 0) >= c.made - 60 }) {
            sharePaired = (new.name?.isEmpty == false ? new.name! : "a viewer")
            shareCode = nil
            shareWaiting = false
        } else if Date().timeIntervalSince1970 > c.expires {
            shareCode = nil
            shareWaiting = false
        }
    }

    /// The switch, a new code, a revoke: one administrator prompt each (01 §14.5), through the
    /// installed CLI. The popup stays under the prompt (§3.8 rule 3), and a code is shown until it is
    /// spent: while it waits, the panel stays where it is.
    func shareRun(_ a: ShareAction) {
        guard let args = a.args, !busy else { return }
        let before = Set((share?.clients ?? []).map(\.id))
        shareError = nil
        sharePaired = nil
        busy = true
        let words = args.map { w in w.range(of: #"^[a-z0-9-]+$"#, options: .regularExpression) != nil ? w : "" }
        let cmd = "/usr/bin/python3 -I -B " + "'\(Store.installedCLI)' " + words.dropLast(a.isRevoke ? 1 : 0).joined(separator: " ")
        let tail = a.isRevoke ? " & \" \" & quoted form of \"\(words.last ?? "")\"" : ""
        DispatchQueue.global().async {
            var err: NSDictionary?
            let src = "do shell script \"\(cmd)\"\(tail) with prompt \"\(a.prompt)\" with administrator privileges"
            let out = NSAppleScript(source: src)?.executeAndReturnError(&err)
            let text = out?.stringValue ?? ""
            DispatchQueue.main.async {
                self.busy = false
                if let e = err {
                    if (e[NSAppleScript.errorNumber] as? Int) != -128 {
                        self.shareError = (e[NSAppleScript.errorMessage] as? String) ?? "failed"
                    }
                } else if case .on = a, let c = Store.parseCode(text, before: before) {
                    self.shareCode = c; self.shareWaiting = true; self.draft.touch()
                } else if case .pair = a, let c = Store.parseCode(text, before: before) {
                    self.shareCode = c; self.shareWaiting = true; self.draft.touch()
                } else if case .off = a {
                    self.shareCode = nil; self.shareWaiting = false
                }
                self.refreshShare()
                if self.popupOpen { self.connectShown = true }
                self.pollShare()
            }
        }
    }

    /// The code's line of `share on --pair --json` / `share pair --json` (the last line of the output).
    static func parseCode(_ text: String, before: Set<String>) -> ShareCode? {
        guard let last = text.split(whereSeparator: \.isNewline).last,
              let o = (try? JSONSerialization.jsonObject(with: Data(last.utf8))) as? [String: Any],
              let code = o["code"] as? String, ConnectInput.normCode(code) != nil,
              let link = o["link"] as? String, let exp = (o["expires"] as? NSNumber)?.doubleValue else { return nil }
        return ShareCode(code: code, link: link, expires: exp, before: before)
    }

    /// While a code waits, Share this Mac looks every 2 s whether it was used.
    func pollShare() {
        guard shareWaiting, !renderMode else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
            guard let self, self.shareWaiting else { return }
            self.refreshShare { self.pollShare() }
        }
    }

    /// Done, Back, Esc: the code stays known (and is shown again when Share this Mac is), the panel
    /// goes back to its own rule, and the popover no longer comes back by itself at this step.
    func shareDone() {
        shareWaiting = false
        sharePaired = nil
        if draft.step == .share { draft.step = .start }
    }
}

extension ShareAction {
    var isRevoke: Bool { if case .revoke = self { return true } else { return false } }
}

/// The + of roadmap 01 §3.1: on the hairline under the header (one machine) or at the end of the
/// tab strip; it opens the connect popover, and Share this Mac is in it.
struct PlusButton: View {
    @ObservedObject var store: Store
    @State private var hover = false

    var body: some View {
        let lit = hover || store.connectShown
        Button { store.toggleConnect() } label: {
            Image(systemName: "plus").font(.system(size: 10, weight: .semibold))
                .foregroundStyle(lit ? Color.accentColor : Color.secondary)
                .frame(width: 20, height: 20)
                .background(Circle().fill(Color(nsColor: .windowBackgroundColor)))
                .overlay(Circle().stroke(lit ? Color.accentColor : Color.primary.opacity(0.2), lineWidth: 0.75))
                .contentShape(Circle())
        }
        .buttonStyle(.plain).focusable(false)
        .background {
            if !renderMode {
                GeometryReader { g in
                    Color.clear
                        .onAppear { store.plusRect = g.frame(in: .global) }
                        .onChange(of: g.frame(in: .global)) { _, f in store.plusRect = f }
                }
            }
        }
        .onHover { h in withAnimation(.easeOut(duration: 0.12)) { hover = h } }
        .help("Connect to another machine, or share this Mac")
        .tourAnchor("plus")
        .anchorPreference(key: PlusAnchorKey.self, value: .bounds) { $0 }
    }
}

struct PlusAnchorKey: PreferenceKey {
    static var defaultValue: Anchor<CGRect>? = nil
    static func reduce(value: inout Anchor<CGRect>?, nextValue: () -> Anchor<CGRect>?) { value = value ?? nextValue() }
}

/// A text field, or in a render its look (a static render draws no AppKit field).
struct ConnectField: View {
    let placeholder: String
    @Binding var text: String
    var mono = false
    var size: CGFloat = 12
    var onSubmit: () -> Void = {}

    var body: some View {
        if renderMode {
            Text(text.isEmpty ? placeholder : text)
                .font(mono ? .system(size: size, design: .monospaced) : .system(size: size))
                .foregroundStyle(text.isEmpty ? Color.secondary.opacity(0.7) : Color.primary)
                .lineLimit(1)
                .padding(.horizontal, 6).padding(.vertical, 4)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 5))
                .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.primary.opacity(0.2), lineWidth: 0.5))
        } else {
            TextField(placeholder, text: $text)
                .textFieldStyle(.roundedBorder)
                .font(mono ? .system(size: size, design: .monospaced) : .system(size: size))
                .onSubmit(onSubmit)
        }
    }
}

/// A spinner, or in a render a static mark (Reduce Motion's "…" of roadmap 01 §3.13).
struct ConnectSpinner: View {
    var body: some View {
        if renderMode { Image(systemName: "ellipsis").font(.system(size: 11, weight: .bold)).foregroundStyle(.secondary) }
        else { ProgressView().controlSize(.small).scaleEffect(0.7).frame(width: 16, height: 16) }
    }
}

/// The connect popover's content (roadmap 01 §3.7): connecting, pairing and sharing alike. 304 pt
/// wide (316 for sharing). Errors stay in it, in plain words, and are kept with the draft.
struct ConnectView: View {
    @ObservedObject var store: Store
    @ObservedObject var draft: ConnectDraft
    @State private var hoverRow: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            switch draft.step {
            case .start: start
            case .connecting: connecting
            case .code: codeStep
            case .ssh: sshStep
            case .ask: askStep
            case .paired: paired
            case .share: ShareView(store: store, draft: draft)
            }
        }
        .padding(14)
        .frame(width: draft.step == .share ? 316 : 304, alignment: .leading)
        .onExitCommand {
            // at Share this Mac, Esc is Done: a fresh code is kept, the panel no longer held
            if draft.step == .share { store.shareDone(); store.closeConnect(discard: false) } else { store.closeConnect(discard: true) }
        }
    }

    func title(_ s: String) -> some View {
        Text(s).font(.system(size: 13, weight: .semibold)).lineLimit(1).truncationMode(.middle)
    }

    func note(_ s: String) -> some View {
        Text((try? AttributedString(markdown: s)) ?? AttributedString(s))
            .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder var errorBox: some View {
        if let e = draft.error {
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: draft.blocked ? "hand.raised.fill" : "exclamationmark.triangle.fill")
                        .font(.system(size: 11)).foregroundStyle(.orange)
                    Text((try? AttributedString(markdown: e)) ?? AttributedString(e))
                        .font(.system(size: 11)).fixedSize(horizontal: false, vertical: true)
                }
                HStack {
                    if draft.blocked { Button("Open Local Network settings") { Store.openLocalNetworkSettings() } }
                    Spacer()
                    Button("Try again") { draft.step == .code ? store.pair() : draft.step == .ssh ? store.runAdd(code: nil) : store.connectTyped() }
                }
                .controlSize(.small)
            }
            .padding(8)
            .background(Color.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 6))
        }
    }

    // the first step: the field, Recents or the matches, Share this Mac
    var start: some View {
        let recents = store.known.filter { $0.pinned != true }.sorted { ($0.last_connected ?? 0) > ($1.last_connected ?? 0) }
        let typed = draft.text.trimmingCharacters(in: .whitespacesAndNewlines)
        let found = ConnectInput.matches(typed, store.completions)
        return VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                ConnectField(placeholder: "Address, name or oomph:// link", text: $draft.text) { store.connectTyped() }
                    .onChange(of: draft.text) { old, new in
                        // a link pasted (⌘V) goes straight on to its confirmation
                        if ConnectInput.link(new) != nil, ConnectInput.link(old) == nil, new.count - old.count > 12 { store.connectTyped() }
                    }
                    .onKeyPress(.tab) {
                        guard let f = found.first else { return .ignored }
                        draft.text = f.matched
                        return .handled
                    }
                Button("Paste") {
                    if let s = NSPasteboard.general.string(forType: .string) {
                        draft.text = String(s.trimmingCharacters(in: .whitespacesAndNewlines).prefix(400))
                        if ConnectInput.link(draft.text) != nil { store.connectTyped() }
                    }
                }
                .controlSize(.small)
            }
            errorBox
            if !typed.isEmpty {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(found.prefix(5), id: \.mid) { f in
                        if let e = store.known.first(where: { $0.mid == f.mid }) { matchRow(e, matched: f.matched, typed: typed) }
                    }
                    Button { store.connectTyped() } label: {
                        HStack(spacing: 8) {
                            Image(systemName: "arrow.right.circle").foregroundStyle(.secondary).frame(width: 18)
                            Text("Connect to “\(typed)” as typed").font(.system(size: 12)).lineLimit(1).truncationMode(.middle)
                            Spacer()
                        }
                        .padding(.vertical, 5).contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            } else if recents.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    note("**On the other machine:** open \(brand), click + › Share this Mac and turn sharing on. It shows a pairing code. (Terminal: `sudo oomph share on --pair`.)")
                    note("**Here:** paste the link it shows, or type its address.")
                    note("The first time, macOS asks whether \(brand) may find devices on your local network. Choose Allow: that is how the dashboard reaches the machine.")
                        .foregroundStyle(.tertiary)
                }
            } else {
                Text("Recents").font(.caption).foregroundStyle(.secondary)
                let rows = VStack(alignment: .leading, spacing: 0) { ForEach(recents, id: \.mid) { recentRow($0) } }
                if recents.count > 5 && !renderMode { ScrollView { rows }.frame(height: 5 * 38) } else { rows }
            }
            Divider()
            Button { store.showShare() } label: {
                HStack(spacing: 8) {
                    Image(systemName: "dot.radiowaves.left.and.right").foregroundStyle(.secondary).frame(width: 18)
                    Text("Share this Mac…").font(.system(size: 12))
                    Spacer()
                    if store.share?.shared == true {
                        Text("on · \(store.share?.clients?.count ?? 0) paired").font(.system(size: 10)).foregroundStyle(.secondary)
                    }
                    Image(systemName: "chevron.right").font(.system(size: 10)).foregroundStyle(.tertiary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
    }

    func entryLine(_ e: MachineEntry) -> String {
        var bits = [e.transport == "ssh" ? (e.user.map { $0 + "@" } ?? "") + (e.host ?? "") : e.address]
        if let v = e.os_version { bits.append(v) }
        if let r = e.ram_gb { bits.append(String(format: "%.0f GB", r)) }
        if let t = e.last_connected { bits.append(ConnectInput.ago(t, now: Date().timeIntervalSince1970)) }
        return bits.joined(separator: " · ")
    }

    func recentRow(_ e: MachineEntry) -> some View {
        let hover = hoverRow == e.mid || (renderMode && e.mid == store.known.first(where: { $0.pinned != true })?.mid && renderRowHover)
        return VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Image(systemName: e.transport == "ssh" ? "terminal" : "desktopcomputer").foregroundStyle(.secondary).frame(width: 18)
                VStack(alignment: .leading, spacing: 1) {
                    Text(e.title).font(.system(size: 12, weight: .medium)).lineLimit(1).truncationMode(.middle)
                    Text(entryLine(e)).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
                }
                Spacer(minLength: 4)
                if hover {
                    Button { draft.forgetting = e.mid } label: { Image(systemName: "trash").font(.system(size: 11)).foregroundStyle(.secondary) }
                        .buttonStyle(.plain).help("Forget \(e.title)…")
                }
            }
            if draft.forgetting == e.mid {
                VStack(alignment: .leading, spacing: 6) {
                    note("Forget \(e.title)? Its history on this Mac is deleted and you'll need a new pairing code to connect again.")
                    HStack {
                        Spacer()
                        Button("Cancel") { draft.forgetting = nil }
                        Button("Forget") { store.forget(e.mid) }
                    }
                    .controlSize(.small)
                }
                .padding(8).background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 6))
            }
        }
        .padding(.vertical, 4).padding(.horizontal, 4)
        .background(hover ? Color.primary.opacity(0.06) : Color.clear, in: RoundedRectangle(cornerRadius: 5))
        .contentShape(Rectangle())
        .onTapGesture { if draft.forgetting == nil { store.useKnown(e) } }
        .onHover { hoverRow = $0 ? e.mid : (hoverRow == e.mid ? nil : hoverRow) }
        .contextMenu { Button("Forget…") { draft.forgetting = e.mid } }
    }

    func matchRow(_ e: MachineEntry, matched: String, typed: String) -> some View {
        let tab = e.pinned == true
        // the address that matched, its matching part bold; a match on the name shows the address plainly
        var shown = AttributedString(matched == e.title ? entryLine(e) : matched)
        if matched != e.title, let r = shown.range(of: String(matched.prefix(typed.count))) {
            shown[r].inlinePresentationIntent = .stronglyEmphasized
        }
        return Button { store.useKnown(e) } label: {
            HStack(spacing: 8) {
                Image(systemName: "desktopcomputer").foregroundStyle(.secondary).frame(width: 18)
                VStack(alignment: .leading, spacing: 1) {
                    Text(e.title).font(.system(size: 12, weight: .medium)).lineLimit(1)
                    Text(shown).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                Text(tab ? "connected" : "recent").font(.system(size: 10)).foregroundStyle(.tertiary)
            }
            .padding(.vertical, 4).contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    var connecting: some View {
        VStack(alignment: .leading, spacing: 10) {
            title("Connecting to \(draft.host)")
            HStack(spacing: 8) {
                ConnectSpinner()
                if renderMode {
                    Text("\(draft.target) · 3 s").font(.system(size: 11)).foregroundStyle(.secondary)
                } else {
                    TimelineView(.periodic(from: .now, by: 1)) { _ in
                        Text("\(draft.target) · \(Int(Date().timeIntervalSince(draft.started ?? Date()))) s")
                            .font(.system(size: 11)).foregroundStyle(.secondary).monospacedDigit()
                    }
                }
            }
            HStack { Spacer(); Button("Cancel") { store.closeConnect(discard: true) }.keyboardShortcut(.cancelAction) }
        }
    }

    var codeStep: some View {
        let n = ConnectInput.shortName(draft.host)
        return VStack(alignment: .leading, spacing: 10) {
            title(draft.host)
            if draft.revoked {
                note("\(n) no longer knows this Mac: its access was revoked, or sharing was reset there. Pair again with a new code.")
            }
            note("Paste the link that Share this Mac, or `sudo oomph share pair`, shows on \(n), or type its pairing code.")
            ConnectField(placeholder: "XXXX-XXXX-XXXX", text: $draft.code, mono: true, size: 17) { store.pair() }
                .onChange(of: draft.code) { _, new in
                    if let l = ConnectInput.link(new) { draft.code = ConnectInput.showCode(l.code) }
                }
            if !draft.fpShort.isEmpty {
                HStack(spacing: 6) {
                    Text("Key").font(.system(size: 10)).foregroundStyle(.secondary)
                    Text(draft.fpShort).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                }
                .help("Compare with `oomph share status` on \(n): the pairing is bound to this key")
            }
            Text("This step is kept while you fetch it: if the popup closes, the menu-bar icon brings it back as you left it.")
                .font(.system(size: 10)).foregroundStyle(.tertiary).fixedSize(horizontal: false, vertical: true)
            errorBox
            HStack {
                Spacer()
                Button("Cancel") { store.closeConnect(discard: true) }.keyboardShortcut(.cancelAction)
                Button("Pair") { store.pair() }.keyboardShortcut(.defaultAction)
                    .disabled(ConnectInput.normCode(draft.code) == nil)
            }
        }
    }

    var sshStep: some View {
        let p = ConnectInput.sshParts(draft.target)
        return VStack(alignment: .leading, spacing: 10) {
            title("\(p.host) over SSH")
            Text(verbatim: ConnectInput.sshCommand(draft.target))
                .font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                .padding(6).frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 5))
            note("Whoever can sign in to \(p.host) as \(p.user) can read what \(brand) logs there; no pairing code is asked.")
            note("It uses your SSH keys or agent and never asks for a password; \(brand) must be installed there.")
            errorBox
            HStack {
                Spacer()
                Button("Cancel") { store.closeConnect(discard: true) }.keyboardShortcut(.cancelAction)
                Button("Connect") { store.runAdd(code: nil) }.keyboardShortcut(.defaultAction)
            }
        }
    }

    var askStep: some View {
        VStack(alignment: .leading, spacing: 10) {
            title("Is this \(draft.askLabel)?")
            note("\(draft.host) reports the same machine id as \(draft.askLabel), but has a different key or address. That is normal after reinstalling \(brand) or resetting sharing there, and for cloned systems.")
            HStack {
                Button("Cancel") { store.answerAsk("") }.keyboardShortcut(.cancelAction)
                Spacer()
                // nothing is merged without a click: Return keeps both (01 §4.5, §7.3)
                Button("Replace") { store.answerAsk("replace:" + draft.askMid) }
                    .help("Replace \(draft.askLabel): keep its history and trust the new key")
                Button("Add separately") { store.answerAsk("new") }.keyboardShortcut(.defaultAction)
                    .help("A tab and a history of its own; \(draft.askLabel) stays as it is")
            }
        }
    }

    var paired: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                title("Paired with \(ConnectInput.shortName(draft.pairedName))")
            }
            if !draft.pairedAbout.isEmpty { note(draft.pairedAbout) }
            if draft.pairedOther {
                note("It is watched from the terminal for now (`oomph remote sync`, `oomph top`); the app gives it a tab in a later release.")
                HStack { Spacer(); Button("Done") { store.closeConnect(discard: true) }.keyboardShortcut(.defaultAction) }
            } else {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Tab name").font(.caption).foregroundStyle(.secondary)
                    ConnectField(placeholder: ConnectInput.shortName(draft.pairedName), text: $draft.tabName) { store.addTab() }
                }
                HStack { Spacer(); Button("Add tab") { store.addTab() }.keyboardShortcut(.defaultAction) }
            }
        }
    }
}

/// Share this Mac (roadmap 01 §3.10): opens without a prompt and shows what is; the switch, a new
/// code and each revoke ask for the administrator password once each.
struct ShareView: View {
    @ObservedObject var store: Store
    @ObservedObject var draft: ConnectDraft

    /// What has to happen first: "activate" (no logger), "update" (the logger is older than the app), or nil.
    var gate: String? {
        if let g = renderShareGate { return g.isEmpty ? nil : g }
        return !store.installed ? "activate" : store.needsUpdate ? "update" : nil
    }

    var body: some View {
        let st = store.share
        let on = st?.shared == true
        return VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Button { store.shareDone() } label: { Image(systemName: "chevron.left").font(.system(size: 11, weight: .semibold)) }
                    .buttonStyle(.plain).help("Back")
                Text("Share this Mac").font(.system(size: 13, weight: .semibold))
                Spacer()
                shareSwitch(on: on).disabled(gate != nil || store.busy)
            }
            if gate == "activate" {
                gateBox("Activate first. This Mac is not logging, so there is nothing to share yet.", "Activate") {
                    store.runPrivileged("install.sh") { e in if let e { store.shareError = e } }
                }
            } else if gate == "update" {
                gateBox("Update the logger first. The logger installed on this Mac is older than this app and cannot share yet.", "Update logger") {
                    store.runPrivileged("install.sh") { e in if let e { store.shareError = e } }
                }
            }
            Text("Paired machines can read this Mac's memory history, reservations and incidents, process names, project folders and purposes included. Read-only; only on the networks it is turned on for.")
                .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let e = store.shareError {
                Text(e).font(.system(size: 11)).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
            }
            if on, let st {
                VStack(alignment: .leading, spacing: 2) {
                    row("Address", (st.host ?? "this Mac") + ((st.port ?? 6674) == 6674 ? "" : ":\(st.port!)"))
                    if let fp = st.fp { row("Key", shortKey(fp), mono: true) }
                    row("Networks", st.any_network == true ? "every network this Mac is on" :
                            (st.networks ?? []).map { ($0.iface ?? "") + " " + ($0.net ?? "") }.joined(separator: ", "))
                }
                codeBlock(st)
                pairedList(st)
            }
        }
    }

    func shortKey(_ fp: String) -> String {
        let h = fp.hasPrefix("sha256:") ? String(fp.dropFirst(7)) : fp
        return stride(from: 0, to: min(16, h.count), by: 4).map { i -> String in
            let a = h.index(h.startIndex, offsetBy: i), b = h.index(a, offsetBy: min(4, h.count - i))
            return String(h[a..<b]).uppercased()
        }.joined(separator: " ")
    }

    @ViewBuilder func shareSwitch(on: Bool) -> some View {
        let binding = Binding(get: { on }, set: { v in store.shareRun(v ? .on : .off) })
        if renderMode {
            Capsule().fill(on ? Color.accentColor : Color.primary.opacity(0.15)).frame(width: 32, height: 18)
                .overlay(alignment: on ? .trailing : .leading) { Circle().fill(Color.white).frame(width: 15, height: 15).padding(1.5).shadow(radius: 0.5) }
                .opacity(gate != nil ? 0.4 : 1)
        } else {
            Toggle("", isOn: binding).toggleStyle(.switch).controlSize(.small).labelsHidden()
                .help(on ? "Stop sharing this Mac (asks for your password)" : "Share this Mac and make a pairing code (asks for your password)")
        }
    }

    func gateBox(_ text: String, _ button: String, action: @escaping () -> Void) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(text).font(.system(size: 11)).fixedSize(horizontal: false, vertical: true)
            HStack { Spacer(); Button(button, action: action).controlSize(.small).disabled(store.busy) }
        }
        .padding(8).background(Color.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
    }

    func row(_ k: String, _ v: String, mono: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(k).font(.system(size: 10)).foregroundStyle(.secondary).frame(width: 56, alignment: .leading)
            Text(v).font(mono ? .system(size: 10, design: .monospaced) : .system(size: 11)).lineLimit(1).truncationMode(.middle)
                .textSelection(.enabled)
        }
    }

    @ViewBuilder func codeBlock(_ st: ShareStatus) -> some View {
        if let c = store.shareCode, renderMode || Date().timeIntervalSince1970 < c.expires {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("Pairing code").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    if renderMode {
                        Text("9:41 left · \(st.pairing?.left ?? 5) tries").font(.system(size: 10)).foregroundStyle(.secondary)
                    } else {
                        TimelineView(.periodic(from: .now, by: 1)) { _ in
                            let left = max(0, Int(c.expires - Date().timeIntervalSince1970))
                            Text(String(format: "%d:%02d left · %d tries", left / 60, left % 60, st.pairing?.left ?? 5))
                                .font(.system(size: 10)).foregroundStyle(.secondary).monospacedDigit()
                        }
                    }
                }
                Text(c.code).font(.system(size: 22, weight: .semibold, design: .monospaced)).textSelection(.enabled)
                HStack(spacing: 6) {
                    Text(c.link).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                    Spacer(minLength: 4)
                    Button("Copy link") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(c.link, forType: .string)
                    }
                    .controlSize(.small)
                }
                HStack(spacing: 6) {
                    ConnectSpinner()
                    Text("Waiting for the other machine…").font(.system(size: 11))
                }
                Text("While this code waits, the popup stays where it is, also when you switch apps. Done or the menu-bar icon puts it away; the code is kept and shown again.")
                    .font(.system(size: 10)).foregroundStyle(.tertiary).fixedSize(horizontal: false, vertical: true)
                HStack { Spacer(); Button("Done") { store.shareDone(); store.closeConnect(discard: false) }.keyboardShortcut(.defaultAction) }
            }
            .padding(10)
            .background(Color.accentColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
        } else {
            VStack(alignment: .leading, spacing: 6) {
                if let p = store.sharePaired {
                    HStack(spacing: 6) {
                        Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                        Text("Paired with \(p).").font(.system(size: 11))
                    }
                }
                if st.pairing?.active == true, let exp = st.pairing?.expires {
                    Text("A pairing code is active for another \(max(1, Int((exp - Date().timeIntervalSince1970) / 60))) min (it is shown only where it was made).")
                        .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                HStack {
                    Spacer()
                    Button("New pairing code") { store.shareRun(.pair) }.controlSize(.small).disabled(store.busy)
                        .help("A code for one more machine (asks for your password)")
                }
            }
        }
    }

    @ViewBuilder func pairedList(_ st: ShareStatus) -> some View {
        let clients = st.clients ?? []
        let reading = Set((st.reading ?? []).map(\.client))
        VStack(alignment: .leading, spacing: 3) {
            Text(clients.isEmpty ? "No machine is paired yet" : "Paired machines").font(.caption).foregroundStyle(.secondary)
            let rows = VStack(alignment: .leading, spacing: 2) {
                ForEach(clients) { c in
                    HStack(spacing: 8) {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(c.name?.isEmpty == false ? c.name! : "viewer").font(.system(size: 12, weight: .medium)).lineLimit(1)
                            Text([c.last_addr ?? "", reading.contains(c.id) ? "reading now" : c.last_seen.map { "last seen " + MemoryChart.when($0) } ?? "never seen"]
                                .filter { !$0.isEmpty }.joined(separator: " · "))
                                .font(.system(size: 10)).foregroundStyle(reading.contains(c.id) ? Color.green : Color.secondary).lineLimit(1)
                        }
                        Spacer()
                        Button("Revoke") { store.shareRun(.revoke(c.id, c.name ?? c.id)) }.controlSize(.small).disabled(store.busy)
                            .help("End this machine's access (\(c.id); asks for your password)")
                    }
                    .padding(.vertical, 2)
                }
            }
            if clients.count > 5 && !renderMode { ScrollView { rows }.frame(height: 5 * 34) } else { rows }
            if let more = st.more, more > 0 { Text("… and \(more) more: oomph share status").font(.system(size: 10)).foregroundStyle(.tertiary) }
        }
    }
}

/// `--ai share:STATE` draws Share this Mac's gates without this Mac's own install state.
var renderShareGate: String?
/// `--ai addhover` draws the first Recents row hovered (its trash).
var renderRowHover = false
/// The fallback if the NSPopover misbehaves inside the borderless panel (roadmap 01 Appendix A: never
/// tried): `defaults write local.oomph.menubar connectSheet -bool YES` shows the same content as a sheet.
var connectAsSheet: Bool { UserDefaults.standard.bool(forKey: "connectSheet") }

// MARK: - App delegate / status item

/// Borderless panel used instead of NSPopover, positioned explicitly below the status item.
final class PopupPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    /// The tabs' keys (Store.machineKey), seen before any view: a ⌃⇥ never reaches the key-view loop.
    var onKey: ((NSEvent) -> Bool)?
    override func sendEvent(_ e: NSEvent) {
        if e.type == .keyDown, attachedSheet == nil, onKey?(e) == true { return }
        super.sendEvent(e)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, NSPopoverDelegate {
    let store = Store()
    var item: NSStatusItem!
    var panel: PopupPanel!
    var hosting: NSHostingView<PopoverView>!
    var timer: Timer?
    var clickMonitor: Any?
    var lastClose = Date.distantPast
    /// The connect popover (roadmap 01 §3.7): an NSPopover anchored to the +, a window of its own, so
    /// it is not clipped by the panel. Built and shown only with machinesUI.
    var popover: NSPopover?
    var watchers: [AnyCancellable] = []

    var isShown: Bool { panel?.isVisible ?? false }

    func applicationDidFinishLaunching(_ n: Notification) {
        signal(SIGPIPE, SIG_IGN)  // a child that ended (the engine, a report) must not take the app with it
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        store.machine.reloadPoints()  // in the background: the first popup then opens with its chart ready
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
        panel.onKey = { [weak self] e in self?.store.machineKey(e) ?? false }
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

        store.local.refreshCurrent()
        store.local.loadIncidents()
        updateIcon()
        timer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in self?.tick() }
        store.onResize = { [weak self] in DispatchQueue.main.async { if self?.isShown == true { self?.position() } } }
        store.onPlusMoved = { [weak self] in
            guard let self, let p = self.popover, p.isShown else { return }
            DispatchQueue.main.async { p.positioningRect = self.plusAnchorRect }
        }
        // the popover's own window giving up the keyboard (to another app) closes the popup as well
        NotificationCenter.default.addObserver(forName: NSWindow.didResignKeyNotification, object: nil, queue: .main) { [weak self] n in
            guard let self, let w = n.object as? NSWindow, w === self.popover?.contentViewController?.view.window else { return }
            self.keyMoved()
        }
        watchers = [
            store.$connectShown.removeDuplicates().sink { [weak self] on in DispatchQueue.main.async { self?.showConnect(on) } },
            // under the administrator prompt and while a fresh code waits, the panel stays and sits
            // below menus and system dialogs (roadmap 01 §3.8 rule 3)
            store.$busy.combineLatest(store.$shareWaiting).sink { [weak self] _ in
                DispatchQueue.main.async { self?.panel.level = self?.store.holdsPanel == true ? .floating : .popUpMenu }
            },
        ]

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
        store.local.refreshCurrent()
        store.local.loadIncidents()
        if isShown { store.machine.reloadPoints(); DispatchQueue.main.async { self.position() } }
        updateIcon()
    }

    @objc func toggle() {
        if isShown { close(); return }
        // clicking the icon first makes the panel resign key (which closes it); don't reopen on that same click
        if Date().timeIntervalSince(lastClose) < 0.35 { return }
        store.applyOpeningRule()
        store.machine.refreshAll()
        store.popupOpened()
        store.machinesOpened()
        position()
        panel.makeKeyAndOrderFront(nil)
        // nothing focused on open: a focus ring is drawn above everything, callouts included
        DispatchQueue.main.async { self.panel.makeFirstResponder(nil) }
        DispatchQueue.main.async { self.position() }  // SwiftUI may settle its size one pass later
        clickMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            if self?.store.holdsPanel != true { self?.close() }
        }
        // a draft outlives a close: the popover comes back at its step (roadmap 01 §3.8 rule 2)
        // (Share this Mac only while a code it made is still good: after Done it no longer comes back)
        let d = store.draft
        if store.machinesUI && (store.shareWaiting || d.step == .share && store.shareCodeValid ||
                                d.alive && (d.step != .start && d.step != .share || !d.text.isEmpty)) {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak self] in self?.store.openConnect() }
        }
    }

    /// The popover on the +, or away. With `connectSheet` the popup shows a sheet instead (PopoverView).
    func showConnect(_ on: Bool) {
        guard !connectAsSheet else { return }
        if !on || !isShown || !store.machinesUI {
            if popover?.isShown == true { popover?.performClose(nil) }
            return
        }
        guard store.plusRect.width > 0, hosting.window != nil else { store.connectShown = false; return }
        if popover == nil {
            let p = NSPopover()
            p.behavior = .applicationDefined
            p.animates = !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
            let host = NSHostingController(rootView: ConnectView(store: store, draft: store.draft))
            host.sizingOptions = .preferredContentSize
            p.contentViewController = host
            p.delegate = self
            popover = p
        }
        if popover?.isShown != true {
            popover?.show(relativeTo: plusAnchorRect, of: hosting, preferredEdge: hosting.isFlipped ? .maxY : .minY)
        }
    }

    /// The + in the hosting view's own coordinates (SwiftUI measures from the top left).
    var plusAnchorRect: NSRect {
        let r = store.plusRect
        return hosting.isFlipped ? r : NSRect(x: r.minX, y: hosting.bounds.height - r.maxY, width: r.width, height: r.height)
    }

    func popoverDidClose(_ n: Notification) {
        if store.connectShown { store.connectShown = false }
    }

    /// The panel or the popover lost the keyboard: it closes, unless the keyboard went from one to the
    /// other, or the panel is held (the administrator prompt, a code that waits).
    func keyMoved() {
        DispatchQueue.main.async { [weak self] in
            guard let self, self.isShown else { return }
            let key = NSApp.keyWindow
            if key === self.panel || (key != nil && key === self.popover?.contentViewController?.view.window) { return }
            if self.panel.attachedSheet != nil || self.store.holdsPanel { return }
            self.close()
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
        if popover?.isShown == true { popover?.close() }
        store.connectShown = false
        store.shareWaiting = false  // the menu-bar icon puts a waiting code away; it is shown again
        panel.orderOut(nil)
        lastClose = Date()
        if let m = clickMonitor { NSEvent.removeMonitor(m); clickMonitor = nil }
        store.machinesClosed()
        updateIcon()
    }

    func windowDidResignKey(_ n: Notification) {
        // with the + the keyboard may move to its popover, and the panel may be held (§3.8 rule 3)
        if store.machinesUI { keyMoved(); return }
        // a sheet/alert attached to the panel takes key status; don't close for that
        if panel.attachedSheet == nil { close() }
    }

    func updateIcon() {
        let running = store.local.daemonRunning
        let c = store.local.current
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
func renderPopup(to path: String, dark: Bool, ai: String = "", mirror: String? = nil) {
    renderMode = true
    let store = Store()
    // `--mirror DIR` draws another machine's mirror (…/machines/<mid>/, as `oomph remote sync` writes it)
    if let dir = mirror { store.machines.append(MachineStore(mirror: dir)); store.selected = 1 }
    // with `-machinesUI YES`: the tabs of OOMPH_MACHINES_DIR, opened by the opening rule
    // (`-selectedMachine MID` is the remembered tab)
    if mirror == nil && store.machinesUI {
        store.local.refreshCurrent()
        store.local.loadIncidents()
        store.applyOpeningRule()
        // a render is the popup just opened (roadmap 01 §3.6); `-openedAgo S` draws it S seconds later
        let opened: Double = Date().timeIntervalSince1970 - UserDefaults.standard.double(forKey: "openedAgo")
        for m in store.machines.dropFirst() { m.refreshCurrent(); m.markOpened(at: opened); m.loadIncidents() }
    }
    if mirror == nil && store.machinesUI { renderConnect(store, ai) }
    store.machine.refreshCurrent()
    store.machine.loadIncidents()
    if ai != "loading" { store.machine.reloadPoints(sync: true) }  // `--ai loading` draws the spinner
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
    let view = PopoverView(store: store, showAI: ["callout", "dialog-connected", "dialog-error"].contains(ai), showTopApps: ai == "top",
                           tourStep: tour, showAllReservations: ai == "resmore")
        .background(Color(nsColor: .windowBackgroundColor))
        .frame(minHeight: store.connectShown ? 820 : nil, alignment: .top)  // room for the popover under the +
        .environment(\.colorScheme, dark ? .dark : .light)
    let r = ImageRenderer(content: view)
    r.scale = 2
    guard let cg = r.cgImage,
          let png = NSBitmapImageRep(cgImage: cg).representation(using: .png, properties: [:]) else { return }
    try? png.write(to: URL(fileURLWithPath: path))
}

/// The + and its popover in a render (roadmap 01 §3.13), with `-machinesUI YES`: `--ai add`, `addhover`,
/// `addtype[:TEXT]`, `addssh[:TARGET]`, `pair[:link]`, `addconnecting`, `adderr:CODE`, `ask`, `paired[:other]`,
/// `share[:off|update|activate]`, `sharecode`. Recents come from OOMPH_MACHINES_DIR; everything else here
/// is invented. `--ai tour:4` is the tour's Machines step.
@MainActor
func renderConnect(_ store: Store, _ ai: String) {
    let d = store.draft
    let parts = ai.split(separator: ":", maxSplits: 1).map(String.init)
    let what = parts.first ?? "", arg = parts.count > 1 ? parts[1] : ""
    let now = Date().timeIntervalSince1970
    let fp = "sha256:328861212bbe5cc89a48359f4426b50b" + String(repeating: "0", count: 32)
    var share = ShareStatus(on: true, port: 6674, networks: [.init(iface: "en0", net: "192.168.1.0/24", router: "192.168.1.1")],
                            any_network: false,
                            clients: [.init(id: "c-4f2a9d10", name: "sams-macbook-pro", paired: now - 3 * 86400, last_seen: now - 40,
                                            last_addr: "192.168.1.12"),
                                      .init(id: "c-91be03f7", name: "air", paired: now - 30 * 86400, last_seen: now - 14 * 86400,
                                            last_addr: "192.168.1.40")],
                            reading: [.init(client: "c-4f2a9d10", peer: "192.168.1.12", since: now - 1800)],
                            pairing: .init(active: false, expires: nil, left: nil), fp: fp, host: "studio.local",
                            service: true, more: 0)
    store.known = MachineEntry.loadAll(machinesDir)
    switch what {
    case "add", "addhover":
        renderRowHover = what == "addhover"
    case "addtype":
        d.text = arg.isEmpty ? "stu" : arg
    case "addssh":
        d.step = .ssh; d.target = arg.isEmpty ? "sam@atlas" : arg
    case "pair":
        d.step = .code; d.target = "studio.local"; d.fp = fp; d.fpShort = "3288 6121 2BBE 5CC8"
        if arg == "link" { d.code = "K7QF-2M9X-D4TR"; d.fp = nil; d.fpShort = "" }  // a link sends nothing before Pair
    case "addconnecting":
        d.step = .connecting; d.target = "studio.local"
    case "adderr":
        let code = arg.isEmpty ? "refused" : arg
        d.text = "studio.local"; d.target = "studio.local"; d.errorCode = code; d.blocked = code == "local_network_denied"
        d.error = ConnectInput.message(code, target: "studio.local")
    case "ask":
        d.step = .ask; d.target = "studio.local"; d.askMid = "m-7f3a9c1e5b2d4a68"; d.askLabel = "studio"
    case "paired":
        d.step = .paired; d.pairedName = "studio.local"; d.pairedAbout = "macOS 27.2 · 64 GB · \(brand) 1.10.2"; d.tabName = "studio"
        if arg == "other" { d.pairedName = "atlas"; d.pairedAbout = "Ubuntu 24.04 · 251 GB · \(brand) 1.10.2"; d.pairedOther = true }
    case "share":
        d.step = .share
        if arg == "off" || arg == "update" || arg == "activate" { share.on = false; share.clients = []; share.reading = [] }
        store.share = share
        renderShareGate = arg == "update" || arg == "activate" ? arg : ""
    case "sharecode":
        d.step = .share
        share.pairing = .init(active: true, expires: now + 581, left: 5)
        store.share = share
        store.shareCode = ShareCode(code: "K7QF-2M9X-D4TR", link: "oomph://K7QF-2M9X-D4TR@studio.local", expires: now + 581, before: [])
        store.shareWaiting = true
        renderShareGate = ""
    default:
        return
    }
    store.connectShown = true
}

/// `oomph --connect-vectors FILE`: the popover's pure functions (ConnectInput) over the inputs of FILE
/// (tools/vectors/connect.json), answered as JSON. tools/connectvectors.py compares them with the file,
/// whose link, code and kind answers the CLI must give too (oomph_sync.parse_link, parse_target).
func connectVectors(_ path: String) -> Int32 {
    guard let data = FileManager.default.contents(atPath: path),
          let v = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
        FileHandle.standardError.write("oomph: --connect-vectors: can't read \(path)\n".data(using: .utf8)!)
        return 2
    }
    func cases(_ k: String) -> [[String: Any]] { (v[k] as? [[String: Any]]) ?? [] }
    func str(_ c: [String: Any], _ k: String = "s") -> String { (c[k] as? String) ?? "" }
    var out: [String: Any] = [:]
    out["link"] = cases("link").map { c -> Any in ConnectInput.link(str(c)).map { [$0.target, $0.code] as Any } ?? NSNull() }
    out["code"] = cases("code").map { c -> Any in ConnectInput.normCode(str(c)) as Any? ?? NSNull() }
    out["kind"] = cases("kind").map { ConnectInput.kind(str($0)) }
    out["ssh_command"] = cases("ssh_command").map { ConnectInput.sshCommand(str($0)) }
    out["host"] = cases("host").map { ConnectInput.host(str($0)) }
    out["ago"] = cases("ago").map { c in
        ConnectInput.ago((c["t"] as? NSNumber)?.doubleValue ?? 0, now: (c["now"] as? NSNumber)?.doubleValue ?? 0)
    }
    out["matches"] = cases("matches").map { c -> [[String]] in
        let known = ((c["known"] as? [[String: Any]]) ?? []).map { k in ((k["mid"] as? String) ?? "", (k["names"] as? [String]) ?? []) }
        return ConnectInput.matches(str(c, "text"), known).map { [$0.mid, $0.matched] }
    }
    out["message"] = cases("message").map { c in
        ConnectInput.message(str(c, "code"), target: str(c, "target"), detail: str(c, "detail"), side: c["side"] as? String)
    }
    guard let json = try? JSONSerialization.data(withJSONObject: out, options: [.sortedKeys]) else { return 1 }
    FileHandle.standardOutput.write(json)
    FileHandle.standardOutput.write("\n".data(using: .utf8)!)
    return 0
}

/// `oomph --chart-vectors FILE`: runs the chart's pure functions over the inputs of FILE (the shared
/// vectors, tools/vectors/chart.json) and prints their answers as JSON. tools/chartvectors.py compares
/// them with the file's expected values, which are this output; `oomph top` must reproduce them too.
@MainActor
func chartVectors(_ path: String) -> Int32 {
    guard let data = FileManager.default.contents(atPath: path),
          let v = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
        FileHandle.standardError.write("oomph: --chart-vectors: can't read \(path)\n".data(using: .utf8)!)
        return 2
    }
    func num(_ x: Any?) -> Double { (x as? NSNumber)?.doubleValue ?? 0 }
    func cases(_ k: String) -> [[String: Any]] { (v[k] as? [[String: Any]]) ?? [] }
    var out: [String: Any] = [:]
    out["mapper"] = cases("mapper").map { c -> [Double] in
        let span = (c["span"] as? NSNumber)?.doubleValue
        let f = MemoryChart.mapper(now: num(c["now"]), first: num(c["first"]), lgRange: log10(span ?? 86400),
                                   blend: span == nil ? 1 : 0)
        return ((c["t"] as? [NSNumber]) ?? []).map { f($0.doubleValue) }
    }
    out["color_index"] = cases("color_index").map { Reservation.colorIndex(($0["purpose"] as? String) ?? "") }
    out["strip_top"] = cases("strip_top").map { MemoryChart.stripTop(num($0["tallest"])) }
    func points(_ x: Any?) -> [Point] {
        ((x as? [[String: Any]]) ?? []).map { p in
            Point(id: num(p["t"]), date: Date(timeIntervalSince1970: num(p["t"])), wired: num(p["wired"]),
                  app: num(p["app"]), comp: num(p["comp"]), swap: num(p["swap"]),
                  away: (p["away"] as? Bool) ?? false, kills: Int(num(p["kills"])))
        }
    }
    out["multires"] = cases("multires").map { c -> [[Any]] in
        Store.multires(points(c["points"]), now: num(c["now"])).map { [$0.id, $0.wired, $0.app, $0.comp, $0.swap, $0.away, $0.kills] }
    }
    out["gaps"] = cases("gaps").map { c -> [[Double]] in
        Store.findGaps(points(c["points"]), now: num(c["now"])).map { [$0.from, $0.to] }
    }
    func spans(_ x: Any?) -> [(Double, Double)] { ((x as? [[NSNumber]]) ?? []).compactMap { $0.count >= 2 ? ($0[0].doubleValue, $0[1].doubleValue) : nil } }
    out["calm_bands"] = cases("calm_bands").map { c -> [String: Any] in
        let r = MemoryChart.calmBands(away: spans(c["away"]), gaps: spans(c["gaps"]), tolerance: num(c["tolerance"]))
        return ["grey": r.grey.map { [$0.0, $0.1] }, "hatched": r.hatched.map { [$0.0, $0.1] }]
    }
    out["stack"] = cases("stack").map { c -> [[String: Any]] in
        let rs = ((c["reservations"] as? [[String: Any]]) ?? []).compactMap { Reservation($0) }
        return ResBlock.stack(rs, now: num(c["now"])).map { b in
            ["key": b.res.id, "lane": b.lane, "steps": b.steps.map { [$0.a, $0.b, $0.lo, $0.hi] }] as [String: Any]
        }
    }
    out["merge"] = cases("merge").map { c -> [[String: Any]] in
        let lines = ((c["records"] as? [Any]) ?? []).compactMap { r -> String? in
            (try? JSONSerialization.data(withJSONObject: r)).flatMap { String(data: $0, encoding: .utf8) }
        }
        let gone = Set(((c["gone"] as? [NSNumber]) ?? []).map { $0.int32Value })
        let rs = Store.mergeReservations(records: lines.joined(separator: "\n").data(using: .utf8),
                                         ledger: (c["ledger"] as? [String: Any]) ?? [:], now: num(c["now"]),
                                         holderGone: { gone.contains($0) })
        return rs.sorted { ($0.requested, $0.id) < ($1.requested, $1.id) }.map { r -> [String: Any] in
            ["key": r.id, "ended": r.ended.map { $0 as Any } ?? NSNull(), "outcome": r.outcome.map { $0 as Any } ?? NSNull(),
             "gb": r.gb, "segments": r.segments.count]
        }
    }
    out["order"] = cases("order").map { c -> [String] in
        let rs: [Reservation]
        if let ledger = c["ledger"] as? [String: Any] {     // through the merge: places in the queue
            rs = Store.mergeReservations(records: nil, ledger: ledger, now: num(c["now"]), holderGone: { _ in false })
        } else {
            rs = ((c["reservations"] as? [[String: Any]]) ?? []).compactMap { Reservation($0) }
        }
        return Reservation.listOrder(rs.filter(\.live)).map(\.id)
    }
    // the hover card over a column (`oomph top`'s inspect readout must say the same): day names in English,
    // as the terminal writes them; the time zone is the environment's (TZ), as for both programs
    MemoryChart.dayFmt.locale = Locale(identifier: "en_US_POSIX")
    out["hover"] = cases("hover").map { c -> [[String: Any]] in
        let now = num(c["now"]), span = (c["span"] as? NSNumber)?.doubleValue
        let rs = ((c["reservations"] as? [[String: Any]]) ?? []).compactMap { Reservation($0) }
        let incs: [Incident] = ((c["incidents"] as? [[String: Any]]) ?? []).compactMap { d in
            (try? JSONSerialization.data(withJSONObject: d)).flatMap { try? JSONDecoder().decode(Incident.self, from: $0) }
        }
        let evs = ((c["events"] as? [[String: Any]]) ?? []).compactMap { ChartEvent($0) }.sorted { $0.t < $1.t }
        let chart = MemoryChart(points: points(c["points"]), gaps: spans(c["gaps"]).map { Gap(from: $0.0, to: $0.1) },
                                now: now, incidents: incs, events: evs, ram: nil,
                                lgRange: log10(span ?? 86400), blend: span == nil ? 1 : 0,
                                reservations: ResBlock.stack(rs, now: now), oldest: num(c["first"]))
        let f = chart.mapper()
        return ((c["u"] as? [NSNumber]) ?? []).map { u -> [String: Any] in
            let i = chart.hoverInfo(u: u.doubleValue, du: num(c["du"]), mapper: f)
            return ["when": i.when, "ago": i.ago, "samples": i.samples, "peak": i.peak, "away": i.away,
                    "readings": i.readings.map { [$0.name, $0.lo, $0.hi] as [Any] },
                    "no_data": i.noData.map { $0 as Any } ?? NSNull(), "incidents": i.incidents,
                    "events": i.events.map { [$0.0, $0.1] as [Any] }, "more_events": i.moreEvents,
                    "reserved": i.reserved.map { $0.0 }, "more_reserved": i.moreReserved]
        }
    }
    guard let json = try? JSONSerialization.data(withJSONObject: out, options: [.sortedKeys]) else { return 1 }
    FileHandle.standardOutput.write(json)
    FileHandle.standardOutput.write("\n".data(using: .utf8)!)
    return 0
}

@main
struct Main {
    static func main() {
        // Development aid: `oomph --render-popup out.png [--dark]` draws the popup into a PNG and exits.
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "--chart-vectors"), i + 1 < args.count {
            exit(MainActor.assumeIsolated { chartVectors(args[i + 1]) })
        }
        if let i = args.firstIndex(of: "--connect-vectors"), i + 1 < args.count {
            exit(connectVectors(args[i + 1]))
        }
        if let i = args.firstIndex(of: "--render-popup"), i + 1 < args.count {
            let ai = args.firstIndex(of: "--ai").map { args.count > $0 + 1 ? args[$0 + 1] : "" } ?? ""
            let mirror = args.firstIndex(of: "--mirror").flatMap { args.count > $0 + 1 ? args[$0 + 1] : nil }
            MainActor.assumeIsolated { renderPopup(to: args[i + 1], dark: args.contains("--dark"), ai: ai, mirror: mirror) }
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
