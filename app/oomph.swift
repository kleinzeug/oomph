// oomph — menu bar front-end for the oomph daemon (see ../DESIGN.md).
// Build: ../build-app.sh
import AppKit
import Charts
import Combine
import Network
import Security
import SwiftUI

/// A render's own flags (`--fixture DIR`, `--now T`): their value, honoured only with `--render-popup`, so
/// that the running app never draws anything but this Mac. Nil without them.
func renderFlag(_ name: String) -> String? {
    let a = CommandLine.arguments
    guard a.contains("--render-popup"), let i = a.firstIndex(of: name), i + 1 < a.count else { return nil }
    return a[i + 1]
}
/// `--fixture DIR` (renders): one directory instead of this Mac's: DIR/log, DIR/ledger and DIR/machines,
/// as tools/renderfixture.py writes it. It wins over OOMPH_DIR, OOMPH_LEDGER_DIR and OOMPH_MACHINES_DIR, so
/// that nothing of the Mac that renders reaches the picture.
let fixtureDir = renderFlag("--fixture")
/// `--now T` (renders): the clock stands at T (seconds since 1970), so that two renders of one fixture
/// are byte-identical (roadmap 02 §8). Every "now" that decides what is drawn reads wallNow().
let frozenNow: Double? = renderFlag("--now").flatMap { Double($0) }.flatMap { $0.isFinite && $0 > 0 ? $0 : nil }
/// `--no-liveness` (renders): a lease's state and a mirror's link come from the files alone; no process
/// is asked whether it lives (kill(pid, 0)), so a fixture's holders need no live process.
let noLiveness = CommandLine.arguments.contains("--render-popup") && CommandLine.arguments.contains("--no-liveness")
/// Now, as the popup draws it: the wall clock, or the clock of `--now`.
func wallNow() -> Double { frozenNow ?? Date().timeIntervalSince1970 }
func wallDate() -> Date { Date(timeIntervalSince1970: wallNow()) }
/// Whether `d` falls on the day of wallNow() (Calendar's isDateInToday asks the wall clock).
func isWallToday(_ d: Date) -> Bool { Calendar.current.isDate(d, inSameDayAs: wallDate()) }

let logDir = fixtureDir.map { $0 + "/log" } ?? ProcessInfo.processInfo.environment["OOMPH_DIR"] ?? "/Library/Logs/oomph"
/// The agents' coordination ledger (ledger.json) and its history log (reservations.jsonl).
let ledgerDir = fixtureDir.map { $0 + "/ledger" } ?? ProcessInfo.processInfo.environment["OOMPH_LEDGER_DIR"] ?? "/Users/Shared/oomph"
/// Where `oomph remote` keeps the machines this Mac watches: machines.json and one mirror per machine.
let machinesDir = fixtureDir.map { $0 + "/machines" } ?? ProcessInfo.processInfo.environment["OOMPH_MACHINES_DIR"]
    ?? (NSHomeDirectory() + "/Library/Application Support/oomph/machines")
let brand = "oomph"  // the product's name in prose and titles (oomph.py's BRAND; tools/brandlint.py)
/// The popup of four resources (roadmap 02 §3.7, §3.8; 1.11.0): tiles that work as tabs, small charts, agent
/// colours, the capsule and chip on oomph's verdict. Behind a default until the owner has looked at the renders:
/// `defaults write local.oomph.menubar resourcesUI -bool YES`, then quit and reopen the app. Read once.
let resourcesUIOn = UserDefaults.standard.bool(forKey: "resourcesUI")
let descriptor = ": memory monitor"  // what the header says after the name
/// … and with the four resources (decided 2026-11-23: the brand stays, the header reads "oomph: resource monitor").
let resourceDescriptor = ": resource monitor"
let agentLabel = "local.oomph.menubar"
let popupWidth: CGFloat = 480
let statColumn: CGFloat = 96
var renderHoverX: CGFloat?  // --ai hover:X / hoverlog:X renders the hover tooltip at x = X pt
var renderBlend: Double?  // --ai blend:0.5 renders the 24h → ∞ morph halfway
var renderMode = false  // --render-popup: static renders don't draw scroll-view contents
var renderStripHover: CGPoint?  // --ai rhover:X:Y renders the reservation strip's tooltip at (X, Y) pt
var renderResRowHover: Int?     // --ai rowhover:N renders the pointer on row N of "Reserved by agents" (with the resources on)
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

/// A field that may be missing or of another shape (another machine's file, an older or newer logger): nil
/// then, instead of failing the whole sample.
struct Soft<T: Decodable>: Decodable {
    let v: T?
    init(from d: Decoder) throws { v = try? T(from: d) }
}
/// The sample's resource blocks (roadmap 02 §5.1, logged since 1.9.1).
struct CPUBlock: Decodable { var n: Double?; var busy: Double?; var user: Double?; var sys: Double?; var therm: Double?
                             var p: Double?; var e: Double? }
struct GPUBlock: Decodable { var id: String?; var name: String?; var util: Double?; var active: Double?; var src: String?
                             var mem_gb: Double?; var mem_alloc_gb: Double?; var mem_limit_gb: Double? }
struct DiskPool: Decodable { var id: String?; var name: String?; var free_gb: Double?; var total_gb: Double?
                             var roles: [String]?; var watch: Bool?; var low_gb: Double?; var crit_gb: Double?; var level: String? }
/// What the verdict reads of a Linux sample's own block (oomph._verdict_parts: strict overcommit), and what a
/// Linux tab's tiles read of it (03 §3.9): the kernel's swap figures, zram's size.
struct LinuxBlock: Decodable { var overcommit: Soft<Double>?; var commit_pct: Soft<Double>?
                               var kswap_total_gb: Soft<Double>?; var kswap_free_gb: Soft<Double>?; var zram_disk_gb: Soft<Double>? }
/// A Linux sample's memory stall time (`psi`, % of the last 10 s; 03 §5.3) and the part of it taken out for
/// containers at their own limit (`limit`).
struct PSILimit: Decodable { var some: Double?; var full: Double?; var cgroups: [String]? }
struct PSIBlock: Decodable { var mem_some: Double?; var mem_full: Double?; var limit: Soft<PSILimit>? }
/// A Linux logger inside a limited cgroup (`scope`, 03 §5.14): the figures are the cgroup's, the host's are here.
struct ScopeBlock: Decodable { var kind: String?; var id: String?; var limit_gb: Double?; var host_ram_gb: Double?
                               var host_avail_gb: Double? }
/// What a machine's logger can measure (`machine.measures`, 03 §6.4): the facts a Linux tab's tiles follow.
/// zswap is "unseen" on a kernel without its fields: that reads as nil.
struct Measures: Decodable { var psi: Soft<Bool>?; var kills: Soft<String>?; var zram: Soft<Bool>?; var zswap: Soft<Bool>?
                             var all_procs: Soft<Bool>? }
/// The machine block the logger puts into current.json (`daemon.machine`): its kind and measures.
struct DaemonMachine: Decodable { var kind: String?; var measures: Soft<Measures>? }
struct RateProc: Decodable { var name: String?; var g: String?; var cpu: Double?; var gpu: Double?; var w: Double? }
struct Group: Decodable { var name: String; var mb: Int; var n: Int? }
struct Session: Decodable { var pid: Int; var cwd: String?; var mb: Int; var n: Int }
struct DaemonInfo: Decodable { var pid: Int?; var version: String?; var interval: Double?; var incident: String?; var root: Bool?
                               var machine: Soft<DaemonMachine>?; var all_procs: Soft<Bool>? }
/// current.json's pools as the verdict reads them (NET 12.8): a metered network's quota, its cap and what this
/// machine used this period (GB), and when it resets.
/// `to` and `label` are only the tooltip's: a mistyped one costs that word, never the warning (as oomph.quota_low).
struct QuotaPool: Decodable { var cap: Double?; var used: Double?; var to: Soft<Double>?; var label: Soft<String>? }
struct PoolsBlock: Decodable {
    var quota: Soft<QuotaPool>?
    enum CodingKeys: String, CodingKey { case quota = "net.quota" }
}

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
    // the other resources (1.9.1) and what the verdict reads besides memory; never a reason to drop the sample
    var cpu: Soft<CPUBlock>?
    var gpu: Soft<[GPUBlock]>?
    var disks: Soft<[DiskPool]>?
    var top_cpu: Soft<[RateProc]>?
    var top_gpu: Soft<[RateProc]>?
    var top_io: Soft<[RateProc]>?
    var unowned_gb: Soft<Double>?
    var os: Soft<String>?
    var linux: Soft<LinuxBlock>?
    // a Linux sample's own (03 §3.9): stall time, a cgroup's scope, file cache and unused memory
    var psi: Soft<PSIBlock>?
    var scope: Soft<ScopeBlock>?
    var cached_gb: Soft<Double>?
    var free_gb: Soft<Double>?
    // what only current.json has: the pools (02 §5.2); the verdict reads a metered network's quota (NET 12.8)
    var pools: Soft<PoolsBlock>?

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
    var psi: Soft<PSIBlock>?
}

/// One line of events.jsonl, reduced to what the chart's hover tooltip shows.
struct ChartEvent {
    let t: Double
    let kind: String
    let text: String
    var kills = 0
    var top: [String: Int] = [:]
    var seconds = 0.0
    /// An oom_kill that is no news: kills only at a cgroup's own limit, routine on a container host (03 §5.6;
    /// oomph.calm_event).
    var calm = false
    /// An oom_kill's own counts (kills, cgroup, by, top), for the hover's merged line.
    var raw: [String: Any] = [:]
    var alarming: Bool {
        kind == "oom_kill" ? !calm
            : ["jetsam", "stall", "unowned_memory", "disk_low", "disk_filling", "pressure_flapping", "daemon_error"].contains(kind)
    }
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
        case "oom_kill":  // a Linux machine's (03 §3.9): named, counted, or at a cgroup's own limit
            let k = LinuxTab.killText(e)
            text = k.0; calm = k.1; kills = k.2; top = k.3
            raw = e.filter { ["kills", "cgroup", "by", "top"].contains($0.key) }
        case "limit_stall":
            let who = ["cgroup", "name"].lazy.compactMap { e[$0] as? String }.first { !$0.isEmpty } ?? "a container"
            text = String(who.prefix(64)) + " stalled at its limit"
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
    // the other resources, with the resources on (roadmap 02 §8); NaN where a sample has none. A bucket keeps
    // the mean and the peak of the rates, the most GPU memory and the least free disk (02 §3.4.3)
    var cpu: Float = .nan, cpuPeak: Float = .nan, cpuSys: Float = .nan, cpuN: Float = .nan
    var gpu: Float = .nan, gpuPeak: Float = .nan, gpuBusy: Float = .nan, gpuMem: Float = .nan
    /// 0 no GPU figure, 1 busy time only, 2 at full speed (IOReport): a bucket never averages the two (02 §3.4.11)
    var gpuKind: UInt8 = 0
    var disk: Float = .nan
    /// A Linux machine's stall time (PSI, % of 10 s; 03 §5.3): "some", "full" and what was taken out at a container's
    /// own limit; NaN where a sample has none (a Mac's). A bucket keeps the highest of each (L3, the hover's line).
    var stall: Float = .nan, stallFull: Float = .nan, stallLimit: Float = .nan

    var used: Double { wired + app + comp }

    /// One sample's resource blocks into this point (ChartSampleR).
    mutating func take(_ r: ChartSampleR) {
        if let c = r.cpu?.v {
            if let b = c.busy { cpu = Float(b); cpuPeak = Float(b) }
            if let x = c.sys { cpuSys = Float(x) }
            if let n = c.n { cpuN = Float(n) }
        }
        if let g = r.gpu?.v?.first {
            if let u = g.util { gpu = Float(u); gpuPeak = Float(u); gpuKind = g.src == "ioreport" ? 2 : 1 }
            if let a = g.active { gpuBusy = Float(a) }
            if let m = g.mem_gb { gpuMem = Float(m) }
        }
        if let d = Tile.pool(r.disks?.v).pool?.free_gb { disk = Float(d) } else if let d = r.disk_free_gb { disk = Float(d) }
    }

    /// The resource fields of a bucket (Store.worst keeps memory's worst point and its time).
    mutating func aggregate(_ slice: ArraySlice<Point>) {
        func mean(_ xs: [Float]) -> Float { xs.isEmpty ? .nan : xs.reduce(0, +) / Float(xs.count) }
        let c = slice.filter { !$0.cpu.isNaN }
        cpu = mean(c.map(\.cpu)); cpuSys = mean(c.compactMap { $0.cpuSys.isNaN ? nil : $0.cpuSys })
        cpuPeak = c.map { max($0.cpu, $0.cpuPeak.isNaN ? $0.cpu : $0.cpuPeak) }.max() ?? .nan
        cpuN = c.map(\.cpuN).filter { !$0.isNaN }.max() ?? .nan
        let kind = slice.last { $0.gpuKind > 0 }?.gpuKind ?? 0
        let g = slice.filter { $0.gpuKind == kind && kind > 0 }
        gpuKind = kind
        gpu = mean(g.map(\.gpu)); gpuBusy = mean(g.compactMap { $0.gpuBusy.isNaN ? nil : $0.gpuBusy })
        gpuPeak = g.map { max($0.gpu, $0.gpuPeak.isNaN ? $0.gpu : $0.gpuPeak) }.max() ?? .nan
        gpuMem = slice.map(\.gpuMem).filter { !$0.isNaN }.max() ?? .nan
        disk = slice.map(\.disk).filter { !$0.isNaN }.min() ?? .nan
    }
}

/// What a history line carries besides memory, decoded only with the resources on.
struct ChartSampleR: Decodable {
    var cpu: Soft<CPUBlock>?
    var gpu: Soft<[GPUBlock]>?
    var disks: Soft<[DiskPool]>?
    var disk_free_gb: Double?
}

/// One reservation of the agents' memory ledger: live (ledger.json) or finished (reservations.jsonl).
struct Reservation: Identifiable {
    let id: String                       // "r12@1795172655": unique across ledger resets
    let rid: String                      // "r12"
    var purpose: String
    var project: String?
    var holder: String?                  // session / process / run
    var user: String?                    // the account that asked (03 §6.5; the ledger open to every account)
    var segments: [(t: Double, gb: Double)]  // its size over time (one entry unless edited)
    var requested: Double
    var granted: Double?
    var ended: Double?                   // nil while live
    var outcome: String?
    var peak = 0.0
    var used: Double?
    var expires: Double?
    var queue: Int?                      // its place in ledger.json's list of leases: the queue's order
    var agentSlot = -1                   // its agent's place in the palette (D11), -1 "agent not known"
    var agentKey: String?                // its agent's key, whose first four digits the card names
    // What it holds besides memory (02 §6.2; B3, 1.12.3; drawn with the resources on): Reservation.vector,
    // oomph_view.res_vector. Cores and GB of disk granted (asked while queued), nil where not held.
    var holdsMemory = true               // a vector without `ram` whose gb is the 0.01 mirror holds none
    var cpu: Double?
    var disk: Double?
    var diskPool: String?
    var diskName: String?
    var cpuUsed: Double?
    var diskWrote: Double?               // what its trees wrote since the grant (res.disk.w)
    var flags: [Resource: (flag: String, since: Double?)] = [:]  // a grant's advice: over, idle (02 §6.3)
    var waitingFor: [Resource] = []      // a queued one: what it waits for (waiting_on), in tile order
    var resSegs: [Resource: [(t: Double, v: Double)]] = [:]     // cores and disk over time (segments[].res)

    var live: Bool { ended == nil }
    var gb: Double { segments.last?.gb ?? 0 }
    func gb(at t: Double) -> Double { (segments.last { $0.t <= t } ?? segments.first)?.gb ?? 0 }
    var projectName: String? { project.map { ($0 as NSString).lastPathComponent }.flatMap { $0.isEmpty ? nil : $0 } }

    /// Colours avoid the memory chart's grey, blue, orange and red. The same purpose always gets the
    /// same colour (a stable hash, not Swift's per-launch one), in the blocks and in the list.
    static let palette: [Color] = [.teal, .purple, .pink, .indigo, Color(red: 0.84, green: 0.62, blue: 0.0), .brown, .green]
    var color: Color { Reservation.palette[Reservation.colorIndex(purpose)] }
    /// With the resources on, every reservation wears its agent's colour (D11, 02 §3.8.3): three hues kept away
    /// from the resource and state hues, then the same three a step lighter; gray for an agent not known (a
    /// record written before the key existed). Light and dark tones differ, so the scheme is passed in.
    static let agentLight: [Color] = [0x0E9021, 0x8A3D24, 0x986AC5, 0x7BC98A, 0xD08A5E, 0xCDA0EE].map(Reservation.rgb)
    static let agentDark: [Color] = [0x7E9A2E, 0x9C4B36, 0x9580C4, 0xB5CF70, 0xD99A82, 0xCBB0F5].map(Reservation.rgb)
    static func rgb(_ h: Int) -> Color {
        Color(red: Double((h >> 16) & 0xFF) / 255, green: Double((h >> 8) & 0xFF) / 255, blue: Double(h & 0xFF) / 255)
    }
    func agentColor(dark: Bool) -> Color {
        guard agentSlot >= 0 else { return dark ? Reservation.rgb(0x6E6E73) : Reservation.rgb(0xA3A3A8) }
        return (dark ? Reservation.agentDark : Reservation.agentLight)[agentSlot]
    }
    /// The colour a block, a row's swatch and the card wear: the purpose's, or with the resources on the agent's.
    func tint(dark: Bool) -> Color { resourcesUIOn ? agentColor(dark: dark) : color }
    /// An `agent` {key, slot} as the ledger and the history log hold it: its palette slot, or -1 for "agent not
    /// known" (oomph_view.agent_index; tools/vectors/chart.json): a key of 8 hex digits and an integer slot 0–5.
    static func agentIndex(_ a: Any?) -> Int {
        guard let d = a as? [String: Any], let k = d["key"] as? String, k.count == 8,
              k.allSatisfy({ "0123456789abcdef".contains($0) }), let n = d["slot"] as? NSNumber,
              CFGetTypeID(n) != CFBooleanGetTypeID(), !CFNumberIsFloatType(n), (0..<6).contains(n.intValue) else { return -1 }
        return n.intValue
    }

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
    /// With `flagsFirst` (the resources on, 02 §3.4.6) a grant with an `over` or `idle` flag comes before them all.
    static func listOrder(_ live: [Reservation], flagsFirst: Bool = false) -> [Reservation] {
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
        if flagsFirst { return granted.filter { !$0.flags.isEmpty } + waiting + granted.filter { $0.flags.isEmpty } }
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
        user = (o["user"] as? String).flatMap { $0.isEmpty ? nil : String($0.prefix(32)) }
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
        agentSlot = Reservation.agentIndex(o["agent"])
        agentKey = ((o["agent"] as? [String: Any])?["key"] as? String).flatMap { $0.count == 8 ? $0 : nil }
        readVector(o)
    }

    // MARK: its resources (B3, 1.12.3; 02 §3.4.5, §3.4.6, §3.7.7; held to oomph_view by tools/vectors/chart.json)

    /// An amount of the shared ledger, which any user can write: a finite number 0 … 1e6, else nil.
    static func amt(_ x: Any?) -> Double? {
        guard let n = x as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return nil }
        let d = n.doubleValue
        return d.isFinite && d >= 0 && d <= 1e6 ? d : nil
    }
    static func since(_ x: Any?) -> Double? {
        guard let n = x as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return nil }
        let d = n.doubleValue
        return d.isFinite && d > 0 && d < 1e11 ? d : nil
    }
    /// The resource of a pool id in `waiting_on` (02 §6.4): ram, mem and "critical" are memory's; cpu; gpu, vram; disk:<id>.
    /// nil for the network's pools (net.down, net.up: NET 1.15, no tile of its own yet), never taken for disk.
    static func waited(_ id: String) -> Resource? {
        if id.hasPrefix("net.") { return nil }
        return id == "ram" || id == "mem" || id == "critical" ? .memory : id == "cpu" ? .cpu
            : id.hasPrefix("gpu") || id.hasPrefix("vram") ? .gpu : .disk
    }

    /// oomph_view.res_vector: what a lease (`res` of parts) or a record (`res` of amounts) holds besides its gb.
    mutating func readVector(_ o: [String: Any]) {
        let isGranted = granted != nil
        let open = ended == nil
        func waits(_ deflt: [String]) {
            guard !isGranted && open else { return }
            let w = ((o["waiting_on"] as? [Any]) ?? []).prefix(16).compactMap { $0 as? String }
            let got = Set((w.isEmpty ? deflt : w).compactMap(Reservation.waited))
            waitingFor = Resource.allCases.filter { got.contains($0) }
        }
        guard let res = o["res"] as? [String: Any] else { waits(["ram"]); return }
        let lease = res.values.contains { $0 is [String: Any] }
        holdsMemory = res["ram"] != nil || (Reservation.amt(o["gb"]) ?? 0) > 0.015
        func s(_ x: Any?) -> String? { (x as? String).map { String($0.prefix(200)) } }
        if lease {
            for (k, r) in [("cpu", Resource.cpu), ("disk", Resource.disk)] {
                let part = (res[k] as? [String: Any]) ?? [:]
                let a = (isGranted ? Reservation.amt(part["got"]) : nil) ?? Reservation.amt(part["ask"])
                if r == .cpu { cpu = a } else { disk = a }
                if a != nil, isGranted, let f = part["flag"] as? String, f == "over" || f == "idle" {
                    flags[r] = (f, Reservation.since(part[f == "over" ? "over_t" : "low_t"]))
                }
            }
            let d = (res["disk"] as? [String: Any]) ?? [:]
            if disk != nil { diskPool = s(d["pool"]); diskName = s(d["name"]) }
            cpuUsed = Reservation.amt((res["cpu"] as? [String: Any])?["used"])
            diskWrote = Reservation.amt(d["w"])
        } else {
            cpu = Reservation.amt(res["cpu"]); disk = Reservation.amt(res["disk"])
            if disk != nil { diskPool = s(res["disk_pool"]) }
        }
        for (k, r) in [("cpu", Resource.cpu), ("disk", Resource.disk)] where (r == .cpu ? cpu : disk) != nil {
            let seq = ((o["segments"] as? [[String: Any]]) ?? []).compactMap { sg -> (t: Double, v: Double)? in
                guard let t = (sg["t"] as? NSNumber)?.doubleValue, let x = Reservation.amt((sg["res"] as? [String: Any])?[k])
                else { return nil }
                return (t, x)
            }
            if !seq.isEmpty { resSegs[r] = seq }
        }
        var asked: [String] = holdsMemory ? ["ram"] : []
        if cpu != nil { asked.append("cpu") }
        if disk != nil { asked.append("disk") }
        waits(asked)
    }

    /// Does it hold resource k (the disk: on `pool`, when one is named)?
    func holds(_ k: Resource, pool: String? = nil) -> Bool {
        switch k {
        case .memory: return holdsMemory
        case .cpu: return cpu != nil
        case .gpu: return false
        case .disk: return disk != nil && (pool == nil || diskPool == pool)
        }
    }
    /// Its amount of k over time, the first from its request.
    func amountSegs(_ k: Resource) -> [(t: Double, v: Double)] {
        if k == .memory { return segments.map { ($0.t, $0.gb) } }
        return resSegs[k] ?? [(requested, (k == .cpu ? cpu : disk) ?? 0)]
    }
    func amount(_ k: Resource, at t: Double) -> Double {
        if k == .memory { return gb(at: t) }
        let s = amountSegs(k)
        return (s.last { $0.t <= t } ?? s.first)?.v ?? 0
    }

    /// The strip's bands (02 §3.4.5, §3.7.6): of the resources shown, those reserved in the 14 days kept, the focus's
    /// first (the tall one), then the others in tile order. The Disk band is the tile's pool's.
    static let bandResources: [Resource] = [.memory, .cpu, .disk]
    static func bands(_ rs: [Reservation], shown: [Resource], focus: Resource, pool: String?) -> [Resource] {
        let have = bandResources.filter { k in shown.contains(k) && rs.contains { $0.holds(k, pool: pool) } }
        return (have.contains(focus) ? [focus] : []) + have.filter { $0 != focus }
    }
    /// A band's scale: the strip's round figures; GB of disk go on up to 64 TB.
    static func bandTop(_ vis: Double, _ k: Resource) -> Double {
        if k == .disk && vis > 256 {
            return [384.0, 512, 768, 1024, 1536, 2048, 3072, 4096, 8192, 16384, 32768, 65536].first { $0 >= vis } ?? vis
        }
        return MemoryChart.stripTop(vis)
    }

    static let word: [Resource: String] = [.memory: "memory", .cpu: "CPU", .gpu: "GPU", .disk: "disk"]
    static func amtG(_ x: Double) -> String { abs(x - x.rounded()) < 0.05 ? "\(Int(x.rounded()))G" : String(format: "%.1fG", x) }
    static func coresWords(_ x: Double) -> String {
        var t = String(format: "%.1f", x)
        if t.hasSuffix(".0") { t.removeLast(2) }
        return t + (t == "1" ? " core" : " cores")
    }
    static func and(_ w: [String]) -> String { w.count <= 1 ? (w.first ?? "") : w.dropLast().joined(separator: ", ") + " and " + w.last! }

    /// Every amount of a row as text (02 §3.8.5): "5G · 6 cores · 20G disk"; disk on another pool is named.
    func amountsText(pool: String?) -> String {
        var parts: [String] = []
        if holdsMemory { parts.append(Reservation.amtG(gb)) }
        if let c = cpu { parts.append(Reservation.coresWords(c)) }
        if let d = disk {
            let other = pool != nil && diskPool != nil && diskPool != pool
            parts.append(Reservation.amtG(d) + " " + (other ? Tile.midFit(diskName ?? diskPool ?? "?", 12) : "disk"))
        }
        return parts.isEmpty ? "–" : parts.joined(separator: " · ")
    }
    /// One use figure of a grant: "using 2.1G", "using 5.2 cores", "wrote 11G of 20G"; nil where not measured.
    func useFigure(_ k: Resource) -> String? {
        switch k {
        case .memory: return String(format: "using %.1fG", used ?? 0)
        case .cpu: return cpuUsed.map { "using " + Reservation.coresWords($0) }
        case .disk:
            guard let w = diskWrote, let d = disk else { return nil }
            let text: String = "wrote " + Reservation.amtG(w)
            return text + " of " + Reservation.amtG(d)
        case .gpu: return nil
        }
    }
    /// The status column (02 §3.4.6, §3.7.7): "waiting 40 s · for CPU"; a grant's flag ("over", "idle 12 min", "over on
    /// CPU" when not about the focus), one use figure (the focus's, else the first shown one's; none after idle), the time left.
    func statusText(shown: [Resource], focus: Resource, now: Double) -> String {
        if granted == nil {
            let w = waitingFor.compactMap { Reservation.word[$0] }
            return "waiting " + MemoryChart.duration(now - requested) + (w.isEmpty ? "" : " · for " + Reservation.and(w))
        }
        var parts: [String] = []
        var idle = false
        let order: [Resource] = [focus] + Resource.allCases
        if let fk = order.first(where: { flags[$0] != nil }), let f = flags[fk] {
            var word: String = f.flag
            if fk != focus { word += " on " + (Reservation.word[fk] ?? "") }
            if f.flag == "idle", let t = f.since { word += " " + MemoryChart.duration(now - t) }
            parts.append(word)
            idle = f.flag == "idle"
        }
        let held: [Resource] = Resource.allCases.filter { holds($0) }
        if !idle, let first = held.first {
            let u: Resource = held.contains(focus) ? focus : (held.first { shown.contains($0) } ?? first)
            if let fig = useFigure(u) { parts.append(fig) }
        }
        if let e = expires { parts.append(MemoryChart.shortDuration(e - now) + " left") }
        return parts.joined(separator: " · ")
    }
    /// The granted totals of `which` over rs, as words: "14.0 GB", "6 cores", "20 GB disk".
    static func totals(_ rs: [Reservation], _ which: [Resource]) -> [String] {
        let g = rs.filter { $0.granted != nil }
        var out: [String] = []
        if which.contains(.memory), g.contains(where: \.holdsMemory) {
            out.append(String(format: "%.1f GB", g.filter(\.holdsMemory).reduce(0) { $0 + $1.gb }))
        }
        if which.contains(.cpu), g.contains(where: { $0.cpu != nil }) {
            let n: Double = g.reduce(0.0) { (a: Double, r: Reservation) in a + (r.cpu ?? 0) }
            out.append(coresWords(n))
        }
        if which.contains(.disk), g.contains(where: { $0.disk != nil }) {
            let n: Double = g.reduce(0.0) { (a: Double, r: Reservation) in a + (r.disk ?? 0) }
            out.append(String(amtG(n).dropLast()) + " GB disk")
        }
        return out
    }
    /// The caption (02 §3.7.7): the shown resources' live grants summed, and the last 24 h: "14.0 GB · 6 cores · 46 in the last 24 h".
    static func captionText(_ live: [Reservation], shown: [Resource], day: Int) -> String {
        (totals(live, shown) + ["\(day) in the last 24 h"]).joined(separator: " · ")
    }
    /// The line for what holds no shown resource: "On other resources: 6 cores and 20 GB disk reserved · 1 waiting for CPU";
    /// short "Other: 6 cores, 20 GB disk · 1 waiting". nil when there is nothing.
    static func otherText(_ rest: [Reservation], short: Bool) -> String? {
        guard !rest.isEmpty else { return nil }
        let tot = totals(rest, Resource.allCases)
        let waiting = rest.filter { $0.granted == nil }
        let what = Resource.allCases.filter { k in waiting.contains { $0.waitingFor.contains(k) } }.compactMap { word[$0] }
        let sep: String = !tot.isEmpty && !waiting.isEmpty ? " · " : ""
        let count: String = waiting.isEmpty ? "" : "\(waiting.count) waiting"
        if short { return "Other: " + tot.joined(separator: ", ") + sep + count }
        let reserved: String = tot.isEmpty ? "" : and(tot) + " reserved"
        let forWhat: String = waiting.isEmpty || what.isEmpty ? "" : " for " + and(what)
        return "On other resources: " + reserved + sep + count + forWhat
    }
    /// The words of a grant's advice on resource k (the card): "over on CPU since 13:26: it uses more than it got".
    static func adviceWords(_ k: Resource, _ f: (flag: String, since: Double?), now: Double, clock: (Double) -> String) -> String {
        var text: String = f.flag + " on " + (word[k] ?? "")
        if f.flag == "idle" {
            if let t = f.since { text += " for " + MemoryChart.duration(now - t) }
            return text + ": it could be released or made smaller"
        }
        if let t = f.since { text += " since " + clock(t) }
        return text + ": " + (k == .disk ? "it wrote more than it reserved" : "it uses more than it got")
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

    /// `kind`: the band's resource (its amounts over time); the caller passes the reservations that hold it.
    static func stack(_ rs: [Reservation], now: Double, kind: Resource = .memory) -> [ResBlock] {
        // by request, then id: `rs` comes out of a Dictionary, whose order changes with every launch
        var blocks = rs.sorted { a, b in
            let ka: (Double, String) = (a.requested, a.id), kb: (Double, String) = (b.requested, b.id)
            return ka < kb
        }
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
            if kind == .memory {
                for s in b.res.segments where s.t > b.res.requested && s.t < b.end { bps.insert(s.t) }
            } else {
                for s in b.res.amountSegs(kind) where s.t > b.res.requested && s.t < b.end { bps.insert(s.t) }
            }
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
                let hi = acc + (kind == .memory ? blocks[j].res.gb(at: a) : blocks[j].res.amount(kind, at: a))
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
    /// A Linux machine's containers at their own limit (03 §5.6): kept, never news.
    var quiet: Bool?
    var dir: String = ""
    enum CodingKeys: String, CodingKey { case id, start, end, open, reasons, summary, quiet }
}

enum Pressure: Int { case unknown = 0, normal = 1, warn = 2, critical = 4
    var label: String { switch self { case .normal: "Normal"; case .warn: "Warning"; case .critical: "Critical"; default: "–" } }
    var color: Color { switch self { case .warn: .yellow; case .critical: .red; default: .green } }
}

// MARK: - Four resources (roadmap 02 §3.7, §3.8; 1.11.0, behind resourcesUI)

/// The resources a tile shows, in tile order. `oomph top` has the same (oomph_view.RESOURCES).
enum Resource: String, CaseIterable {
    case memory, cpu, gpu, disk
    var name: String { ["memory": "Memory", "cpu": "CPU", "gpu": "GPU", "disk": "Disk"][rawValue]! }
    var letter: String { String(rawValue.prefix(1)) }
    /// The resource hues (02 §3.4): blue, teal, violet, magenta. Agents never wear them (§3.8.3).
    var color: Color {
        switch self {
        case .memory: Color(red: 0.0, green: 0.53, blue: 1.0)
        case .cpu: Color(red: 0.0, green: 0.66, blue: 0.70)
        case .gpu: Color(red: 0.62, green: 0.36, blue: 0.95)
        case .disk: Color(red: 0.90, green: 0.25, blue: 0.62)
        }
    }
    var unit: String { ["memory": "GB", "cpu": "cores", "gpu": "%", "disk": "GB"][rawValue]! }

    /// The tiles a machine shows: every resource, except a GPU the logger looked for and found none of
    /// (`gpu: []`, a VM). Without the blocks (a logger older than 1.9.1, or none) the tiles stay and say "–".
    static func available(_ s: Sample?) -> [Resource] {
        Resource.allCases.filter { !($0 == .gpu && s?.gpu?.v?.isEmpty == true) }
    }
}

/// The selection of 02 §3.7.1: the resources shown (a set, in tile order, never empty) and the focus, which has
/// the big chart. Held to `oomph top`'s by tools/vectors/chart.json (oomph_view.selection_apply).
struct Selection: Equatable {
    var shown: [Resource]
    var focus: Resource
    enum Gesture: String { case click, cmd, shift }
    enum Outcome: String { case changed, callout, refused, none }

    /// A remembered selection as drawn: what is not available is skipped (and comes back with it), an
    /// unavailable focus gives way to the first shown, nothing at all is Memory alone (§3.7.9).
    static func shown(_ sel: [Resource], focus: Resource, available: [Resource]) -> Selection {
        var shown = Resource.allCases.filter { sel.contains($0) && available.contains($0) }
        if shown.isEmpty { shown = [.memory] }
        return Selection(shown: shown, focus: shown.contains(focus) ? focus : shown[0])
    }

    /// A gesture on a tile (§3.7.2): a click shows a resource alone (on the focus alone: the callout), a ⌘-click
    /// adds or removes one (the last one is refused), a ⇧-click adds the run from the focus. Only a click
    /// moves the focus, or removing it, which hands it to the next shown resource, wrapping round.
    func apply(_ g: Gesture, _ r: Resource, available: [Resource]) -> (Selection, Outcome) {
        let order = Resource.allCases
        guard available.contains(r) else { return (self, .none) }
        switch g {
        case .click:
            if r != focus { return (Selection(shown: [r], focus: r), .changed) }
            return shown.count > 1 ? (Selection(shown: [focus], focus: focus), .changed) : (self, .callout)
        case .cmd:
            if !shown.contains(r) { return (Selection(shown: order.filter { shown.contains($0) || $0 == r }, focus: focus), .changed) }
            if r != focus { return (Selection(shown: shown.filter { $0 != r }, focus: focus), .changed) }
            if shown.count == 1 { return (self, .refused) }
            let i = shown.firstIndex(of: r)!
            return (Selection(shown: shown.filter { $0 != r }, focus: shown[(i + 1) % shown.count]), .changed)
        case .shift:
            if r == focus { return (self, .none) }
            let avail = order.filter { available.contains($0) }
            let a = avail.firstIndex(of: focus) ?? 0, b = avail.firstIndex(of: r) ?? 0
            let run = avail[min(a, b)...max(a, b)]
            let out = order.filter { shown.contains($0) || run.contains($0) }
            return out == shown ? (self, .none) : (Selection(shown: out, focus: focus), .changed)
        }
    }
}

/// oomph's verdict, as the capsule and the menu-bar chip show it (02 §3.4.9, §3.5, §15.13): oomph.py's
/// `capsule` over `_verdict_parts`, held together by tools/vectors/chart.json, so the chip agrees with
/// `oomph check`. The machine-wide verdict: no one caller's coordination, no pins.
enum Verdict {
    struct Capsule: Equatable { var text: String; var level: Int; var memory: Int; var disk: Int; var network: Int = 0 }

    /// GB left of a metered network's cap while under 10 % of it (oomph.quota_low; NET D-N13): the one network
    /// state the capsule shows (D-N20). nil otherwise, and for figures oomph could not have written.
    static func quotaLeft(_ s: Sample) -> Double? {
        guard let q = s.pools?.v?.quota?.v, let cap = q.cap, let used = q.used, cap.isFinite, used.isFinite,
              cap >= 0.1, cap <= 100000, used >= 0, used <= 1e6 else { return nil }
        let left: Double = cap - used
        return left < 0.1 * cap ? max(0, left) : nil
    }

    /// The capsule tooltip's line about a metered network under 10 % (NET 12.15), on a Mac's tab and a Linux
    /// machine's: what is left, until when, and the command. nil while it is not under 10 %.
    static func quotaHelp(_ s: Sample) -> String? {
        guard let left = quotaLeft(s), let q = s.pools?.v?.quota?.v, let cap = q.cap else { return nil }
        let label: String? = q.label?.v
        let name: String = (label?.isEmpty == false) ? "the metered network " + String(label!.prefix(32)) : "this metered network"
        var until = ""
        if let t = q.to?.v, t.isFinite, t > 0, t < 1e11 {
            let f = DateFormatter()
            f.locale = Locale(identifier: "en_US_POSIX")   // "14 Dec", as the hook and `oomph net` say it
            f.dateFormat = "d MMM"
            until = " until " + f.string(from: Date(timeIntervalSince1970: t))
        }
        return String(format: "%@: %.1f of %g GB left%@ (oomph net)", name, left, cap, until)
    }

    static func capsule(_ s: Sample) -> Capsule {
        let os = s.os?.v ?? "macos"
        let mac = os == "macos", lin = os == "linux"
        let ram = s.ram_gb
        let free = (max(0, s.ram_gb - s.app_gb - s.wired_gb - s.compressed_gb) * 10).rounded() / 10
        let disk = s.disk_free_gb
        let swapFull = s.swap_total_gb > 0 && s.swap_used_gb >= 0.9 * s.swap_total_gb
        var mem = 0, dsk = 0
        if s.pressure >= 4 { mem = 2 } else if s.pressure >= 2 { mem = 1 }
        if mac && disk < 5 { dsk = 2 } else if mac && disk < 20 { dsk = 1 }
        if mac && swapFull && disk < 20 { mem = 2 }
        if ram > 0 && free < 0.05 * ram && !lin { mem = max(mem, 1) }
        // strict overcommit near its limit: allocations are about to fail (a finite, sane figure, as oomph._num)
        if lin, s.linux?.v?.overcommit?.v == 2, let c = s.linux?.v?.commit_pct?.v, c.isFinite, c >= 95, c <= 1e15 {
            mem = max(mem, 1)
        }
        if (s.jetsam_kills ?? 0) > 0 { mem = max(mem, 1) }
        if let u = s.unowned_gb?.v, ram > 0, u >= max(16.0, 0.4 * ram) { mem = max(mem, 1) }
        let left = quotaLeft(s)
        let net = left == nil ? 0 : 1
        let worst: Int = max(mem, dsk, net)
        var text: String = "Normal"
        if worst == 0 {
            text = "Normal"
        } else if mem == worst {
            text = mem == 2 ? "Memory critical" : "Memory tight"
        } else if dsk == worst {
            text = dsk == 2 ? "Disk critical" : "Disk low"
        } else {
            text = String(format: "Network %.1f GB left", left ?? 0)
        }
        return Capsule(text: text, level: worst, memory: mem, disk: dsk, network: net)
    }

    static func color(_ level: Int) -> Color { level >= 2 ? .red : level == 1 ? .yellow : .green }

    /// The resource the popup opens on when something is critical (§3.4.9, §3.7.9), memory first. Only
    /// Critical steers the opening (D9): a standing tight or low stays on the capsule and the tile.
    static func trouble(_ c: Capsule) -> Resource? { c.memory == 2 ? .memory : c.disk == 2 ? .disk : nil }
}

/// What a tile says (02 §3.4.1; oomph_view.tiles, held together by tools/vectors/chart.json).
struct Tile {
    var reading = "–"
    var flag: String?           // the one flag slot
    var level = 0               // 2 red, 1 amber: the border and the glyph; 0 quiet
    var queue = 0               // requests waiting for this resource
    var top: String?            // the biggest consumer
    var meter = 0.0             // 0…1; a tank for Disk
    var full = false            // the GPU figure is at full speed

    /// The flag slot as drawn: a flag of rank 1 to 6 keeps the queue after it; a queue alone outranks busy.
    var flagText: String {
        if queue > 0 && (flag == nil || flag == "busy") { return "\(queue) waiting" }
        if let f = flag, queue > 0 { return "\(f) ◻\(queue)" }
        return flag ?? ""
    }

    /// The pool the Disk tile shows: the home folder's or the temp directory's, else the first watched one,
    /// else the first.
    static func pool(_ disks: [DiskPool]?) -> (pool: DiskPool?, at: Int?, pools: [DiskPool]) {
        let pools = (disks ?? []).filter { $0.free_gb != nil }
        let rules: [(DiskPool) -> Bool] = [{ ($0.roles ?? []).contains { $0 == "home" || $0 == "tmp" } },
                                           { $0.watch == true }, { _ in true }]
        for want in rules { if let i = pools.firstIndex(where: want) { return (pools[i], i, pools) } }
        return (nil, nil, pools)
    }

    static func busiest(_ rows: [RateProc]?, _ key: KeyPath<RateProc, Double?>) -> String? {
        var tot: [String: Double] = [:], order: [String] = []
        for x in rows ?? [] {
            guard let v = x[keyPath: key] else { continue }
            let name = (x.g?.isEmpty == false ? x.g : x.name) ?? ""
            if name.isEmpty { continue }
            if tot[name] == nil { order.append(name) }
            tot[name, default: 0] += v
        }
        var best: String?
        for k in order where best == nil || tot[k]! > tot[best!]! { best = k }
        return best
    }

    /// A name shortened in its middle to n characters (02 §3.4.2).
    static func midFit(_ t: String, _ n: Int) -> String {
        let c = Array(t)
        guard c.count > n else { return t }
        let a = n / 2
        return String(c[..<a]) + "…" + String(c[(c.count - (n - 1 - a))...])
    }

    static func facts(_ s: Sample, _ cap: Verdict.Capsule, waiting: [Resource: Int] = [:]) -> [Resource: Tile] {
        var out: [Resource: Tile] = [:]
        let used = s.app_gb + s.wired_gb + s.compressed_gb
        out[.memory] = Tile(reading: String(format: "%.1f / %.0f GB", used, s.ram_gb),
                            flag: cap.memory == 2 ? "critical" : cap.memory == 1 ? "tight" : nil, level: cap.memory,
                            top: s.groups?.first(where: { !$0.name.isEmpty })?.name, meter: s.ram_gb > 0 ? used / s.ram_gb : 0)
        let c = s.cpu?.v
        var t = Tile(top: busiest(s.top_cpu?.v, \.cpu))
        if let n = c?.n, n > 0, let b = c?.busy {
            // never Int(n): another machine's sample may say 1e300 cores (as Python's "%d", truncated)
            t.reading = String(format: "%.1f / %.0f cores", b, n.rounded(.towardZero)); t.meter = b / n
            if b >= 0.9 * n { t.flag = "busy" }
        }
        if (c?.therm ?? 0) >= 2 { t.flag = "throttled" }
        out[.cpu] = t
        let g = s.gpu?.v?.first
        t = Tile(top: busiest(s.top_gpu?.v, \.gpu))
        t.full = g?.src == "ioreport"
        if let u = g?.util {
            t.reading = String(format: "%.0f %%", u) + (t.full ? "" : " busy") + (g?.mem_gb.map { String(format: " · %.1f GB", $0) } ?? "")
            t.meter = u / 100
            if t.full && u >= 90 { t.flag = "busy" }
        }
        out[.gpu] = t
        let (d, at, pools) = pool(s.disks?.v)
        let free = d?.free_gb ?? s.disk_free_gb
        t = Tile(level: cap.disk, top: busiest(s.top_io?.v, \.w))
        t.flag = cap.disk == 2 ? "critical" : cap.disk == 1 ? "low" : nil
        if t.flag == nil {
            let others = pools.enumerated().filter { $0.offset != at && $0.element.watch == true }.map { $0.element.level }
            let k = others.filter { $0 == "critical" }.count, l = others.filter { $0 == "low" }.count
            if k > 0 { t.flag = "+\(k) critical"; t.level = 2 } else if l > 0 { t.flag = "+\(l) low"; t.level = 1 }
        }
        t.reading = String(format: "%.0f GB free", free)
        if let d, pools.count > 1 { t.reading += " · " + midFit((d.name?.isEmpty == false ? d.name : nil) ?? d.id ?? "?", 12) }
        if let tot = d?.total_gb, tot > 0 { t.meter = min(1, free / tot) }
        out[.disk] = t
        for r in Resource.allCases { out[r]!.queue = waiting[r] ?? 0 }
        return out
    }

    /// How many queued requests wait for each resource, from ledger.json's leases (oomph_view.waiting_on): a
    /// request without `waiting_on` (every writer before 1.12) waits for memory.
    static func waiting(_ leases: [[String: Any]]) -> [Resource: Int] {
        var out: [Resource: Int] = [:]
        for l in leases where (l["state"] as? String) == "queued" {
            let ids = ((l["waiting_on"] as? [Any]) ?? []).map { "\($0)" }
            let got = Set((ids.isEmpty ? ["ram"] : ids).compactMap(Reservation.waited))  // "critical": memory's
            for r in got { out[r, default: 0] += 1 }
        }
        return out
    }
}

// MARK: - A Linux tab (roadmap 03 §3.9, the Linux-tab gate; 1.13.3, behind machinesUI)

/// What a tab whose machine runs Linux says in place of the Mac's words: the tile matrix (a tile's meaning
/// follows facts of the machine, never its momentary state), Kernel for Wired, the OOM killer's kills, quiet
/// incidents folded, who holds a reservation, and the texts of a machine that is reached but has little to
/// show (states A to E). Pure functions over a sample and the machine's facts: `oomph --linux-vectors FILE`
/// runs them over tools/vectors/linux.json (tools/linuxvectors.py).
enum LinuxTab {
    /// The facts the tiles follow (03 §3.9 "Which figure goes where"): the machine's kind (a desktop or laptop
    /// has presence, a server or container stall time), whether stall time is measured (PSI), whether memory is
    /// compressed there (zram or zswap), how kills are seen, whether the logger sees every process.
    struct Facts: Equatable {
        var desktop = false
        var psi: Bool?
        var zram = false
        var zswap = false
        var kills: String?
        var allProcs: Bool?
        /// Whether it has swap (on disk; zram's own figures are its tile's): the chart has no Swap series without (L3)
        var swap = true
        var compressed: Bool { zram || zswap }

        init(desktop: Bool = false, psi: Bool? = nil, zram: Bool = false, zswap: Bool = false, kills: String? = nil, allProcs: Bool? = nil,
             swap: Bool = true) {
            self.desktop = desktop; self.psi = psi; self.zram = zram; self.zswap = zswap; self.kills = kills; self.allProcs = allProcs
            self.swap = swap
        }

        /// From the sample's own machine block, else from what the machine said when it was reached.
        init(_ s: Sample?, info: MachineInfo?) {
            let dm = s?.daemon?.machine?.v
            let ms = dm?.measures?.v ?? info?.measures?.v
            let kind = dm?.kind ?? info?.kind ?? "server"
            self.init(desktop: kind == "desktop" || kind == "laptop", psi: ms?.psi?.v, zram: ms?.zram?.v ?? false,
                      zswap: ms?.zswap?.v ?? false, kills: ms?.kills?.v, allProcs: s?.daemon?.all_procs?.v ?? ms?.all_procs?.v,
                      swap: s.map { $0.swap_total_gb > 0 || $0.swap_used_gb > 0 || ($0.swapfiles ?? 0) > 0 } ?? true)
        }
    }

    /// One tile: its figure, a small grey figure after it, its label, a line under it (the group tile's name),
    /// its tooltip, and whether the figure is red.
    struct Cell: Equatable {
        var label: String
        var value: String
        var small: String? = nil
        var sub: String? = nil
        var help = ""
        var red = false
    }

    static func gb(_ x: Double) -> String { String(format: "%.1f GB", x) }
    /// A stall figure: one decimal under 10 %, whole numbers above.
    static func pct(_ x: Double) -> String { x < 9.95 ? String(format: "%.1f %%", x) : String(format: "%.0f %%", x) }

    /// Does the stall pair fit the 96 pt column (03 §3.9 state 3)? Measured in the tile's own fonts.
    static func fits(_ value: String, _ small: String) -> Bool {
        let a = NSAttributedString(string: value, attributes: [.font: NSFont.monospacedDigitSystemFont(ofSize: 13, weight: .semibold)])
        let b = NSAttributedString(string: small, attributes: [.font: NSFont.systemFont(ofSize: 9.5)])
        let w: CGFloat = a.size().width + 4 + b.size().width
        return w <= statColumn
    }

    /// A Linux group's name as a tile shows it (03 §3.9 state 7): a container's program first and its runtime
    /// after it ("nginx · docker"), shortened in the middle beyond 22 characters; the full name is the tooltip's.
    static func groupName(_ n: String) -> String {
        var out = n
        let re = try! NSRegularExpression(pattern: #"^(docker|podman|pod):[^ ]+ \((.+)\)$"#)
        if let m = re.firstMatch(in: n, range: NSRange(n.startIndex..., in: n)),
           let kind = Range(m.range(at: 1), in: n), let prog = Range(m.range(at: 2), in: n) {
            out = String(n[prog]) + " · " + String(n[kind])
        }
        return Tile.midFit(out, 22)
    }

    /// The eight tiles of a Linux tab, in the Mac's places: App, the second (Available, or Compressed where
    /// memory is compressed), Kernel, RAM (or the cgroup's limit); swap (or zram), free disk, the seventh (stall
    /// time on a server, Idle on a desktop, what is available where PSI is off), the biggest group.
    static func tiles(_ s: Sample, _ f: Facts, name: String) -> [Cell] {
        let avail = max(0, s.ram_gb - s.app_gb - s.wired_gb - s.compressed_gb)
        let scope = s.scope?.v
        let cg = scope?.kind == "cgroup"
        var out: [Cell] = [Cell(label: "App memory", value: gb(s.app_gb))]
        if f.compressed {
            out.append(Cell(label: "Compressed", value: gb(s.compressed_gb),
                            help: "Compressed: RAM that holds compressed pages (zram, zswap)."))
        } else {
            var h = "Available: what processes can still get without swapping."
            if let c = s.cached_gb?.v, let u = s.free_gb?.v {
                h += String(format: " Of it %.1f GB is file cache that the kernel gives back on demand; %.1f GB is unused.", c, u)
            }
            out.append(Cell(label: "Available", value: gb(avail), help: h))
        }
        out.append(Cell(label: "Kernel", value: gb(s.wired_gb),
                        help: "Kernel: slab, page tables, drivers and reserves; what is neither app memory nor available."))
        // the RAM tile carries at most one small figure, by precedence: "N available" where the second tile is
        // Compressed, else the host's RAM in a cgroup's scope (then with both the host moves into the label)
        var ram = Cell(label: cg ? "Memory limit" : "RAM total", value: gb(s.ram_gb))
        let host = scope?.host_ram_gb
        if f.compressed {
            ram.small = String(format: "%.1f available", avail)
            if cg, let h = host { ram.label += String(format: " · host %.1f GB", h) }
        } else if cg, let h = host {
            ram.small = String(format: "host %.1f", h)
        }
        if cg {
            ram.help = String(format: "This logger runs inside a container: every figure is about the container's %.1f GB limit.", s.ram_gb)
                + (scope?.host_avail_gb.map { String(format: " The host has %.1f GB available.", $0) } ?? "")
        }
        out.append(ram)
        // swap, or zram where it is the machine's only swap: there zram's fullness drives the level
        let lx = s.linux?.v
        if f.zram && !f.zswap && (s.swapfiles ?? 0) == 0 && s.swap_total_gb < 0.05 {
            let help = "zram: swap kept compressed in RAM, this machine's only swap. How full it is counts towards the level."
            if let size = lx?.zram_disk_gb?.v, let tot = lx?.kswap_total_gb?.v, let free = lx?.kswap_free_gb?.v {
                let used = max(0, tot - free - s.swap_used_gb)
                out.append(Cell(label: "zram used / size", value: String(format: "%.1f / %.1f GB", used, size), help: help))
            } else {  // a logger before 1.13.3 does not send zram's figures: none rather than "0.0 / 0.0 GB"
                out.append(Cell(label: "zram used / size", value: "—",
                                help: help + " The \(brand) on this machine is too old to report zram's figures; a newer one does."))
            }
        } else {
            out.append(Cell(label: "Swap used / size", value: String(format: "%.1f / %.0f GB", s.swap_used_gb, s.swap_total_gb)))
        }
        out.append(Cell(label: "Free disk", value: String(format: "%.0f GB", s.disk_free_gb), red: s.disk_free_gb < 20))
        out.append(seventh(s, f, avail: avail))
        out.append(group(s, f, name: name))
        return out
    }

    /// The Memory tile of the four-resource row (layout C, 02 §3.7) on a Linux tab (gap G3, settled in 1.13.3):
    /// layout C keeps its four tiles; the eight tiles' words move into Memory's. The RAM (or the cgroup's limit)
    /// with its decimal, the biggest group by its Linux name (none where the logger sees only its own
    /// processes), and "stalled" in the flag slot where tasks wait for memory as the stall tile turns red and no
    /// graver flag is there. Kernel is the chart's legend's and hover's word already.
    static func memoryTile(_ t: Tile, _ s: Sample, _ f: Facts) -> Tile {
        var t = t
        t.reading = String(format: "%.1f / %.1f GB", s.app_gb + s.wired_gb + s.compressed_gb, s.ram_gb)
        t.top = f.allProcs == false ? nil : s.groups?.first(where: { !$0.name.isEmpty }).map { groupName($0.name) }
        if t.flag == nil, !f.desktop, f.psi != false, let p = s.psi?.v, let some = p.mem_some, some >= 10 || (p.mem_full ?? 0) >= 5 {
            t.flag = "stalled"
        }
        return t
    }

    /// The seventh tile: Idle on a desktop ("—" where it reports no idle time), stall time on a server in its
    /// three forms, or what is available where stall time is not measured (03 §3.9 states 1 to 4).
    static func seventh(_ s: Sample, _ f: Facts, avail: Double) -> Cell {
        if f.desktop {
            guard let idle = s.away?.idle_s else {
                return Cell(label: "Idle", value: "—",
                            help: "This desktop does not report idle time. A locked screen or a display that is off still counts as away.")
            }
            return Cell(label: "Idle", value: idle >= 120 ? "\(idle / 60) min" : "\(idle) s")
        }
        let p = s.psi?.v
        guard f.psi != false, let some = p?.mem_some else {
            let share = s.free_pct.map(Double.init) ?? (s.ram_gb > 0 ? 100 * avail / s.ram_gb : 0)
            return Cell(label: "of RAM available", value: String(format: "%.0f %%", share),
                        help: "Stall time is not measured on this kernel (PSI is off: boot with psi=1). The level comes from what is available, and stops at Warning.")
        }
        let full = p?.mem_full ?? 0
        var c = Cell(label: "Stalled on memory", value: pct(some), red: some >= 10 || full >= 5)
        c.help = "Tasks waited for memory " + pct(some) + " of the last 10 s" + (full >= 0.05 ? "; all of them at once (fully stalled) " + pct(full) : "") + "."
        if let lim = p?.limit?.v, let more = lim.some, more >= 0.05 {
            // stall time taken out for containers at their own limit: a quiet addition, never red (state 4)
            let who = lim.cgroups?.first.map { $0 } ?? "a container"
            c.small = "+" + pct(more) + " ▣"
            c.help += " " + pct(more) + " more inside \(who), which is at its own limit. That is the container's stall time, not this machine's."
        } else if full >= 0.05 {
            let tail = "· fully " + pct(full)
            c.small = fits(c.value, tail) ? tail : "●"   // the long form: the second figure is read in the tooltip
        }
        return c
    }

    /// The biggest group (a systemd unit, a container or a program with all its processes); "—" over "not
    /// visible" where the logger sees only its own processes (state D).
    static func group(_ s: Sample, _ f: Facts, name: String) -> Cell {
        if f.allProcs == false {
            return Cell(label: "biggest group", value: "—", sub: "not visible",
                        help: "The logger on \(name) sees only its own processes (/proc is mounted with hidepid). Groups, sessions and what a reservation uses are not known. `oomph doctor` there names the two ways to change that.")
        }
        guard let g = s.groups?.first(where: { !$0.name.isEmpty }) else { return Cell(label: "biggest group", value: "–", sub: "#1 –") }
        let size = Double(g.mb) / 1024
        return Cell(label: "biggest group", value: gb(size), sub: "#1 " + groupName(g.name),
                    help: "Biggest group: \(g.name) — " + gb(size) + (g.n.map { " in \($0) processes" } ?? "") + " · click for the biggest groups")
    }

    /// An oom_kill event (03 §5.5): "3 killed by the OOM killer: java ×2, node", by systemd-oomd or earlyoom when
    /// they did it, "(names not known)" where kills are only counted, and kills at a cgroup's own limit said so:
    /// alone ("6 killed at their cgroup's limit"), or after the machine's own ("5 killed by the OOM killer (+1 at
    /// their limit)"): those are the container's, not the machine's.
    /// (text, whether it is no news (oomph.calm_event: only kills at a limit), all kills, names)
    static func killText(_ e: [String: Any]) -> (String, Bool, Int, [String: Int]) {
        func int(_ x: Any?) -> Int { (x as? NSNumber).map { max(0, min($0.intValue, 1_000_000)) } ?? 0 }
        let machine = int(e["kills"]), atLimit = int(e["cgroup"]), all = machine + atLimit
        var top: [String: Int] = [:]
        for (k, v) in ((e["top"] as? [String: Any]) ?? [:]).prefix(64) where int(v) > 0 { top[String(k.prefix(64))] = int(v) }
        let by = ((e["by"] as? [String: Any]) ?? [:]).filter { $0.key != "cgroup" && int($0.value) > 0 }.map(\.key)
        let killer = by.count == 1 && by[0] == "systemd-oomd" ? "systemd-oomd" : by.count == 1 && by[0] == "earlyoom" ? "earlyoom"
            : "the OOM killer"
        let head = machine == 0 && atLimit > 0 ? "\(atLimit) killed at their cgroup's limit"
            : "\(max(machine, 1)) killed by \(killer)" + (atLimit > 0 ? " (+\(atLimit) at their limit)" : "")
        let names = top.sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }
        let calm = e["cgroup"] != nil && machine == 0
        guard !names.isEmpty else { return (head + " (names not known)", calm, all, top) }
        let list = names.prefix(3).map { $0.value > 1 ? "\($0.key) ×\($0.value)" : $0.key }.joined(separator: ", ")
        return (head + ": " + list + (names.count > 3 ? ", …" : ""), calm, all, top)
    }

    /// The oom_kill events of one pixel as one (the hover's line): the kills, those at a limit, the killers and
    /// the names added up; a cgroup count only where an event had one (oomph.calm_event).
    static func merged(_ es: [[String: Any]]) -> [String: Any] {
        func add(_ a: inout [String: Int], _ x: Any?) {
            for (k, v) in ((x as? [String: Any]) ?? [:]).prefix(64) { a[k, default: 0] += (v as? NSNumber)?.intValue ?? 0 }
        }
        var kills = 0, atLimit = 0, by: [String: Int] = [:], top: [String: Int] = [:]
        for e in es {
            kills += (e["kills"] as? NSNumber)?.intValue ?? 0; atLimit += (e["cgroup"] as? NSNumber)?.intValue ?? 0
            add(&by, e["by"]); add(&top, e["top"])
        }
        var out: [String: Any] = ["kind": "oom_kill", "kills": kills, "by": by, "top": top]
        if es.contains(where: { $0["cgroup"] != nil }) { out["cgroup"] = atLimit }
        return out
    }

    /// The incidents list of a tab (03 §3.9 state 9): the machine's own incidents, and the quiet ones (containers
    /// at their own limit) folded into one grey row for the latest with how many came before it, in date order.
    enum Row: Hashable { case incident(String), quiet(String, earlier: Int) }
    static func rows(_ incidents: [Incident], quiet: [Incident]) -> [Row] {
        var out: [(Double, Row)] = incidents.map { ($0.start, .incident($0.id)) }
        if let q = quiet.max(by: { $0.start < $1.start }) { out.append((q.start, .quiet(q.id, earlier: quiet.count - 1))) }
        return out.sorted { $0.0 > $1.0 }.map(\.1)
    }

    /// Whether the reservation rows say who holds them: once more than one account holds a live one (state 8).
    static func showsWho(_ live: [Reservation]) -> Bool { Set(live.compactMap(\.user)).count > 1 }

    /// A machine that is reached but has little to show (03 §3.9, states A to C), as the capsule, the status
    /// line and the remedy say it: A its logger stopped (`at`: when it last wrote), B this account may not
    /// read the logs, C nothing is logged there. (capsule, status line, title, text, the command to copy)
    enum Quiet: String { case stopped, denied, absent }
    static func remedy(_ q: Quiet, os: String?, name: String, user: String?, at: String) -> (String, String, String, String, String) {
        let lin = os == "linux"
        let who = user ?? "this Mac's account"
        switch q {
        case .stopped:
            if !lin {  // a Mac's: Activate in its app, or the command its doctor gives (with the reason)
                return ("No readings", "Connected, but its logger stopped at \(at)", "The logger on \(name) is not running.",
                        "It wrote its last reading at \(at). Start it there with Activate in its \(brand) app; the command below, run on \(name), says why it stopped and how to start it.",
                        "oomph doctor")
            }
            return ("No readings", "Connected, but its logger stopped at \(at)", "The logger on \(name) is not running.",
                    "It wrote its last reading at \(at). Start it there. If it stops again: journalctl -u oomphd -n 20 and oomph doctor on \(name) say why.",
                    "sudo systemctl restart oomphd")
        case .denied:
            return ("No access", "Connected, but \(who) may not read the logs there", "The logs on \(name) are closed to \(who).",
                    (user.map { "This Mac connects as \($0), who may not read them there." } ?? "This Mac may not read them there.")
                        + (lin ? " The logger there is running; an administrator there can open its logs to every account again, in the checkout on \(name) (it puts the log folder and its files right):"
                               : " The logger there is running; on \(name), this says why:"),
                    lin ? "sudo linux/install.sh --system" : "oomph doctor")
        case .absent:
            return ("No logger", "Connected, but nothing is logged there",
                    lin ? "\(brand) on \(name) runs from a checkout." : "\(name) has no logger.",
                    "Agents take turns there, but nothing is recorded: no history, no incidents. To get both, in the checkout on \(name)"
                        + (lin ? ":" : " (or Activate in its \(brand) app):"),
                    lin ? "sudo linux/install.sh --system" : "sudo ./install.sh")
        }
    }

    // MARK: L3 (1.13.4): the hover card, the capsule's tooltip, the legend, the callout and the tour in Linux words

    /// The hover card's series on a Linux tab, top to bottom (03 §3.9's row budget: the ones the machine has, 2 to
    /// 4 lines): App, Compressed where memory is compressed, Kernel, Swap where it has swap.
    static func hoverSeries(_ f: Facts) -> [String] {
        ["App"] + (f.compressed ? ["Compressed"] : []) + ["Kernel"] + (f.swap ? ["Swap"] : [])
    }

    /// "lo–hi" of one decimal, or one figure when both read the same (the card's ranges).
    static func range(_ lo: Double, _ hi: Double, _ fmt: (Double) -> String) -> String {
        let a = fmt(lo), b = fmt(hi)
        return a == b ? b : a.replacingOccurrences(of: " %", with: "").replacingOccurrences(of: " GB", with: "") + "–" + b
    }

    /// The card's Available line, in place of the Mac's "all four, peak": what was available in the pixel
    /// (RAM less app, kernel and compressed memory), lowest to highest.
    static func availText(_ pts: [Point], ram: Double) -> String? {
        guard !pts.isEmpty, ram > 0 else { return nil }
        let av = pts.map { max(0, ram - $0.app - $0.wired - $0.comp) }
        return range(av.min()!, av.max()!, gb)
    }

    /// The card's one Stalled line: "28–35 % · fully 10–12 %", with stall time taken out at a container's own
    /// limit "0.0 % · +97 % at a limit"; nil where the pixel's samples have no stall time.
    static func stallText(_ pts: [Point]) -> String? {
        func r(_ k: KeyPath<Point, Float>) -> (Double, Double)? {
            let v = pts.map { $0[keyPath: k] }.filter { !$0.isNaN }.map(Double.init)
            return v.isEmpty ? nil : (v.min()!, v.max()!)
        }
        guard let some = r(\.stall) else { return nil }
        var t = range(some.0, some.1, pct)
        if let lim = r(\.stallLimit), lim.1 >= 0.05 {
            t += " · +" + pct(lim.1) + " at a limit"
        } else if let full = r(\.stallFull), full.1 >= 0.05 {
            t += " · fully " + range(full.0, full.1, pct)
        }
        return t
    }

    /// The capsule's tooltip on a Linux tab (Mockup B): the level in Linux terms, "Stalled on memory 14 % (fully
    /// 3 %) over the last 10 s. 2.7 GB available; zram 76 % full.", after oomph's verdict.
    static func capsuleHelp(_ s: Sample, _ f: Facts) -> String {
        let v = Verdict.capsule(s)
        var lines = [brand + "'s verdict, the same as `oomph check` there: memory " + ["ok", "tight", "critical"][v.memory]]
        var t = ""
        let p = s.psi?.v
        if f.psi != false, let some = p?.mem_some {
            let full = p?.mem_full ?? 0
            t = "Stalled on memory " + pct(some) + (full >= 0.05 ? " (fully " + pct(full) + ")" : "") + " over the last 10 s"
            if let lim = p?.limit?.v, let more = lim.some, more >= 0.05 {
                t += ", and " + pct(more) + " more inside " + (lim.cgroups?.first ?? "a container") + " at its own limit (not this machine's)"
            }
            t += ". "
        } else {
            t = "Stall time is not measured on this kernel (PSI is off). "
        }
        let avail = max(0, s.ram_gb - s.app_gb - s.wired_gb - s.compressed_gb)
        t += String(format: "%.1f GB available", avail)
        let lx = s.linux?.v
        if f.zram, let tot = lx?.kswap_total_gb?.v, let free = lx?.kswap_free_gb?.v, let size = lx?.zram_disk_gb?.v, size > 0 {
            let used = max(0, tot - free - s.swap_used_gb)
            t += String(format: "; zram %.0f %% full", 100 * used / size)
        } else if s.swap_total_gb > 0 {
            t += String(format: "; swap %.1f of %.0f GB", s.swap_used_gb, s.swap_total_gb)
        }
        lines.append(t + ".")
        if let h = Verdict.quotaHelp(s) { lines.append(h) }   // a metered network under 10 % (NET 12.15)
        return lines.joined(separator: "\n")
    }

    /// The chart legend's series on a Linux tab with their texts (03 §3.9): Kernel for Wired, App, Compressed and
    /// Swap only where the machine has them; "no data" without the Mac's sleep.
    static let legendHelp: [String: String] = [
        "Kernel": "Kernel: slab, page tables, drivers and reserves; what is neither app memory nor available.",
        "App": "App: anonymous and shared memory of processes; it can only be swapped, not dropped.",
        "Compressed": "Compressed: RAM that holds compressed pages (zram, zswap).",
        "Swap": "Swap: pages written to disk.",
        "no data": "Hatched: no samples — the machine was off or suspended, or the logger wasn't running."]

    /// The biggest-consumers callout on a Linux tab: its title and footnote (03 §3.9).
    static let calloutTitle = "Biggest groups now"
    static let calloutFoot = "A group is a systemd unit, a container or a program with all its processes. Sizes are private memory (anonymous + swapped); shared memory is not attributed."

    /// The tour's notes that speak of the system, on a Linux tab (03 §3.9): (Right now ×2, Incidents).
    static let tourNotes = [
        "The glyph's colour is this machine's memory pressure: how long tasks waited for memory, and what is left. The badge on the right names it; the menu bar always shows this Mac.",
        "Updated every 30 seconds: the figures `free` and /proc/meminfo give. Click the biggest group for the twelve largest.",
        "Each stretch of high memory pressure, or a kill by the kernel's OOM killer, with what was killed. Red: still open. Orange: new since you last looked.",
    ]

    /// State E: kills cannot be seen at all on this machine (the Incidents caption says so at the right).
    static let killsHidden = "kills are not visible on this machine"
    static let killsHiddenHelp = "This kernel has no kill counter and the logger cannot read the kernel log, so an OOM kill shows only as a process that disappeared. `oomph doctor` there says how to change that."
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
    /// What its logger can measure (a Linux machine's tiles follow it), and whether its logs can be read:
    /// "ok", "absent" (nothing is logged there), "denied" (03 §3.9, states B and C).
    var measures: Soft<Measures>?
    var logs: Soft<String>?
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

    /// The systems the app can label (01 §4.3: a machine of another os is not drawn). Linux from 1.13.3, the
    /// Linux-tab gate (03 §3.9, ROADMAP's LG row): Kernel, the tile matrix, its kills and quiet incidents.
    static let labeled: Set<String> = ["macos", "linux"]

    /// The pinned machines (tabs), in the order they were added; entries whose mirror name is not of
    /// the fixed pattern are skipped, since that name becomes a path. Only systems the app can label (or a
    /// machine not yet reached).
    static func load(_ dir: String) -> [MachineEntry] {
        loadAll(dir).filter { $0.pinned == true }.sorted { ($0.order ?? 0) < ($1.order ?? 0) }
    }

    /// Every machine this Mac knows (tabs and Recents), under the same rules as `load`.
    static func loadAll(_ dir: String) -> [MachineEntry] {
        struct File: Decodable { var machines: [MachineEntry]? }
        guard let d = readShared(dir + "/machines.json", cap: 4 << 20),
              let f = try? JSONDecoder().decode(File.self, from: d) else { return [] }
        return (f.machines ?? []).filter { e in
            (e.os == nil || labeled.contains(e.os!))
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
    @Published var historyNow = wallNow()
    /// Stretches without samples (asleep, off, logger stopped), found in the raw samples; for a
    /// mirror also the stretches it has not received (Gap.kind).
    @Published var gaps: [Gap] = []
    /// events.jsonl(.1), oldest first, for the hover tooltip.
    @Published var events: [ChartEvent] = []
    /// The agents' reservations, live and of the last 14 days, stacked for the strip under the chart.
    @Published var reservations: [ResBlock] = []
    var liveReservations: [Reservation] { Reservation.listOrder(reservations.map(\.res).filter(\.live), flagsFirst: resourcesUIOn) }
    private var eventsStamp = ""
    @Published var incidents: [Incident] = []
    /// A Linux machine's quiet incidents (containers at their own limit, 03 §5.6), newest first: one folded grey
    /// row, never unseen, never on the tab's badge.
    @Published var quiet: [Incident] = []
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
    var now: Double { wallNow() + (isLocal ? 0 : sync?.offset_s ?? 0) }

    /// A mirror is live while its engine says so and has rewritten status.json within the last 10 s
    /// from a process that still exists; in every other case it is drawn stale, so a crashed engine
    /// can never leave a pane looking live (roadmap 01 §4.4).
    var linkLive: Bool {
        guard let l = link, l.state == "live" || l.state == "catching_up", let u = l.updated, let pid = l.pid, pid > 0
        else { return false }
        return wallNow() - u < 10 && (noLiveness || kill(pid, 0) == 0 || errno == EPERM)
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

    func markOpened(at t: Double = wallNow()) {
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
        let age: Double = wallNow() - t
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
    /// Another machine that runs Linux (03 §3.9): its tab speaks Linux, and since L3 (1.13.4) so does the AI
    /// prompt, so ✦ follows its owner's consent there as on a Mac.
    var isLinux: Bool { !isLocal && (current?.os?.v ?? info?.os ?? entry?.os) == "linux" }
    /// The facts a Linux tab's tiles follow.
    var facts: LinuxTab.Facts { LinuxTab.Facts(current, info: info) }
    /// A server (or a container) sits in no one's room: no "away" for it.
    var hasPresence: Bool { !isLinux || facts.desktop }
    /// A machine that is reached but has little to show (03 §3.9, states A to C): connected, and its logger
    /// stopped writing, or this account may not read its logs, or nothing is logged there.
    var quietState: LinuxTab.Quiet? {
        guard !isLocal, linkLive else { return nil }
        let logs = info?.logs?.v
        if logs == "denied" { return .denied }
        guard let c = current else { return logs == "absent" ? .absent : nil }
        // a current.json left by an earlier logger is old, not live; while catching up it is not rewritten yet
        // (as the terminal dashboard: oomph_view.link_view)
        guard link?.state != "catching_up" else { return nil }
        return currentAge > 3 * (c.daemon?.interval ?? 30) + 15 ? .stopped : nil
    }
    /// The texts of that state.
    var remedy: (capsule: String, status: String, title: String, text: String, command: String)? {
        guard let q = quietState else { return nil }
        let at = current.map { MemoryChart.when($0.t - (sync?.offset_s ?? 0)) } ?? "?"
        let r = LinuxTab.remedy(q, os: info?.os ?? entry?.os, name: title, user: entry?.user, at: at)
        return (r.0, r.1, r.2, r.3, r.4)
    }
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
                            let reservations: [ResBlock]; var waiting: [Resource: Int] = [:]
                            var bands: [String: [ResBlock]] = [:] }

    private func apply(_ r: Loaded) {
        history = r.history
        gaps = r.gaps
        historyNow = r.now
        if let e = r.events { events = e }
        reservations = r.reservations
        if resourcesUIOn { waiting = r.waiting; bandBlocks = r.bands }
    }

    /// With the resources on, the blocks of each band the strip can draw (B3, 02 §3.4.5), stacked at the load:
    /// "memory" (what holds memory), "cpu", and "disk:<pool id>" per disk pool reserved (the band shows the tile's).
    @Published var bandBlocks: [String: [ResBlock]] = [:]
    private var bandsLoaded: [String: [ResBlock]] = [:]
    func blocks(for k: Resource, pool: String?) -> [ResBlock] {
        bandBlocks[k == .disk ? pool.map { "disk:" + $0 } ?? "disk" : k.rawValue] ?? []
    }
    static func bandBlocks(_ rs: [Reservation], now: Double) -> [String: [ResBlock]] {
        var out: [String: [ResBlock]] = [:]
        out["memory"] = ResBlock.stack(rs.filter(\.holdsMemory), now: now)
        let cpu = rs.filter { $0.cpu != nil }
        if !cpu.isEmpty { out["cpu"] = ResBlock.stack(cpu, now: now, kind: .cpu) }
        let disk = rs.filter { $0.disk != nil }
        if !disk.isEmpty { out["disk"] = ResBlock.stack(disk, now: now, kind: .disk) }   // a sample that names no pool
        for p in Set(disk.compactMap(\.diskPool)) {
            out["disk:" + p] = ResBlock.stack(disk.filter { $0.diskPool == p }, now: now, kind: .disk)
        }
        return out
    }

    /// Queued requests by the resource they wait for (the tiles' "n waiting"), as of the last load.
    @Published var waiting: [Resource: Int] = [:]
    private var waitingLoaded: [Resource: Int] = [:]

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
                                         holderGone: { pid in local && !noLiveness && kill(pid, 0) != 0 && errno == ESRCH })
        if resourcesUIOn {
            waitingLoaded = Tile.waiting((ledger["leases"] as? [[String: Any]]) ?? [])
            bandsLoaded = MachineStore.bandBlocks(rs, now: now)
        }
        return ResBlock.stack(rs, now: now)
    }

    /// On loadQueue only. For a mirror: its coverage, whether its link is down (or in the grace of
    /// an opening: the stretch from its last data to now is then left blank), its oldest sample.
    private func loadHistory(_ state: SyncState?, down: Bool, grace: Bool = false, oldest: Double?) -> Loaded {
        let now = wallNow() + (isLocal ? 0 : state?.offset_s ?? 0)
        let fmt = DateFormatter(); fmt.dateFormat = "yyyy-MM-dd"
        let today = fmt.string(from: wallDate())
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
        let res = loadReservations(now: known)
        return Loaded(history: Store.multires(all, now: now), gaps: gaps, now: now, events: loadEvents(),
                      reservations: res, waiting: waitingLoaded, bands: bandsLoaded)
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
            let d = Data(line)
            guard let s = try? loadDecoder.decode(ChartSample.self, from: d) else { continue }
            let away = s.away.map { ($0.idle_s ?? 0) >= 300 || ($0.locked ?? false) || $0.display_on == false } ?? false
            var p = Point(id: s.t, date: Date(timeIntervalSince1970: s.t), wired: s.wired_gb, app: s.app_gb,
                          comp: s.compressed_gb, swap: s.swap_used_gb, away: away, kills: s.jetsam_kills ?? 0)
            if let q = s.psi?.v {  // a Linux machine's (L3): the hover's Stalled line
                if let x = q.mem_some { p.stall = Float(x) }
                if let x = q.mem_full { p.stallFull = Float(x) }
                if let x = q.limit?.v?.some { p.stallLimit = Float(x) }
            }
            if resourcesUIOn, let r = try? loadDecoder.decode(ChartSampleR.self, from: d) { p.take(r) }
            out.append(p)
        }
        return out
    }

    func loadIncidents() {
        let dir = logDir + "/incidents"
        // newest first until 30 of the machine's own, with every quiet one among them (at most 200 folders: a mirror
        // keeps 90 days): on a container host that opens a quiet one a day they would otherwise push the real ones
        // out, and "+N earlier" would stop at 29
        let ids = ((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []).sorted(by: >).prefix(200)
        var own: [Incident] = [], still: [Incident] = []
        for id in ids where own.count < 30 {
            let p = "\(dir)/\(id)/incident.json"
            guard let d = FileManager.default.contents(atPath: p), var inc = try? decoder.decode(Incident.self, from: d) else { continue }
            inc.dir = "\(dir)/\(id)"
            if inc.quiet == true { still.append(inc) } else { own.append(inc) }
        }
        incidents = own
        // only a Linux tab folds them into its list (This Mac never has any)
        quiet = isLinux ? still : []
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

    // MARK: resources (roadmap 02 §3.7, 1.11.0; behind resourcesUI)

    /// The remembered selection (§3.7.9): `selectedResources` (in tile order) and `focusResource` in
    /// UserDefaults, written on every change the user makes. Default: Memory alone.
    @Published var resSelection: [Resource] = Store.storedSelection()
    @Published var resFocus: Resource = Resource(rawValue: UserDefaults.standard.string(forKey: "focusResource") ?? "") ?? .memory
    /// The resource the verdict named when the popup opened: focused and added for this opening, never written
    /// back (§3.4.9, §3.7.9).
    @Published var trouble: Resource?
    /// The compact level (§3.7.5): chosen when the popup opens and again when the selection changes, never
    /// otherwise while it is open. `--ai lvl:N` draws one.
    @Published var compactLevel = 0
    /// A click on the focus shown alone: the biggest consumers open (PopoverView toggles its callout).
    @Published var calloutAsked = 0
    /// The last refused ⌘-click (the tile shakes): which tile, and a count that changes each time.
    @Published var refused: (Resource, Int)?
    var onSelectionChanged: (() -> Void)?

    static func storedSelection() -> [Resource] {
        let a = (UserDefaults.standard.array(forKey: "selectedResources") as? [String]) ?? ["memory"]
        let r = Resource.allCases.filter { a.contains($0.rawValue) }
        return r.isEmpty ? [.memory] : r
    }

    /// What the popup draws for machine `m`: the remembered selection with the resource in trouble added and
    /// focused, over the tiles that machine has.
    func selection(for m: MachineStore) -> Selection {
        var sel = resSelection, focus = resFocus
        if let t = trouble { if !sel.contains(t) { sel.append(t) }; focus = t }
        return Selection.shown(sel, focus: focus, available: Resource.available(m.current))
    }

    /// A click, ⌘-click or ⇧-click on a tile, or its key (m c g d, ⇧ for the toggle). A change is written
    /// back, keeping a remembered resource this machine does not have unless the click showed one alone.
    @discardableResult
    func resourceGesture(_ g: Selection.Gesture, _ r: Resource) -> Selection.Outcome {
        let avail = Resource.available(machine.current)
        let (next, out) = selection(for: machine).apply(g, r, available: avail)
        switch out {
        case .callout: calloutAsked += 1
        case .refused: refused = (r, (refused?.1 ?? 0) + 1)
        case .changed:
            let keep = g == .click ? [] : resSelection.filter { !avail.contains($0) }
            trouble = nil
            resSelection = Resource.allCases.filter { next.shown.contains($0) || keep.contains($0) }
            resFocus = next.focus
            if !renderMode {
                UserDefaults.standard.set(resSelection.map(\.rawValue), forKey: "selectedResources")
                UserDefaults.standard.set(resFocus.rawValue, forKey: "focusResource")
            }
            onSelectionChanged?()
        case .none: break
        }
        return out
    }

    /// Opening the popup on trouble (§3.4.9): this Mac's verdict, while its logger reports.
    func resourcesOpened() {
        guard resourcesUIOn else { return }
        let m = machine
        trouble = (m.daemonRunning || !m.isLocal) ? m.current.flatMap { Verdict.trouble(Verdict.capsule($0)) } : nil
    }

    /// m c g d and M C G D while the popup is key and no text field has the keyboard (§3.7.3).
    func resourceKey(_ e: NSEvent) -> Bool {
        guard resourcesUIOn, e.type == .keyDown, !(e.window?.firstResponder is NSText) else { return false }
        let mods = e.modifierFlags.intersection([.command, .control, .option])
        guard mods.isEmpty, let c = e.characters, c.count == 1,
              let r = Resource.allCases.first(where: { $0.letter == c.lowercased() }) else { return false }
        resourceGesture(c == c.lowercased() ? .click : .cmd, r)
        return true
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
        lastSelected[m.mid] = wallNow()
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
        var p = Point(id: w.id, date: w.date, wired: w.wired, app: w.app, comp: w.comp,
                      swap: w.swap, away: slice.contains { $0.away }, kills: slice.reduce(0) { $0 + $1.kills })
        if slice.contains(where: { !$0.stall.isNaN }) {  // a Linux machine's stall time: the highest of the bucket
            func top(_ k: KeyPath<Point, Float>) -> Float { slice.map { $0[keyPath: k] }.filter { !$0.isNaN }.max() ?? .nan }
            p.stall = top(\.stall); p.stallFull = top(\.stallFull); p.stallLimit = top(\.stallLimit)
        }
        if resourcesUIOn { p.aggregate(slice) }
        return p
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
        let now = Date().timeIntervalSince1970  // real time: what is saved and scheduled, never a render's clock
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

/// One resource tile (roadmap 02 §3.4.1, §3.7.8): name and its one flag, the reading, a meter (a tank for
/// Disk, which fills as things get better), the biggest consumer. The focus has the strong highlight, every
/// other shown resource a light one; a flag of rank 1 to 5 colours the border, never the fill.
struct ResourceTile: View {
    enum Role { case focus, shown, plain }
    let resource: Resource
    let tile: Tile
    let role: Role
    let chevron: Bool          // the focus shown alone: a click opens its biggest consumers
    let open: Bool             // and they are open
    let compact: Bool          // level 3 and up: no line 4, the chevron moves to line 1
    var shake = 0
    var help = ""

    var body: some View {
        let c = resource.color
        let border: Color = tile.level >= 2 ? .red : tile.level == 1 ? .orange
            : role == .focus ? c.opacity(0.6) : role == .shown ? c.opacity(0.3) : Color.primary.opacity(0.08)
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 3) {
                Text(resource.name).font(.system(size: 10.5, weight: .semibold)).lineLimit(1).fixedSize()
                    .foregroundStyle(role == .focus ? Color.primary : Color.secondary)
                Spacer(minLength: 2)
                ViewThatFits(in: .horizontal) { flag(true); flag(false) }
                if chevron && compact { arrow }
            }
            Text(tile.reading).font(.system(size: 13, weight: .semibold)).monospacedDigit()
                .lineLimit(1).minimumScaleFactor(0.75)
            meter.padding(.vertical, 1)
            if !compact {
                HStack(spacing: 2) {
                    Text(tile.top.map(ResourceTile.friendly) ?? " ").lineLimit(1).truncationMode(.middle)
                    Spacer(minLength: 0)
                    if chevron { arrow }
                }
                .font(.system(size: 10)).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 7).padding(.vertical, 5)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 7, style: .continuous)
            .fill(role == .focus ? c.opacity(0.10) : role == .shown ? c.opacity(0.045) : Color.primary.opacity(0.025)))
        .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous).strokeBorder(border, lineWidth: tile.level > 0 ? 1.5 : 1))
        .modifier(ShakeEffect(animatableData: CGFloat(shake)))
        .help(help)
    }

    var arrow: some View {
        Image(systemName: open ? "chevron.up" : "chevron.down").font(.system(size: 7, weight: .bold)).foregroundStyle(.secondary)
    }

    /// The flag slot (§3.4.1): a shape and a word, never colour alone; the queue after a flag of rank 1 to 6,
    /// or "n waiting" on its own (outranking busy). A two-digit queue drops the word.
    @ViewBuilder func flag(_ words: Bool) -> some View {
        let f = tile.flag, q = tile.queue
        HStack(spacing: 2) {
            if let f, f != "busy" {
                let glyph = f.hasSuffix("critical") ? "●" : f == "throttled" ? "△" : "▲"
                Text(glyph).foregroundStyle(f.hasSuffix("critical") ? Color.red : f == "throttled" ? Color.primary : Color.orange)
                Text(f).foregroundStyle(Color.primary)
                if q > 0 { Text("◻\(q)").foregroundStyle(resource.color) }
            } else if q > 0 {
                Text("◻").foregroundStyle(resource.color)
                Text(q > 9 || !words ? "\(q)" : "\(q) waiting").foregroundStyle(Color.primary)
            } else if f == "busy" {
                Text("busy").foregroundStyle(.secondary)
            }
        }
        .font(.system(size: 9.5)).lineLimit(1).fixedSize()
    }

    @ViewBuilder var meter: some View {
        let frac = CGFloat(min(max(tile.meter, 0), 1))
        if resource == .disk {
            GeometryReader { g in
                let w: CGFloat = g.size.width
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 2).fill(resource.color.opacity(0.55)).frame(width: max(w * frac, frac > 0 ? 1.5 : 0))
                    RoundedRectangle(cornerRadius: 2).strokeBorder(resource.color.opacity(0.7), lineWidth: 0.75)
                }
            }
            .frame(height: 6)
        } else {
            GeometryReader { g in
                let w: CGFloat = g.size.width
                ZStack(alignment: .leading) {
                    Capsule().fill(Color.primary.opacity(0.1))
                    Capsule().fill(resource.color.opacity(0.85)).frame(width: max(w * frac, frac > 0 ? 2 : 0))
                }
            }
            .frame(height: 3).padding(.vertical, 1.5)
        }
    }

    /// "com.apple.WebKit.WebContent" → "WebKit.WebContent".
    static func friendly(_ n: String) -> String {
        let parts = n.split(separator: ".")
        guard parts.count >= 3, ["com", "org", "net", "io", "de", "app"].contains(parts[0].lowercased()) else { return n }
        return parts.dropFirst(2).joined(separator: ".")
    }
}

/// The standard 0.2 s "no" of a refused ⌘-click: 2 pt left and right, twice.
struct ShakeEffect: GeometryEffect {
    var animatableData: CGFloat
    func effectValue(size: CGSize) -> ProjectionTransform {
        ProjectionTransform(CGAffineTransform(translationX: 2 * sin(animatableData * .pi * 4), y: 0))
    }
}

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

/// A tile of a Linux tab (03 §3.9): Stat with a small grey figure after the value (the RAM tile's
/// "available" or host, stall time's "· fully N %", "+97 % ▣" or "●") and a tooltip.
struct LinuxStat: View {
    let cell: LinuxTab.Cell
    var wide = false
    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            HStack(alignment: .firstTextBaseline, spacing: 4) {
                Text(cell.value).font(.system(size: 13, weight: .semibold)).monospacedDigit().foregroundStyle(cell.red ? .red : .primary)
                    .lineLimit(1).fixedSize()
                if let s = cell.small {
                    Text(s).font(.system(size: 9.5)).foregroundStyle(s == "●" && cell.red ? Color.red : Color.secondary)
                        .lineLimit(1).fixedSize()
                }
            }
            Text(cell.label).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
        }
        .frame(minWidth: statColumn, maxWidth: wide ? .infinity : statColumn, alignment: .leading)
        .contentShape(Rectangle())
        .help(cell.help)
    }
}

// MARK: - Time axis

/// The time axis every chart row shares (roadmap 02 §8): where a moment lies across the plot and back
/// (the hover's inversion), the clock-aligned grid and its labels, a row's history bucketed into screen
/// columns with its away spans, the no-data hatch and the not-received dots behind the series, and the
/// incident rules. x is a blend of a linear axis (the last 10^lgRange seconds) and a log axis over all
/// history (blend 0 → 1), both animatable: a row draws only its own series on the axis it is handed, so
/// every row morphs alike when the range changes. The numbers are `oomph top`'s too (tools/vectors/chart.json).
struct TimeAxis {
    var now: Double
    var first: Double            // where the ∞ axis begins (`start`)
    var lgRange: Double          // log10 of the linear range, seconds
    var blend: Double            // 0 = linear, 1 = log

    var animatableData: AnimatablePair<Double, Double> {
        get { AnimatablePair(lgRange, blend) }
        set { lgRange = newValue.first; blend = newValue.second }
    }

    /// Where the ∞ axis begins: the oldest point loaded, or another machine's oldest sample as it reported
    /// it, so the axis does not rescale while history arrives (roadmap 01 §3.5).
    static func start(oldest: Double?, firstPoint: Double?, now: Double) -> Double {
        guard let o = oldest else { return firstPoint ?? now }
        return min(o, firstPoint ?? o)
    }

    static let minAge: Double = 300          // ages below this share the right edge of the log axis
    static let buckets = 360                 // screen columns a row's history is bucketed into
    // grid levels, coarse first: a week, a day, 6 h, 1 h, 15 min, 5 min, 1 min (local time)
    static let levels: [Double] = [604800, 86400, 21600, 3600, 900, 300, 60]

    struct Band: Identifiable { let id: Int; let from: Double; let to: Double }
    struct GridLine: Identifiable { let id: Double; let x: Double; let alpha: Double }
    struct Label { let x: Double; let text: String }
    /// One screen column of a row's history: its point, and whether a gap parts it from the older
    /// (gapBefore) or the newer (gapAfter) neighbour, where the row's area drops to zero.
    struct Column<P> { let x: Double; let p: P; let gapBefore: Bool; let gapAfter: Bool }

    /// Time → x in 0…1 (1 = now) for the current blend.
    func mapper() -> (Double) -> Double {
        TimeAxis.mapper(now: now, first: first, lgRange: lgRange, blend: blend)
    }

    /// Linear: the last 10^lgRange s. Log: all history, ages under minAge at the right edge.
    /// Shared with `oomph top` (tools/vectors/chart.json).
    static func mapper(now: Double, first: Double, lgRange: Double, blend b: Double) -> (Double) -> Double {
        let r = pow(10, lgRange), m = TimeAxis.minAge
        let span = log10(max(now - first, 3600) / m)
        return { t in
            let a = max(now - t, 0)
            return (1 - b) * (1 - a / r) + b * (1 - log10(max(a, m) / m) / span)
        }
    }

    /// Time for x (the mapper is monotonic, so bisection inverts it). Shared with `oomph top`.
    func time(at u: Double, _ f: (Double) -> Double) -> Double {
        var lo = first - 1, hi = now
        if u >= f(hi) { return hi }
        if u <= f(lo) { return lo }
        for _ in 0..<50 {
            let mid = (lo + hi) / 2
            if f(mid) < u { lo = mid } else { hi = mid }
        }
        return (lo + hi) / 2
    }

    // MARK: columns and away spans

    /// A row's history (oldest first) bucketed into screen columns, each reduced to one point (the
    /// worst, so spikes survive), breaking at every gap instead of bridging it; one point past the left
    /// edge is kept. Oldest first, x clamped into the plot.
    func columns<P>(_ points: [P], time: (P) -> Double, gaps: [Gap], _ f: (Double) -> Double,
                    reduce: (ArraySlice<P>) -> P) -> [Column<P>] {
        var cols: [(x: Double, p: P)] = []
        var gi = gaps.count - 1
        var bucket: [P] = [], bucketCol = Int.min, bucketX = 0.0
        var segBreaks: Set<Int> = []                  // indices in cols that start a new segment (older side)
        func flush() {
            if !bucket.isEmpty { cols.append((bucketX, reduce(ArraySlice(bucket)))) }
            bucket = []
        }
        var prevT = Double.infinity
        for p in points.reversed() {
            let t = time(p)
            let x = f(t)
            // a gap between this point and the newer one?
            var broke = false
            while gi >= 0 && gaps[gi].from >= t {
                if gaps[gi].to <= prevT { broke = true }
                gi -= 1
            }
            let col = Int((x * Double(TimeAxis.buckets)).rounded(.down))
            if broke || col != bucketCol {
                flush()
                if broke { segBreaks.insert(cols.count) }
                bucketCol = col; bucketX = x
            }
            bucket.append(p)
            prevT = t
            if x < 0 { break }                        // one point past the left edge, clamped below
        }
        flush()
        let n = cols.count
        return stride(from: n - 1, through: 0, by: -1).map { (i: Int) -> Column<P> in
            Column(x: min(max(cols[i].x, 0), 1), p: cols[i].p,
                   gapBefore: i != n - 1 && segBreaks.contains(i + 1), gapAfter: i != 0 && segBreaks.contains(i))
        }
    }

    /// The away spans of a row's columns: a run of columns whose point was away, ended by one that was
    /// not, by a gap, or by now.
    static func awayBands<P>(_ cols: [Column<P>], away: (P) -> Bool) -> [Band] {
        var out: [Band] = []
        var start: Double?
        for (k, c) in cols.enumerated() {
            let isAway = away(c.p)
            if isAway { if start == nil { start = c.x } }
            if (!isAway || c.gapAfter || k == cols.count - 1), let s = start {
                out.append(Band(id: out.count, from: s, to: c.x)); start = nil   // the last column closes any band
            }
        }
        return out
    }

    /// The no-data stretches on screen, or with `missing` the ones not received from another machine.
    static func gapBands(_ gaps: [Gap], _ f: (Double) -> Double, missing: Bool = false) -> [Band] {
        var out: [Band] = []
        for g in gaps where (g.kind != .noData) == missing {
            let a = max(f(g.from), 0), b = min(f(g.to), 1)
            if b > a { out.append(Band(id: out.count, from: a, to: b)) }
        }
        return out
    }

    // MARK: grid, labels and incident rules

    /// Clock-aligned lines at every level, faded by their on-screen spacing: lines closer than a
    /// few pixels vanish, so the log axis shows its decades of grids without turning solid.
    func gridLines(_ f: (Double) -> Double, plotW: Double) -> [GridLine] {
        let tz = Double(TimeZone.current.secondsFromGMT())
        var alpha: [Double: (x: Double, a: Double)] = [:]
        for unit in TimeAxis.levels {
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
        for unit in TimeAxis.levels {
            let offset = unit == 604800 ? 4 * 86400.0 : 0
            var t = ((now + tz - offset) / unit).rounded(.down) * unit - tz + offset
            var guardN = 0
            while guardN < 400 {
                guardN += 1
                let x = f(t)
                if x < 0 { break }
                if (x - f(t - unit)) * plotW < 20 { break }
                if x >= 0.03 && x <= 0.95 && !out.contains(where: { abs($0.x - x) < minGap }) {
                    out.append(Label(x: x, text: TimeAxis.label(t, unit: unit)))
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

    /// Where incidents start, on screen.
    static func incidentXs(_ incidents: [Incident], _ f: (Double) -> Double) -> [Double] {
        incidents.map { f($0.start) }.filter { $0 >= 0 && $0 <= 1 }
    }

    @ChartContentBuilder static func gridMarks(_ lines: [GridLine], color: Color, scale: Double) -> some ChartContent {
        ForEach(lines) { (l: GridLine) in
            RuleMark(x: .value("grid", l.x))
                .lineStyle(StrokeStyle(lineWidth: 0.5))
                .foregroundStyle(color.opacity(l.alpha * scale))
        }
    }

    @ChartContentBuilder static func incidentMarks(_ xs: [Double]) -> some ChartContent {
        ForEach(xs, id: \.self) { (x: Double) in
            RuleMark(x: .value("incident", x)).foregroundStyle(Color.red)
        }
    }

    // MARK: away bands and no-data hatching

    /// Away bands and no-data stretches, drawn behind the series in one Canvas: stretches closer
    /// than 2 px merge (a Mac that keeps dozing off reads as one calm band, not a grey comb), and
    /// one hatch pattern, anchored to the plot, shows through all no-data stretches.
    static func bandLayer(_ proxy: ChartProxy, away: [Band], gaps: [Band], missing: [Band]) -> some View {
        GeometryReader { g in
            let plot = proxy.plotFrame.map { g[$0] } ?? CGRect(origin: .zero, size: g.size)
            Canvas { ctx, size in
                let W = Double(size.width)
                let (grey, hatched) = TimeAxis.calmBands(away: away.map { ($0.from * W, $0.to * W) },
                                                         gaps: gaps.map { ($0.from * W, $0.to * W) }, tolerance: 2)
                var greyPath = Path(), hatchPath = Path()
                for (a, b) in grey { greyPath.addRect(CGRect(x: a, y: 0, width: max(b - a, 1), height: size.height)) }
                for (a, b) in hatched { hatchPath.addRect(CGRect(x: a, y: 0, width: max(b - a, 1), height: size.height)) }
                ctx.fill(greyPath, with: .color(.gray.opacity(0.15)))
                ctx.fill(hatchPath, with: .color(.gray.opacity(0.06)))
                var c = ctx
                c.clip(to: hatchPath)
                c.stroke(TimeAxis.hatchLines(in: CGRect(origin: .zero, size: size)), with: .color(.gray.opacity(0.45)), lineWidth: 1)
                if !missing.isEmpty { TimeAxis.drawMissing(ctx, missing.map { ($0.from * W, $0.to * W) }, height: size.height) }
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
        c.fill(TimeAxis.dots(in: field.boundingRect, spacing: 4), with: .color(.gray.opacity(0.55)))
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
}

// MARK: - Memory chart

/// The popup's memory chart. One view for every range, on the TimeAxis it is handed: a range switch
/// animates the axis, so the chart morphs and every point visibly travels to its new place. Each frame
/// re-buckets the preloaded history into ~360 columns; nothing is reloaded.
struct MemoryChart: View, Animatable {
    var points: [Point]          // oldest first, multi-resolution (Store.multires)
    var gaps: [Gap]
    var incidents: [Incident]
    var events: [ChartEvent]
    var ram: Double?
    var axis: TimeAxis
    /// The agents' reservations, drawn as a strip of blocks under the chart on the same time axis.
    var reservations: [ResBlock] = []
    var stripHeight: CGFloat = 0 // 0 = no strip
    /// With the resources on: the strip's bands, each with its blocks, the first tall (02 §3.7.6); none: the one
    /// memory strip of `reservations`. A small band's height; the reservation a row of the list points at.
    var bands: [(kind: Resource, blocks: [ResBlock])] = []
    var smallBand: CGFloat = 12
    var highlight: String? = nil
    // With the resources on (roadmap 02 §3.7): the resource with the big chart, the small charts under it (in
    // tile order) and their height, and the scales the charts need from the current sample.
    var focus: Resource = .memory
    var rows: [Resource] = []
    var rowHeight: CGFloat = 22
    var cores: Double?
    var floors: (low: Double, crit: Double)?
    /// The wired series' name: "Kernel" on a Linux tab (03 §3.9: the same field, `wired_gb`).
    var wiredName = "Wired"
    /// A Linux tab's facts (nil on a Mac's): its hover card keeps 03 §3.9's row budget (L3).
    var linux: LinuxTab.Facts? = nil
    @Environment(\.colorScheme) private var scheme
    /// The pointer's x over the chart (overlay coordinates), nil when it isn't hovering.
    @State private var hoverX: CGFloat? = renderHoverX
    /// The pointer over the reservation strip (strip coordinates).
    @State private var stripHover: CGPoint? = renderStripHover

    var animatableData: AnimatablePair<Double, Double> {
        get { axis.animatableData }
        set { axis.animatableData = newValue }
    }

    var now: Double { axis.now }

    static let series = ["Wired", "App", "Compressed", "Swap"]

    struct Entry: Identifiable { let id: Int; let x: Double; let kind: String; let gb: Double }

    var body: some View {
        GeometryReader { geo in
            let f = axis.mapper()
            let plotW = max(geo.size.width - 30, 50)
            let (entries, away) = columns(f)
            let gaps = TimeAxis.gapBands(self.gaps, f)
            let missing = TimeAxis.gapBands(self.gaps, f, missing: true)
            let grid = axis.gridLines(f, plotW: plotW)
            let labels = axis.axisLabels(f, plotW: plotW)
            VStack(spacing: MemoryChart.stripGap) {
                if resourcesUIOn {
                    resourceChart(f, entries: entries, away: away, gaps: gaps, missing: missing, grid: grid, labels: labels)
                } else {
                Chart {
                    TimeAxis.gridMarks(grid, color: .primary, scale: 1)
                    areaMarks(entries)
                    TimeAxis.gridMarks(grid, color: .white, scale: 0.45)
                    ramMark
                    TimeAxis.incidentMarks(TimeAxis.incidentXs(incidents, f))
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
                .chartBackground { proxy in TimeAxis.bandLayer(proxy, away: away, gaps: gaps, missing: missing) }
                .chartOverlay { proxy in
                    ZStack(alignment: .topLeading) {
                        axisLabelLayer(proxy, labels: labels)
                        hoverTracker(proxy)
                    }
                }
                }
                if !rows.isEmpty {
                    Color.clear.frame(height: rowsHeight).tourAnchor("rows")
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
                        if !rows.isEmpty {
                            rowsLayer(plot: plot, top: rowsTop(geo.size.height), mapper: f, grid: grid, labels: labels)
                        }
                        if stripHeight > 0 { stripLayer(plot: plot, top: geo.size.height - stripHeight, mapper: f, grid: grid, missing: missing) }
                        hoverLayer(plot: plot, mapper: f, stripTop: geo.size.height - stripHeight,
                                   rowsTop: rows.isEmpty ? nil : rowsTop(geo.size.height))
                        if stripHeight > 0 { stripCard(plot: plot, top: geo.size.height - stripHeight, width: geo.size.width, mapper: f) }
                    }
                }
                .frame(width: geo.size.width, height: geo.size.height, alignment: .topLeading)
            }
        }
    }

    static let seriesColors: [Color] = [.gray, .blue, .orange, .red]
    static let stripGap: CGFloat = 4

    // MARK: four resources (roadmap 02 §3.4.3, §3.7; with resourcesUI)

    /// The small charts' room: each with the gap above it.
    var rowsHeight: CGFloat { CGFloat(rows.count) * (rowHeight + 3) }
    /// Where the small charts begin, in a chart of height h: under the big chart, above the strip.
    func rowsTop(_ h: CGFloat) -> CGFloat { h - (stripHeight > 0 ? stripHeight + MemoryChart.stripGap : 0) - rowsHeight }

    /// The focus's series, as the big chart and its legend name and colour them.
    var seriesStyle: (names: [String], colors: [Color]) {
        switch focus {
        case .memory: return (MemoryChart.series, MemoryChart.seriesColors)
        case .cpu: return (["System", "User"], [.gray, Resource.cpu.color])
        case .gpu: return (["Full speed", "Busy time", "Busy"],
                           [Resource.gpu.color, Resource.gpu.color.opacity(0.3), Resource.gpu.color.opacity(0.95)])
        case .disk: return (["Free", "Free line"], [Resource.disk.color.opacity(0.16), Resource.disk.color])
        }
    }

    /// The first of 1, 2, 4, 8 × 10ⁿ at or above v: the Disk row's scale (02 §3.4.3).
    static func niceStep(_ v: Double) -> Double {
        guard v > 0 else { return 1 }
        let e = pow(10, (log10(v)).rounded(.down))
        for m in [1.0, 2, 4, 8, 10] where m * e >= v - 1e-9 { return m * e }
        return 10 * e
    }

    /// The big chart's y scale: memory to the next 10 GB above RAM or the highest stack (02 §8), the cores with
    /// room for their dashed line, the GPU to 100 %, free disk on the Disk row's steps over the range in view.
    func yTop(_ entries: [Entry]) -> Double {
        var stack: [Double: Double] = [:]
        for e in entries where e.kind != "Busy" && e.kind != "Free line" { stack[e.x, default: 0] += e.gb }
        let peak = stack.values.max() ?? 0
        switch focus {
        case .memory: return max(10, (max(ram ?? 0, peak) / 10).rounded(.up) * 10)
        case .cpu: return max(cores ?? 0, peak, 1) * 1.08
        case .gpu: return 100
        case .disk: return MemoryChart.niceStep(max(peak, 2 * (floors?.low ?? 0), 1))
        }
    }

    /// The focus's series by screen column (02 §3.4.3): for the rates each column's mean, the System part of
    /// the cores under the User part; the GPU at full speed solid, busy time faint with the busy line over
    /// it; free disk as a faint area under its line. Zero at both edges of every gap, as memory's.
    func resourceEntries(_ f: (Double) -> Double) -> [Entry] {
        let cols = axis.columns(points, time: { $0.id }, gaps: gaps, f, reduce: Store.worst)
        let kinds = seriesStyle.names
        var out: [Entry] = []
        var id = 0
        func v(_ x: Float?) -> Double { x.map { $0.isNaN ? 0 : Double($0) } ?? 0 }
        func add(_ x: Double, _ p: Point?) {
            var vals: [Double] = []
            switch focus {
            case .cpu:
                let busy = v(p?.cpu), sys = min(v(p?.cpuSys), busy)
                vals = [sys, busy - sys]
            case .gpu:
                let k = p?.gpuKind ?? 0, u = v(p?.gpu)
                vals = [k == 2 ? u : 0, k == 1 ? u : 0, k == 2 ? v(p?.gpuBusy) : 0]
            case .disk: vals = [v(p?.disk), v(p?.disk)]
            case .memory: return
            }
            for (k, name) in kinds.enumerated() { out.append(Entry(id: id, x: x, kind: name, gb: vals[k])); id += 1 }
        }
        for c in cols {
            if c.gapBefore { add(c.x - 1e-6, nil) }
            add(c.x, c.p)
            if c.gapAfter { add(c.x + 1e-6, nil) }
        }
        return out
    }

    @ChartContentBuilder func resourceMarks(_ entries: [Entry]) -> some ChartContent {
        ForEach(entries) { (e: Entry) in
            if e.kind == "Busy" || e.kind == "Free line" {
                LineMark(x: .value("time", e.x), y: .value("value", e.gb), series: .value("kind", e.kind))
                    .foregroundStyle(by: .value("kind", e.kind))
                    .lineStyle(StrokeStyle(lineWidth: 1))
            } else {
                AreaMark(x: .value("time", e.x), y: .value("value", e.gb))
                    .foregroundStyle(by: .value("kind", e.kind))
            }
        }
    }

    /// What the focus is measured against: RAM, the cores, a watched pool's "low" and "critical" floors.
    @ChartContentBuilder var capacityMarks: some ChartContent {
        if focus == .memory {
            ramMark
        } else if focus == .cpu, let n = cores {
            RuleMark(y: .value("cores", n))
                .lineStyle(StrokeStyle(lineWidth: 1, dash: [4, 3]))
                .foregroundStyle(Color.primary.opacity(0.6))
        } else if focus == .disk, let fl = floors {
            RuleMark(y: .value("low", fl.low))
                .lineStyle(StrokeStyle(lineWidth: 1, dash: [4, 3]))
                .foregroundStyle(Color.orange.opacity(0.8))
            RuleMark(y: .value("critical", fl.crit))
                .lineStyle(StrokeStyle(lineWidth: 1, dash: [4, 3]))
                .foregroundStyle(Color.red.opacity(0.8))
        }
    }

    /// The big chart with the resources on: memory's four series, or the focus's, on an explicit y scale.
    func resourceChart(_ f: @escaping (Double) -> Double, entries: [Entry], away: [TimeAxis.Band], gaps: [TimeAxis.Band],
                       missing: [TimeAxis.Band], grid: [TimeAxis.GridLine], labels: [TimeAxis.Label]) -> some View {
        let rentries = focus == .memory ? entries : resourceEntries(f)
        let style = seriesStyle
        let top = yTop(rentries)
        return Chart {
            TimeAxis.gridMarks(grid, color: .primary, scale: 1)
            if focus == .memory { areaMarks(rentries) } else { resourceMarks(rentries) }
            TimeAxis.gridMarks(grid, color: .white, scale: 0.45)
            capacityMarks
            TimeAxis.incidentMarks(TimeAxis.incidentXs(incidents, f))
        }
        .chartXScale(domain: 0...1)
        .chartYScale(domain: 0...top)
        .chartXAxis {
            AxisMarks(values: labels.map(\.x)) { _ in
                AxisTick(length: 3)
                AxisValueLabel { Text(" ").font(.system(size: 10)) }
            }
        }
        .chartForegroundStyleScale(domain: style.names, range: style.colors)
        .chartLegend(.hidden)
        .transaction { $0.animation = nil }
        .chartBackground { proxy in TimeAxis.bandLayer(proxy, away: away, gaps: gaps, missing: missing) }
        .chartOverlay { proxy in
            ZStack(alignment: .topLeading) {
                axisLabelLayer(proxy, labels: labels)
                hoverTracker(proxy)
            }
        }
    }

    /// A small chart's value of a point, and its scale (02 §3.4.3: memory used, cores busy, the GPU, free disk
    /// of the tile's pool; disk on its steps over all history, so it does not move with the range).
    func rowValue(_ r: Resource, _ p: Point) -> Float {
        switch r {
        case .memory: return Float(p.used)
        case .cpu: return p.cpu
        case .gpu: return p.gpu
        case .disk: return p.disk
        }
    }

    func rowScale(_ r: Resource) -> Double {
        switch r {
        case .memory: return max(ram ?? 0, points.map(\.used).max() ?? 0, 1)
        case .cpu: return max(cores ?? Double(points.map(\.cpuN).filter { !$0.isNaN }.max() ?? 1), 1)
        case .gpu: return 100
        case .disk:
            return MemoryChart.niceStep(max(Double(points.map(\.disk).filter { !$0.isNaN }.max() ?? 1), 2 * (floors?.low ?? 0)))
        }
    }

    /// The reading a small chart shows in the gutter: its newest value.
    func rowReading(_ r: Resource) -> String {
        guard let p = points.last(where: { !rowValue(r, $0).isNaN }) else { return "–" }
        let v = Double(rowValue(r, p))
        switch r {
        case .memory, .disk: return v < 9.95 ? String(format: "%.1fG", v) : String(format: "%.0fG", v)
        case .cpu: return String(format: "%.1f", v)
        case .gpu: return String(format: "%.0f%%", v)
        }
    }

    /// The small charts under the big one, on its time axis: the grid, no-data hatching, incident rules, one
    /// curve in the resource's colour (disk the calmest: a line over a faint fill), the name at the left over a
    /// halo, the newest reading in the gutter. Not a click target (§3.7.2).
    func rowsLayer(plot: CGRect, top: CGFloat, mapper f: @escaping (Double) -> Double, grid: [TimeAxis.GridLine],
                   labels: [TimeAxis.Label]) -> some View {
        let W = plot.width, H = rowHeight
        let cols = axis.columns(points, time: { $0.id }, gaps: gaps, f, reduce: Store.worst)
        let hatch = TimeAxis.gapBands(gaps, f)
        let incs = TimeAxis.incidentXs(incidents, f)
        let bg = Color(nsColor: .windowBackgroundColor)
        return ZStack(alignment: .topLeading) {
            ForEach(Array(rows.enumerated()), id: \.offset) { i, r in
                let scale = rowScale(r), reading = rowReading(r)
                Canvas { ctx, _ in
                    let w = Double(W), h = Double(H)
                    for l in grid {
                        ctx.fill(Path(CGRect(x: l.x * w - 0.25, y: 0, width: 0.5, height: h)), with: .color(.primary.opacity(l.alpha)))
                    }
                    ctx.fill(Path(CGRect(x: 0, y: h - 0.5, width: w, height: 0.5)), with: .color(.primary.opacity(0.2)))
                    var hp = Path()
                    for b in hatch { hp.addRect(CGRect(x: b.from * w, y: 0, width: max((b.to - b.from) * w, 1), height: h)) }
                    if !hp.isEmpty {
                        ctx.fill(hp, with: .color(.gray.opacity(0.06)))
                        var c = ctx
                        c.clip(to: hp)
                        c.stroke(TimeAxis.hatchLines(in: CGRect(x: 0, y: 0, width: w, height: h)), with: .color(.gray.opacity(0.4)), lineWidth: 1)
                    }
                    var line = Path(), area = Path()
                    var open = false, startX = 0.0, lastX = 0.0
                    func close() {
                        if open {
                            area.addLine(to: CGPoint(x: lastX, y: h)); area.addLine(to: CGPoint(x: startX, y: h)); area.closeSubpath()
                        }
                        open = false
                    }
                    for c in cols {
                        let v = rowValue(r, c.p)
                        if v.isNaN || c.gapBefore { close() }
                        if v.isNaN { continue }
                        let x = c.x * w, y = h - min(Double(v) / scale, 1) * (h - 2)
                        if open { line.addLine(to: CGPoint(x: x, y: y)); area.addLine(to: CGPoint(x: x, y: y)) } else {
                            line.move(to: CGPoint(x: x, y: y)); area.move(to: CGPoint(x: x, y: h)); area.addLine(to: CGPoint(x: x, y: y))
                            open = true; startX = x
                        }
                        lastX = x
                        if c.gapAfter { close() }
                    }
                    close()
                    let color = r.color
                    ctx.fill(area, with: .color(color.opacity(r == .disk ? 0.10 : 0.35)))
                    ctx.stroke(line, with: .color(color.opacity(0.9)), lineWidth: 1)
                    for x in incs { ctx.fill(Path(CGRect(x: x * w - 0.5, y: 0, width: 1, height: h)), with: .color(.red)) }
                    let name = ctx.resolve(Text(r.name).font(.system(size: 8.5, weight: .medium)).foregroundColor(.secondary))
                    let sz = name.measure(in: CGSize(width: 200, height: 20))
                    ctx.fill(Path(roundedRect: CGRect(x: 1, y: 1, width: sz.width + 6, height: sz.height), cornerRadius: 3),
                             with: .color(bg.opacity(0.75)))
                    ctx.draw(name, at: CGPoint(x: 4, y: 1), anchor: .topLeading)
                    ctx.draw(Text(reading).font(.system(size: 8.5)).foregroundColor(.secondary), at: CGPoint(x: w + 4, y: h / 2), anchor: .leading)
                }
                .frame(width: W + 40, height: H)
                .offset(x: plot.minX, y: top + CGFloat(i) * (H + 3))
            }
        }
        .allowsHitTesting(false)
    }

    // MARK: reservation strip

    /// Every reservation as blocks on the chart's time axis: height ∝ GB, stacked where they
    /// overlap, solid while granted, hatched while queued. The scale's top is a round figure above
    /// the highest stack in view.
    func stripRects(_ f: (Double) -> Double, W: CGFloat, H: CGFloat, blocks: [ResBlock]? = nil,
                    kind: Resource = .memory) -> (rects: [(i: Int, r: CGRect, queued: Bool)], top: Double) {
        let reservations = blocks ?? self.reservations
        var vis = 0.0
        for b in reservations where f(b.end) >= 0 {
            for st in b.steps where f(st.b) >= 0 { vis = max(vis, st.hi) }
        }
        let top = Reservation.bandTop(vis, kind)
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

    // With the resources on (B3, 02 §3.4.5, §3.7.6): a band per reserved resource shown, each on its own scale.
    static let bandGap: CGFloat = 4
    /// The strip's bands as drawn: (resource, its blocks, top, height); the first is tall and takes what the others
    /// leave of stripHeight. Without bands: the one memory strip of every reservation.
    var bandRects: [(kind: Resource, blocks: [ResBlock], y: CGFloat, h: CGFloat)] {
        guard !bands.isEmpty else { return [(.memory, reservations, 0, stripHeight)] }
        let tall: CGFloat = stripHeight - CGFloat(bands.count - 1) * (smallBand + MemoryChart.bandGap)
        var out: [(kind: Resource, blocks: [ResBlock], y: CGFloat, h: CGFloat)] = [(bands[0].kind, bands[0].blocks, 0, tall)]
        var y: CGFloat = tall
        for b in bands.dropFirst() {
            y += MemoryChart.bandGap
            out.append((b.kind, b.blocks, y, smallBand))
            y += smallBand
        }
        return out
    }

    func stripLayer(plot: CGRect, top: CGFloat, mapper f: @escaping (Double) -> Double, grid: [TimeAxis.GridLine],
                    missing: [TimeAxis.Band] = []) -> some View {
        let W = plot.width
        let rects = bandRects
        return ZStack(alignment: .topLeading) {
            ForEach(Array(rects.enumerated()), id: \.offset) { i, b in
                bandCanvas(b.blocks, kind: b.kind, tall: i == 0, W: W, H: b.h, mapper: f, grid: grid, missing: missing)
                    .offset(y: b.y)
            }
            Rectangle().fill(Color.clear).contentShape(Rectangle())
                .frame(width: W, height: stripHeight)
                .onContinuousHover { phase in
                    switch phase {
                    case .active(let p): stripHover = p
                    case .ended: stripHover = nil
                    }
                }
                .help(stripHover.flatMap { stripHit($0, f, W: W) } != nil ? "" : bands.isEmpty
                      ? "Memory reserved by agents (Claude sessions, oomph run), one block per reservation: height = GB reserved, hatched while queued, stacked where they overlap. Hover a block for details."
                      : "What agents reserve (Claude sessions, oomph run), a band per resource shown, each on its own scale: one block per reservation in its agent's colour, height = the amount, hatched while queued, stacked where they overlap. Hover a block for details.")
        }
        .offset(x: plot.minX, y: top)
    }

    /// One band: its blocks on the chart's time axis. The tall one has its scale, the time left of live grants and
    /// purpose labels; a small one is a baseline, its blocks and its name in the gutter (02 §3.4.5).
    func bandCanvas(_ blocks: [ResBlock], kind: Resource, tall: Bool, W: CGFloat, H: CGFloat, mapper f: (Double) -> Double,
                    grid: [TimeAxis.GridLine], missing: [TimeAxis.Band]) -> some View {
        let (rects, scaleTop) = stripRects(f, W: W, H: H, blocks: blocks, kind: kind)
        let now = now, dark = scheme == .dark
        let lit = highlight
        return Canvas { ctx, size in
                let usable = H - 4
                for l in grid where tall {
                    ctx.fill(Path(CGRect(x: l.x * W - 0.25, y: 0, width: 0.5, height: H)), with: .color(.primary.opacity(l.alpha)))
                }
                ctx.fill(Path(CGRect(x: 0, y: H - 0.5, width: W, height: 0.5)), with: .color(.primary.opacity(0.25)))
                if tall {
                    var topLine = Path()
                    topLine.move(to: CGPoint(x: 0, y: H - usable)); topLine.addLine(to: CGPoint(x: W, y: H - usable))
                    ctx.stroke(topLine, with: .color(.primary.opacity(0.12)), style: StrokeStyle(lineWidth: 0.5, dash: [2, 2]))
                }
                var plotCtx = ctx
                plotCtx.clip(to: Path(CGRect(x: 0, y: 0, width: W, height: H)))
                if !missing.isEmpty {
                    let w = Double(W)
                    TimeAxis.drawMissing(plotCtx, missing.map { ($0.from * w, $0.to * w) }, height: H)
                }
                var solid: [Int: Path] = [:], waiting: [Int: Path] = [:]
                for x in rects {
                    if x.queued { waiting[x.i, default: Path()].addRect(x.r) } else { solid[x.i, default: Path()].addRect(x.r) }
                }
                // a row of the list or a block under the pointer: its blocks stay, the rest dims (linked highlighting)
                func dim(_ i: Int) -> Double { lit == nil || blocks[i].res.id == lit ? 1 : 0.3 }
                // in the blocks' order: a Dictionary's changes with every launch, and so would the edges
                for (i, p) in solid.sorted(by: { $0.key < $1.key }) { plotCtx.fill(p, with: .color(blocks[i].res.tint(dark: dark).opacity(0.8 * dim(i)))) }
                for (i, p) in waiting.sorted(by: { $0.key < $1.key }) {
                    let c = blocks[i].res.tint(dark: dark)
                    plotCtx.fill(p, with: .color(c.opacity(0.12 * dim(i))))
                    var h = plotCtx
                    h.clip(to: p)
                    h.stroke(TimeAxis.hatchLines(in: p.boundingRect, spacing: 4), with: .color(c.opacity(0.75 * dim(i))), lineWidth: 1)
                }
                if let lit {
                    for x in rects where blocks[x.i].res.id == lit {
                        plotCtx.stroke(Path(x.r.insetBy(dx: -0.5, dy: -0.5)), with: .color(.primary.opacity(0.7)), lineWidth: 1)
                    }
                }
                // purpose labels on the widest granted part of each block, when it fits
                var best: [Int: CGRect] = [:]
                for x in rects where !x.queued && x.r.height >= 9 && x.r.width > (best[x.i]?.width ?? 0) { best[x.i] = x.r }
                for (i, r) in best.sorted(by: { $0.key < $1.key }) where r.width >= 24 && tall {
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
                guard tall else {  // a small band: its name in the gutter, nothing else
                    ctx.draw(Text(kind.name).font(.system(size: 8.5)).foregroundColor(.secondary),
                             at: CGPoint(x: W + 4, y: H / 2), anchor: .leading)
                    return
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
                    let scale = String(format: kind == .cpu ? "%.0fc" : "%.0fG", scaleTop)  // "24c": the gutter is 30 pt
                    ctx.draw(Text(scale).font(.system(size: 8.5)).foregroundColor(.secondary),
                             at: CGPoint(x: W + 4, y: H - usable), anchor: .leading)
                }
                if rects.isEmpty {
                    let none = kind == .memory ? "No reservations in this range" : "No \(kind.name) reservations in this range"
                    ctx.draw(Text(none).font(.system(size: 9)).foregroundColor(.secondary),
                             at: CGPoint(x: W / 2, y: H / 2), anchor: .center)
                }
            }
            .frame(width: W + 40, height: H)
            .allowsHitTesting(false)
    }

    /// The reservation under the pointer on the strip, if any, and its rect in strip coordinates (in its band).
    func stripHit(_ p: CGPoint, _ f: (Double) -> Double, W: CGFloat) -> (block: ResBlock, rect: CGRect)? {
        guard let band = bandRects.first(where: { p.y >= $0.y - 2 && p.y <= $0.y + $0.h + 2 }) else { return nil }
        let q = CGPoint(x: p.x, y: p.y - band.y)
        let (rects, _) = stripRects(f, W: W, H: band.h, blocks: band.blocks, kind: band.kind)
        let hit = rects.last { $0.r.insetBy(dx: -2, dy: -1).contains(q) }
            ?? rects.filter { q.x >= $0.r.minX - 2 && q.x <= $0.r.maxX + 2 }.min { abs($0.r.midY - q.y) < abs($1.r.midY - q.y) }
        return hit.map { (band.blocks[$0.i], $0.r.offsetBy(dx: 0, dy: band.y)) }
    }

    @ViewBuilder func stripCard(plot: CGRect, top: CGFloat, width: CGFloat, mapper f: (Double) -> Double) -> some View {
        if let p = stripHover, let (b, r) = stripHit(p, f, W: plot.width) {
            let x = plot.minX + p.x
            let w = MemoryChart.cardWidth
            if bands.count > 1 {  // the same reservation in every other band (linked highlighting)
                ForEach(Array(otherRects(of: b.res.id, besides: r, f, W: plot.width).enumerated()), id: \.offset) { _, o in
                    Rectangle().strokeBorder(Color.primary.opacity(0.7), lineWidth: 1)
                        .frame(width: max(o.width, 1.5) + 2, height: o.height + 2)
                        .offset(x: plot.minX + o.minX - 1, y: top + o.minY - 1)
                        .allowsHitTesting(false)
                }
            }
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

    /// The rects of reservation `id` in every band but the one hovered, in strip coordinates.
    func otherRects(of id: String, besides hit: CGRect, _ f: (Double) -> Double, W: CGFloat) -> [CGRect] {
        var out: [CGRect] = []
        for band in bandRects where !(hit.minY >= band.y - 1 && hit.maxY <= band.y + band.h + 1) {
            let (rects, _) = stripRects(f, W: W, H: band.h, blocks: band.blocks, kind: band.kind)
            out += rects.filter { band.blocks[$0.i].res.id == id }.map { $0.r.offsetBy(dx: 0, dy: band.y) }
        }
        return out
    }

    static func shortDuration(_ s: Double) -> String {
        let m = max(Int((s / 60).rounded()), 0)
        return m < 60 ? "\(m)m" : (m % 60 == 0 || m >= 600 ? "\(m / 60)h" : "\(m / 60)h\(String(format: "%02d", m % 60))")
    }

    func axisLabelLayer(_ proxy: ChartProxy, labels: [TimeAxis.Label]) -> some View {
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
    @ViewBuilder func hoverLayer(plot: CGRect, mapper f: @escaping (Double) -> Double, stripTop: CGFloat,
                                 rowsTop: CGFloat? = nil) -> some View {
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
            if let rt = rowsTop {  // and through every small chart (02 §3.4.4)
                Rectangle().fill(Color.primary.opacity(0.4))
                    .frame(width: 1, height: max(rowsHeight - 3, 1))
                    .offset(x: x - 0.5, y: rt)
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
        var others: [(String, String, Color)] = []  // with the resources on: CPU, GPU and disk in this pixel
        // a Linux tab (03 §3.9, L3): what was available in place of the peak, the one Stalled line, the row budget
        var linux = false
        var avail: String?
        var stalled: String?
    }

    /// Everything under one horizontal pixel, aggregated: on the log axis one pixel can hold hours.
    func hoverInfo(u: Double, du: Double, mapper f: (Double) -> Double) -> HoverInfo {
        var info = HoverInfo()
        let t0 = axis.time(at: max(u - du / 2, 0), f), t1 = axis.time(at: min(u + du / 2, 1), f)
        let tc = (t0 + t1) / 2
        // the time under the pointer
        let day = TimeAxis.dayFmt, clock = TimeAxis.timeFmt
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
            var cols: [(String, KeyPath<Point, Double>)] = [("App", \.app), ("Compressed", \.comp), (wiredName, \.wired), ("Swap", \.swap)]
            if let lf = linux {  // the series the machine has (03 §3.9's row budget)
                let have = Set(LinuxTab.hoverSeries(lf))
                cols = cols.filter { have.contains($0.0) }
                info.avail = ram.flatMap { LinuxTab.availText(pts, ram: $0) }
                info.stalled = LinuxTab.stallText(pts)
            }
            info.readings = cols.map { (name, k) in
                Reading(name: name, lo: pts.map { $0[keyPath: k] }.min()!, hi: pts.map { $0[keyPath: k] }.max()!)
            }
            info.away = pts.contains { $0.away }
            info.peak = pts.map { $0.wired + $0.app + $0.comp + $0.swap }.max() ?? 0
            if resourcesUIOn { info.others = MemoryChart.otherReadings(pts, cores: cores) }
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
        let e0 = axis.time(at: max(u - 3 * du, 0), f), e1 = axis.time(at: min(u + 3 * du, 1), f)
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
            case "oom_kill":  // a Linux machine's kills in one pixel (03 §3.9)
                let k = LinuxTab.killText(LinuxTab.merged(es.map(\.raw)))  // the same words as each event's
                lines.append((k.0, !k.1))
            case "pressure_change":
                lines.append(("pressure changed \(es.count)× · last: " + es.last!.text.replacingOccurrences(of: "pressure ", with: ""), false))
            case "sleep_gap", "stall":
                lines.append(((k == "stall" ? "system stalled" : "asleep") + " \(es.count)×, "
                              + MemoryChart.duration(es.reduce(0) { $0 + $1.seconds }) + " in all", es[0].alarming))
            default:
                lines.append((es.last!.text + " ×\(es.count)", es[0].alarming))
            }
        }
        // the row budget of a Linux tab (03 §3.9): one incident, two events, two reservations; the Mac's six and four
        let lin = linux != nil
        info.linux = lin
        if lin { info.incidents = Array(info.incidents.prefix(1)) }
        let maxEv = lin ? 2 : 6, maxRes = lin ? 2 : 4
        info.events = Array(lines.prefix(maxEv))
        info.moreEvents = max(lines.count - maxEv, 0)
        let res = reservations.filter { $0.res.requested <= t1 && $0.end >= t0 }
        info.reserved = res.prefix(maxRes).map { b in
            let queued = (b.res.granted ?? .infinity) > tc
            return (String(format: "%.1f GB ", b.res.gb(at: min(max(tc, b.res.requested), b.end))) + b.res.purpose
                    + (queued ? " (queued)" : ""), resourcesUIOn ? b.res.agentColor(dark: scheme == .dark) : b.res.color)
        }
        info.moreReserved = max(res.count - maxRes, 0)
        return info
    }

    /// The hover card's line per resource besides memory (02 §3.4.4), over the samples in the pixel.
    static func otherReadings(_ pts: [Point], cores: Double?) -> [(String, String, Color)] {
        func mean(_ xs: [Float]) -> Double? {
            let v = xs.filter { !$0.isNaN }
            return v.isEmpty ? nil : Double(v.reduce(0, +)) / Double(v.count)
        }
        var out: [(String, String, Color)] = []
        if let c = mean(pts.map(\.cpu)) {
            let n = cores ?? mean(pts.map(\.cpuN))
            out.append(("CPU", String(format: "%.1f", c) + (n.map { String(format: " of %.0f cores", $0) } ?? " cores"), Resource.cpu.color))
        }
        let kind = pts.last { $0.gpuKind > 0 }?.gpuKind ?? 0
        if let g = mean(pts.filter { $0.gpuKind == kind }.map(\.gpu)) {
            let mem = mean(pts.map(\.gpuMem)).map { String(format: " · %.1f GB", $0) } ?? ""
            out.append((kind == 2 ? "GPU" : "GPU busy", String(format: "%.0f %%", g) + mem, Resource.gpu.color))
        }
        if let d = pts.map(\.disk).filter({ !$0.isNaN }).min() {
            out.append(("Disk", String(format: "%.0f GB free", Double(d)), Resource.disk.color))
        }
        return out
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
        static let colors: [String: Color] = ["App": .blue, "Compressed": .orange, "Wired": .gray, "Kernel": .gray, "Swap": .red]

        func gb(_ r: Reading) -> String {
            let lo = String(format: "%.1f", r.lo), hi = String(format: "%.1f", r.hi)
            return lo == hi ? hi + " GB" : "\(lo)–\(hi) GB"
        }

        /// A line of the card in the secondary colour: a name and its figure (a Linux tab's Available and Stalled).
        func cardLine(_ name: String, _ value: String) -> some View {
            HStack {
                Text(name).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
                Spacer(minLength: 4)
                Text(value).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
            }
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
                if info.linux, !info.readings.isEmpty {  // in place of "all four, peak" (03 §3.9)
                    if let a = info.avail { cardLine("Available" + (info.away ? " · away" : ""), a) }
                    if let st = info.stalled { cardLine("Stalled", st) }
                } else if !info.readings.isEmpty {
                    HStack {
                        Text((info.samples > 1 ? "all four, peak" : "all four") + (info.away ? " · away" : ""))
                            .font(.system(size: 10)).foregroundStyle(.secondary)
                        Spacer()
                        Text(String(format: "%.1f GB", info.peak)).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary)
                    }
                }
                ForEach(Array(info.others.enumerated()), id: \.offset) { _, o in
                    HStack(spacing: 5) {
                        RoundedRectangle(cornerRadius: 1.5).fill(o.2).frame(width: 6, height: 6)
                        Text(o.0).font(.system(size: 10))
                        Spacer(minLength: 4)
                        Text(o.1).font(.system(size: 10, design: .monospaced))
                    }
                }
                if let n = info.noData {
                    SwiftUI.Label(n, systemImage: info.noDataIcon).font(.system(size: 10)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if !info.incidents.isEmpty || !info.events.isEmpty { Divider().padding(.vertical, 1) }
                ForEach(Array(info.incidents.prefix(2).enumerated()), id: \.offset) { _, t in
                    Text(t).font(.system(size: 10, weight: .medium)).foregroundStyle(.red).lineLimit(info.linux ? 2 : 3)
                        .fixedSize(horizontal: false, vertical: true)
                }
                ForEach(Array(info.events.enumerated()), id: \.offset) { _, e in
                    Text("• " + e.0).font(.system(size: 10)).foregroundStyle(e.1 ? Color.red : Color.primary).lineLimit(info.linux ? 1 : 2)
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
    func columns(_ f: (Double) -> Double) -> ([Entry], [TimeAxis.Band]) {
        let cols = axis.columns(points, time: { $0.id }, gaps: gaps, f, reduce: Store.worst)
        var entries: [Entry] = []
        var id = 0
        func add(_ x: Double, _ p: Point?) {
            let v: [Double] = p.map { [$0.wired, $0.app, $0.comp, $0.swap] } ?? [0, 0, 0, 0]
            for (k, name) in MemoryChart.series.enumerated() {
                entries.append(Entry(id: id, x: x, kind: name, gb: v[k])); id += 1
            }
        }
        for c in cols {
            if c.gapBefore { add(c.x - 1e-6, nil) }
            add(c.x, c.p)
            if c.gapAfter { add(c.x + 1e-6, nil) }
        }
        return (entries, TimeAxis.awayBands(cols, away: { $0.away }))
    }

    /// "06:36" today, "Tue 4 Nov 06:36" before.
    static func when(_ t: Double) -> String {
        let d = Date(timeIntervalSince1970: t)
        if isWallToday(d) { return TimeAxis.timeFmt.string(from: d) }
        let f = DateFormatter(); f.dateFormat = "EEE d MMM HH:mm"
        return f.string(from: d)
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
    @Environment(\.colorScheme) private var scheme

    static let clock: DateFormatter = { let f = DateFormatter(); f.dateFormat = "HH:mm"; return f }()
    static let dayClock: DateFormatter = { let f = DateFormatter(); f.dateFormat = "EEE d HH:mm"; return f }()
    func at(_ t: Double) -> String {
        let d = Date(timeIntervalSince1970: t)
        return isWallToday(d) ? ReservationCard.clock.string(from: d) : ReservationCard.dayClock.string(from: d)
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

    func cardCores(_ c: Double, on: Bool) -> String {
        var t: String = Reservation.coresWords(c)
        if on, let u = res.cpuUsed { t += " · using " + Reservation.coresWords(u) }
        return t
    }
    func cardDisk(_ d: Double, on: Bool) -> String {
        var t: String = Reservation.amtG(d) + " on " + Tile.midFit(res.diskName ?? res.diskPool ?? "?", 24)
        if on, let w = res.diskWrote { t += " · wrote " + Reservation.amtG(w) }
        return t
    }

    /// A queued one's "Now": with the resources on, what it waits for (02 §3.4.6), "queued, waiting for CPU".
    var queuedText: String {
        let w: [String] = resourcesUIOn ? res.waitingFor.compactMap { Reservation.word[$0] } : []
        return w.isEmpty ? "queued, waiting for room" : "queued, waiting for " + Reservation.and(w)
    }

    var body: some View {
        let gbs = res.segments.map { String(format: "%.1f", $0.gb) }.joined(separator: " → ") + " GB"
        let edits = res.segments.count > 1 ? " (changed " + res.segments.dropFirst().map { at($0.t) }.joined(separator: ", ") + ")" : ""
        VStack(alignment: .leading, spacing: 3) {
            HStack(alignment: .firstTextBaseline, spacing: 5) {
                RoundedRectangle(cornerRadius: 2).fill(res.tint(dark: scheme == .dark).opacity(0.85)).frame(width: 8, height: 8)
                Text(res.purpose).font(.system(size: 11, weight: .semibold)).lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 4)
                Text(res.rid).font(.system(size: 9, design: .monospaced)).foregroundStyle(.tertiary)
            }
            if res.projectName != nil || res.holder != nil {
                // with the resources on the colour is the agent's, so the card says whose in words (02 §3.8.5)
                let agent = resourcesUIOn ? res.agentKey.map { "agent " + String($0.prefix(4)) } : nil
                Text([res.projectName, res.holder.map { $0 == "run" ? "oomph run" : $0 }, agent].compactMap { $0 }.joined(separator: " · "))
                    .font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
            }
            Divider().padding(.vertical, 1)
            if !resourcesUIOn || res.holdsMemory {
            row("Reserved", gbs + edits)
            row("Peak used", res.live && res.granted != nil
                ? String(format: "%.1f GB so far (%.1f GB now)", res.peak, res.used ?? 0)
                : String(format: "%.1f GB", res.peak))
            }
            if resourcesUIOn {  // the vector card (02 §3.4.5): its cores and disk space, and the advice on them
                let on = res.live && res.granted != nil
                if let c = res.cpu { row("Cores", cardCores(c, on: on)) }
                if let d = res.disk { row("Disk", cardDisk(d, on: on)) }
                if on {
                    ForEach(Resource.allCases.filter { res.flags[$0] != nil }, id: \.self) { (k: Resource) in
                        row("Advice", Reservation.adviceWords(k, res.flags[k]!, now: now, clock: { at($0) }))
                            .foregroundStyle(.orange)
                    }
                }
            }
            if let g = res.granted {
                row("Granted", at(g) + (g - res.requested >= 60 ? " · waited " + MemoryChart.duration(g - res.requested) : ""))
            } else {
                row("Requested", at(res.requested) + " · waited " + MemoryChart.duration((res.ended ?? now) - res.requested))
            }
            if let e = res.ended {
                row("Ended", at(e) + " · " + (ReservationCard.outcomes[res.outcome ?? ""] ?? (res.outcome ?? "")))
                if let g = res.granted { row("Held", MemoryChart.duration(e - g)) }
            } else if res.granted == nil {
                row("Now", queuedText)
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
    /// A Linux tab (03 §3.9): Wired is "Kernel"; a server has no "away" entry (no one sits at it); only the series the
    /// machine has, with Linux texts (L3: no Compressed without zram or zswap, no Swap without swap).
    var linux = false
    var away = true
    var compressed = true
    var swap = true
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
                ctx.stroke(TimeAxis.hatchLines(in: r, spacing: 3.5), with: .color(.gray.opacity(0.75)), lineWidth: 1)
            }
            .frame(width: 9, height: 7)
        case 4:
            Canvas { ctx, size in
                let r = CGRect(origin: .zero, size: size)
                ctx.fill(Path(r), with: .color(.gray.opacity(0.06)))
                ctx.fill(TimeAxis.dots(in: r, spacing: 3), with: .color(.gray.opacity(0.75)))
            }
            .frame(width: 9, height: 7)
        default: Rectangle().fill(Color.red).frame(width: 1.5, height: 8).frame(width: 5)
        }
    }

    /// A series' colour by its name (a Linux tab may leave some out).
    static func color(_ name: String) -> Color {
        let i = MemoryChart.series.firstIndex(of: name == "Kernel" ? "Wired" : name) ?? 0
        return MemoryChart.seriesColors[i]
    }

    static let kernel = Item(name: "Kernel", help: "Kernel: slab, page tables, drivers and reserves; what is neither app memory nor available.", kind: 0)

    /// The rows as this tab shows them.
    var shownRows: [[Item]] {
        var r = ChartLegend.rows
        if linux {
            r[0][0] = ChartLegend.kernel
            r[0] = r[0].filter { ($0.name != "Compressed" || compressed) && ($0.name != "Swap" || swap) }
                .map { Item(name: $0.name, help: LinuxTab.legendHelp[$0.name] ?? $0.help, kind: $0.kind) }
            r[1] = r[1].map { Item(name: $0.name, help: LinuxTab.legendHelp[$0.name] ?? $0.help, kind: $0.kind) }
        }
        if !away { r[1].removeAll { $0.kind == 1 } }
        if missing { r[1].append(ChartLegend.notReceived) }
        return r
    }

    static let notReceived = Item(name: "not received", help: "Dotted: this Mac has not received this stretch from that machine — it was not connected then. It fills in when the machine is back; a stretch older than what it keeps never will.", kind: 4)

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(Array(shownRows.enumerated()), id: \.offset) { r, row in
                HStack(spacing: 7) {
                    ForEach(Array(row.enumerated()), id: \.offset) { _, it in
                        HStack(spacing: 3) {
                            swatch(it, r == 0 ? ChartLegend.color(it.name) : .clear)
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

/// The legend with the resources on (roadmap 02 §3.4.2): the focus's series with their live values in row 1,
/// the away, no-data and incident entries in row 2 as before. Values come from the current sample.
struct ResourceLegend: View {
    let focus: Resource
    let sample: Sample?
    var missing = false
    var linux = false
    var away = true
    var compressed = true
    var hasSwap = true

    struct Entry { let name: String; let value: String?; let color: Color; let line: Bool; let help: String }

    static func unitHelp(_ r: Resource) -> String {
        switch r {
        case .memory: return "Memory in GB; the dashed line is the Mac's RAM. "
        case .cpu: return "Cores busy, of the logical cores; the dashed line is all of them. "
        case .gpu: return "The GPU in % of what it can do at full speed, or of the time it was busy where the speed is not reported. "
        case .disk: return "Free space in GB on the disk the tile shows; dashed: its low and critical floors. "
        }
    }

    var entries: [Entry] {
        let s = sample
        func f1(_ x: Double?) -> String? { x.map { String(format: "%.1f", $0) } }
        switch focus {
        case .memory:
            let swap = s.map { $0.swap_used_gb > 0 ? String(format: "%.1f / %.0f", $0.swap_used_gb, $0.swap_total_gb)
                                                   : String(format: "%.1f", $0.swap_used_gb) }
            let wired = linux ? ChartLegend.kernel : ChartLegend.rows[0][0]
            let all = [Entry(name: wired.name, value: f1(s?.wired_gb), color: .gray, line: false, help: wired.help),
                       Entry(name: "App", value: f1(s?.app_gb), color: .blue, line: false, help: ChartLegend.rows[0][1].help),
                       Entry(name: "Compressed", value: f1(s?.compressed_gb), color: .orange, line: false, help: ChartLegend.rows[0][2].help),
                       Entry(name: "Swap", value: swap, color: .red, line: false, help: ChartLegend.rows[0][3].help)]
            guard linux else { return all }  // a Linux tab: its series and texts (L3)
            return all.filter { ($0.name != "Compressed" || compressed) && ($0.name != "Swap" || hasSwap) }
                .map { Entry(name: $0.name, value: $0.value, color: $0.color, line: $0.line, help: LinuxTab.legendHelp[$0.name] ?? $0.help) }
        case .cpu:
            let c = s?.cpu?.v
            let user = c?.busy.map { $0 - (c?.sys ?? 0) }
            return [Entry(name: "System", value: f1(c?.sys), color: .gray, line: false, help: "Cores busy in the kernel."),
                    Entry(name: "User", value: f1(user), color: Resource.cpu.color, line: false, help: "Cores busy in apps and processes."),
                    Entry(name: c?.p != nil && c?.e != nil ? String(format: "%.0f P + %.0f E cores", c!.p!, c!.e!) : c?.n.map { String(format: "%.0f cores", $0) } ?? "cores",
                          value: nil, color: .clear, line: false, help: "The logical cores of this Mac.")]
        case .gpu:
            let g = s?.gpu?.v?.first
            let mem = g?.mem_gb.map { String(format: "%.1f GB", $0) }
            if g?.src == "ioreport" {
                return [Entry(name: "Full speed", value: g?.util.map { String(format: "%.0f", $0) }, color: Resource.gpu.color, line: false,
                              help: "The share of what the GPU can do at full speed."),
                        Entry(name: "Busy", value: g?.active.map { String(format: "%.0f", $0) }, color: Resource.gpu.color, line: true,
                              help: "The share of time the GPU was working, at any speed."),
                        Entry(name: "Memory", value: mem, color: .gray, line: false, help: "GPU memory in use.")]
            }
            return [Entry(name: "Busy", value: g?.util.map { String(format: "%.0f", $0) }, color: Resource.gpu.color.opacity(0.4), line: false,
                          help: "the share of time the GPU was working, at any speed. This Mac does not report how fast the GPU ran, so light work reads higher here than it weighs: an idle desktop shows 30 to 50 %"),
                    Entry(name: "Memory", value: mem, color: .gray, line: false, help: "GPU memory in use."),
                    Entry(name: "speed not reported", value: nil, color: .clear, line: false,
                          help: "Busy time only: the full-speed figure needs the IOReport helper (`oomph doctor`).")]
        case .disk:
            let d = Tile.pool(s?.disks?.v).pool
            let free = d?.free_gb ?? s?.disk_free_gb
            let name = "Free on " + Tile.midFit((d?.name?.isEmpty == false ? d?.name : nil) ?? "disk", 12)
            let of = d?.total_gb.map { String(format: " of %.0f GB", $0) } ?? " GB"
            return [Entry(name: name, value: free.map { String(format: "%.0f", $0) + of }, color: Resource.disk.color, line: false,
                          help: "Free space on the disk that holds your home folder and the temporary files.")]
        }
    }

    /// Row 1 at a level of shortening (§3.4.2's overflow rule: values are never dropped; "Compressed" becomes
    /// "Compr.", then the names go, the swatch and the value stay).
    func valuesRow(_ short: Int) -> some View {
        HStack(spacing: 4) {
            ForEach(Array(entries.enumerated()), id: \.offset) { _, e in
                HStack(spacing: 2.5) {
                    if e.line {
                        Rectangle().fill(e.color).frame(width: 8, height: 1.5)
                    } else if e.color != .clear {
                        RoundedRectangle(cornerRadius: 1.5).fill(e.color).frame(width: 7, height: 7)
                    } else {
                        Text("·")
                    }
                    if short < 2 || e.value == nil { Text(short >= 1 && e.name == "Compressed" ? "Compr." : e.name) }
                    if let v = e.value { Text(v).fontWeight(.semibold).foregroundStyle(.primary).monospacedDigit() }
                }
                .contentShape(Rectangle())
                .help(e.help)
            }
        }
        .fixedSize()
    }

    var body: some View {
        let legend = ChartLegend(missing: missing, linux: linux, away: away, compressed: compressed, swap: hasSwap)
        VStack(alignment: .trailing, spacing: 2) {
            ViewThatFits(in: .horizontal) { valuesRow(0); valuesRow(1); valuesRow(2) }
            HStack(spacing: 7) {
                ForEach(Array(legend.shownRows[1].enumerated()), id: \.offset) { _, it in
                    HStack(spacing: 3) {
                        legend.swatch(it, .clear)
                        Text(it.name)
                    }
                    .contentShape(Rectangle())
                    .help(it.help)
                }
            }
        }
        .font(.system(size: 9))
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: 246, alignment: .trailing)
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
    /// The reservation whose row the pointer is on: its blocks are outlined in every band (02 §3.4.5, resources on).
    @State var hoveredRow: String? = nil
    /// The callout of a quiet machine's capsule: its logger stopped, and what starts it again (03 §3.9 state A).
    @State var showRemedy = false
    @State private var shakes: [Resource: Int] = [:]  // a refused ⌘-click shakes its tile (§3.7.2)
    @Environment(\.colorScheme) private var scheme
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
                if let r = m.remedy, m.quietState != .stopped {
                    remedyBlock(r).tourAnchor("stats")   // no tiles there: the remedy stands in their place (B, C)
                } else if resourcesUIOn {
                    if m.stale || m.quietState == .stopped { tilesRow.grayscale(1).opacity(0.5).tourAnchor("stats") }
                    else { tilesRow.opacity(m.inGrace ? 0.6 : 1).tourAnchor("stats") }
                } else if let c = m.current, m.showsStats {
                    if m.stale || m.quietState == .stopped { stats(c).grayscale(1).opacity(0.5).tourAnchor("stats") }
                    else { stats(c).opacity(m.inGrace ? 0.6 : 1).tourAnchor("stats") }
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
        // taller than its content only while the panel animates down to it: the content stays at the top
        // (and the panel, not AppKit's layout, decides when the window shrinks); a render keeps its own size
        .frame(maxHeight: renderMode ? nil : .infinity, alignment: .top)
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
                        focusCallout(arrowX: r.midX - left)
                            .frame(width: w)
                            .padding(.leading, left)
                            .padding(.top, r.maxY + 2)
                            .transition(.opacity.combined(with: .scale(scale: 0.96, anchor: .topTrailing)))
                    }
                }
            }
        }
        .overlayPreferenceValue(RemedyAnchorKey.self) { anchor in
            GeometryReader { geo in
                if showRemedy, let anchor, let r = m.remedy {
                    let a = geo[anchor]
                    let w: CGFloat = 300
                    let left = min(max(8, a.midX - w + 40), geo.size.width - w - 8)
                    ZStack(alignment: .topLeading) {
                        Color.black.opacity(0.001)
                            .onTapGesture { withAnimation(.easeOut(duration: 0.15)) { showRemedy = false } }
                        remedyCallout(r, arrowX: a.midX - left, width: w)
                            .frame(width: w)
                            .padding(.leading, left)
                            .padding(.top, a.maxY + 2)
                            .transition(.opacity.combined(with: .scale(scale: 0.96, anchor: .topTrailing)))
                    }
                }
            }
        }
        .overlayPreferenceValue(MoreAnchorKey.self) { anchor in
            GeometryReader { geo in
                if showAllReservations, let anchor {
                    let r = geo[anchor]
                    let w: CGFloat = resourcesUIOn ? min(geo.size.width - 16, 470) : 360  // the amounts need room (B3)
                    let left = min(max(8, r.minX + 40 - w / 2), geo.size.width - w - 8)
                    ZStack(alignment: .topLeading) {
                        Color.black.opacity(0.001)
                            .onTapGesture { withAnimation(.easeOut(duration: 0.15)) { showAllReservations = false } }
                        allReservationsCallout(arrowX: r.minX + 40 - left, width: w)
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
        .onExitCommand { withAnimation(.easeOut(duration: 0.15)) { showTopApps = false; showAI = false; showAllReservations = false; showRemedy = false; tourStep = nil } }
        .onChange(of: store.calloutAsked) { _, _ in
            withAnimation(.easeOut(duration: 0.15)) { showTopApps.toggle(); showAI = false }
        }
        .onChange(of: store.refused?.1) { _, _ in
            guard let r = store.refused?.0 else { return }
            withAnimation(.linear(duration: 0.2)) { shakes[r, default: 0] += 1 }
        }
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
        // with the resources on, the capsule and the chip's tile are oomph's verdict (02 §3.4.9, §15.13)
        let cap = resourcesUIOn && live ? Verdict.capsule(m.current!) : nil
        let tint: Color = live ? (cap.map { Verdict.color($0.level) } ?? p.color) : .secondary
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
                    (Text(brand).fontWeight(.bold) + Text(resourcesUIOn ? resourceDescriptor : descriptor).fontWeight(.medium))
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
            if let cap {
                Text(cap.text).font(.system(size: 11, weight: .semibold))
                    .padding(.horizontal, 10).padding(.vertical, 4)
                    .background(Verdict.color(cap.level).opacity(0.2), in: Capsule())
                    .foregroundStyle(cap.level == 0 ? Color.primary : Verdict.color(cap.level))
                    .help(m.current.map { capsuleHelp($0) } ?? "")
            } else if resourcesUIOn && !live {  // logging is off, or the logger says nothing (02 §3.4.9)
                Text("Off").font(.system(size: 11, weight: .semibold))
                    .padding(.horizontal, 10).padding(.vertical, 4)
                    .background(Color.gray.opacity(0.2), in: Capsule())
            } else if live {
                Text(p.label).font(.system(size: 11, weight: .semibold))
                    .padding(.horizontal, 10).padding(.vertical, 4)
                    .background(p.color.opacity(0.2), in: Capsule())
                    .foregroundStyle(p == .normal ? .primary : p.color)
            }
        }
    }

    /// The capsule's tooltip: what the verdict found, memory and disk, in words.
    func capsuleHelp(_ c: Sample) -> String {
        let v = Verdict.capsule(c)
        var parts = [brand + "'s verdict, the same as `oomph check`: memory " + ["ok", "tight", "critical"][v.memory]
                     + ", disk " + ["ok", "low", "critical"][v.disk]]
        parts.append(String(format: "pressure %@ · %.1f GB free · swap %.1f / %.0f GB · %.0f GB disk free",
                            (Pressure(rawValue: c.pressure) ?? .unknown).label.lowercased(),
                            max(0, c.ram_gb - c.app_gb - c.wired_gb - c.compressed_gb), c.swap_used_gb, c.swap_total_gb, c.disk_free_gb))
        // The metered warning is measuring, behind no switch (NET 12.11): with resourcesUI off the pressure capsule's
        // tooltip carries this line too, the one place the switched-off popup says it (deliberate).
        if let h = Verdict.quotaHelp(c) { parts.append(h) }
        return parts.joined(separator: "\n")
    }

    /// The header of another machine (roadmap 01 §3.3, §3.5): its name, its kind's tile tinted by
    /// its pressure, its state in the status line and the capsule. Not connected: the tile and
    /// the capsule's fill are grey, the capsule's words stay in the primary colour.
    var mirrorHeader: some View {
        let live = !m.stale && m.current != nil && m.remedy == nil
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
                if let r = m.remedy {  // reached, but little to show (03 §3.9, A to C): grey; A's opens its remedy
                    if m.quietState == .stopped {
                        Button { withAnimation(.easeOut(duration: 0.15)) { showRemedy.toggle(); showTopApps = false } } label: {
                            Text(r.capsule).padding(.horizontal, 10).padding(.vertical, 4)
                                .background(Color.gray.opacity(0.22), in: Capsule()).foregroundStyle(.primary)
                        }
                        .buttonStyle(.plain).padding(.horizontal, -10).padding(.vertical, -4)
                        .help(r.title + " Click for what starts it again.")
                        .anchorPreference(key: RemedyAnchorKey.self, value: .bounds) { $0 }
                    } else {
                        Text(r.capsule).background(Color.gray.opacity(0.22), in: Capsule()).foregroundStyle(.primary)
                    }
                } else if live {
                    Text(p.label).background(p.color.opacity(0.2), in: Capsule()).foregroundStyle(p == .normal ? .primary : p.color)
                        .help(m.isLinux ? LinuxTab.capsuleHelp(m.current!, m.facts) : capsuleHelp(m.current!))  // L3: Linux terms
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
        if let r = m.remedy { return r.status }
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
            let left: Double = (m.link?.next_try ?? 0) - wallNow()
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

    @ViewBuilder func stats(_ c: Sample) -> some View {
        if m.isLinux { linuxStats(c) } else { macStats(c) }
    }

    func macStats(_ c: Sample) -> some View {
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

    /// A Linux tab's tiles (03 §3.9): LinuxTab's matrix in the Mac's two rows of four, the biggest group last.
    func linuxStats(_ c: Sample) -> some View {
        let cells = LinuxTab.tiles(c, m.facts, name: m.title)
        return VStack(spacing: 8) {
            HStack {
                LinuxStat(cell: cells[0]); LinuxStat(cell: cells[1]); LinuxStat(cell: cells[2])
                LinuxStat(cell: cells[3], wide: true)
            }
            HStack {
                LinuxStat(cell: cells[4]); LinuxStat(cell: cells[5]); LinuxStat(cell: cells[6])
                groupTile(cells[7])
            }
        }
    }

    /// The biggest group: its size, its name below; a click lists the biggest groups (not where the logger
    /// sees only its own processes).
    func groupTile(_ cell: LinuxTab.Cell) -> some View {
        let visible = m.facts.allProcs != false
        return Button {
            guard visible else { return }
            NSApp.keyWindow?.makeFirstResponder(nil)
            withAnimation(.easeOut(duration: 0.15)) { showTopApps.toggle(); showAI = false; showRemedy = false }
        } label: {
            VStack(alignment: .leading, spacing: 1) {
                HStack(alignment: .firstTextBaseline, spacing: 5) {
                    Text(cell.value).font(.system(size: 13, weight: .semibold)).monospacedDigit()
                    Text(cell.label).font(.system(size: 10)).foregroundStyle(.secondary)
                }
                HStack(spacing: 3) {
                    Text(cell.sub ?? "").lineLimit(1).truncationMode(.middle)
                    if visible { Image(systemName: showTopApps ? "chevron.up" : "chevron.down").font(.system(size: 7, weight: .bold)) }
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
        .help(cell.help)
        .anchorPreference(key: TopAppAnchorKey.self, value: .bounds) { $0 }
    }

    /// A command for the other machine and its Copy button (03 §3.9: inside the frame, never cut off).
    func commandRow(_ cmd: String) -> some View {
        HStack(spacing: 6) {
            Text(cmd).font(.system(size: 10.5, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                .padding(.horizontal, 6).padding(.vertical, 3)
                .background(Color.primary.opacity(0.07), in: RoundedRectangle(cornerRadius: 4))
            Button("Copy") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(cmd, forType: .string)
            }
            .controlSize(.small).focusable(false)
            .help("Copy the command, to run it on \(m.title)")
        }
    }

    /// States B and C (03 §3.9): there are no tiles, so the remedy stands in their place.
    func remedyBlock(_ r: (capsule: String, status: String, title: String, text: String, command: String)) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            (Text(r.title).fontWeight(.semibold) + Text(" " + r.text))
                .font(.system(size: 11)).fixedSize(horizontal: false, vertical: true)
            commandRow(r.command)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: four resources (roadmap 02 §3.4.1, §3.7; with resourcesUI)

    /// The tiles, in the place of the two stats rows: the summary of every resource and the selector of what
    /// the charts show. A click shows one alone, ⌘-click adds or removes one, ⇧-click adds a run; a click on
    /// the focus shown alone opens its biggest consumers.
    var tilesRow: some View {
        let sel = store.selection(for: m)
        let live = m.current != nil && (m.isLocal ? m.daemonRunning : true)
        var facts: [Resource: Tile] = live ? Tile.facts(m.current!, Verdict.capsule(m.current!), waiting: m.waiting) : [:]
        if m.isLinux, let s = m.current, let t = facts[.memory] { facts[.memory] = LinuxTab.memoryTile(t, s, m.facts) }
        let avail = Resource.available(m.current)
        // equal tiles (02 §3.4.1: four of 108 pt, three of 146): the panel's content width shared out
        let n = CGFloat(avail.count)
        let width: CGFloat = (popupWidth - 28 - 6 * (n - 1)) / n
        return HStack(spacing: 6) {
            ForEach(avail, id: \.self) { r in tile(r, sel: sel, facts: facts, width: width) }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Resources")
    }

    /// One tile of the row, apart from it, its parts typed one by one: as one expression with the row
    /// the older Swift of CI (6.1) could not type-check it in time.
    func tile(_ r: Resource, sel: Selection, facts: [Resource: Tile], width: CGFloat) -> some View {
        let role: ResourceTile.Role = sel.focus == r ? .focus : sel.shown.contains(r) ? .shown : .plain
        let focus: Bool = role == .focus, plain: Bool = role == .plain
        let alone: Bool = sel.shown.count == 1
        let removable: Bool = !plain && !(focus && alone)
        let help: String = tileHelp(r, role: role, alone: alone, tile: facts[r])
        let base: ResourceTile = ResourceTile(resource: r, tile: facts[r] ?? Tile(), role: role, chevron: focus && alone,
                                              open: showTopApps && focus, compact: store.compactLevel >= 3,
                                              shake: shakes[r] ?? 0, help: help)
        let value: String = focus ? "shown with the big chart" : role == .shown ? "shown" : "not shown"
        let traits: AccessibilityTraits = plain ? [.isButton] : [.isButton, .isSelected]
        let hint: String = "Shows \(r.name) alone. Command-click \(plain ? "adds" : "removes") it."
        let toggle: String = plain ? "Add to view" : "Remove from view"
        let anchor: (Anchor<CGRect>) -> Anchor<CGRect>? = { focus ? $0 : nil }
        let clickable = base.contentShape(Rectangle()).onTapGesture { tapTile(r) }
        let menu = clickable.contextMenu { tileMenu(r, plain: plain, removable: removable) }
        let spoken = menu.accessibilityElement(children: .ignore).accessibilityLabel(tileLabel(r, tile: facts[r]))
            .accessibilityValue(value).accessibilityAddTraits(traits).accessibilityHint(hint)
        return spoken
            .accessibilityAction(named: "Show alone") { gesture(.click, r, alone: true) }
            .accessibilityAction(named: toggle) { gesture(.cmd, r) }
            .accessibilityAction(named: "Biggest apps") { biggestApps(r) }
            .frame(width: width)
            .anchorPreference(key: TopAppAnchorKey.self, value: .bounds, transform: anchor)
    }

    /// A tile's menu: show it alone, add it or remove it (not the focus shown alone), its biggest apps.
    @ViewBuilder func tileMenu(_ r: Resource, plain: Bool, removable: Bool) -> some View {
        Button("Show \(r.name) alone") { gesture(.click, r, alone: true) }
        if plain { Button("Add to view") { gesture(.cmd, r) } }
        if removable { Button("Remove from view") { gesture(.cmd, r) } }
        Button("Biggest apps…") { biggestApps(r) }
    }

    /// Shows a resource alone and opens its biggest consumers.
    func biggestApps(_ r: Resource) {
        gesture(.click, r, alone: true)
        openCallout()
    }

    /// A tile's spoken name: the resource, its reading and its flag.
    func tileLabel(_ r: Resource, tile: Tile?) -> String {
        let reading: String = tile?.reading ?? "no reading"
        let flag: String = tile?.flagText ?? ""
        return r.name + ", " + reading + (flag.isEmpty ? "" : ", " + flag)
    }

    /// A tile's tooltip (§3.7.2): its reading in words, then what the clicks do.
    func tileHelp(_ r: Resource, role: ResourceTile.Role, alone: Bool, tile: Tile?) -> String {
        let what = tile.map { r.name + ": " + $0.reading + ($0.flagText.isEmpty ? "" : " · " + $0.flagText)
                              + ($0.top.map { " · biggest: " + $0 } ?? "") } ?? r.name
        let click = role == .focus && alone ? "Click: biggest apps · ⌘-click another tile to add it"
            : "Click: \(r == .gpu ? "the GPU" : r.name) alone · ⌘-click to \(role == .plain ? "add" : "remove")"
        return what + "\n" + click
    }

    /// A click on a tile, with the modifiers held: ⌘ toggles, ⇧ adds a run.
    func tapTile(_ r: Resource) {
        let f = NSEvent.modifierFlags
        gesture(f.contains(.command) ? .cmd : f.contains(.shift) ? .shift : .click, r)
    }

    func gesture(_ g: Selection.Gesture, _ r: Resource, alone: Bool = false) {
        NSApp.keyWindow?.makeFirstResponder(nil)
        if alone && store.selection(for: m) == Selection(shown: [r], focus: r) { return }
        let reduce = NSWorkspace.shared.accessibilityDisplayShouldReduceMotion || renderMode
        withAnimation(reduce ? nil : .easeInOut(duration: 0.2)) {
            if store.resourceGesture(g, r) == .changed { showTopApps = false; showAllReservations = false }
        }
    }

    func openCallout() {
        withAnimation(.easeOut(duration: 0.15)) { showTopApps = true; showAI = false }
    }

    // Memory Claude sessions and other agents reserved through `oomph reserve` / `oomph run` / the
    // MCP server, in the colours of their blocks on the strip above.
    /// The height contract for one machine (roadmap 01 §3.11): at most this many lines of
    /// reservations; with more, the last line is "+N more", which lists them all in a callout.
    static let reservationLines = 5

    func reservedList(_ all: [Reservation]) -> some View {
        // a machine that is not connected is shown as of the moment knowledge of it ends
        let now = m.isLocal ? wallNow() : m.stale || m.inGrace ? (m.knownUntil ?? m.now) : m.now
        let day = m.reservations.filter { ($0.res.ended ?? now) >= now - 86400 }.count
        // with the resources on (§3.7.7): the rows of what holds a shown resource (every reservation holds
        // memory until 1.12), the list's cap by the compact level, and one line for the rest
        let sel = resourcesUIOn ? store.selection(for: m) : nil
        let (live, other) = PopoverView.split(all, sel?.shown)
        let lines = !resourcesUIOn ? PopoverView.reservationLines : store.compactLevel >= 3 ? 3 : store.compactLevel >= 1 ? 4 : PopoverView.reservationLines
        let capped = live.count > lines
        let shown = capped ? Array(live.prefix(lines - 1)) : live
        let reserved = live.filter { $0.granted != nil }.reduce(0) { $0 + $1.gb }
        var summary = live.isEmpty ? "\(day) in the last 24 h" : String(format: "%.1f GB reserved · %d in the last 24 h", reserved, day)
        if let s = sel, !live.isEmpty { summary = Reservation.captionText(live, shown: s.shown, day: day) }
        if m.stale && !live.isEmpty { summary = "as of " + MemoryChart.when(now) + String(format: ": %.1f GB reserved", reserved) }
        let amountsWidth: CGFloat = sel == nil ? 40 : min(150, max(40, 6.3 * CGFloat(shown.map { $0.amountsText(pool: tilePool).count }.max() ?? 0)))
        let nothing = sel.map { s in "Nothing reserved right now on " + ListFormatter.localizedString(byJoining: s.shown.map {
            $0 == .memory ? "memory" : $0.name }) } ?? "Nothing reserved right now"
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
                Text(nothing).font(.caption).foregroundStyle(.tertiary)
            }
            ForEach(shown) { (r: Reservation) in
                if m.stale { reservationRow(r, now: now, amountsWidth: amountsWidth).grayscale(1).opacity(0.6) }
                else { reservationRow(r, now: now, amountsWidth: amountsWidth) }
            }
            if capped { moreLine(Array(live.dropFirst(shown.count))) }
            if !other.isEmpty && !m.fetchingLedger { otherLine(other) }
        }
    }

    /// (the live reservations that hold a shown resource, the rest) (02 §3.7.7); everything without a selection.
    static func split(_ all: [Reservation], _ shown: [Resource]?) -> (rows: [Reservation], rest: [Reservation]) {
        guard let shown else { return (all, []) }
        return (all.filter { r in shown.contains { r.holds($0) } }, all.filter { r in !shown.contains { r.holds($0) } })
    }
    /// The id of the disk pool the Disk tile shows (its band's).
    var tilePool: String? { Tile.pool(m.current?.disks?.v).pool?.id }
    /// The reservation a row points at: the one under the pointer, or in a render (`--ai rowhover:N`) row N.
    var rowHighlight: String? {
        guard resourcesUIOn else { return nil }
        if let h = hoveredRow { return h }
        guard let n = renderResRowHover else { return nil }
        let rows = PopoverView.split(m.liveReservations, store.selection(for: m).shown).rows
        return n >= 0 && n < rows.count ? rows[n].id : nil
    }

    /// "On other resources: 14.0 GB reserved · 1 waiting for memory ›" (§3.7.7): the live totals of the
    /// resources not shown and how many of the hidden requests wait; a click lists them all. Shorter from
    /// level 1, never without the count of waiting requests.
    func otherLine(_ rest: [Reservation]) -> some View {
        let text = Reservation.otherText(rest, short: store.compactLevel >= 1) ?? ""
        return Button {
            NSApp.keyWindow?.makeFirstResponder(nil)
            withAnimation(.easeOut(duration: 0.15)) { showAllReservations.toggle(); showTopApps = false; showAI = false }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "ellipsis").font(.system(size: 8, weight: .bold)).foregroundStyle(.secondary).frame(width: 8, height: 8)
                Text(text + " ›").font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
                Spacer(minLength: 4)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain).focusable(false).focusEffectDisabled()
        .help("Every live reservation, in a list")
        .anchorPreference(key: MoreAnchorKey.self, value: .bounds) { $0 }
    }

    func reservationRow(_ r: Reservation, now: Double, amountsWidth: CGFloat = 40) -> some View {
        let c = resourcesUIOn ? r.agentColor(dark: scheme == .dark) : r.color
        let flagged = resourcesUIOn && !r.flags.isEmpty && !m.stale
        return HStack(spacing: 6) {
            ZStack {
                RoundedRectangle(cornerRadius: 2).fill(c.opacity(r.granted == nil ? 0.15 : 0.8))
                if r.granted == nil {
                    RoundedRectangle(cornerRadius: 2).strokeBorder(c.opacity(0.8), lineWidth: 1)
                }
            }
            .frame(width: 8, height: 8)
            if resourcesUIOn {  // every amount as text (02 §3.8.5)
                // never cut (02 §3.4.6): a row whose amounts outgrow the column widens it for itself
                Text(r.amountsText(pool: tilePool)).font(.system(size: 11, weight: .semibold)).monospacedDigit()
                    .lineLimit(1).fixedSize().frame(minWidth: amountsWidth, alignment: .leading)
            } else {
            Text(String(format: "%.1fG", r.gb)).font(.system(size: 11, weight: .semibold)).monospacedDigit()
                .frame(width: 40, alignment: .trailing)
            }
            // with the resources on, the project gives way first, then the purpose in its middle (02 §3.4.6)
            Text(r.purpose).font(.system(size: 11)).lineLimit(1)
                .truncationMode(resourcesUIOn ? .middle : .tail).layoutPriority(resourcesUIOn ? 1 : 0)
            if let p = rowDetail(r) {
                Text(p).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 4)
            Text(reservationTail(r, now: now)).font(.system(size: 10, weight: flagged ? .semibold : .regular))
                .foregroundStyle(flagged ? .primary : .secondary).monospacedDigit()
                .lineLimit(1).fixedSize()
        }
        .contentShape(Rectangle())
        .onHover { inside in
            guard resourcesUIOn else { return }
            if inside { hoveredRow = r.id } else if hoveredRow == r.id { hoveredRow = nil }
        }
        .help(rowHelp(r))
    }

    func rowHelp(_ r: Reservation) -> String {
        let head: String = "\(r.rid): \(r.purpose)" + (r.project.map { " — " + $0 } ?? "")
        if resourcesUIOn { return head + " · " + r.amountsText(pool: tilePool) + String(format: " · peak %.1f GB so far", r.peak) }
        return head + String(format: " · reserved %.1f GB, peak %.1f GB so far", r.gb, r.peak)
    }

    /// The fifth line when there are more: "+3 more · 5.0 GB reserved · 1 waiting" (of the ones
    /// not listed); a click lists them all.
    func moreLine(_ rest: [Reservation]) -> some View {
        let gb = rest.filter { $0.granted != nil }.reduce(0) { $0 + $1.gb }
        let waiting = rest.filter { $0.granted == nil }.count
        var text = "+\(rest.count) more"
        if resourcesUIOn {  // amounts of several kinds do not add up: how many are granted, how many wait (02 §3.4.6)
            var counts: [String] = []
            if rest.count - waiting > 0 && store.compactLevel < 1 { counts.append("\(rest.count - waiting) granted") }
            if waiting > 0 { counts.append("\(waiting) waiting") }
            if !counts.isEmpty { text += (store.compactLevel >= 1 ? " · " : ": ") + counts.joined(separator: ", ") }
        } else {
        if gb > 0 { text += String(format: " · %.1f GB reserved", gb) }
        if waiting > 0 { text += " · \(waiting) waiting" }
        }
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
    func allReservationsCallout(arrowX: CGFloat, width: CGFloat = 360) -> some View {
        let live = m.liveReservations
        let now = m.isLocal ? wallNow() : m.stale || m.inGrace ? (m.knownUntil ?? m.now) : m.now
        let reserved = live.filter { $0.granted != nil }.reduce(0) { $0 + $1.gb }
        let rows = renderMode ? Array(live.prefix(14)) : live
        let aw: CGFloat = !resourcesUIOn ? 40 : min(120, max(40, 6.3 * CGFloat(rows.map { $0.amountsText(pool: tilePool).count }.max() ?? 0)))
        return VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline) {
                    Text("Reserved by agents").font(.system(size: 13, weight: .semibold))
                    Spacer()
                    Text(String(format: "%d · %.1f GB reserved", live.count, reserved)).font(.system(size: 10)).foregroundStyle(.secondary)
                }
                .padding(.bottom, 3)
                if rows.count > 14 {
                    ScrollView { VStack(alignment: .leading, spacing: 3) { ForEach(rows) { reservationRow($0, now: now, amountsWidth: aw) } } }
                        .frame(maxHeight: 14 * 17)
                } else {
                    ForEach(rows) { reservationRow($0, now: now, amountsWidth: aw) }
                }
            }
            .padding(12)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
            CalloutArrow()
                .fill(.regularMaterial)
                .overlay(CalloutArrow().stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
                .frame(width: 16, height: 8)
                .offset(x: arrowX - width / 2)  // centre of the bubble
        }
        .shadow(color: .black.opacity(0.22), radius: 12, y: 4)
    }

    /// "who · project" on a Linux tab once several accounts hold reservations there (03 §3.9 state 8).
    var showsWho: Bool { m.isLinux && LinuxTab.showsWho(m.liveReservations) }
    /// After the purpose: the project, or "who · project".
    func rowDetail(_ r: Reservation) -> String? {
        let parts: [String] = [showsWho ? r.user : nil, r.projectName].compactMap { $0 }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    func reservationTail(_ r: Reservation, now: Double) -> String {
        if m.stale { return r.granted == nil ? "was waiting" : String(format: "was using %.1fG", r.used ?? 0) }
        // what a reservation uses is not known where the logger sees only its own processes, or nothing is
        // logged (03 §3.9 states C and D)
        if m.isLinux && (m.facts.allProcs == false || m.quietState == .absent) && r.granted != nil {
            return r.expires.map { MemoryChart.shortDuration($0 - now) + " left" } ?? "granted"
        }
        if resourcesUIOn {  // its flag, what it waits for, one use figure (02 §3.4.6)
            let sel = store.selection(for: m)
            return r.statusText(shown: sel.shown, focus: sel.focus, now: now)
        }
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

    /// The callout of a click on the focus shown alone: the biggest apps, or with the resources on the twelve
    /// biggest consumers of the focus (02 §3.4.1: by cores, by share of the GPU, by MB/s written).
    @ViewBuilder func focusCallout(arrowX: CGFloat) -> some View {
        let focus = resourcesUIOn ? store.selection(for: m).focus : .memory
        if focus == .memory { topAppsCallout(arrowX: arrowX) } else { consumersCallout(focus, arrowX: arrowX) }
    }

    func consumersCallout(_ r: Resource, arrowX: CGFloat) -> some View {
        let c = m.current
        let full = c?.gpu?.v?.first?.src == "ioreport"
        let (rows, key): ([RateProc], KeyPath<RateProc, Double?>) = r == .cpu ? (c?.top_cpu?.v ?? [], \.cpu)
            : r == .gpu ? (c?.top_gpu?.v ?? [], \.gpu) : (c?.top_io?.v ?? [], \.w)
        var tot: [String: (Double, Int)] = [:], order: [String] = []
        for x in rows {
            guard let v = x[keyPath: key] else { continue }
            let name = (x.g?.isEmpty == false ? x.g : x.name) ?? "?"
            if tot[name] == nil { order.append(name) }
            tot[name] = ((tot[name]?.0 ?? 0) + v, (tot[name]?.1 ?? 0) + 1)
        }
        let items = Array(order.sorted { tot[$0]!.0 > tot[$1]!.0 }.prefix(12))
        let top = items.first.map { tot[$0]!.0 } ?? 1
        func fmt(_ v: Double) -> String {
            r == .cpu ? String(format: "%.1f cores", v) : r == .gpu ? String(format: "%.0f %%", v) : String(format: "%.1f MB/s", v)
        }
        let title = r == .cpu ? "Busiest apps now" : r == .gpu ? "Busiest on the GPU" : "Biggest writers now"
        let note = r == .cpu ? "Cores an app keeps busy, all its processes together, over the last sample."
            : r == .gpu ? (full ? "Each app's share of the GPU at full speed." : "Each app's share of the time the GPU was busy, at any speed.")
            : "What each app wrote to disk, all its processes together, over the last sample."
        return VStack(spacing: 0) {
            CalloutArrow()
                .fill(.regularMaterial)
                .overlay(CalloutArrow().stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
                .frame(width: 16, height: 8)
                .rotationEffect(.degrees(180))
                .offset(x: arrowX - 160)
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline) {
                    Text(title).font(.system(size: 13, weight: .semibold))
                    Spacer()
                    Text(r.name).font(.system(size: 10)).foregroundStyle(.secondary)
                }
                ForEach(Array(items.enumerated()), id: \.offset) { i, name in
                    HStack(spacing: 8) {
                        Text("\(i + 1)").font(.system(size: 10)).foregroundStyle(.tertiary).monospacedDigit()
                            .frame(width: 14, alignment: .trailing)
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 4) {
                                Text(name).font(.system(size: 11.5)).lineLimit(1).truncationMode(.middle)
                                if tot[name]!.1 > 1 {
                                    Text("\(tot[name]!.1)").font(.system(size: 9.5)).foregroundStyle(.secondary).monospacedDigit()
                                        .padding(.horizontal, 4).background(Color.primary.opacity(0.08), in: Capsule())
                                }
                            }
                            GeometryReader { geo in
                                Capsule().fill(r.color.opacity(i == 0 ? 0.75 : 0.45))
                                    .frame(width: max(2, geo.size.width * CGFloat(tot[name]!.0 / max(top, 1e-9))))
                            }.frame(height: 3)
                        }
                        Text(fmt(tot[name]!.0)).font(.system(size: 11, weight: .medium)).monospacedDigit()
                            .frame(width: 68, alignment: .trailing)
                    }
                    .help(name)
                }
                if items.isEmpty { Text("No data yet").font(.system(size: 11)).foregroundStyle(.secondary) }
                Text(note).font(.system(size: 9.5)).foregroundStyle(.tertiary).fixedSize(horizontal: false, vertical: true)
            }
            .padding(12)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
        }
        .shadow(color: .black.opacity(0.22), radius: 12, y: 4)
    }

    /// State A's callout from the capsule (03 §3.9): the logger on the other machine stopped, and the command
    /// that starts it again there.
    func remedyCallout(_ r: (capsule: String, status: String, title: String, text: String, command: String), arrowX: CGFloat,
                       width: CGFloat) -> some View {
        VStack(spacing: 0) {
            CalloutArrow()
                .fill(.regularMaterial)
                .overlay(CalloutArrow().stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
                .frame(width: 16, height: 8)
                .rotationEffect(.degrees(180))
                .offset(x: arrowX - width / 2)
            VStack(alignment: .leading, spacing: 6) {
                Text(r.title).font(.system(size: 12, weight: .semibold))
                Text(r.text).font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                commandRow(r.command)
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
        }
        .shadow(color: .black.opacity(0.22), radius: 12, y: 4)
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
                    Text(m.isLinux ? LinuxTab.calloutTitle : "Biggest apps now").font(.system(size: 13, weight: .semibold))
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
                Text(m.isLinux ? LinuxTab.calloutFoot : "An app counts all its helper processes; sizes are physical footprints like Activity Monitor's Memory column.")
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
                if resourcesUIOn {
                    let focus = store.selection(for: m).focus
                    ResourceLegend(focus: focus, sample: m.current, missing: missingInView, linux: m.isLinux, away: m.hasPresence,
                                   compressed: !m.isLinux || m.facts.compressed, hasSwap: !m.isLinux || m.facts.swap)
                    Text(focus.unit).font(.caption).foregroundStyle(.secondary)
                        .help(ResourceLegend.unitHelp(focus) + (store.allHistory
                              ? "∞: all history on a logarithmic time axis — the last hours wide, older days squeezed."
                              : "Time runs left to right up to now."))
                } else {
                ChartLegend(missing: missingInView, linux: m.isLinux, away: m.hasPresence,
                            compressed: !m.isLinux || m.facts.compressed, swap: !m.isLinux || m.facts.swap)
                Text("GB").font(.caption).foregroundStyle(.secondary)
                    .help("Memory in GB; the dashed line is the \(m.isLinux ? "machine" : "Mac")'s RAM. " + (store.allHistory
                          ? "∞: all history on a logarithmic time axis — the last hours wide, older days squeezed."
                          : "Time runs left to right up to now."))
                }
            }
            ZStack {
                if !m.historyLoaded {
                    VStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Loading history…").font(.caption).foregroundStyle(.secondary)
                    }
                } else if m.history.isEmpty && m.isLocal {
                    Text("No samples yet").font(.caption).foregroundStyle(.secondary)
                } else if resourcesUIOn {
                    let sel = store.selection(for: m)
                    let pool = Tile.pool(m.current?.disks?.v).pool
                    MemoryChart(points: m.history, gaps: m.gaps, incidents: m.incidents, events: m.events,
                                ram: m.current?.ram_gb, axis: axis,
                                reservations: m.reservations, stripHeight: stripHeight,
                                bands: stripBands, smallBand: smallBandHeight, highlight: rowHighlight,
                                focus: sel.focus, rows: smallRows, rowHeight: smallRowHeight, cores: m.current?.cpu?.v?.n,
                                floors: pool?.watch == true ? pool.flatMap { p in p.low_gb.map { (low: $0, crit: p.crit_gb ?? 0) } } : nil,
                                wiredName: m.isLinux ? "Kernel" : "Wired", linux: m.isLinux ? m.facts : nil)
                        .id(sel.focus)  // a plain click cross-fades the chart area (§3.7.4)
                        .transition(.opacity)
                } else {
                    MemoryChart(points: m.history, gaps: m.gaps, incidents: m.incidents, events: m.events,
                                ram: m.current?.ram_gb, axis: axis,
                                reservations: m.reservations, stripHeight: stripHeight, wiredName: m.isLinux ? "Kernel" : "Wired",
                                linux: m.isLinux ? m.facts : nil)
                        .transition(.opacity)  // fades in (0.33 s) once the history has loaded
                }
            }
            .frame(maxWidth: .infinity)
            .frame(height: chartHeight + smallRowsHeight + (stripHeight > 0 ? MemoryChart.stripGap + stripHeight : 0))
            .tourAnchor("plot")
            .zIndex(1)  // the hover tooltips may reach over what follows
        }
    }

    /// The time axis of the chart and of every row drawn with it (roadmap 02 §8): the range chosen, or ∞;
    /// another machine's spans back to the oldest sample it reported.
    var axis: TimeAxis {
        TimeAxis(now: m.historyNow,
                 first: TimeAxis.start(oldest: m.isLocal ? nil : m.info?.oldest, firstPoint: m.history.first?.id, now: m.historyNow),
                 lgRange: log10(store.allHistory ? 24 * 3600 : store.range), blend: renderBlend ?? (store.allHistory ? 1 : 0))
    }

    /// The reservation strip under the chart: there once any agent reserved memory (14 days kept). With the
    /// resources on, the memory band is drawn while memory is shown (§3.7.6: no other resource has a band yet).
    var stripHeight: CGFloat {
        if resourcesUIOn {  // a band per reserved resource shown (B3): the first 46 pt, each other one 12 (9 from level 2) and its gap
            let n = stripBands.count
            return n == 0 ? 0 : 46 + CGFloat(n - 1) * (smallBandHeight + MemoryChart.bandGap)
        }
        return m.historyLoaded && (!m.history.isEmpty || !m.isLocal) && !m.reservations.isEmpty ? 46 : 0
    }
    var smallBandHeight: CGFloat { store.compactLevel >= 2 ? 9 : 12 }
    /// With the resources on: the strip's bands (02 §3.4.5, §3.7.6), each with its blocks: the shown resources reserved
    /// in the 14 days, the focus's first; the Disk band is the tile's pool's. At the solo level only the first.
    var stripBands: [(kind: Resource, blocks: [ResBlock])] {
        guard resourcesUIOn, m.historyLoaded, !m.history.isEmpty || !m.isLocal, !m.reservations.isEmpty else { return [] }
        let sel = store.selection(for: m)
        let pool = Tile.pool(m.current?.disks?.v).pool?.id
        let ks = Reservation.bands(m.reservations.map(\.res), shown: sel.shown, focus: sel.focus, pool: pool)
        return (store.compactLevel >= 4 ? Array(ks.prefix(1)) : ks).map { k in (k, m.blocks(for: k, pool: pool)) }
    }

    /// The big chart with its time labels: 140 pt and its axis, 118 at the tight level (§3.7.5).
    var chartHeight: CGFloat { resourcesUIOn && store.compactLevel >= 3 ? 138 : 160 }
    /// The small charts: the other shown resources in tile order, the focus left out; none at the solo level.
    var smallRows: [Resource] {
        guard resourcesUIOn, store.compactLevel < 4 else { return [] }
        let sel = store.selection(for: m)
        return sel.shown.filter { $0 != sel.focus }
    }
    var smallRowHeight: CGFloat { store.compactLevel >= 2 ? 16 : 22 }
    var smallRowsHeight: CGFloat { smallRows.isEmpty ? 0 : CGFloat(smallRows.count) * (smallRowHeight + 3) + MemoryChart.stripGap }

    var incidentsList: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline) {
                Text("Incidents").font(.caption).foregroundStyle(.secondary)
                if m.isLinux && m.facts.kills == "none" {  // 03 §3.9 state E
                    Spacer()
                    Text(LinuxTab.killsHidden).font(.system(size: 10)).foregroundStyle(.tertiary).help(LinuxTab.killsHiddenHelp)
                }
            }
            if m.fetchingIncidents {
                Text("fetching…").font(.caption).foregroundStyle(.tertiary)
            } else if m.incidents.isEmpty && m.quiet.isEmpty {
                Text("None recorded").font(.caption).foregroundStyle(.tertiary)
            } else if resourcesUIOn && store.compactLevel >= 5, let inc = m.incidents.first {
                // the last resort (§3.4.8): the list becomes one line
                Button { if m.isLocal { store.open(inc) } } label: {
                    Text("\(m.incidents.count) recorded · latest " + MemoryChart.when(inc.start) + (inc.open == true ? " · open" : "") + " ›")
                        .font(.system(size: 11)).foregroundStyle(inc.open == true ? Color.red : Color.secondary).lineLimit(1)
                }
                .buttonStyle(.plain)
            } else if !m.quiet.isEmpty {
                // a Linux tab: the quiet incidents fold into one grey row for the latest (03 §3.9 state 9). A render
                // draws the rows without the scroll view, whose content ImageRenderer leaves out
                if renderMode {
                    linuxRows.frame(maxHeight: resourcesUIOn && store.compactLevel >= 1 ? 68 : 130, alignment: .top).clipped()
                } else {
                    ScrollView { linuxRows }.frame(maxHeight: resourcesUIOn && store.compactLevel >= 1 ? 68 : 130)
                }
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
                }.frame(maxHeight: resourcesUIOn && store.compactLevel >= 1 ? 68 : 130)
            }
        }
    }

    var linuxRows: some View {
        VStack(spacing: 2) {
            ForEach(LinuxTab.rows(m.incidents, quiet: m.quiet), id: \.self) { row in
                switch row {
                case .incident(let id):
                    if let inc = m.incidents.first(where: { $0.id == id }) { incidentButton(inc) }
                case .quiet(let id, let earlier):
                    if let inc = m.quiet.first(where: { $0.id == id }) { quietRow(inc, earlier: earlier) }
                }
            }
        }
    }

    func incidentButton(_ inc: Incident) -> some View {
        Button { if m.isLocal { store.open(inc) } } label: { row(inc) }
            .buttonStyle(.plain)
            .contextMenu {
                Button("Copy path") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(inc.dir, forType: .string)
                }
                Button("Reveal in Finder") { NSWorkspace.shared.selectFile(inc.dir + "/incident.json", inFileViewerRootedAtPath: inc.dir) }
            }
    }

    /// The quiet incidents of a Linux machine, folded (03 §3.9 state 9): grey, "· quiet" after the date, how many
    /// came before it where the kills sit; never orange, never on the tab's badge.
    func quietRow(_ inc: Incident, earlier: Int) -> some View {
        let f = DateFormatter(); f.dateFormat = "EEE d MMM HH:mm"
        return HStack(alignment: .top, spacing: 6) {
            Circle().fill(Color.secondary.opacity(0.4)).frame(width: 6, height: 6).padding(.top, 5)
            VStack(alignment: .leading, spacing: 0) {
                Text(f.string(from: Date(timeIntervalSince1970: inc.start)) + " · quiet" + (inc.open == true ? " · open" : ""))
                    .font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
                Text(inc.reasons.first?.desc ?? "containers at their own limit").font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if earlier > 0 { Text("+\(earlier) earlier").font(.system(size: 10)).foregroundStyle(.secondary) }
        }
        .padding(.vertical, 3).padding(.horizontal, 4)
        .contentShape(Rectangle())
        .help("Containers at their own memory limit: kept, never news. Their stall time and kills are the containers', not this machine's.")
        .contextMenu {
            Button("Copy path") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(inc.dir, forType: .string)
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
                TourNote(title: resourcesUIOn ? "Is anything short?" : "Memory pressure",
                         text: resourcesUIOn
                            ? "The badge at the right names it: Memory tight, Disk low … or Normal, and the chip takes its colour. In the menu bar the chip is memory (colour and free GB); a ring or a disc on it means a disk needs attention. Hover the chip here to come back to this tour."
                            : self.m.isLinux ? LinuxTab.tourNotes[0]
                            : "The chip's colour is macOS memory pressure, and the badge on the right names it. The figure in the menu bar is free memory. Hover the chip to come back to this tour.",
                         left: m, width: half, above: false,
                         xs: [chip.midX], y: chip.maxY + 3, reach: zone.maxY - chip.maxY + 10),
                TourNote(title: resourcesUIOn ? "Four resources" : "Live readings",
                         text: resourcesUIOn
                            ? "Memory, CPU, GPU and disk right now. Click a tile to see it alone; ⌘-click another to add it below. Click the one with the big chart again for its twelve biggest apps. One flag per tile says what needs you: critical, low, throttled, 2 waiting. Hover it for the rest."
                            : self.m.isLinux ? LinuxTab.tourNotes[1]
                            : "Updated every 30 seconds: the same figures as Activity Monitor. Click the biggest app for the twelve largest.",
                         left: m + half + 8, width: half, above: false,
                         xs: [top.midX], y: top.maxY + 3, reach: zone.maxY - top.maxY + 10),
            ])
        case "History":
            let zone = union(["chart", "leases"])
            let picker = r["picker"] ?? .zero, plot = r["plot"] ?? zone
            let half = (W - 2 * m - 8) / 2
            let timeRange = TourNote(title: "Time range",
                                     text: "∞ shows all history on a logarithmic time axis: the last hours wide, older days and weeks squeezed. 24h, 6h and 1h are linear."
                                        + (self.m.isLocal ? " A blue ↻ beside it means the logger needs an update." : ""),
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
            let chartBottom = strip.minY - 22 - (r["rows"]?.height ?? 0)
            let alone = store.selection(for: store.machine).shown.count == 1
            return (zone, [timeRange,
                TourNote(title: resourcesUIOn ? "The big chart, then what you added" : "Memory over time",
                         text: resourcesUIOn
                            ? (alone ? "Hover to read the values under the cursor. ⌘-click a tile to add a thin row of it here, on the same time axis."
                                     : "The resource you clicked keeps the big chart. Each one you ⌘-click adds a thin row on the same time axis, so you see what else happened.")
                            : "Hover to read the values and events under the cursor; try it now. The legend above the chart explains the colours: hover an entry for more.",
                         left: m, width: half, above: false,
                         xs: [plot.minX + 90], y: chartBottom, reach: zone.maxY - chartBottom + 10),
                TourNote(title: "Reserved by agents",
                         text: resourcesUIOn
                            ? "Claude sessions and other agents reserve before heavy work and take turns (the oomph skill). One band per resource shown, one colour per agent: every reservation of one session has its colour. Height is the amount, hatched while it waits. Hover a block or a row to find it in every band."
                            : "Claude sessions and other agents reserve memory before heavy work and take turns (the oomph skill). One block per reservation: its height the GB, hatched while it waited, stacked where they overlap. Hover a block for its peak and how it ended.",
                         left: m + half + 8, width: half, above: false,
                         xs: [strip.midX + 60], y: strip.maxY + 2, reach: zone.maxY - strip.maxY + 11),
            ])
        case "Incidents":
            let zone = union(["incidents"])
            return (zone, [
                TourNote(title: "Incidents",
                         text: self.m.isLinux ? LinuxTab.tourNotes[2]
                            : "Each stretch of high memory pressure, with the apps macOS killed to free memory. Red: still open. Orange: new since you last looked."
                                + (self.m.isLocal ? " Click one for its report; right-click to copy its path or show it in Finder." : ""),
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
        return " — last checked " + f.localizedString(for: Date(timeIntervalSince1970: t), relativeTo: wallDate())
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

/// Where a quiet machine's capsule is: its remedy's callout hangs from it (03 §3.9 state A).
struct RemedyAnchorKey: PreferenceKey {
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
    var made: Double = wallNow()
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
    var shareCodeValid: Bool { shareCode.map { wallNow() < $0.expires } ?? false }

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
        } else if wallNow() > c.expires {
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
        if let t = e.last_connected { bits.append(ConnectInput.ago(t, now: wallNow())) }
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
        if let c = store.shareCode, renderMode || wallNow() < c.expires {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("Pairing code").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    if renderMode {
                        Text("9:41 left · \(st.pairing?.left ?? 5) tries").font(.system(size: 10)).foregroundStyle(.secondary)
                    } else {
                        TimelineView(.periodic(from: .now, by: 1)) { _ in
                            let left = max(0, Int(c.expires - wallNow()))
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
                    Text("A pairing code is active for another \(max(1, Int((exp - wallNow()) / 60))) min (it is shown only where it was made).")
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

/// The popup's SwiftUI content, which tells the panel when its ideal size changes (a click on a tile, the
/// history arriving, a reservation coming or going), so the panel follows it at once and in step with the
/// content's own animation, instead of at the next open, click or tick.
final class PopupHostingView: NSHostingView<PopoverView> {
    var onSizeChange: (() -> Void)?
    override func invalidateIntrinsicContentSize() {
        super.invalidateIntrinsicContentSize()
        onSizeChange?()
    }
}

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
    var hosting: PopupHostingView!
    /// A size change waits for the end of SwiftUI's pass (coalesced); the frame the panel is moving to;
    /// the compact level being searched (each step changes the size: only its end places the panel).
    var sizePending = false
    var frameTarget: NSRect?
    var choosingLevel = false
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
        panel.onKey = { [weak self] e in (self?.store.machineKey(e) ?? false) || (self?.store.resourceKey(e) ?? false) }
        let fx = NSVisualEffectView()
        fx.material = .popover
        fx.blendingMode = .behindWindow
        fx.state = .active
        fx.wantsLayer = true
        fx.layer?.cornerRadius = 10
        fx.layer?.masksToBounds = true
        hosting = PopupHostingView(rootView: PopoverView(store: store))
        hosting.onSizeChange = { [weak self] in self?.sizeChanged() }
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
        store.onResize = { [weak self] in DispatchQueue.main.async { if self?.isShown == true { self?.position(animated: true) } } }
        // the size follows by itself (sizeChanged); a compact popup searches its level again, as a smaller
        // selection may fit a roomier level
        store.onSelectionChanged = { [weak self] in
            DispatchQueue.main.async { if let self, self.isShown, self.store.compactLevel > 0 { self.chooseLevel(animated: true) } }
        }
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
        if isShown { store.machine.reloadPoints(); DispatchQueue.main.async { self.position(animated: true) } }
        updateIcon()
    }

    @objc func toggle() {
        if isShown { close(); return }
        // clicking the icon first makes the panel resign key (which closes it); don't reopen on that same click
        if Date().timeIntervalSince(lastClose) < 0.35 { return }
        store.applyOpeningRule()
        store.machine.refreshAll()
        store.resourcesOpened()
        store.popupOpened()
        store.machinesOpened()
        chooseLevel()
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

    /// The content's ideal size changed: once SwiftUI has finished this pass, the panel takes the new size,
    /// animated like the content (a click on a tile animates both for 0.2 s, its top edge staying put). Too tall
    /// for the screen, a popup with the resources on goes to its next compact level instead.
    func sizeChanged() {
        guard !sizePending else { return }
        sizePending = true
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.sizePending = false
            guard self.isShown, !self.choosingLevel else { return }
            if resourcesUIOn, self.store.compactLevel < 5, let room = self.room(),
               self.hosting.fittingSize.height > room {
                self.chooseLevel(from: self.store.compactLevel + 1, animated: true)
            } else {
                self.position(animated: true)
            }
        }
    }

    /// The height the popup may take on the screen of the status item: from just below the menu bar down.
    func room() -> CGFloat? {
        guard let button = item.button, let win = button.window else { return nil }
        let screen = win.screen ?? NSScreen.main!
        let r = win.convertToScreen(button.convert(button.bounds, to: nil))
        return min(r.minY, screen.visibleFrame.maxY) - 4 - screen.visibleFrame.minY - 6
    }

    /// Place the panel directly under the status item, top edge just below the menu bar,
    /// clamped to the visible area of the screen the icon is on. Animated: a panel on screen moves to the new
    /// frame in 0.2 s (none with reduced motion); the frame it is already moving to is left alone.
    func position(animated: Bool = false) {
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
        let frame = NSRect(x: x, y: y, width: size.width, height: min(size.height, top - vis.minY - 6))
        let smooth = animated && isShown && !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
        if smooth && frame == frameTarget { return }
        frameTarget = frame
        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = smooth ? 0.2 : 0
            ctx.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
            panel.animator().setFrame(frame, display: true)
        }
    }

    /// The compact level (roadmap 02 §3.7.5): the first whose popup fits the screen's visible height, chosen
    /// when the popup opens and when the selection changes. Only with the resources on.
    /// SwiftUI takes a state change into its layout on a later pass, so each level is measured a moment after
    /// it is set; a screen too small for the full popup sees it shrink once.
    /// The panel keeps its frame while the levels are tried; the one chosen is placed at the end.
    func chooseLevel(from lv: Int = 0, animated: Bool = false) {
        guard resourcesUIOn, let room = room() else { choosingLevel = false; return }
        choosingLevel = true
        store.compactLevel = lv
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.03) { [weak self] in
            guard let self else { return }
            guard self.isShown else { self.choosingLevel = false; return }
            guard self.store.compactLevel == lv else { return }  // a newer search runs
            self.hosting.layoutSubtreeIfNeeded()
            if self.hosting.fittingSize.height > room && lv < 5 { self.chooseLevel(from: lv + 1, animated: animated) } else {
                self.choosingLevel = false
                self.position(animated: animated)
            }
        }
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
        if resourcesUIOn, running, let c {
            // the chip's body is the verdict's memory level (02 §3.5, §15.13); a mark only for a critical disk:
            // a standing low disk stays on the capsule and the tile (D9)
            let cap = Verdict.capsule(c)
            let body: Pressure = cap.memory == 2 ? .critical : cap.memory == 1 ? .warn : .normal
            item.button?.image = ChipIcon.make(running: true, pressure: body, label: label, mark: cap.disk == 2 ? 2 : 0)
            let t = Tile.facts(c, cap)
            item.button?.toolTip = "\(brand) — \(cap.text)\n\(label ?? "?") memory free · pressure \(p.label.lowercased())"
                + "\nCPU \(t[.cpu]!.reading) · GPU \(t[.gpu]!.reading) · Disk \(t[.disk]!.reading)"
            return
        }
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

    /// `mark` (with the resources on, 02 §3.5): 2 a red disc with a white "!" at the top right (the disk is
    /// critical), on a halo in the bar's colour. 02's amber ring for a low disk is not drawn (D9).
    static func make(running: Bool, pressure: Pressure, label: String?, mark: Int = 0) -> NSImage {
        let mark = mark == 2 ? 2 : 0
        let size = NSSize(width: mark > 0 ? 31 : 28, height: 18)
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
            if mark > 0 {
                let dark = NSApp?.effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
                let r: CGFloat = 4.2
                let c = NSPoint(x: size.width - r - 0.8, y: size.height - r - 0.8)
                let halo = NSBezierPath(ovalIn: NSRect(x: c.x - r - 1.2, y: c.y - r - 1.2, width: 2 * r + 2.4, height: 2 * r + 2.4))
                let cg = NSGraphicsContext.current!.cgContext
                cg.saveGState(); cg.setBlendMode(.clear); halo.fill(); cg.restoreGState()
                let dot = NSBezierPath(ovalIn: NSRect(x: c.x - r, y: c.y - r, width: 2 * r, height: 2 * r))
                (dark ? NSColor(srgbRed: 1.0, green: 0.42, blue: 0.40, alpha: 1) : NSColor(srgbRed: 0.85, green: 0.16, blue: 0.16, alpha: 1)).setFill()
                dot.fill()
                let bang = NSAttributedString(string: "!", attributes: [.font: NSFont.systemFont(ofSize: 7, weight: .black),
                                                                       .foregroundColor: NSColor.white])
                let bs = bang.size()
                bang.draw(at: NSPoint(x: c.x - bs.width / 2, y: c.y - bs.height / 2))
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
        let opened: Double = wallNow() - UserDefaults.standard.double(forKey: "openedAgo")
        for m in store.machines.dropFirst() { m.refreshCurrent(); m.markOpened(at: opened); m.loadIncidents() }
    }
    if mirror == nil && store.machinesUI { renderConnect(store, ai) }
    store.machine.refreshCurrent()
    store.machine.loadIncidents()
    if ai != "loading" { store.machine.reloadPoints(sync: true) }  // `--ai loading` draws the spinner
    // with `-resourcesUI YES` (and `-selectedResources "(memory,cpu)" -focusResource cpu`): opened on trouble,
    // as the popup opens; `--ai lvl:N` draws compact level N (02 §3.7.5)
    store.resourcesOpened()
    if ai.hasPrefix("lvl:") { store.compactLevel = min(max(Int(ai.dropFirst(4)) ?? 0, 0), 5) }
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
    if ai.hasPrefix("rowhover:") { renderResRowHover = Int(ai.dropFirst(9)) }  // the pointer on a row of the list
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
    // `--ai tour:N` draws step N of the guided tour (1-based), on the selected tab (a Linux tab's in its words, L3)
    let tour = ai.hasPrefix("tour:") ? Int(ai.dropFirst(5)).map { $0 - 1 } : nil
    let view = PopoverView(store: store, showAI: ["callout", "dialog-connected", "dialog-error"].contains(ai), showTopApps: ai == "top",
                           tourStep: tour, showAllReservations: ai == "resmore", showRemedy: ai == "remedy")
        .background(Color(nsColor: .windowBackgroundColor))
        .frame(minHeight: store.connectShown ? 820 : nil, alignment: .top)  // room for the popover under the +
        .environment(\.colorScheme, dark ? .dark : .light)
    let r = ImageRenderer(content: view)
    r.scale = 2
    guard let cg = r.cgImage,
          let png = NSBitmapImageRep(cgImage: cg).representation(using: .png, properties: [:]) else { return }
    try? png.write(to: URL(fileURLWithPath: path))
}

/// `oomph --render-chip out.png [--dark]`: the menu-bar chip as the resources draw it (02 §3.5, §15.13, D9),
/// on a menu bar's grey at 4×. Top row: the body on the verdict's memory level (Normal, tight, critical) and
/// logging off; bottom row: the same with the critical disk's disc (31 pt wide). Each chip is drawn into a
/// bitmap of its own first, as the menu bar does, so its halo cuts only the chip.
@MainActor
func renderChip(to path: String, dark: Bool) {
    renderMode = true
    let look = NSAppearance(named: dark ? .darkAqua : .aqua)!
    NSApplication.shared.appearance = look
    let cells: [(running: Bool, body: Pressure, label: String?, mark: Int)] = [
        (true, .normal, "18G", 0), (true, .warn, "4.2G", 0), (true, .critical, "0.6G", 0), (false, .normal, nil, 0),
        (true, .normal, "18G", 2), (true, .warn, "4.2G", 2), (true, .critical, "0.6G", 2)]
    let scale: CGFloat = 4, cw: CGFloat = 44, ch: CGFloat = 26, pad: CGFloat = 4
    let w: CGFloat = 4 * cw + 2 * pad, h: CGFloat = 2 * ch + 2 * pad
    func bitmap(_ size: NSSize) -> NSBitmapImageRep? {
        let r = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size.width * scale), pixelsHigh: Int(size.height * scale),
                                 bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                 colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)
        r?.size = size
        return r
    }
    func drawn(into rep: NSBitmapImageRep, _ body: () -> Void) {
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
        look.performAsCurrentDrawingAppearance(body)
        NSGraphicsContext.restoreGraphicsState()
    }
    guard let out = bitmap(NSSize(width: w, height: h)) else { return }
    var chips: [(NSBitmapImageRep, NSRect)] = []
    for (i, c) in cells.enumerated() {
        let img = ChipIcon.make(running: c.running, pressure: c.body, label: c.label, mark: c.mark)
        guard let rep = bitmap(img.size) else { return }
        drawn(into: rep) { img.draw(in: NSRect(origin: .zero, size: img.size)) }
        let row: CGFloat = i < 4 ? 0 : 1, col: CGFloat = CGFloat(i < 4 ? i : i - 4)
        let x: CGFloat = pad + col * cw + (cw - img.size.width) / 2
        let y: CGFloat = h - pad - (row + 1) * ch + (ch - img.size.height) / 2
        chips.append((rep, NSRect(x: x, y: y, width: img.size.width, height: img.size.height)))
    }
    drawn(into: out) {
        (dark ? NSColor(white: 0.17, alpha: 1) : NSColor(white: 0.93, alpha: 1)).setFill()
        NSRect(x: 0, y: 0, width: w, height: h).fill()
        for (rep, r) in chips { rep.draw(in: r, from: .zero, operation: .sourceOver, fraction: 1, respectFlipped: false, hints: nil) }
    }
    guard let png = out.representation(using: .png, properties: [:]) else { return }
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
    let now = wallNow()
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

/// `oomph --linux-vectors FILE`: runs a Linux tab's words (LinuxTab, 03 §3.9; 1.13.3) over the inputs of FILE
/// (tools/vectors/linux.json) and prints their answers as JSON; tools/linuxvectors.py compares them with the
/// file's expected values and holds those to the CLI and to the gate's rules (no Wired, no "Idle 0 s" …).
@MainActor
func linuxVectors(_ path: String) -> Int32 {
    guard let data = FileManager.default.contents(atPath: path),
          let v = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
        FileHandle.standardError.write("oomph: --linux-vectors: can't read \(path)\n".data(using: .utf8)!)
        return 2
    }
    func cases(_ k: String) -> [[String: Any]] { (v[k] as? [[String: Any]]) ?? [] }
    func json<T: Decodable>(_ x: Any?, _ t: T.Type) -> T? {
        guard let x, JSONSerialization.isValidJSONObject(x), let d = try? JSONSerialization.data(withJSONObject: x) else { return nil }
        return try? JSONDecoder().decode(t, from: d)
    }
    func opt(_ x: String?) -> Any { x.map { $0 as Any } ?? NSNull() }
    var out: [String: Any] = [:]
    out["tiles"] = cases("tiles").map { c -> Any in
        guard let s = json(c["sample"], Sample.self) else { return NSNull() }
        let f = LinuxTab.Facts(s, info: json(c["machine"], MachineInfo.self))
        return LinuxTab.tiles(s, f, name: (c["name"] as? String) ?? "build-01").map { x -> [Any] in
            [x.label, x.value, opt(x.small), opt(x.sub), x.help, x.red]
        }
    }
    out["event"] = cases("event").map { c -> Any in
        guard let e = ChartEvent((c["e"] as? [String: Any]) ?? [:]) else { return NSNull() }
        return [e.text, e.alarming] as [Any]
    }
    out["rows"] = cases("rows").map { c -> [[Any]] in
        let a: [Incident] = json(c["incidents"], [Incident].self) ?? [], q: [Incident] = json(c["quiet"], [Incident].self) ?? []
        return LinuxTab.rows(a, quiet: q).map { r -> [Any] in
            switch r {
            case .incident(let id): return ["incident", id]
            case .quiet(let id, let n): return ["quiet", id, n]
            }
        }
    }
    out["who"] = cases("who").map { c -> Bool in
        let rs = ((c["leases"] as? [[String: Any]]) ?? []).compactMap { Reservation($0) }
        return LinuxTab.showsWho(rs)
    }
    out["remedy"] = cases("remedy").map { c -> Any in
        guard let q = LinuxTab.Quiet(rawValue: (c["state"] as? String) ?? "") else { return NSNull() }
        let r = LinuxTab.remedy(q, os: c["os"] as? String, name: (c["name"] as? String) ?? "", user: c["user"] as? String,
                                at: (c["at"] as? String) ?? "")
        return [r.0, r.1, r.2, r.3, r.4]
    }
    // a case with a sample: its series from the machine's facts, as a Linux tab's chart takes them (1.13.4)
    func legendOf(_ c: [String: Any]) -> ChartLegend {
        let f: LinuxTab.Facts? = json(c["sample"], Sample.self).map { LinuxTab.Facts($0, info: nil) }
        return ChartLegend(missing: (c["missing"] as? Bool) ?? false, linux: (c["linux"] as? Bool) ?? false,
                           away: (c["away"] as? Bool) ?? true,
                           compressed: f.map { $0.compressed } ?? (c["compressed"] as? Bool) ?? true,
                           swap: f.map { $0.swap } ?? (c["swap"] as? Bool) ?? true)
    }
    out["legend"] = cases("legend").map { c -> [[String]] in legendOf(c).shownRows.map { $0.map(\.name) } }
    // L3 (1.13.4): the legend's texts, the capsule's tooltip, the hover card's Linux lines, the callout and the tour
    out["legend_help"] = cases("legend").map { c -> [String] in legendOf(c).shownRows.flatMap { $0.map(\.help) } }
    out["capsule"] = cases("tiles").map { c -> Any in
        guard let s = json(c["sample"], Sample.self) else { return NSNull() }
        return LinuxTab.capsuleHelp(s, LinuxTab.Facts(s, info: json(c["machine"], MachineInfo.self)))
    }
    func num(_ x: Any?) -> Double { (x as? NSNumber)?.doubleValue ?? .nan }
    out["hover"] = cases("hover").map { c -> [Any] in
        let pts = ((c["points"] as? [[String: Any]]) ?? []).map { p -> Point in
            var q = Point(id: num(p["t"]), date: Date(timeIntervalSince1970: num(p["t"])), wired: num(p["wired"]), app: num(p["app"]),
                          comp: num(p["comp"]), swap: num(p["swap"]), away: false, kills: 0)
            q.stall = Float(num(p["some"])); q.stallFull = Float(num(p["full"])); q.stallLimit = Float(num(p["limit"]))
            return q
        }
        let f = LinuxTab.Facts(zram: (c["zram"] as? Bool) ?? false, swap: (c["swap"] as? Bool) ?? true)
        return [LinuxTab.hoverSeries(f), opt(LinuxTab.availText(pts, ram: num(c["ram"]))), opt(LinuxTab.stallText(pts))]
    }
    out["words"] = [LinuxTab.calloutTitle, LinuxTab.calloutFoot] + LinuxTab.tourNotes
    out["group_name"] = cases("group_name").map { LinuxTab.groupName(($0["name"] as? String) ?? "") }
    out["labeled"] = cases("labeled").map { c -> Bool in (c["os"] as? String).map { MachineEntry.labeled.contains($0) } ?? true }
    guard let j = try? JSONSerialization.data(withJSONObject: out, options: [.sortedKeys]) else { return 1 }
    FileHandle.standardOutput.write(j)
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
        let f = TimeAxis.mapper(now: num(c["now"]), first: num(c["first"]), lgRange: log10(span ?? 86400),
                                   blend: span == nil ? 1 : 0)
        return ((c["t"] as? [NSNumber]) ?? []).map { f($0.doubleValue) }
    }
    // the hover's inversion, x back to time, as an age (TimeAxis.time(at:); oomph_view.time_at), on an axis that
    // starts where TimeAxis.start puts it: "first" the first point loaded, "oldest" another machine's oldest sample
    out["invert"] = cases("invert").map { c -> [Double] in
        let now = num(c["now"]), span = (c["span"] as? NSNumber)?.doubleValue
        let first = TimeAxis.start(oldest: (c["oldest"] as? NSNumber)?.doubleValue,
                                   firstPoint: (c["first"] as? NSNumber)?.doubleValue, now: now)
        let axis = TimeAxis(now: now, first: first, lgRange: log10(span ?? 86400), blend: span == nil ? 1 : 0)
        let f = axis.mapper()
        return ((c["u"] as? [NSNumber]) ?? []).map { now - axis.time(at: $0.doubleValue, f) }
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
        let r = TimeAxis.calmBands(away: spans(c["away"]), gaps: spans(c["gaps"]), tolerance: num(c["tolerance"]))
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
    TimeAxis.dayFmt.locale = Locale(identifier: "en_US_POSIX")
    out["hover"] = cases("hover").map { c -> [[String: Any]] in
        let now = num(c["now"]), span = (c["span"] as? NSNumber)?.doubleValue
        let rs = ((c["reservations"] as? [[String: Any]]) ?? []).compactMap { Reservation($0) }
        let incs: [Incident] = ((c["incidents"] as? [[String: Any]]) ?? []).compactMap { d in
            (try? JSONSerialization.data(withJSONObject: d)).flatMap { try? JSONDecoder().decode(Incident.self, from: $0) }
        }
        let evs = ((c["events"] as? [[String: Any]]) ?? []).compactMap { ChartEvent($0) }.sorted { $0.t < $1.t }
        let pts = points(c["points"])
        let axis = TimeAxis(now: now, first: TimeAxis.start(oldest: num(c["first"]), firstPoint: pts.first?.id, now: now),
                            lgRange: log10(span ?? 86400), blend: span == nil ? 1 : 0)
        let chart = MemoryChart(points: pts, gaps: spans(c["gaps"]).map { Gap(from: $0.0, to: $0.1) },
                                incidents: incs, events: evs, ram: nil, axis: axis,
                                reservations: ResBlock.stack(rs, now: now))
        let f = axis.mapper()
        return ((c["u"] as? [NSNumber]) ?? []).map { u -> [String: Any] in
            let i = chart.hoverInfo(u: u.doubleValue, du: num(c["du"]), mapper: f)
            return ["when": i.when, "ago": i.ago, "samples": i.samples, "peak": i.peak, "away": i.away,
                    "readings": i.readings.map { [$0.name, $0.lo, $0.hi] as [Any] },
                    "no_data": i.noData.map { $0 as Any } ?? NSNull(), "incidents": i.incidents,
                    "events": i.events.map { [$0.0, $0.1] as [Any] }, "more_events": i.moreEvents,
                    "reserved": i.reserved.map { $0.0 }, "more_reserved": i.moreReserved]
        }
    }
    // the four resources (1.11.0): the selection's gestures, the capsule's words, what each tile says, an agent's slot
    out["selection"] = cases("selection").map { c -> [Any] in
        let sel = ((c["sel"] as? [String]) ?? []).compactMap { Resource(rawValue: $0) }
        let avail = ((c["avail"] as? [String]) ?? []).compactMap { Resource(rawValue: $0) }
        let now = Selection.shown(sel, focus: Resource(rawValue: (c["focus"] as? String) ?? "") ?? .memory, available: avail)
        let (next, outcome) = now.apply(Selection.Gesture(rawValue: (c["gesture"] as? String) ?? "") ?? .click,
                                        Resource(rawValue: (c["res"] as? String) ?? "") ?? .memory, available: avail)
        return [next.shown.map(\.rawValue), next.focus.rawValue, outcome.rawValue]
    }
    func sample(_ x: Any?) -> Sample? {
        (x as? [String: Any]).flatMap { try? JSONSerialization.data(withJSONObject: $0) }.flatMap { try? JSONDecoder().decode(Sample.self, from: $0) }
    }
    out["capsule"] = cases("capsule").map { c -> Any in
        guard let s = sample(c["sample"]) else { return NSNull() }
        let v = Verdict.capsule(s)
        return ["text": v.text, "level": v.level, "memory": v.memory, "disk": v.disk, "network": v.network] as [String: Any]
    }
    out["tiles"] = cases("tiles").map { c -> Any in
        guard let s = sample(c["sample"]) else { return NSNull() }
        var waiting: [Resource: Int] = [:]
        for (k, n) in (c["waiting"] as? [String: Any]) ?? [:] { if let r = Resource(rawValue: k) { waiting[r] = (n as? NSNumber)?.intValue ?? 0 } }
        let t = Tile.facts(s, Verdict.capsule(s), waiting: waiting)
        return Resource.allCases.map { r -> [Any] in
            let x = t[r]!
            return [x.reading, x.flagText, x.level, x.queue, x.top.map { $0 as Any } ?? NSNull(), x.meter]
        }
    }
    out["agent"] = cases("agent").map { Reservation.agentIndex($0["agent"]) }
    // a band per reserved resource and the list's words (B3, 1.12.3): the bands of a selection, the rows of what holds a
    // shown resource in their order with their amounts and status, the caption, the line for the rest
    func merged(_ c: [String: Any]) -> [Reservation] {
        let lines = ((c["records"] as? [Any]) ?? []).compactMap { r -> String? in
            (try? JSONSerialization.data(withJSONObject: r)).flatMap { String(data: $0, encoding: .utf8) }
        }
        return Store.mergeReservations(records: lines.joined(separator: "\n").data(using: .utf8),
                                       ledger: (c["ledger"] as? [String: Any]) ?? [:], now: num(c["now"]), holderGone: { _ in false })
            .sorted { ($0.requested, $0.id) < ($1.requested, $1.id) }
    }
    out["rows"] = cases("rows").map { c -> [String: Any] in
        let all = merged(c), now = num(c["now"])
        let shown = ((c["shown"] as? [String]) ?? []).compactMap { Resource(rawValue: $0) }
        let focus = Resource(rawValue: (c["focus"] as? String) ?? "") ?? .memory
        let pool = c["pool"] as? String
        let live = Reservation.listOrder(all.filter(\.live), flagsFirst: true)
        let (rows, rest) = PopoverView.split(live, shown)
        func opt(_ s: String?) -> Any { s.map { $0 as Any } ?? NSNull() }
        let bands: [String] = Reservation.bands(all, shown: shown, focus: focus, pool: pool).map(\.rawValue)
        let words: [[String]] = rows.map { (r: Reservation) -> [String] in
            [r.id, r.amountsText(pool: pool), r.statusText(shown: shown, focus: focus, now: now)]
        }
        var o: [String: Any] = ["bands": bands, "rows": words, "rest": rest.map(\.id)]
        o["caption"] = Reservation.captionText(rows, shown: shown, day: Int(num(c["day"])))
        o["other"] = opt(Reservation.otherText(rest, short: false))
        o["other_short"] = opt(Reservation.otherText(rest, short: true))
        return o
    }
    out["band_stack"] = cases("band_stack").map { c -> [[String: Any]] in
        let k = Resource(rawValue: (c["kind"] as? String) ?? "") ?? .memory
        let pool = c["pool"] as? String
        let rs = merged(c).filter { $0.holds(k, pool: pool) }
        return ResBlock.stack(rs, now: num(c["now"]), kind: k).map { b in
            ["key": b.res.id, "lane": b.lane, "steps": b.steps.map { [$0.a, $0.b, $0.lo, $0.hi] }] as [String: Any]
        }
    }
    out["band_top"] = cases("band_top").map { c -> Double in
        Reservation.bandTop(num(c["tallest"]), Resource(rawValue: (c["kind"] as? String) ?? "") ?? .memory)
    }
    guard let json = try? JSONSerialization.data(withJSONObject: out, options: [.sortedKeys]) else { return 1 }
    FileHandle.standardOutput.write(json)
    FileHandle.standardOutput.write("\n".data(using: .utf8)!)
    return 0
}

@main
struct Main {
    static func main() {
        // Development aid: `oomph --render-popup out.png [--dark] [--fixture DIR] [--now T] [--no-liveness]`
        // draws the popup into a PNG and exits.
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "--chart-vectors"), i + 1 < args.count {
            exit(MainActor.assumeIsolated { chartVectors(args[i + 1]) })
        }
        if let i = args.firstIndex(of: "--connect-vectors"), i + 1 < args.count {
            exit(connectVectors(args[i + 1]))
        }
        if let i = args.firstIndex(of: "--linux-vectors"), i + 1 < args.count {
            exit(MainActor.assumeIsolated { linuxVectors(args[i + 1]) })
        }
        if let i = args.firstIndex(of: "--render-chip"), i + 1 < args.count {
            MainActor.assumeIsolated { renderChip(to: args[i + 1], dark: args.contains("--dark")) }
            return
        }
        if let i = args.firstIndex(of: "--render-popup"), i + 1 < args.count {
            // `--now T`, `--no-liveness` and `--fixture DIR` make a render repeat itself (roadmap 02 §8):
            // `oomph --render-popup out.png --fixture DIR --now T --no-liveness` is byte-identical every time
            var isDir: ObjCBool = false
            if args.contains("--now") && frozenNow == nil {
                FileHandle.standardError.write("oomph: --now takes a time in seconds since 1970\n".data(using: .utf8)!)
                exit(2)
            }
            if let d = fixtureDir, !(FileManager.default.fileExists(atPath: d + "/log", isDirectory: &isDir) && isDir.boolValue) {
                FileHandle.standardError.write("oomph: --fixture \(d): no log folder in it\n".data(using: .utf8)!)
                exit(2)
            }
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
