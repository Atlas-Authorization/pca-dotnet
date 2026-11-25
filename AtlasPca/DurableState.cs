// DurableState: crash-safe, tamper-evident, multi-process-safe persistent key/value state (a faithful port of the reference durable-state;
// the on-disk format is the same, byte for byte, so a directory written by any lane opens in any other).
//
// LAYOUT (a directory you own, mode 0700): state.journal (hash-chained records, one JSON object per line), state.head (seq + hash of the
// last record, written AFTER the journal), state.lock.<g> (the lock: immutable numbered generation files created atomically with link(2)),
// state.fence* (operator-recovery cuts).
//
// GUARANTEES: every mutation is write-temp, fsync, rename, fsync(directory): a crash leaves the old or the new journal, never a torn one, and the
// head trails by at most one record (repaired by the next writer). No lost updates across processes: every mutation runs under the exclusive
// generation lock; a lock is taken over only from a PROVABLY dead holder on this host and PID namespace, never by age; the generation is
// re-checked right before every rename. A holder that is only PAUSED across RecoverDurableState is fenced: every record and head carries the
// writer's generation, and the fence recovery wrote makes load refuse a late record from a released generation. Records are hash-chained (and
// HMAC-tagged with a key); a corrupt, truncated or rolled-back state makes every operation throw DurableStateError, never silently starting
// empty; the ONLY way past is RecoverFromCorruption, which quarantines the files (kept for forensics) and starts from genesis.
//
// NOT GUARANTEED: ONE HOST and ONE PID namespace per directory (a holder on another host or in another namespace is never judged dead:
// waiters time out, fail closed); a LOCAL filesystem with working hard links (probed at open: link-unsupported); a stalled live holder blocks
// until it dies (lock-timeout). Windows: the lock uses CreateHardLink (NTFS) and liveness uses the process table; there is no directory
// fsync there (NTFS journals the rename).
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The failure of a durable-state operation. <see cref="Code"/> is one of corrupt, rollback, lock-timeout, lock-lost, link-unsupported,
/// key-mismatch, invalid, too-large.</summary>
public sealed class DurableStateError : Exception
{
    public string Code { get; }
    public DurableStateError(string code, string message) : base(code + ": " + message) { Code = code; }
}

/// <summary>A key/value store of JSON values with the durable-state semantics (the text view is the <see cref="IKeyedAtomicKv"/> contract).</summary>
public interface IDurableKv : IKeyedAtomicKv
{
    /// <summary>The value under <paramref name="key"/> as a JSON tree, or <see cref="DurableState.Undefined"/> when absent.</summary>
    object? GetValue(string key);
    /// <summary>Unconditional write (still serialised and hash-chained). Prefer <see cref="UpdateValue"/> for monotone state.</summary>
    void SetValue(string key, object? value);
    /// <summary>Atomic read-modify-write. <paramref name="fn"/> gets the current value (<see cref="DurableState.Undefined"/> when absent) and returns the
    /// next, or <see cref="DurableState.Undefined"/> to leave the key unchanged. Returns the value now stored.</summary>
    object? UpdateValue(string key, Func<object?, object?> fn);
}

/// <summary>The holder record of the lock file an operator has confirmed dead (copy it from the lock-timeout error or the state.lock.N file).</summary>
public sealed record ExpectedLockHolder(string Host, double Pid, string Nonce);

public sealed class DurableStateOptions
{
    /// <summary>Directory holding the state (created 0700 if missing).</summary>
    public string Dir { get; set; } = "";
    /// <summary>Optional key of at least 32 bytes: records and head are tagged; forging or re-chaining then needs the key.</summary>
    public byte[]? HmacKey { get; set; }
    /// <summary>Explicit recovery: quarantine corrupt or rolled-back files and start from genesis. Default false (fail closed).</summary>
    public bool RecoverFromCorruption { get; set; }
    public long LockTimeoutMs { get; set; } = 10_000;
    public long CompactEvery { get; set; } = 256;
    public long MaxValueBytes { get; set; } = 1_048_576;
    public Func<long>? Now { get; set; }
    /// <summary>TEST ONLY: kill this process at the named point of a commit (after-temp-write | after-journal-rename).</summary>
    public string? TestCrashAt { get; set; }
}

public sealed class RecoverDurableStateOptions
{
    public string Dir { get; set; } = "";
    /// <summary>Must be true: this is an out-of-band operator action, never automatic.</summary>
    public bool Force { get; set; }
    /// <summary>The holder the operator attests is gone: an <see cref="ExpectedLockHolder"/> copied EXACTLY from a complete holder record, or the string
    /// "unreadable" for an unreadable or INCOMPLETE top lock file. A complete record never accepts "unreadable", an unreadable or incomplete
    /// one never accepts copied fields.</summary>
    public object? ExpectedHolder { get; set; }
    /// <summary>Release the LEGACY single-file state.lock of an older version (moved aside, never deleted). Refused when the blocker is a generation lock.</summary>
    public bool LegacyLock { get; set; }
}

public sealed record RecoverDurableStateResult(bool Released, string Reason, string? LockFile = null);

/// <summary>A fence: records after journal <c>Seq</c> must come from lock generation &gt;= <c>Gen</c>; <c>H</c> is the hash of the record at <c>Seq</c> when the cut was taken.</summary>
public sealed record DurableFence(long Gen, long Seq, string H);

static class DsNative
{
    public const int Eexist = 17;
    const int Eperm = 1;

    [DllImport("libc", EntryPoint = "link", SetLastError = true)] static extern int LinkC(string existing, string created);
    [DllImport("libc", EntryPoint = "open", SetLastError = true)] static extern int OpenC(string path, int flags);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)] static extern int FsyncC(int fd);
    [DllImport("libc", EntryPoint = "close", SetLastError = true)] static extern int CloseC(int fd);
    [DllImport("libc", EntryPoint = "kill", SetLastError = true)] static extern int KillC(int pid, int sig);
    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateHardLinkW(string newName, string existing, IntPtr security);

    /// <summary>link(2) / CreateHardLink: 0 when created, <see cref="Eexist"/> when the name is taken, another errno otherwise.</summary>
    public static int Link(string existing, string created)
    {
        if (OperatingSystem.IsWindows())
        {
            if (CreateHardLinkW(created, existing, IntPtr.Zero)) return 0;
            var w = Marshal.GetLastPInvokeError();
            return w is 183 or 80 ? Eexist : w; // ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS
        }
        if (LinkC(existing, created) == 0) return 0;
        return Marshal.GetLastPInvokeError();
    }

    public static string ErrName(int e) => e switch
    {
        1 => "EPERM", 2 => "ENOENT", 13 => "EACCES", 17 => "EEXIST", 18 => "EXDEV", 31 => "EMLINK", 95 => "ENOTSUP", 45 => "ENOTSUP", 38 => "ENOSYS",
        _ => "errno " + e.ToString(CultureInfo.InvariantCulture),
    };

    public static void FsyncDir(string dir)
    {
        if (OperatingSystem.IsWindows()) return;
        var fd = OpenC(dir, 0); // O_RDONLY
        if (fd < 0) throw new IOException("open(" + dir + "): " + ErrName(Marshal.GetLastPInvokeError()));
        try
        {
            if (FsyncC(fd) != 0) throw new IOException("fsync(" + dir + "): " + ErrName(Marshal.GetLastPInvokeError()));
        }
        finally { CloseC(fd); }
    }

    /// <summary>kill(pid, 0) semantics: alive, or exists but is not ours (EPERM). A pid that is not a plain int is never alive.</summary>
    public static bool PidAlive(double pid)
    {
        if (!double.IsFinite(pid) || Math.Floor(pid) != pid || pid > int.MaxValue || pid < int.MinValue) return false;
        var p = (int)pid;
        try
        {
            if (OperatingSystem.IsWindows())
            {
                using var proc = System.Diagnostics.Process.GetProcessById(p);
                return !proc.HasExited;
            }
            if (KillC(p, 0) == 0) return true;
            return Marshal.GetLastPInvokeError() == Eperm;
        }
        catch (Exception) { return false; }
    }

    public static void KillSelf()
    {
        if (OperatingSystem.IsWindows()) { System.Diagnostics.Process.GetCurrentProcess().Kill(); return; }
        KillC(Environment.ProcessId, 9);
    }

    /// <summary>Field 22 of /proc/&lt;pid&gt;/stat (process start time), null off Linux or when gone.</summary>
    public static string? ProcStartOf(double pid)
    {
        try
        {
            var st = Encoding.UTF8.GetString(File.ReadAllBytes("/proc/" + NumStr(pid) + "/stat"));
            var f = st[(st.LastIndexOf(')') + 2)..].Split(' ');
            return f.Length > 19 ? f[19] : null;
        }
        catch (Exception) { return null; }
    }

    public static string? MyNs()
    {
        try { return new FileInfo("/proc/self/ns/pid").LinkTarget; }
        catch (Exception) { return null; }
    }

    public static string NumStr(double d) => JsJson.NumberToString(d);
}

/// <summary>The shared file and JSON helpers of the durable store.</summary>
static class Ds
{
    public const string Domain = "pca-durable-state/v1\n";
    public static readonly string Genesis = new('0', 64);
    public const int MaxKey = 256;
    public const string FenceFile = "state.fence";
    public const string RecoverCrashEnv = "PCA_DURABLE_TEST_RECOVER_CRASH_AT";
    public static readonly string BootId = Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();
    static readonly UTF8Encoding Utf8 = new(false);
    public const long MaxSafe = 9007199254740991L;

    public static string Hex(int n) => Convert.ToHexString(RandomNumberGenerator.GetBytes(n)).ToLowerInvariant();
    public static string Sha(string s) => Convert.ToHexString(SHA256.HashData(Utf8.GetBytes(s))).ToLowerInvariant();
    public static long NowMs() => AtlasPca.ReplayClock.NowMs();
    public static string Host() => System.Net.Dns.GetHostName();
    public static string ReadText(string path) => Utf8.GetString(File.ReadAllBytes(path));

    public static bool Hex64(object? o)
    {
        if (o is not string s || s.Length != 64) return false;
        foreach (var c in s) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        return true;
    }

    public static bool AllDigits(string s, int from, int to)
    {
        if (to <= from) return false;
        for (var i = from; i < to; i++) if (s[i] < '0' || s[i] > '9') return false;
        return true;
    }

    public static bool IsNum(object? o, out double d)
    {
        d = 0;
        return o is Num n && double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out d);
    }

    /// <summary>Number.isSafeInteger of a JSON number (3.0 and 1e2 count, -0 counts as 0).</summary>
    public static bool SafeInt(object? o, out long v)
    {
        v = 0;
        if (!IsNum(o, out var d) || !double.IsFinite(d) || Math.Floor(d) != d || Math.Abs(d) > MaxSafe) return false;
        v = (long)d;
        return true;
    }

    public static bool NegZero(object? o) => IsNum(o, out var d) && d == 0 && double.IsNegative(d);
    public static bool IsGen(object? o) => SafeInt(o, out var v) && v >= 1;
    public static object? Get(object? o, string k) => o is D m && m.TryGetValue(k, out var v) ? v : null;
    public static bool Has(object? o, string k) => o is D m && m.ContainsKey(k);

    /// <summary>The single-digit-run suffix of a name of the form prefix + digits (no overflow past 18 digits), else -1.</summary>
    public static long NumSuffix(string name, string prefix)
    {
        if (!name.StartsWith(prefix, StringComparison.Ordinal) || !AllDigits(name, prefix.Length, name.Length) || name.Length - prefix.Length > 18) return -1;
        return long.Parse(name.AsSpan(prefix.Length), NumberStyles.None, CultureInfo.InvariantCulture);
    }

    public static IEnumerable<string> Names(string dir) => Directory.EnumerateFileSystemEntries(dir).Select(p => Path.GetFileName(p)!).ToList();

    public static (string Name, long Gen)? FenceEntry(string name)
    {
        // ^state\.fence\.(\d+)-([0-9a-f]+)$
        const string pre = FenceFile + ".";
        if (!name.StartsWith(pre, StringComparison.Ordinal)) return null;
        var dash = name.IndexOf('-', pre.Length);
        if (dash < 0 || !AllDigits(name, pre.Length, dash) || dash - pre.Length > 18 || dash + 1 >= name.Length) return null;
        for (var i = dash + 1; i < name.Length; i++) if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f'))) return null;
        return (name, long.Parse(name.AsSpan(pre.Length, dash - pre.Length), NumberStyles.None, CultureInfo.InvariantCulture));
    }

    public static List<(string Name, long Gen)> FenceEntryFiles(string dir) =>
        Names(dir).Select(FenceEntry).Where(e => e != null).Select(e => e!.Value).ToList();

    public static long TopGeneration(string dir)
    {
        long g = 0;
        foreach (var f in Names(dir)) { var n = NumSuffix(f, "state.lock."); if (n > g) g = n; }
        return g;
    }

    public static void TestCrashPoint(string point)
    {
        if (Environment.GetEnvironmentVariable("PCA_DURABLE_TEST") == "1" && Environment.GetEnvironmentVariable(RecoverCrashEnv) == point) DsNative.KillSelf();
    }

    public static void WriteNew(string path, string data)
    {
        using var fs = OwnerOnly.CreateFile(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        var b = Utf8.GetBytes(data);
        fs.Write(b, 0, b.Length);
        fs.Flush(true);
    }

    public static void AtomicWrite(string path, string data, bool crashAfterTemp, Action? beforeRename)
    {
        var tmp = path + ".tmp-" + Environment.ProcessId.ToString(CultureInfo.InvariantCulture) + "-" + Hex(6);
        WriteNew(tmp, data);
        if (crashAfterTemp) DsNative.KillSelf();
        if (beforeRename != null)
        {
            try { beforeRename(); }
            catch (Exception)
            {
                try { File.Delete(tmp); } catch (Exception) { /* best effort: the orphan temp is harmless */ }
                throw;
            }
        }
        File.Move(tmp, path, true);
        DsNative.FsyncDir(Path.GetDirectoryName(Path.GetFullPath(path))!);
    }

    public static object? ParseFile(string path, string what)
    {
        try { return Pca.ParseJson(ReadText(path)); }
        catch (Exception) { throw new DurableStateError("corrupt", what + " is not valid JSON"); }
    }

    public static DurableFence ParseFence(object? f, string where)
    {
        if (f is not D x || !SafeInt(Get(x, "gen"), out var gen) || gen < 1 || !SafeInt(Get(x, "seq"), out var seq) || seq < 0 || NegZero(Get(x, "seq")) || !Hex64(Get(x, "h")))
            throw new DurableStateError("corrupt", where + " has an invalid entry");
        return new DurableFence(gen, seq, (string)x["h"]!);
    }

    /// <summary>Every fence: the list in state.fence (absent = none) then each state.fence.&lt;gen&gt;-&lt;rand&gt; by generation. Malformed = corrupt.</summary>
    public static List<DurableFence> ReadFences(string dir)
    {
        var res = new List<DurableFence>();
        var p = Path.Combine(dir, FenceFile);
        if (File.Exists(p) || Directory.Exists(p))
        {
            var o = ParseFile(p, "state.fence");
            if (o is not D r || !IsNum(Get(r, "v"), out var v) || v != 1 || Get(r, "fences") is not L list)
                throw new DurableStateError("corrupt", "state.fence has an invalid shape");
            foreach (var f in list) res.Add(ParseFence(f, "state.fence"));
        }
        foreach (var (name, gen) in FenceEntryFiles(dir).OrderBy(e => e.Gen).ThenBy(e => e.Name, StringComparer.Ordinal))
        {
            var o = ParseFile(Path.Combine(dir, name), name);
            if (o is not D r || !IsNum(Get(r, "v"), out var v) || v != 1) throw new DurableStateError("corrupt", name + " has an invalid shape");
            var f = ParseFence(Get(r, "fence"), name);
            if (f.Gen != gen) throw new DurableStateError("corrupt", name + " names generation " + gen.ToString(CultureInfo.InvariantCulture) + " but holds " + f.Gen.ToString(CultureInfo.InvariantCulture));
            res.Add(f);
        }
        return res;
    }

    /// <summary>(seq, hash) of the last journal record as it is on disk right now; absent or unparsable gives (0, zeros).</summary>
    public static (long Seq, string H) JournalTail(string dir)
    {
        try
        {
            var lines = ReadText(Path.Combine(dir, "state.journal")).Split('\n').Where(l => l.Length > 0).ToList();
            var o = Pca.ParseJson(lines.Count > 0 ? lines[^1] : "null");
            if (o is D m && SafeInt(Get(m, "seq"), out var seq) && seq >= 1 && Hex64(Get(m, "h"))) return (seq, (string)m["h"]!);
        }
        catch (Exception) { /* none */ }
        return (0, Genesis);
    }

    /// <summary>The operator's CUT: every journal record after the tail seen NOW must come from a generation above g. Its own immutable file.</summary>
    public static void WriteFence(string dir, long g, Action? beforeRename)
    {
        ReadFences(dir); // an unreadable fence set fails closed here too, before anything new is written
        var (seq, h) = JournalTail(dir);
        var fence = new D { ["gen"] = g + 1, ["seq"] = seq, ["h"] = h, ["from"] = g, ["t"] = NowMs() };
        AtomicWrite(Path.Combine(dir, FenceFile + "." + (g + 1).ToString(CultureInfo.InvariantCulture) + "-" + Hex(6)), JsJson.Stringify(new D { ["v"] = 1, ["fence"] = fence }) + "\n", false, beforeRename);
    }

    // ---- lock files ----
    public enum Kind { Unreadable, Free, Incomplete, Complete }
    public sealed record Classified(Kind Kind, object? Raw, D? Body);

    /// <summary>A holder record is COMPLETE only with a numeric pid, a host and a non-empty nonce; JSON that is not an object or array is unreadable.</summary>
    public static Classified ClassifyLockFile(string path)
    {
        object? o;
        try { o = Pca.ParseJson(ReadText(path)); }
        catch (Exception) { return new Classified(Kind.Unreadable, null, null); }
        if (o is L) return new Classified(Kind.Incomplete, o, null);
        if (o is not D r) return new Classified(Kind.Unreadable, null, null);
        if (Get(r, "st") is string st && st == "free") return new Classified(Kind.Free, null, null);
        if (IsNum(Get(r, "pid"), out _) && Get(r, "host") is string && Get(r, "nonce") is string n && n != "") return new Classified(Kind.Complete, r, r);
        return new Classified(Kind.Incomplete, r, null);
    }

    /// <summary>Is the recorded holder demonstrably ALIVE here? Judged by PID-namespace identity when the record names one, else by hostname.</summary>
    public static bool HolderAliveHere(object? b)
    {
        if (!IsNum(Get(b, "pid"), out var pid)) return false;
        var nsNow = DsNative.MyNs();
        var judgeable = Get(b, "ns") is string ns ? nsNow != null && ns == nsNow : Get(b, "host") is string h && h == Host();
        if (!judgeable || !DsNative.PidAlive(pid)) return false;
        if (Get(b, "start") is string start)
        {
            var cur = DsNative.ProcStartOf(pid);
            if (cur != null && cur != start) return false; // the pid was reused by a different process
        }
        return true;
    }

    public static string JsField(object? o, string k) => o is D m && m.TryGetValue(k, out var v) ? JsJson.ToJsString(v) : "undefined";

    public static void ConfirmHolder(Classified c, object? exp, string path)
    {
        var unread = exp is string s && s == "unreadable";
        switch (c.Kind)
        {
            case Kind.Unreadable:
                if (!unread) throw new DurableStateError("invalid", path + " is unreadable; pass expectedHolder: 'unreadable' to release it");
                return;
            case Kind.Incomplete:
                if (!unread)
                {
                    var raw = JsJson.Stringify(c.Raw);
                    throw new DurableStateError("invalid", path + " has an incomplete holder record (" + (raw.Length > 160 ? raw[..160] : raw) + "); after confirming its holder is gone, pass expectedHolder: 'unreadable' to release it");
                }
                if (HolderAliveHere(c.Raw)) throw new DurableStateError("invalid", "the holder of " + path + " (pid " + JsField(c.Raw, "pid") + ") is alive in this PID namespace; refusing to release a live holder");
                return;
            case Kind.Free:
                return;
        }
        var b = c.Body!;
        if (unread) throw new DurableStateError("invalid", path + " is readable (holder pid=" + JsField(b, "pid") + " host=" + JsField(b, "host") + "); expectedHolder 'unreadable' does not match");
        var e = (ExpectedLockHolder)exp!;
        IsNum(b["pid"], out var bp);
        if ((string)b["host"]! != e.Host || bp != e.Pid || (string)b["nonce"]! != e.Nonce)
            throw new DurableStateError("invalid", "expectedHolder does not match the holder recorded in " + path + " (recorded pid=" + JsField(b, "pid") + " host=" + JsField(b, "host") + " nonce=" + JsField(b, "nonce") + "); nothing was changed");
        if (HolderAliveHere(b)) throw new DurableStateError("invalid", "the holder of " + path + " (pid " + JsField(b, "pid") + ") is alive in this PID namespace; refusing to release a live holder");
    }

    public static RecoverDurableStateResult Recover(RecoverDurableStateOptions opts)
    {
        if (opts == null || !opts.Force) throw new DurableStateError("invalid", "recoverDurableState requires force: true");
        var exp = opts.ExpectedHolder;
        var unread = exp is string us && us == "unreadable";
        if (!unread && !(exp is ExpectedLockHolder eh && eh.Nonce != ""))
            throw new DurableStateError("invalid", "expectedHolder must be { host, pid, nonce } as recorded in the lock file, or 'unreadable'");
        var dir = opts.Dir;
        var g = TopGeneration(dir);
        var path = Path.Combine(dir, "state.lock." + g.ToString(CultureInfo.InvariantCulture));
        Classified? top = g == 0 ? null : ClassifyLockFile(path);
        var legacyPath = Path.Combine(dir, "state.lock");
        if (opts.LegacyLock)
        {
            if (top != null && top.Kind != Kind.Free)
                throw new DurableStateError("invalid", "legacyLock: true, but the blocking lock is the generation lock " + path + "; call recoverDurableState without legacyLock");
            if (!File.Exists(legacyPath) && !Directory.Exists(legacyPath)) return new RecoverDurableStateResult(false, "not-held");
            var legacy = ClassifyLockFile(legacyPath);
            if (legacy.Kind == Kind.Free) return new RecoverDurableStateResult(false, "not-held", legacyPath);
            ConfirmHolder(legacy, exp, legacyPath);
            // A legacy (older-version) writer stamps no generation (reads as 0): every record after the cut needs >= g + 1 >= 1.
            WriteFence(dir, g, null);
            File.Move(legacyPath, Path.Combine(dir, "state.lock.legacy-recovered-" + NowMs().ToString(CultureInfo.InvariantCulture) + "-" + Hex(3)));
            DsNative.FsyncDir(dir);
            return new RecoverDurableStateResult(true, "released", legacyPath);
        }
        if (top == null || top.Kind == Kind.Free)
        {
            if (File.Exists(legacyPath))
            {
                var lb = ClassifyLockFile(legacyPath);
                var who = lb.Kind == Kind.Complete
                    ? "holder pid=" + JsField(lb.Body, "pid") + " host=" + JsField(lb.Body, "host") + " nonce=" + JsField(lb.Body, "nonce")
                    : lb.Kind.ToString().ToLowerInvariant() + " holder record";
                throw new DurableStateError("invalid", "the blocking lock is the legacy single-file " + legacyPath + " (" + who + "); after confirming that holder is gone, pass legacyLock: true with its expectedHolder (or 'unreadable')");
            }
            return top == null ? new RecoverDurableStateResult(false, "not-held") : new RecoverDurableStateResult(false, "not-held", path);
        }
        ConfirmHolder(top, exp, path);
        // In this order (formal DurableFence): TAKE generation g+1 (marked `recovering`), CUT + FENCE under it, RELEASE as g+2 free. Recovery
        // itself may crash after any step: g+1 is then held by a dead process and marked, so the next taker cuts and fences under its own generation.
        void LinkBody(long gen, D body, string crashPoint)
        {
            var tmp = Path.Combine(dir, "state.lock.tmp-" + Environment.ProcessId.ToString(CultureInfo.InvariantCulture) + "-" + Hex(6));
            WriteNew(tmp, JsJson.Stringify(body));
            TestCrashPoint(crashPoint);
            try
            {
                var rc = DsNative.Link(tmp, Path.Combine(dir, "state.lock." + gen.ToString(CultureInfo.InvariantCulture)));
                if (rc == DsNative.Eexist) throw new DurableStateError("invalid", path + " was superseded while recovering; re-read the lock state and retry");
                if (rc != 0) throw new IOException("link: " + DsNative.ErrName(rc));
            }
            finally
            {
                try { File.Delete(tmp); } catch (Exception) { /* best effort */ }
            }
        }
        var ns = DsNative.MyNs();
        TestCrashPoint("before-lock");
        var start = DsNative.ProcStartOf(Environment.ProcessId);
        var held = new D { ["st"] = "held", ["pid"] = (long)Environment.ProcessId, ["host"] = Host(), ["nonce"] = Hex(12), ["boot"] = BootId };
        if (ns != null) held["ns"] = ns;
        if (start != null) held["start"] = start;
        held["recovering"] = g;
        held["t"] = NowMs();
        LinkBody(g + 1, held, "after-lock-temp");
        TestCrashPoint("after-lock");
        WriteFence(dir, g, () => TestCrashPoint("after-fence-temp"));
        TestCrashPoint("after-fence");
        LinkBody(g + 2, new D { ["st"] = "free", ["t"] = NowMs(), ["recoveredFrom"] = g }, "after-release-temp");
        TestCrashPoint("after-release");
        return new RecoverDurableStateResult(true, "released", path);
    }
}

/// <summary>In-memory key/value store with the durable-state semantics and no durability (tests, one process).</summary>
public sealed class MemoryDurableKv : IDurableKv
{
    readonly Dictionary<string, string> _m = new(StringComparer.Ordinal);
    readonly object _lock = new();

    public string? Get(string key) { lock (_lock) return _m.TryGetValue(key, out var v) ? v : null; }

    public IReadOnlyList<string> Keys() { lock (_lock) return _m.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList(); }

    public void Update(string key, Func<string?, string?> fn)
    {
        lock (_lock)
        {
            var next = fn(_m.TryGetValue(key, out var v) ? v : null);
            if (next != null) _m[key] = DurableState.Normalise(next);
        }
    }

    public object? GetValue(string key)
    {
        var t = Get(key);
        return t == null ? DurableState.Undefined : Pca.ParseJson(t);
    }

    public void SetValue(string key, object? value) { lock (_lock) _m[key] = DurableState.EncodeTree(value, long.MaxValue); }

    public object? UpdateValue(string key, Func<object?, object?> fn)
    {
        lock (_lock)
        {
            var next = fn(_m.TryGetValue(key, out var v) ? Pca.ParseJson(v) : DurableState.Undefined);
            if (!ReferenceEquals(next, DurableState.Undefined)) _m[key] = DurableState.EncodeTree(next, long.MaxValue);
            return _m.TryGetValue(key, out var w) ? Pca.ParseJson(w) : DurableState.Undefined;
        }
    }

    /// <summary>A copy of every key and its value.</summary>
    public Dictionary<string, object?> Snapshot()
    {
        lock (_lock) return _m.ToDictionary(kv => kv.Key, kv => Pca.ParseJson(kv.Value), StringComparer.Ordinal);
    }
}

/// <summary>A durable state directory handle. Build with <see cref="Pca.OpenDurableState"/>.</summary>
public sealed class DurableState : IDurableKv
{
    /// <summary>The "absent" marker of <see cref="IDurableKv"/> (JSON null is a real value).</summary>
    public static readonly object Undefined = new();

    sealed class Rec
    {
        public long Seq; public string Prev = ""; public string Op = ""; public string Payload = ""; public long Ts; public long? Gen; public string H = ""; public string? Mac;

        public string ToJson()
        {
            var sb = new StringBuilder();
            sb.Append("{\"seq\":").Append(Seq.ToString(CultureInfo.InvariantCulture)).Append(",\"prev\":").Append(JsJson.Quote(Prev)).Append(",\"op\":").Append(JsJson.Quote(Op))
              .Append(",\"payload\":").Append(JsJson.Quote(Payload)).Append(",\"ts\":").Append(Ts.ToString(CultureInfo.InvariantCulture));
            if (Gen != null) sb.Append(",\"gen\":").Append(Gen.Value.ToString(CultureInfo.InvariantCulture));
            sb.Append(",\"h\":").Append(JsJson.Quote(H));
            if (Mac != null) sb.Append(",\"mac\":").Append(JsJson.Quote(Mac));
            return sb.Append('}').ToString();
        }
    }

    sealed class Head { public long Seq; public string H = ""; public long? Gen; public string? Mac; }
    sealed class Loaded { public List<Rec> Recs = new(); public Dictionary<string, string> State = new(StringComparer.Ordinal); public Head? Head; }
    sealed class LockBody
    {
        public string St = "held"; public double? Pid; public string? Host, Nonce, Start, Ns, Boot; public long? Recovering;
    }

    readonly string _dir, _journalPath, _headPath;
    readonly byte[]? _key;
    readonly bool _recoverOpt;
    readonly long _lockTimeout, _compactEvery, _maxValue;
    readonly Func<long> _now;
    readonly string? _testCrashAt;
    readonly string? _myNs;
    readonly string? _myStart;
    readonly object _mutex = new();
    (long Seq, string Hash) _seen = (0, Ds.Genesis);
    string? _heldNonce;
    long _myGen = -1;

    /// <summary>True when this open quarantined corrupt state (see <see cref="DurableStateOptions.RecoverFromCorruption"/>).</summary>
    public bool Recovered { get; private set; }

    internal DurableState(DurableStateOptions opts)
    {
        if (opts == null || string.IsNullOrEmpty(opts.Dir)) throw new DurableStateError("invalid", "dir is required");
        if (opts.HmacKey != null && opts.HmacKey.Length < 32) throw new DurableStateError("invalid", "hmacKey must be at least 32 bytes");
        _dir = opts.Dir;
        _key = opts.HmacKey == null ? null : (byte[])opts.HmacKey.Clone();
        _recoverOpt = opts.RecoverFromCorruption;
        _lockTimeout = opts.LockTimeoutMs;
        _compactEvery = Math.Max(2, opts.CompactEvery);
        _maxValue = opts.MaxValueBytes;
        _now = opts.Now ?? Ds.NowMs;
        _testCrashAt = opts.TestCrashAt;
        _journalPath = Path.Combine(_dir, "state.journal");
        _headPath = Path.Combine(_dir, "state.head");
        _myNs = DsNative.MyNs();
        _myStart = DsNative.ProcStartOf(Environment.ProcessId);
        try { OwnerOnly.CreateDirectory(_dir); } // owner-only from creation; an existing one is restricted in place
        catch (Exception) { /* not ours to restrict (e.g. a shared parent); keep going */ }
        Directory.CreateDirectory(_dir);
        ProbeLinks();
        // Initial open: verify under the lock (so a half-finished writer is not mistaken for corruption), repair the head.
        WithLock(() =>
        {
            var l = LoadOrRecover();
            Observe(l);
            var last = l.Recs.Count > 0 ? l.Recs[^1] : null;
            if (last != null && (l.Head == null || l.Head.Seq != last.Seq)) WriteHead(last, "nothing was written");
            return 0;
        });
    }

    // ---- hashing ----
    static string RecHash(long seq, string prev, string op, string payload, long ts, long? gen)
    {
        var arr = new L { seq, prev, op, payload, ts };
        if (gen != null) arr.Add(gen.Value);
        return Ds.Sha(Ds.Domain + JsJson.Stringify(arr));
    }

    string MacOf(string msg) => Convert.ToHexString(HMACSHA256.HashData(_key!, Encoding.UTF8.GetBytes(msg))).ToLowerInvariant();

    static bool MacEq(string a, string b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    static string HeadMsg(long seq, string h, long? gen) =>
        gen == null ? "head\n" + seq.ToString(CultureInfo.InvariantCulture) + "\n" + h : "head\n" + seq.ToString(CultureInfo.InvariantCulture) + "\n" + h + "\n" + gen.Value.ToString(CultureInfo.InvariantCulture);

    // ---- values ----
    internal static string Normalise(string json)
    {
        object? t;
        try { t = Pca.ParseJson(json); }
        catch (Exception) { throw new DurableStateError("invalid", "value is not JSON-serialisable"); }
        return JsJson.Stringify(t);
    }

    internal static string EncodeTree(object? value, long max)
    {
        string s;
        try { s = JsJson.Stringify(value); }
        catch (Exception) { throw new DurableStateError("invalid", "value is not JSON-serialisable"); }
        if (s.Length > max) throw new DurableStateError("too-large", "value exceeds maxValueBytes=" + max.ToString(CultureInfo.InvariantCulture));
        return s;
    }

    string Encode(string json)
    {
        var s = Normalise(json);
        if (s.Length > _maxValue) throw new DurableStateError("too-large", "value exceeds maxValueBytes=" + _maxValue.ToString(CultureInfo.InvariantCulture));
        return s;
    }

    static void CheckKey(string? k)
    {
        if (k == null || k.Length == 0 || k.Length > Ds.MaxKey || k.Contains('\n')) throw new DurableStateError("invalid", "key must be 1..256 chars without newlines");
    }

    // ---- reading ----
    Head? ReadHead()
    {
        if (!File.Exists(_headPath) && !Directory.Exists(_headPath)) return null;
        object? o;
        try { o = Pca.ParseJson(Ds.ReadText(_headPath)); }
        catch (Exception) { throw new DurableStateError("corrupt", "state.head is not valid JSON"); }
        if (o is not D r || !Ds.SafeInt(Ds.Get(r, "seq"), out var seq) || seq < 0 || Ds.NegZero(Ds.Get(r, "seq")) || !Ds.Hex64(Ds.Get(r, "h")) || (r.ContainsKey("gen") && !Ds.IsGen(r["gen"])))
            throw new DurableStateError("corrupt", "state.head has an invalid shape");
        var head = new Head { Seq = seq, H = (string)r["h"]! };
        if (r.ContainsKey("gen")) { Ds.SafeInt(r["gen"], out var g); head.Gen = g; }
        if (Ds.Get(r, "mac") is string mac) head.Mac = mac;
        if (_key != null && (head.Mac == null || !MacEq(head.Mac, MacOf(HeadMsg(head.Seq, head.H, head.Gen)))))
            throw new DurableStateError("key-mismatch", "state.head MAC does not verify (wrong key or forged head)");
        return head;
    }

    static string N(long v) => v.ToString(CultureInfo.InvariantCulture);

    Loaded Load()
    {
        var head = ReadHead();
        var fences = Ds.ReadFences(_dir);
        if (!File.Exists(_journalPath) && !Directory.Exists(_journalPath))
        {
            if (head != null && head.Seq > 0) throw new DurableStateError("rollback", "state.journal is missing but state.head records seq " + N(head.Seq));
            var cut = fences.FirstOrDefault(f => f.Seq > 0);
            if (cut != null) throw new DurableStateError("rollback", "state.journal is missing but operator recovery cut it at seq " + N(cut.Seq));
            if (_seen.Seq > 0) throw new DurableStateError("rollback", "state was deleted while open");
            return new Loaded { Head = head };
        }
        var lines = Ds.ReadText(_journalPath).Split('\n').ToList();
        if (lines[^1] != "") throw new DurableStateError("corrupt", "journal does not end with a newline (torn or truncated)");
        lines.RemoveAt(lines.Count - 1);
        var recs = new List<Rec>();
        var state = new Dictionary<string, string>(StringComparer.Ordinal);
        var prevHash = Ds.Genesis;
        long prevSeq = 0, prevGen = 0;
        for (var i = 0; i < lines.Count; i++)
        {
            object? o;
            try { o = Pca.ParseJson(lines[i]); }
            catch (Exception) { throw new DurableStateError("corrupt", "journal line " + (i + 1) + " is not valid JSON"); }
            if (o is not D r || !Ds.SafeInt(Ds.Get(r, "seq"), out var seq) || !Ds.Hex64(Ds.Get(r, "prev")) || Ds.Get(r, "op") is not string op || (op != "set" && op != "checkpoint")
                || Ds.Get(r, "payload") is not string payload || !Ds.SafeInt(Ds.Get(r, "ts"), out var ts) || Ds.NegZero(Ds.Get(r, "ts")) || !Ds.Hex64(Ds.Get(r, "h"))
                || (r.ContainsKey("gen") && !Ds.IsGen(r["gen"])))
                throw new DurableStateError("corrupt", "journal line " + (i + 1) + " has an invalid shape");
            var rec = new Rec { Seq = seq, Prev = (string)r["prev"]!, Op = op, Payload = payload, Ts = ts, H = (string)r["h"]! };
            if (r.ContainsKey("gen")) { Ds.SafeInt(r["gen"], out var gg); rec.Gen = gg; }
            if (Ds.Get(r, "mac") is string mac) rec.Mac = mac;
            if (i == 0)
            {
                if (rec.Op == "set" && (rec.Seq != 1 || rec.Prev != Ds.Genesis)) throw new DurableStateError("corrupt", "journal does not start at genesis");
                if (rec.Op == "checkpoint" && rec.Seq < 1) throw new DurableStateError("corrupt", "bad checkpoint seq");
            }
            else
            {
                if (rec.Seq != prevSeq + 1) throw new DurableStateError("corrupt", "journal line " + (i + 1) + ": sequence gap");
                if (rec.Prev != prevHash) throw new DurableStateError("corrupt", "journal line " + (i + 1) + ": hash chain broken");
            }
            if (RecHash(rec.Seq, rec.Prev, rec.Op, rec.Payload, rec.Ts, rec.Gen) != rec.H) throw new DurableStateError("corrupt", "journal line " + (i + 1) + ": record hash mismatch (edited)");
            if (_key != null)
            {
                if (rec.Mac == null || !MacEq(rec.Mac, MacOf(rec.H))) throw new DurableStateError("key-mismatch", "journal line " + (i + 1) + ": MAC does not verify (wrong key or forged record)");
            }
            else if (rec.Mac != null) throw new DurableStateError("key-mismatch", "journal is MAC-tagged but no hmacKey was supplied");
            // generation fencing (the record is authentic here: hash and MAC verified above). Generations never decrease along the chain;
            // a record from a generation that operator recovery fenced off, after the position the operator cut at, is a paused holder's late write.
            var rg = rec.Gen ?? 0;
            if (rg < prevGen)
                throw new DurableStateError("corrupt", "journal line " + (i + 1) + " (seq " + N(rec.Seq) + ") was written by lock generation " + N(rg) + ", older than generation " + N(prevGen) + " of an earlier record: a stale writer's record (refused)");
            foreach (var f in fences)
            {
                if (rec.Seq > f.Seq && rg < f.Gen)
                    throw new DurableStateError("corrupt", "journal line " + (i + 1) + " (seq " + N(rec.Seq) + ") was written by lock generation " + N(rg) + ", but operator recovery fenced generations below " + N(f.Gen) + " after seq " + N(f.Seq)
                        + ": a holder paused across recoverDurableState resumed and replaced the journal late (refused; records committed after the recovery may be lost; recoverFromCorruption quarantines the files)");
            }
            prevGen = rg;
            if (rec.Op == "checkpoint")
            {
                object? entries;
                try { entries = Pca.ParseJson(rec.Payload); }
                catch (Exception) { throw new DurableStateError("corrupt", "checkpoint payload is not JSON"); }
                if (entries is not L el) throw new DurableStateError("corrupt", "checkpoint payload is not an array");
                state.Clear();
                foreach (var e in el)
                {
                    if (e is not L pair || pair.Count != 2 || pair[0] is not string ek || pair[1] is not string ev) throw new DurableStateError("corrupt", "checkpoint entry is malformed");
                    state[ek] = ev;
                }
            }
            else
            {
                var nl = rec.Payload.IndexOf('\n');
                if (nl < 1) throw new DurableStateError("corrupt", "journal line " + (i + 1) + ": malformed payload");
                state[rec.Payload[..nl]] = rec.Payload[(nl + 1)..];
            }
            recs.Add(rec);
            prevHash = rec.H;
            prevSeq = rec.Seq;
        }
        var last = recs.Count > 0 ? recs[^1] : null;
        var lastSeq = last?.Seq ?? 0;
        // the journal must EXTEND the exact journal each recovery cut at (it reaches the cut, and the record at the cut is the one the
        // operator saw, unless a later generation compacted past it)
        foreach (var f in fences)
        {
            if (lastSeq < f.Seq) throw new DurableStateError("rollback", "journal is at seq " + N(lastSeq) + " but operator recovery cut it at seq " + N(f.Seq) + " (truncation, or a stale writer replaced it)");
            var atCut = recs.FirstOrDefault(r => r.Seq == f.Seq);
            if (f.Seq > 0 && atCut != null && atCut.H != f.H)
                throw new DurableStateError("corrupt", "journal record at seq " + N(f.Seq) + " is not the record operator recovery cut at: a stale writer replaced the journal (refused; recoverFromCorruption quarantines the files)");
        }
        if (head != null)
        {
            var hg = head.Gen ?? 0;
            if (lastSeq < head.Seq) throw new DurableStateError("rollback", "journal is at seq " + N(lastSeq) + " but state.head recorded seq " + N(head.Seq) + " (truncation or older copy)");
            // the head is written by the lock holder of generation hg; any record AFTER it, or a different record AT its position, from a
            // LOWER generation was written by a writer that had already lost the lock to hg
            if (last != null && (last.Gen ?? 0) < hg && (lastSeq == head.Seq + 1 || (lastSeq == head.Seq && last.H != head.H)))
                throw new DurableStateError("corrupt", "journal tail (seq " + N(lastSeq) + ") was written by lock generation " + N(last.Gen ?? 0) + ", older than generation " + N(hg) + " that wrote state.head: a stale writer replaced the journal (refused)");
            // a stale LATE head (a holder paused between its journal rename and its head rename resumed after recovery) is recognised and
            // repaired by the next writer; anything else more than one record ahead stays corrupt
            var staleHead = lastSeq > head.Seq + 1 && fences.Any(f => hg < f.Gen && head.Seq <= f.Seq && lastSeq > f.Seq) && recs.Any(r => r.Seq == head.Seq && r.H == head.H);
            if (lastSeq > head.Seq + 1 && !staleHead) throw new DurableStateError("corrupt", "journal (seq " + N(lastSeq) + ") is more than one record ahead of state.head (seq " + N(head.Seq) + ")");
            if (last != null)
            {
                if (lastSeq == head.Seq && last.H != head.H) throw new DurableStateError("corrupt", "journal tail does not match state.head");
                if (lastSeq == head.Seq + 1 && last.Prev != head.H) throw new DurableStateError("corrupt", "journal tail is not chained from state.head");
            }
        }
        else if (lastSeq > 1) throw new DurableStateError("rollback", "state.head is missing but the journal is at seq " + N(lastSeq));
        if (last != null)
        {
            if (last.Seq < _seen.Seq) throw new DurableStateError("rollback", "state moved backwards from seq " + N(_seen.Seq) + " to " + N(last.Seq) + " while open");
            if (last.Seq == _seen.Seq && last.H != _seen.Hash) throw new DurableStateError("rollback", "state forked at seq " + N(last.Seq) + " while open");
        }
        else if (_seen.Seq > 0) throw new DurableStateError("rollback", "state was emptied while open");
        return new Loaded { Recs = recs, State = state, Head = head };
    }

    void Quarantine()
    {
        var tag = N(_now()) + "-" + Ds.Hex(3);
        AssertLockHeld("nothing was written"); // a writer that lost the lock must not move a newer holder's files aside
        // After an operator recovery the journal restarts from genesis, so the old cuts no longer describe it: the fence list is replaced
        // (old one kept aside) by "every record from genesis on needs generation >= mine". The genesis fence lands BEFORE the old ones move aside.
        var fencePath = Path.Combine(_dir, Ds.FenceFile);
        var oldEntries = Ds.FenceEntryFiles(_dir);
        var listExists = File.Exists(fencePath) || Directory.Exists(fencePath);
        if (listExists || oldEntries.Count > 0)
        {
            if (listExists)
            {
                var rc = DsNative.Link(fencePath, fencePath + ".quarantine-" + tag);
                if (rc != 0) throw new IOException("link: " + DsNative.ErrName(rc));
            }
            var gf = new D { ["gen"] = _myGen, ["seq"] = 0, ["h"] = Ds.Genesis, ["from"] = _myGen - 1, ["t"] = _now() };
            Ds.AtomicWrite(fencePath, JsJson.Stringify(new D { ["v"] = 1, ["fences"] = new L { gf } }) + "\n", false, null);
            foreach (var (name, _) in oldEntries) File.Move(Path.Combine(_dir, name), Path.Combine(_dir, name + ".quarantine-" + tag));
        }
        foreach (var p in new[] { _journalPath, _headPath })
            if (File.Exists(p)) File.Move(p, p + ".quarantine-" + tag);
        DsNative.FsyncDir(_dir);
        _seen = (0, Ds.Genesis);
        Recovered = true;
    }

    Loaded LoadOrRecover()
    {
        try { return Load(); }
        catch (DurableStateError) when (_recoverOpt)
        {
            Quarantine();
            return Load();
        }
    }

    void Observe(Loaded l)
    {
        if (l.Recs.Count > 0 && l.Recs[^1].Seq >= _seen.Seq) _seen = (l.Recs[^1].Seq, l.Recs[^1].H);
    }

    // ---- the lock: immutable numbered generation files ----
    //   state.lock.<g>  g >= 1, created atomically WITH its body by link(2) (never torn, never renamed, never rewritten). The lock belongs to the
    //   process named in the highest-numbered file ("held") or is free ("free"). The only way to take it is to create generation g+1, and link(2)
    //   lets exactly one creator win. A live holder is NEVER superseded: a lock is breakable only when its holder is provably dead on this host
    //   (kill(pid,0) fails, or the pid's start time changed). A legacy single file state.lock is honoured as an additional holder, never touched.
    string LockFile(long g) => Path.Combine(_dir, "state.lock." + N(g));
    string LegacyLock => Path.Combine(_dir, "state.lock");

    LockBody? ReadBody(string path)
    {
        try
        {
            var o = Pca.ParseJson(Ds.ReadText(path));
            if (o is not (D or L)) return null;
            var b = new LockBody { St = Ds.Get(o, "st") is string st && st == "free" ? "free" : "held" };
            if (Ds.IsNum(Ds.Get(o, "pid"), out var pid)) b.Pid = pid;
            if (Ds.Get(o, "host") is string h) b.Host = h;
            if (Ds.Get(o, "nonce") is string n) b.Nonce = n;
            if (Ds.Get(o, "start") is string s) b.Start = s;
            if (Ds.Get(o, "ns") is string ns) b.Ns = ns;
            if (Ds.Get(o, "boot") is string bt) b.Boot = bt;
            if (Ds.SafeInt(Ds.Get(o, "recovering"), out var rv)) b.Recovering = rv;
            return b;
        }
        catch (Exception) { return null; }
    }

    /// <summary>Highest numbered generation: (g, body); g = 0 and no body when there is none; a null body is unreadable.</summary>
    (long G, LockBody? Body) TopLock()
    {
        var g = Ds.TopGeneration(_dir);
        return g >= 1 ? (g, ReadBody(LockFile(g))) : (0, null);
    }

    bool HolderDead(LockBody? b, double legacyAgeMs)
    {
        if (b == null) return legacyAgeMs > 1000; // an unreadable legacy file (torn by an old version) older than 1 s
        if (b.Host != Ds.Host() || b.Pid == null) return false; // another host: cannot judge, never break
        if (b.Ns != null && b.Ns != _myNs) return false; // another PID namespace or unknowable: cannot judge, never break
        if (!DsNative.PidAlive(b.Pid.Value)) return true;
        if (b.Start != null)
        {
            var cur = DsNative.ProcStartOf(b.Pid.Value);
            if (cur != null && cur != b.Start) return true; // the pid was reused by a different process
        }
        return false;
    }

    /// <summary>Create generation g atomically with its body. false = somebody else created it first.</summary>
    bool CreateGen(long g, D body)
    {
        var tmp = Path.Combine(_dir, "state.lock.tmp-" + N(Environment.ProcessId) + "-" + Ds.Hex(6));
        var b = new D(body) { ["t"] = Ds.NowMs() };
        Ds.WriteNew(tmp, JsJson.Stringify(b));
        try
        {
            var rc = DsNative.Link(tmp, LockFile(g));
            if (rc == 0) return true;
            if (rc == DsNative.Eexist) return false;
            throw new DurableStateError("invalid", "the state directory's filesystem cannot create the lock atomically (link: " + DsNative.ErrName(rc) + ")");
        }
        finally
        {
            try { File.Delete(tmp); } catch (Exception) { /* best effort */ }
        }
    }

    void GcLocks(long keepFrom)
    {
        try
        {
            foreach (var f in Ds.Names(_dir))
            {
                var n = Ds.NumSuffix(f, "state.lock.");
                if (n >= 0) { if (n < keepFrom) File.Delete(Path.Combine(_dir, f)); }
                else if (f.StartsWith("state.lock.tmp-", StringComparison.Ordinal))
                {
                    var rest = f["state.lock.tmp-".Length..];
                    var dash = rest.IndexOf('-');
                    if (dash > 0 && Ds.AllDigits(rest, 0, dash) && dash <= 18)
                    {
                        var pid = long.Parse(rest.AsSpan(0, dash), NumberStyles.None, CultureInfo.InvariantCulture);
                        if (pid > 0 && !DsNative.PidAlive(pid)) File.Delete(Path.Combine(_dir, f));
                    }
                }
            }
        }
        catch (Exception) { /* best effort */ }
    }

    /// <summary>Fail closed at open time when this filesystem cannot give the lock its atomic hard-link semantics.</summary>
    void ProbeLinks()
    {
        var a = Path.Combine(_dir, "state.probe-" + N(Environment.ProcessId) + "-" + Ds.Hex(6));
        var b = a + ".lnk";
        try
        {
            Ds.WriteNew(a, "probe");
            var rc = DsNative.Link(a, b);
            if (rc != 0) throw new ProbeFailed(DsNative.ErrName(rc));
            if (DsNative.Link(a, b) != DsNative.Eexist) throw new ProbeFailed("link(2) is not atomic/exclusive here"); // must fail with EEXIST: exclusive create
            // a real hard link shares its inode: a byte appended through one name shows through the other (nlink is not portable in .NET)
            using (var fs = new FileStream(a, FileMode.Append, FileAccess.Write)) fs.WriteByte((byte)'!');
            if (Ds.ReadText(b) != "probe!") throw new ProbeFailed("link(2) is not atomic/exclusive here");
        }
        catch (Exception e) when (e is not DurableStateError)
        {
            throw new DurableStateError("link-unsupported", "the state directory's filesystem does not provide working hard links with exclusive-create semantics (" + (e is ProbeFailed ? e.Message : e.GetType().Name) + "); use a local filesystem (ext4, xfs, btrfs, tmpfs, APFS, NTFS), not NFS/SMB/FUSE");
        }
        finally
        {
            foreach (var f in new[] { a, b }) { try { File.Delete(f); } catch (Exception) { /* best effort */ } }
        }
    }

    sealed class ProbeFailed : Exception { public ProbeFailed(string m) : base(m) { } }

    T WithLock<T>(Func<T> fn)
    {
        lock (_mutex) return WithLockLocked(fn);
    }

    T WithLockLocked<T>(Func<T> fn)
    {
        var nonce = Ds.Hex(12);
        var mustFence = false;
        var deadline = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + _lockTimeout;
        for (; ; )
        {
            var top = TopLock();
            // A single-file state.lock left by (or still used by) an older version counts as a holder too: wait for it unless its owner is
            // provably dead. We never delete or rename it (do not mix versions on one directory).
            var legacyBlocks = false;
            if (File.Exists(LegacyLock) || Directory.Exists(LegacyLock))
            {
                double age = 0;
                try { age = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - new DateTimeOffset(File.GetLastWriteTimeUtc(LegacyLock)).ToUnixTimeMilliseconds(); } catch (Exception) { /* vanished */ }
                legacyBlocks = !HolderDead(ReadBody(LegacyLock), age);
            }
            var free = top.G == 0 || top.Body?.St == "free";
            if (!legacyBlocks && (free || HolderDead(top.Body, 0)))
            {
                // Taking over a DEAD holder whose lock is marked `recovering` (an operator recovery, or a taker of one, that died midway):
                // carry the mark and cut + fence before loading.
                long? recovering = !free ? top.Body?.Recovering : null;
                var body = new D { ["st"] = "held", ["pid"] = (long)Environment.ProcessId, ["host"] = Ds.Host(), ["nonce"] = nonce, ["boot"] = Ds.BootId };
                if (_myNs != null) body["ns"] = _myNs;
                if (_myStart != null) body["start"] = _myStart;
                if (recovering != null) body["recovering"] = recovering.Value;
                if (CreateGen(top.G + 1, body))
                {
                    // The generation must still be the HIGHEST one: a creator working from a stale directory view can re-create a generation
                    // that garbage collection already removed; that grab is buried below the real top and is not a lock.
                    if (TopLock().G != top.G + 1) continue;
                    _myGen = top.G + 1;
                    mustFence = recovering != null;
                    break;
                }
                continue; // lost the race for that generation: look again immediately
            }
            if (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() > deadline)
            {
                string Desc(LockBody? b) =>
                    b == null ? "an unreadable holder record"
                    : b.Pid == null || b.Host == null || string.IsNullOrEmpty(b.Nonce)
                        ? "an incomplete holder record (pid=" + (b.Pid == null ? "?" : DsNative.NumStr(b.Pid.Value)) + " host=" + (b.Host ?? "?") + " nonce=" + (string.IsNullOrEmpty(b.Nonce) ? "?" : b.Nonce) + "); release it with expectedHolder: 'unreadable'"
                        : "holder pid=" + DsNative.NumStr(b.Pid.Value) + " host=" + b.Host + " nonce=" + b.Nonce + (b.Ns != null && b.Ns != _myNs ? " (another PID namespace)" : "");
                // name the file that actually blocks (the legacy single-file lock is not a generation)
                if (legacyBlocks && (free || HolderDead(top.Body, 0)))
                    throw new DurableStateError("lock-timeout", "could not acquire the state lock in " + _dir + " within " + N(_lockTimeout) + " ms; blocked by " + LegacyLock + " (legacy single-file lock of an older version; " + Desc(ReadBody(LegacyLock))
                        + "). If that holder is provably gone, an operator can release it with recoverDurableState({ dir, force: true, legacyLock: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs");
                throw new DurableStateError("lock-timeout", "could not acquire the state lock in " + _dir + " within " + N(_lockTimeout) + " ms; blocked by " + LockFile(top.G) + " (" + Desc(top.Body)
                    + "). If that holder is provably gone (e.g. a crashed container in another PID namespace), an operator can release it with recoverDurableState({ dir, force: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs");
            }
            Thread.Sleep(5 + Random.Shared.Next(15));
        }
        _heldNonce = nonce;
        GcLocks(_myGen - 16);
        try
        {
            if (mustFence)
            {
                // The recovery we took over may have died before (or after) writing its fence; the holder it was releasing may be merely paused.
                // Cut and fence now, under OUR generation, before anything is loaded.
                Ds.TestCrashPoint("takeover-after-lock");
                Ds.WriteFence(_dir, _myGen - 1, () => Ds.TestCrashPoint("takeover-after-fence-temp"));
            }
            return fn();
        }
        finally
        {
            _heldNonce = null;
            try
            {
                CreateGen(_myGen + 1, new D { ["st"] = "free" }); // release; a live holder is never superseded, so this cannot lose a race
                GcLocks(_myGen - 15);
            }
            catch (Exception) { /* the lock stays "held" by a process about to be judged dead or alive by its pid: still safe */ }
        }
    }

    /// <summary>Immediately before EVERY rename this writer makes (journal, head, quarantine): this handle's generation must still be the highest and must still
    /// name us. After RecoverDurableState released a holder that was only PAUSED, it is what makes the resumed holder fail with lock-lost. The residual
    /// window between this check and rename(2) is closed on the READ side: every record and head carries the generation and load refuses a late one.</summary>
    void AssertLockHeld(string outcome)
    {
        var top = TopLock();
        if (_heldNonce == null || top.G != _myGen || top.Body?.St != "held" || top.Body.Nonce != _heldNonce)
            throw new DurableStateError("lock-lost", "the state lock is no longer held by this writer (generation " + N(_myGen) + ", highest " + N(top.G) + " " + (top.Body?.St ?? "unreadable") + "); " + outcome);
    }

    void Commit(Loaded l, string key, string valueJson)
    {
        var last = l.Recs.Count > 0 ? l.Recs[^1] : null;
        var seq = (last?.Seq ?? 0) + 1;
        var prev = last?.H ?? Ds.Genesis;
        var payload = key + "\n" + valueJson;
        var ts = _now();
        var rec = new Rec { Seq = seq, Prev = prev, Op = "set", Payload = payload, Ts = ts, Gen = _myGen, H = RecHash(seq, prev, "set", payload, ts, _myGen) };
        if (_key != null) rec.Mac = MacOf(rec.H);
        var all = new List<Rec>(l.Recs) { rec };
        if (all.Count > _compactEvery)
        {
            // Compact: ONE checkpoint at the same seq the new record would have, chained from the current tail and carrying the full state
            // (including the new value). Head lag stays at most one record.
            var next = new Dictionary<string, string>(l.State, StringComparer.Ordinal) { [key] = valueJson };
            var entries = new L();
            foreach (var kv in next.OrderBy(kv => kv.Key, StringComparer.Ordinal)) entries.Add(new L { kv.Key, kv.Value });
            var cpay = JsJson.Stringify(entries);
            var cts = _now();
            var cp = new Rec { Seq = seq, Prev = prev, Op = "checkpoint", Payload = cpay, Ts = cts, Gen = _myGen, H = RecHash(seq, prev, "checkpoint", cpay, cts, _myGen) };
            if (_key != null) cp.Mac = MacOf(cp.H);
            all = new List<Rec> { cp };
        }
        var tail = all[^1];
        // Journal first (atomic), head second (atomic). A crash between leaves the head one record behind: repaired by the next writer.
        // The lock re-check runs AFTER the temp file is written and fsynced, i.e. as close to the rename as possible.
        Ds.AtomicWrite(_journalPath, string.Join("\n", all.Select(r => r.ToJson())) + "\n", _testCrashAt == "after-temp-write", () => AssertLockHeld("nothing was written"));
        if (_testCrashAt == "after-journal-rename") DsNative.KillSelf();
        WriteHead(tail, "the journal record (seq " + N(tail.Seq) + ") was renamed into place but state.head was not written; whether it counts depends on whether operator recovery cut before it (re-read the value)");
        _seen = (tail.Seq, tail.H);
    }

    /// <summary>Head write, stamped with this writer's generation and guarded by the same lock re-check as the journal.</summary>
    void WriteHead(Rec tail, string outcome)
    {
        var sb = new StringBuilder();
        sb.Append("{\"seq\":").Append(N(tail.Seq)).Append(",\"h\":").Append(JsJson.Quote(tail.H)).Append(",\"gen\":").Append(N(_myGen));
        if (_key != null) sb.Append(",\"mac\":").Append(JsJson.Quote(MacOf(HeadMsg(tail.Seq, tail.H, _myGen))));
        sb.Append("}\n");
        Ds.AtomicWrite(_headPath, sb.ToString(), false, () => AssertLockHeld(outcome));
    }

    void RepairHead(Loaded l)
    {
        var last = l.Recs.Count > 0 ? l.Recs[^1] : null;
        if (last != null && (l.Head == null || l.Head.Seq != last.Seq)) WriteHead(last, "nothing was written");
    }

    // ---- the store ----
    /// <summary>Highest chain position this handle has observed.</summary>
    public (long Seq, string Hash) Position() { lock (_mutex) return _seen; }

    /// <summary>Verify the chain from disk now; throws <see cref="DurableStateError"/> on any problem.</summary>
    public (long Seq, string Hash) Verify() => WithLock(() => { Observe(Load()); return _seen; });

    /// <summary>The stored JSON text of <paramref name="key"/>, or null when absent.</summary>
    public string? Get(string key)
    {
        CheckKey(key);
        return WithLock(() =>
        {
            var l = Load();
            Observe(l);
            return l.State.TryGetValue(key, out var v) ? v : null;
        });
    }

    /// <summary>Every key, sorted.</summary>
    public IReadOnlyList<string> Keys() => WithLock<IReadOnlyList<string>>(() =>
    {
        var l = Load();
        Observe(l);
        return l.State.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
    });

    /// <summary>Unconditional write of a JSON text (still serialised and hash-chained). Prefer <see cref="Update"/> for monotone state.</summary>
    public void Set(string key, string json)
    {
        CheckKey(key);
        var vj = Encode(json);
        WithLock(() =>
        {
            var l = Load();
            RepairHead(l);
            Commit(l, key, vj);
            return 0;
        });
    }

    /// <summary>Atomic read-modify-write over JSON text: <paramref name="fn"/> gets the current text (null when absent) and returns the next, or null to leave
    /// the key unchanged. Runs under the cross-process lock and must be quick.</summary>
    public void Update(string key, Func<string?, string?> fn) => UpdateText(key, fn);

    string? UpdateText(string key, Func<string?, string?> fn)
    {
        CheckKey(key);
        return WithLock(() =>
        {
            var l = Load();
            RepairHead(l);
            l.State.TryGetValue(key, out var cur);
            var next = fn(cur);
            if (next == null) return cur;
            var vj = Encode(next);
            if (vj != cur) Commit(l, key, vj);
            return vj;
        });
    }

    public object? GetValue(string key)
    {
        var t = Get(key);
        return t == null ? Undefined : Pca.ParseJson(t);
    }

    public void SetValue(string key, object? value)
    {
        CheckKey(key);
        Set(key, EncodeTree(value, _maxValue));
    }

    public object? UpdateValue(string key, Func<object?, object?> fn)
    {
        var t = UpdateText(key, cur =>
        {
            var r = fn(cur == null ? Undefined : Pca.ParseJson(cur));
            return ReferenceEquals(r, Undefined) ? null : EncodeTree(r, _maxValue);
        });
        return t == null ? Undefined : Pca.ParseJson(t);
    }
}

public static partial class Pca
{
    /// <summary>In-memory key/value store with the durable-state semantics and no durability (tests, one process).</summary>
    public static MemoryDurableKv CreateMemoryDurableKv() => new();

    /// <summary>Open (creating if needed) a durable state directory. Throws <see cref="DurableStateError"/> on corrupt or rolled-back state unless recovering.</summary>
    public static DurableState OpenDurableState(DurableStateOptions opts) => new(opts);

    /// <summary>Operator recovery for a lock whose holder cannot be judged dead automatically (another PID namespace, a changed hostname, an unreadable
    /// or incomplete top lock file, or a legacy single-file state.lock). Takes the lock itself (generation g+1), cuts and FENCES the released
    /// generation, then appends a free generation g+2. Throws <see cref="DurableStateError"/> (invalid) on a mismatch, a live holder or bad arguments.</summary>
    public static RecoverDurableStateResult RecoverDurableState(RecoverDurableStateOptions opts) => Ds.Recover(opts);
}
