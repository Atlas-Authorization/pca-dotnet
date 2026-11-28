using System.Globalization;
using System.Text.RegularExpressions;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The durable store's generation lock: the wait loop driven by a fake clock and pause (exact lock-timeout errors, the exact number
/// of pauses, the deadline bounding a lost race), takeover of dead / reused / recovering holders, the legacy single-file lock, the holder
/// record written, the lock's link and the open-time link probe through a fake hard link, lock garbage collection, lock-lost on every rename,
/// head repair and the public reads. The name contains DurableStateTests so the Windows mutation shards run it.</summary>
public class DurableStateTestsLock
{
    const long Dead = 999999999;
    const string FakeNs = "pid:[4026530001]";
    static readonly string Pid = Environment.ProcessId.ToString(CultureInfo.InvariantCulture);
    static readonly string Host = Ds.Host();
    static readonly long Mtime2020 = new DateTimeOffset(new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc)).ToUnixTimeMilliseconds();

    /// <summary>Swaps the lock seams for the test and restores them: a clock that moves only when the loop pauses (Step per pause) or on every
    /// read (PerCall), a pause that records its length, an optional hard link. A runaway loop fails the test instead of hanging it.</summary>
    sealed class Rig : IDisposable
    {
        public long T, Step, PerCall;
        public int Calls;
        public readonly List<int> Sleeps = new();
        readonly Func<long> _clock = DurableState.LockClock;
        readonly Action<int> _sleep = DurableState.LockSleep;
        readonly Func<string, string, int> _link = DurableState.Linker;

        public Rig(long t, long step = 10)
        {
            T = t; Step = step;
            DurableState.LockClock = Now;
            DurableState.LockSleep = Sleep;
        }

        public Func<string, string, int> Link { set => DurableState.Linker = value; }

        long Now()
        {
            if (++Calls > 400) throw new InvalidOperationException("runaway lock loop");
            var v = T;
            T += PerCall;
            return v;
        }

        void Sleep(int ms)
        {
            Sleeps.Add(ms);
            T += Step;
        }

        public void Dispose()
        {
            DurableState.LockClock = _clock;
            DurableState.LockSleep = _sleep;
            DurableState.Linker = _link;
        }
    }

    sealed class Tmp : IDisposable
    {
        public readonly string Dir = Directory.CreateTempSubdirectory("pca-dsl-").FullName;
        public string P(string f) => Path.Combine(Dir, f);
        public string Lock(long g) => P("state.lock." + g.ToString(CultureInfo.InvariantCulture));
        public void Write(string f, string text) => File.WriteAllText(P(f), text);
        public string Read(string f) => File.ReadAllText(P(f));
        public string[] Names() => Directory.GetFileSystemEntries(Dir).Select(p => Path.GetFileName(p)!).OrderBy(x => x, StringComparer.Ordinal).ToArray();
        public long[] Gens() => Names().Where(f => Regex.IsMatch(f, "^state\\.lock\\.[0-9]+$")).Select(f => long.Parse(f[11..], CultureInfo.InvariantCulture)).OrderBy(x => x).ToArray();
        public void Dispose() { try { Directory.Delete(Dir, true); } catch (Exception) { /* best effort */ } }
    }

    static DurableState Open(Tmp t, long timeout = 2000, string? crashAt = null, long maxValue = 1_048_576) =>
        Pca.OpenDurableState(new DurableStateOptions { Dir = t.Dir, LockTimeoutMs = timeout, TestCrashAt = crashAt, MaxValueBytes = maxValue });

    static D J(string json) => (D)Pca.ParseJson(json)!;

    static string Holder(object pid, string nonce, string extra = "") =>
        "{\"st\":\"held\",\"pid\":" + pid + ",\"host\":\"" + Host + "\",\"nonce\":\"" + nonce + "\"" + extra + "}";

    static string Within(Tmp t, long ms) => "lock-timeout: could not acquire the state lock in " + t.Dir + " within " + ms.ToString(CultureInfo.InvariantCulture) + " ms; ";

    static string GenBlocked(Tmp t, long ms, long g, string desc) =>
        Within(t, ms) + "blocked by " + t.Lock(g) + " (" + desc + "). If that holder is provably gone (e.g. a crashed container in another PID namespace), an operator can release it with recoverDurableState({ dir, force: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs";

    static string LegacyBlocked(Tmp t, long ms, string desc) =>
        Within(t, ms) + "blocked by " + t.P("state.lock") + " (legacy single-file lock of an older version; " + desc + "). If that holder is provably gone, an operator can release it with recoverDurableState({ dir, force: true, legacyLock: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs";

    static string Lost(long gen, long top, string st, string outcome) =>
        "lock-lost: the state lock is no longer held by this writer (generation " + gen + ", highest " + top + " " + st + "); " + outcome;

    static void WithEnv(Dictionary<string, string?> vars, Action body)
    {
        var prev = vars.Keys.ToDictionary(k => k, k => Environment.GetEnvironmentVariable(k));
        try
        {
            foreach (var kv in vars) Environment.SetEnvironmentVariable(kv.Key, kv.Value);
            body();
        }
        finally { foreach (var kv in prev) Environment.SetEnvironmentVariable(kv.Key, kv.Value); }
    }

    static bool IsGenPath(string p) => Regex.IsMatch(Path.GetFileName(p), "^state\\.lock\\.[0-9]+$");
    static bool Held(string tmp) => File.ReadAllText(tmp).Contains("\"st\":\"held\"");
    static long GenOf(string p) => long.Parse(Path.GetFileName(p)[11..], CultureInfo.InvariantCulture);

    // ---- the wait loop ----

    [Fact]
    public void ALiveHolderTimesOutAfterExactlyTheDeadlineWithItsHolderNamed()
    {
        using var t = new Tmp();
        t.Write("state.lock.1", Holder(Pid, "n1"));
        using var rig = new Rig(1_000_000);
        var e = Assert.Throws<DurableStateError>(() => Open(t, 100));
        Assert.Equal(GenBlocked(t, 100, 1, "holder pid=" + Pid + " host=" + Host + " nonce=n1"), e.Message);
        Assert.Equal("lock-timeout", e.Code);
        // one look at the start, one after each pause: the clock (+10 per pause) passes start + 100 after the 11th pause
        Assert.Equal(11, rig.Sleeps.Count);
        Assert.All(rig.Sleeps, ms => Assert.InRange(ms, 5, 19));
        Assert.Equal(new long[] { 1 }, t.Gens());
    }

    [Fact]
    public void AHolderInAnotherPidNamespaceIsNeverJudgedAndIsNamedSo()
    {
        using var t = new Tmp();
        t.Write("state.lock.1", Holder(Dead, "n1", ",\"ns\":\"" + FakeNs + "\""));
        using var rig = new Rig(0);
        var e = Assert.Throws<DurableStateError>(() => Open(t, 20));
        Assert.Equal(GenBlocked(t, 20, 1, "holder pid=" + Dead + " host=" + Host + " nonce=n1 (another PID namespace)"), e.Message);
    }

    [Fact]
    public void ADeadHolderIsTakenOverAtOnce()
    {
        using var t = new Tmp();
        t.Write("state.lock.1", Holder(Dead, "d"));
        using var rig = new Rig(0);
        var s = Open(t, 0);
        Assert.Empty(rig.Sleeps);
        s.Set("a", "1");
        Assert.Equal("1", s.Get("a"));
        Assert.Equal(Pid, ((Num)J(t.Read("state.lock.2"))["pid"]!).Raw);
    }

    [Fact]
    public void ALivePidWhoseStartTimeChangedIsAReusedPidWhereTheStartTimeIsKnown()
    {
        using var t = new Tmp();
        t.Write("state.lock.1", Holder(Pid, "n1", ",\"start\":\"not-the-start-time\""));
        using var rig = new Rig(0);
        if (DsNative.ProcStartOf(Environment.ProcessId) != null)
        {
            Open(t, 20).Set("a", "1"); // Linux: the start time differs, so the pid was reused: taken over
            Assert.Empty(rig.Sleeps);
        }
        else
        {
            var e = Assert.Throws<DurableStateError>(() => Open(t, 20)); // no start time to compare: a live pid blocks
            Assert.Equal(GenBlocked(t, 20, 1, "holder pid=" + Pid + " host=" + Host + " nonce=n1"), e.Message);
        }
    }

    [Fact]
    public void ALostRaceLooksAgainAtOnceWithoutAPause()
    {
        using var t = new Tmp();
        var buried = false;
        using var rig = new Rig(0);
        rig.Link = (src, dst) =>
        {
            var rc = DsNative.Link(src, dst);
            if (!buried && IsGenPath(dst) && Held(src)) { buried = true; File.WriteAllText(Path.Combine(t.Dir, "state.lock." + (GenOf(dst) + 3)), "{\"st\":\"free\"}"); }
            return rc;
        };
        var s = Open(t, 0); // generation 1 is buried below 4 at once: the next look (still at the deadline) takes 5
        Assert.Empty(rig.Sleeps);
        Assert.Equal(new long[] { 1, 4, 5, 6 }, t.Gens());
        s.Set("a", "1");
        Assert.Equal("1", s.Get("a"));
    }

    [Fact]
    public void LostRacesStopAtTheDeadline()
    {
        using var t = new Tmp();
        using var rig = new Rig(0) { PerCall = 1 };
        rig.Link = (src, dst) =>
        {
            var rc = DsNative.Link(src, dst);
            if (IsGenPath(dst) && Held(src)) File.WriteAllText(Path.Combine(t.Dir, "state.lock." + (GenOf(dst) + 3)), "{\"st\":\"free\"}");
            return rc;
        };
        // deadline 0 + 1: the look after the first lost race runs at 1 (not past it), the one after the second at 2 (past it)
        var e = Assert.Throws<DurableStateError>(() => Open(t, 1));
        Assert.Equal(Within(t, 1) + "every attempt to take the lock lost the race to another writer (last: generation 5)", e.Message);
        Assert.Empty(rig.Sleeps);
    }

    [Fact]
    public void TheDefaultClockIsTheWallClockInMilliseconds()
    {
        var before = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var now = DurableState.LockClock();
        Assert.InRange(now, before, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    }

    // ---- the legacy single-file lock ----

    static void Legacy(Tmp t, string text)
    {
        t.Write("state.lock", text);
        File.SetLastWriteTimeUtc(t.P("state.lock"), new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc));
    }

    [Fact]
    public void AnUnreadableLegacyLockOlderThanOneSecondIsDead()
    {
        using var t = new Tmp();
        Legacy(t, "{torn");
        using var rig = new Rig(Mtime2020 + 1001);
        Open(t, 50).Set("a", "1");
        Assert.Empty(rig.Sleeps);
        Assert.Equal("{torn", t.Read("state.lock")); // never touched
    }

    [Fact]
    public void AnUnreadableLegacyLockOfExactlyOneSecondStillBlocks()
    {
        using var t = new Tmp();
        Legacy(t, "{torn");
        using var rig = new Rig(Mtime2020 + 1000);
        Open(t, 0); // 1000 ms old: blocks; after one pause (+10 ms) it is dead
        Assert.Single(rig.Sleeps);
    }

    [Fact]
    public void AYoungUnreadableLegacyLockBlocksAndIsNamed()
    {
        using var t = new Tmp();
        Legacy(t, "{torn");
        using var rig = new Rig(Mtime2020 + 500);
        var e = Assert.Throws<DurableStateError>(() => Open(t, 100));
        Assert.Equal(LegacyBlocked(t, 100, "an unreadable holder record"), e.Message);
        Assert.Equal(11, rig.Sleeps.Count);
    }

    [Fact]
    public void ALiveLegacyHolderIsNamedUnlessAGenerationAlsoBlocks()
    {
        using (var t = new Tmp())
        {
            Legacy(t, Holder(Pid, "L"));
            using var rig = new Rig(0);
            var e = Assert.Throws<DurableStateError>(() => Open(t, 20));
            Assert.Equal(LegacyBlocked(t, 20, "holder pid=" + Pid + " host=" + Host + " nonce=L"), e.Message);
        }
        using (var t = new Tmp())
        {
            Legacy(t, Holder(Pid, "L"));
            t.Write("state.lock.1", Holder(Pid, "G"));
            using var rig = new Rig(0);
            var e = Assert.Throws<DurableStateError>(() => Open(t, 20));
            Assert.Equal(GenBlocked(t, 20, 1, "holder pid=" + Pid + " host=" + Host + " nonce=G"), e.Message);
        }
    }

    // ---- the holder record and recovering takeovers ----

    [Fact]
    public void TheLockIsTakenWithAFullHolderRecordAndReleasedWithAFreeOne()
    {
        using var t = new Tmp();
        Open(t);
        Assert.Equal(new long[] { 1, 2 }, t.Gens());
        var held = J(t.Read("state.lock.1"));
        var keys = new List<string> { "st", "pid", "host", "nonce", "boot", "t" };
        var ns = DsNative.MyNs();
        var start = DsNative.ProcStartOf(Environment.ProcessId);
        if (ns != null) keys.Add("ns");
        if (start != null) keys.Add("start");
        Assert.Equal(keys.OrderBy(k => k, StringComparer.Ordinal), held.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal("held", held["st"]);
        Assert.Equal(Pid, ((Num)held["pid"]!).Raw);
        Assert.Equal(Host, held["host"]);
        Assert.Matches("^[0-9a-f]{24}$", (string)held["nonce"]!);
        Assert.Equal(Ds.BootId, held["boot"]);
        Assert.IsType<Num>(held["t"]);
        if (ns != null) Assert.Equal(ns, held["ns"]);
        if (start != null) Assert.Equal(start, held["start"]);
        var free = J(t.Read("state.lock.2"));
        Assert.Equal(new[] { "st", "t" }, free.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal("free", free["st"]);
        Assert.IsType<Num>(free["t"]);
        Assert.DoesNotContain(t.Names(), f => f.StartsWith("state.lock.tmp-", StringComparison.Ordinal) || f.StartsWith("state.probe-", StringComparison.Ordinal));
    }

    [Fact]
    public void TakingOverADeadRecoveringHolderCarriesTheMarkAndFences()
    {
        using var t = new Tmp();
        t.Write("state.lock.1", Holder(Dead, "d", ",\"recovering\":3"));
        Open(t).Set("a", "1");
        Assert.Equal("3", ((Num)J(t.Read("state.lock.2"))["recovering"]!).Raw);
        Assert.Single(t.Names(), f => Regex.IsMatch(f, "^state\\.fence\\.2-[0-9a-f]+$"));
    }

    [Fact]
    public void AFreeLockNeverCarriesARecoveringMark()
    {
        using var t = new Tmp();
        t.Write("state.lock.1", "{\"st\":\"free\",\"recovering\":3}");
        Open(t);
        Assert.False(J(t.Read("state.lock.2")).ContainsKey("recovering"));
        Assert.DoesNotContain(t.Names(), f => f.StartsWith("state.fence", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("takeover-after-lock")]
    [InlineData("takeover-after-fence-temp")]
    public void TheTakeoverCrashHooksFireAtTheirPoint(string point)
    {
        using var t = new Tmp();
        t.Write("state.lock.1", Holder(Dead, "d", ",\"recovering\":3"));
        WithEnv(new() { ["PCA_DURABLE_TEST"] = "1", [Ds.RecoverCrashEnv] = point, [DsNative.CrashChildEnv] = null }, () =>
        {
            var e = Assert.Throws<InvalidOperationException>(() => Open(t));
            Assert.Equal("crash hook fired outside a crash child (" + point + ")", e.Message);
        });
        Assert.DoesNotContain(t.Names(), f => f.StartsWith("state.fence", StringComparison.Ordinal));
    }

    // ---- the lock's link and the open-time probe ----

    [Fact]
    public void TemporariesAreNamedByPrefixPidAndRandomHex()
    {
        Assert.Equal("state.lock.tmp-", DurableState.LockTmpPrefix);
        Assert.Equal("state.probe-", DurableState.ProbePrefix);
        Assert.Matches("^state\\.lock\\.tmp-" + Pid + "-[0-9a-f]{12}$", DurableState.TmpName(DurableState.LockTmpPrefix));
        Assert.Matches("^state\\.probe-" + Pid + "-[0-9a-f]{12}$", DurableState.TmpName(DurableState.ProbePrefix));
    }

    [Fact]
    public void ALockLinkFailingOtherwiseThanEexistIsInvalid()
    {
        using var t = new Tmp();
        using var rig = new Rig(0) { Link = (src, dst) => IsGenPath(dst) ? 13 : DsNative.Link(src, dst) };
        var x = Assert.Throws<DurableStateError>(() => Open(t));
        Assert.Equal("invalid: the state directory's filesystem cannot create the lock atomically (link: EACCES)", x.Message);
        Assert.Empty(t.Names());
    }

    static string Unsupported(string why) =>
        "link-unsupported: the state directory's filesystem does not provide working hard links with exclusive-create semantics (" + why + "); use a local filesystem (ext4, xfs, btrfs, tmpfs, APFS, NTFS), not NFS/SMB/FUSE";

    static void ProbeFails(Func<int, string, string, int> link, string why)
    {
        using var t = new Tmp();
        var n = 0;
        using var rig = new Rig(0) { Link = (src, dst) => dst.EndsWith(".lnk", StringComparison.Ordinal) ? link(++n, src, dst) : DsNative.Link(src, dst) };
        var x = Assert.Throws<DurableStateError>(() => Open(t));
        Assert.Equal(Unsupported(why), x.Message);
        Assert.Empty(t.Names()); // the probe files are gone and no lock was taken
    }

    [Fact]
    public void AProbeLinkThatFailsNamesTheErrno() => ProbeFails((_, _, _) => 95, "ENOTSUP");

    [Fact]
    public void AProbeLinkThatCreatesAnExistingNameIsNotExclusive() => ProbeFails((i, e, c) => i == 1 ? DsNative.Link(e, c) : 0, "link(2) is not atomic/exclusive here");

    [Fact]
    public void AProbeLinkThatCopiesIsNotAHardLink() => ProbeFails((i, e, c) => { if (i == 1) File.Copy(e, c); return i == 1 ? 0 : DsNative.Eexist; }, "link(2) is not atomic/exclusive here");

    [Fact]
    public void AProbeThatThrowsNamesTheExceptionType() => ProbeFails((_, _, _) => throw new IOException("boom"), "IOException");

    [Fact]
    public void AWorkingProbeLeavesNothingBehind()
    {
        using var t = new Tmp();
        Open(t);
        Assert.DoesNotContain(t.Names(), f => f.StartsWith("state.probe-", StringComparison.Ordinal));
    }

    // ---- lock garbage collection ----

    [Fact]
    public void OldGenerationsAndDeadWritersTemporariesAreCollected()
    {
        using var t = new Tmp();
        var s = Open(t);
        foreach (var g in new[] { 0, 24, 25, 26 }) t.Write("state.lock." + g, "{\"st\":\"free\"}");
        t.Write("state.lock.40", "{\"st\":\"free\"}");
        var p = DurableState.LockTmpPrefix;
        var kept = new[] { p + "-x", p + "0-zero", p + "1000000000000000000-x", p + "1a-x", p + Pid + "-live", p + "nodash" };
        var gone = new[] { p + "999999999-dead", p + "100000000000000000-x" };
        foreach (var f in kept.Concat(gone)) t.Write(f, "x");
        string[]? inside = null;
        long[]? gensInside = null;
        s.Update("k", _ => { inside = t.Names(); gensInside = t.Gens(); return null; });
        // taking 41 collects below 41 - 16 = 25; releasing as 42 collects below 26
        Assert.Equal(new long[] { 25, 26, 40, 41 }, gensInside);
        Assert.Equal(new long[] { 26, 40, 41, 42 }, t.Gens());
        foreach (var f in kept) Assert.Contains(f, inside!);
        foreach (var f in gone) Assert.DoesNotContain(f, inside!);
        foreach (var f in kept) Assert.Contains(f, t.Names());
    }

    // ---- lock-lost before every rename ----

    [Fact]
    public void ANewerGenerationMakesTheJournalWriteLoseTheLock()
    {
        using var t = new Tmp();
        var s = Open(t);
        long g = 0;
        var e = Assert.Throws<DurableStateError>(() => s.Update("a", _ =>
        {
            g = Ds.TopGeneration(t.Dir);
            File.Copy(t.Lock(g), t.Lock(g + 1)); // the same holder record, one generation up
            return "1";
        }));
        Assert.Equal(Lost(g, g + 1, "held", "nothing was written"), e.Message);
        Assert.False(File.Exists(t.P("state.journal")));
    }

    [Fact]
    public void ItsOwnGenerationMarkedFreeMakesTheJournalWriteLoseTheLock()
    {
        using var t = new Tmp();
        var s = Open(t);
        long g = 0;
        var e = Assert.Throws<DurableStateError>(() => s.Update("a", _ =>
        {
            g = Ds.TopGeneration(t.Dir);
            File.WriteAllText(t.Lock(g), File.ReadAllText(t.Lock(g)).Replace("\"st\":\"held\"", "\"st\":\"free\"")); // same nonce
            return "1";
        }));
        Assert.Equal(Lost(g, g, "free", "nothing was written"), e.Message);
    }

    [Fact]
    public void WithNoGenerationLeftTheTopIsUnreadableEvenBesideAStateLockZero()
    {
        using var t = new Tmp();
        var s = Open(t);
        long g = 0;
        var e = Assert.Throws<DurableStateError>(() => s.Update("a", _ =>
        {
            g = Ds.TopGeneration(t.Dir);
            foreach (var n in t.Gens()) File.Delete(t.Lock(n));
            t.Write("state.lock.0", Holder(Pid, "zero")); // generation 0 is no generation: its record is never read
            return "1";
        }));
        Assert.Equal(Lost(g, 0, "unreadable", "nothing was written"), e.Message);
    }

    [Fact]
    public void LosingTheLockAfterTheJournalRenameNamesTheRecordInLimbo()
    {
        using var t = new Tmp();
        var s = Open(t, crashAt: "after-journal-rename");
        long g = 0;
        var prev = DsNative.CrashHalter;
        DsNative.CrashHalter = () => { g = Ds.TopGeneration(t.Dir); File.WriteAllText(t.Lock(g + 1), "{\"st\":\"free\"}"); };
        try
        {
            WithEnv(new() { [DsNative.CrashChildEnv] = "1", ["PCA_DURABLE_TEST"] = null }, () =>
            {
                var e = Assert.Throws<DurableStateError>(() => s.Set("a", "1"));
                Assert.Equal(Lost(g, g + 1, "free", "the journal record (seq 1) was renamed into place but state.head was not written; whether it counts depends on whether operator recovery cut before it (re-read the value)"), e.Message);
            });
        }
        finally { DsNative.CrashHalter = prev; }
        Assert.False(File.Exists(t.P("state.head")));
    }

    // a journal one record ahead of state.head (a writer died between its journal and head renames)
    static (DurableState W, string Head2) Lag(Tmp t)
    {
        var w = Open(t);
        w.Set("a", "1");
        var head1 = t.Read("state.head");
        w.Set("a", "2");
        var head2 = t.Read("state.head");
        t.Write("state.head", head1);
        return (w, head2);
    }

    static string LastH(Tmp t) => (string)J(t.Read("state.journal").Split('\n', StringSplitOptions.RemoveEmptyEntries)[^1])["h"]!;

    [Fact]
    public void AnUpdateRepairsALaggingHeadEvenWhenItChangesNothing()
    {
        using var t = new Tmp();
        var (w, _) = Lag(t);
        w.Update("a", _ => null);
        var head = J(t.Read("state.head"));
        Assert.Equal("2", ((Num)head["seq"]!).Raw);
        Assert.Equal(LastH(t), head["h"]);
        var bytes = t.Read("state.head");
        w.Update("a", _ => null); // up to date: not rewritten (it would carry the new generation)
        Assert.Equal(bytes, t.Read("state.head"));
    }

    [Fact]
    public void AnUpdateWritesAMissingHeadForAOneRecordJournal()
    {
        using var t = new Tmp();
        var w = Open(t);
        w.Set("a", "1");
        File.Delete(t.P("state.head"));
        w.Update("a", _ => null);
        Assert.Equal("1", ((Num)J(t.Read("state.head"))["seq"]!).Raw);
    }

    [Fact]
    public void ASetRepairsALaggingHeadBeforeItsOwnCommit()
    {
        using var t = new Tmp();
        var c = Open(t, crashAt: "after-journal-rename");
        Lag(t);
        WithEnv(new() { [DsNative.CrashChildEnv] = null }, () =>
        {
            var e = Assert.Throws<InvalidOperationException>(() => c.Set("b", "1"));
            Assert.Equal("crash hook fired outside a crash child (after-journal-rename)", e.Message);
        });
        Assert.Equal("2", ((Num)J(t.Read("state.head"))["seq"]!).Raw); // repaired to seq 2 before seq 3 was renamed in
    }

    // the next lock this writer links is not its own record: the generation is right, the nonce is somebody else's
    static Func<string, string, int> Stolen(Func<bool> armed) => (src, dst) =>
    {
        if (IsGenPath(dst) && Held(src) && armed()) { File.WriteAllText(dst, Holder(Pid, "someone-else")); return 0; }
        return DsNative.Link(src, dst);
    };

    [Fact]
    public void AHeadRepairUnderALostLockWritesNothing()
    {
        using var t = new Tmp();
        var (w, _) = Lag(t);
        var head1 = t.Read("state.head");
        var g = Ds.TopGeneration(t.Dir) + 1;
        var armed = true;
        using var rig = new Rig(0) { Link = Stolen(() => { var a = armed; armed = false; return a; }) };
        var e = Assert.Throws<DurableStateError>(() => w.Update("a", _ => null));
        Assert.Equal(Lost(g, g, "held", "nothing was written"), e.Message);
        Assert.Equal(head1, t.Read("state.head"));
    }

    [Fact]
    public void AnOpenTimeHeadRepairUnderALostLockWritesNothing()
    {
        using var t = new Tmp();
        Lag(t);
        var head1 = t.Read("state.head");
        var g = Ds.TopGeneration(t.Dir) + 1;
        var armed = true;
        using var rig = new Rig(0) { Link = Stolen(() => { var a = armed; armed = false; return a; }) };
        var e = Assert.Throws<DurableStateError>(() => Open(t));
        Assert.Equal(Lost(g, g, "held", "nothing was written"), e.Message);
        Assert.Equal(head1, t.Read("state.head"));
    }

    // ---- the public reads ----

    [Fact]
    public void GetAndKeysAdvanceThePosition()
    {
        using var t = new Tmp();
        var a = Open(t);
        var b = Open(t);
        b.Set("x", "1");
        Assert.Equal(0, a.Position().Seq);
        Assert.Equal("1", a.Get("x"));
        Assert.Equal(b.Position(), a.Position());
        b.Set("y", "2");
        Assert.Equal(new[] { "x", "y" }, a.Keys());
        Assert.Equal(b.Position(), a.Position());
        Assert.Equal(2, a.Position().Seq);
    }

    [Fact]
    public void GetAndSetValueCheckTheKeyFirst()
    {
        using var t = new Tmp();
        var s = Open(t, maxValue: 1);
        const string bad = "invalid: key must be 1..256 chars without newlines";
        Assert.Equal(bad, Assert.Throws<DurableStateError>(() => s.Get("")).Message);
        Assert.Equal(bad, Assert.Throws<DurableStateError>(() => s.SetValue("", new Num("12"))).Message); // before the too-large value
        Assert.Equal("too-large: value exceeds maxValueBytes=1", Assert.Throws<DurableStateError>(() => s.SetValue("k", new Num("12"))).Message);
    }
}
