using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// The durable-state store: replays ref-durable-state (the reference's whole scenario traces: commit and compaction bytes, tamper / rollback /
// generation-fence loading, the lock protocol, operator recovery) with every message compared whole, plus the platform-dependent behaviours
// the corpus leaves to each lane (a live holder in this PID namespace, threads sharing a directory, the operation store over a durable store).
public class DurableStateTests
{
    const long Dead = 999999999;
    const string FakeNs = "pid:[4026530001]";

    static Num N(long v) => new(v.ToString(System.Globalization.CultureInfo.InvariantCulture));
    static string Subst(string s, string host) => s.Replace("$HOST", host).Replace("$PID", Environment.ProcessId.ToString()).Replace("$DEAD", Dead.ToString());

    static D Err(DurableStateError e, string dir, string host) => new() { ["err"] = new D { ["code"] = e.Code, ["msg"] = Norm(e.Message, dir, host) } };

    static string Norm(string s, string dir, string host) =>
        s.Replace(dir, "$DIR").Replace("$DIR\\", "$DIR/").Replace(host, "$HOST").Replace("pid=" + Environment.ProcessId, "pid=$PID").Replace("pid " + Environment.ProcessId, "pid $PID");

    static string NormName(string f)
    {
        f = Regex.Replace(f, "^(state\\.fence\\.[0-9]+)-[0-9a-f]+", "$1-*");
        f = Regex.Replace(f, "\\.quarantine-.*$", ".quarantine-*");
        f = Regex.Replace(f, "^state\\.lock\\.legacy-recovered-.*$", "state.lock.legacy-recovered-*");
        return Regex.Replace(f, "^state\\.lock\\.tmp-.*$", "state.lock.tmp-*");
    }

    static string? Read(string dir, string f) { var p = Path.Combine(dir, f); return File.Exists(p) ? Encoding.UTF8.GetString(File.ReadAllBytes(p)) : null; }
    static void Write(string dir, string f, string? text)
    {
        var p = Path.Combine(dir, f);
        if (text == null) { if (File.Exists(p)) File.Delete(p); } else File.WriteAllBytes(p, new UTF8Encoding(false).GetBytes(text));
    }

    static D Snapshot(string dir)
    {
        var names = Directory.GetFileSystemEntries(dir).Select(p => Path.GetFileName(p)!).OrderBy(x => x, StringComparer.Ordinal).ToList();
        var fences = new L();
        void TryFence(string f, Func<object?, IEnumerable<object?>> pick)
        {
            try
            {
                foreach (var x in pick(Pca.ParseJson(Read(dir, f)!)))
                {
                    if (x == null) throw new InvalidOperationException();
                    var r = new D();
                    if (x is D xd) foreach (var kv in xd) { if (kv.Key != "t") r[kv.Key] = kv.Value; }
                    fences.Add(r);
                }
            }
            catch (Exception) { fences.Add(new D { ["unreadable"] = NormName(f) }); }
        }
        if (names.Contains("state.fence")) TryFence("state.fence", x => (L)((D)x!)["fences"]!);
        var entries = names.Where(x => Regex.IsMatch(x, "^state\\.fence\\.[0-9]+-[0-9a-f]+$"))
            .OrderBy(x => long.Parse(x.Split('.')[2].Split('-')[0])).ThenBy(x => x, StringComparer.Ordinal);
        foreach (var f in entries) TryFence(f, x => new L { ((D)x!)["fence"] });
        long g = 0;
        foreach (var f in names) if (Regex.IsMatch(f, "^state\\.lock\\.[0-9]+$")) g = Math.Max(g, long.Parse(f[11..]));
        object? top = null;
        if (g > 0)
        {
            try
            {
                var b = Pca.ParseJson(Read(dir, "state.lock." + g)!);
                var t = new D { ["g"] = N(g) };
                if (b is D bd)
                {
                    if (bd.TryGetValue("st", out var st)) t["st"] = st;
                    if (bd.TryGetValue("recovering", out var rc)) t["recovering"] = rc;
                    if (bd.TryGetValue("recoveredFrom", out var rf)) t["recoveredFrom"] = rf;
                }
                else if (b == null) throw new InvalidOperationException();
                top = t;
            }
            catch (Exception) { top = new D { ["g"] = N(g), ["st"] = "unreadable" }; }
        }
        return new D
        {
            ["t"] = "dir",
            ["files"] = new L(names.Where(f => !f.StartsWith("state.lock.tmp-") && !f.StartsWith("state.probe-") && !Regex.IsMatch(f, "\\.tmp-")).Select(f => (object?)NormName(f))),
            ["journal"] = Read(dir, "state.journal"), ["head"] = Read(dir, "state.head"), ["fences"] = fences, ["top"] = top,
        };
    }

    static object? Substitute(object? v, string host) => v switch
    {
        string s when s == "$HOST" => host,
        string s when s == "$PID" => N(Environment.ProcessId),
        L l => new L(l.Select(x => Substitute(x, host))),
        D m => SubstituteMap(m, host),
        _ => v,
    };

    static D SubstituteMap(D m, string host)
    {
        var r = new D();
        foreach (var kv in m) r[kv.Key] = Substitute(kv.Value, host);
        return r;
    }

    static double Dbl(object? o) => double.Parse(((Num)o!).Raw, System.Globalization.CultureInfo.InvariantCulture);

    static object? ExpectedHolder(object? v) =>
        v is string s ? s
        : v is D m && m.GetValueOrDefault("host") is string h && m.GetValueOrDefault("pid") is Num p && m.GetValueOrDefault("nonce") is string n ? new ExpectedLockHolder(h, Dbl(p), n)
        : v ?? new object();

    static D Open(D st, string dir, string host)
    {
        long c = 1000;
        var op = (D?)st.GetValueOrDefault("opts") ?? new D();
        var o = new DurableStateOptions { Dir = op.ContainsKey("dir") ? (string)op["dir"]! : dir, Now = () => c++ };
        if (op.GetValueOrDefault("hmacKey") is string label) o.HmacKey = SHA256.HashData(Encoding.UTF8.GetBytes(label));
        if (op.GetValueOrDefault("hmacKeyBytes") is Num kb) o.HmacKey = new byte[(int)Dbl(kb)];
        if (op.GetValueOrDefault("recoverFromCorruption") is bool rf) o.RecoverFromCorruption = rf;
        if (op.GetValueOrDefault("lockTimeoutMs") is Num lt) o.LockTimeoutMs = (long)Dbl(lt);
        if (op.GetValueOrDefault("compactEvery") is Num ce) o.CompactEvery = (long)Dbl(ce);
        if (op.GetValueOrDefault("maxValueBytes") is Num mv) o.MaxValueBytes = (long)Dbl(mv);
        DurableState h;
        try { h = Pca.OpenDurableState(o); }
        catch (DurableStateError e) { return Err(e, dir, host); }
        var res = new L();
        var saved = new Dictionary<string, (string?, string?)>();
        foreach (var x in ((L?)st.GetValueOrDefault("ops") ?? new L()).Cast<D>())
        {
            try
            {
                object? v;
                var key = x.GetValueOrDefault("key") as string ?? "";
                switch ((string)x["op"]!)
                {
                    case "set": h.SetValue(key, x["value"]); v = null; break;
                    case "get": v = h.GetValue(key); break;
                    case "keys": v = new L(h.Keys().Select(k => (object?)k)); break;
                    case "verify": case "position":
                        var p = (string)x["op"]! == "verify" ? h.Verify() : h.Position();
                        v = new D { ["seq"] = N(p.Seq), ["hash"] = p.Hash }; break;
                    case "update":
                        var arg = x.GetValueOrDefault("arg");
                        v = h.UpdateValue(key, prev => (string)x["kind"]! switch
                        {
                            "append" => new L((prev is L pl ? pl : new L()).Append(arg)),
                            "max" => ReferenceEquals(prev, DurableState.Undefined) || Dbl(arg) > Dbl(prev) ? arg : DurableState.Undefined,
                            "noop" => DurableState.Undefined,
                            "same" => prev,
                            _ => arg,
                        });
                        break;
                    case "fs": Write(dir, (string)x["file"]!, x["text"] is string tx ? Subst(tx, host) : null); v = null; break;
                    case "save": saved[(string)x["name"]!] = (Read(dir, "state.journal"), Read(dir, "state.head")); v = null; break;
                    case "restore": { var (j, hd) = saved[(string)x["name"]!]; Write(dir, "state.journal", j); Write(dir, "state.head", hd); v = null; break; }
                    default: throw new InvalidOperationException("unknown op");
                }
                res.Add(new D { ["ok"] = ReferenceEquals(v, DurableState.Undefined) ? new D { ["$undef"] = true } : v });
            }
            catch (DurableStateError e) { res.Add(Err(e, dir, host)); }
        }
        return new D { ["ok"] = new D { ["recovered"] = h.Recovered, ["ops"] = res } };
    }

    static D Recover(D st, string dir, string host)
    {
        var opts = (D)Substitute(st["opts"], host)!;
        try
        {
            var r = Pca.RecoverDurableState(new RecoverDurableStateOptions
            {
                Dir = dir,
                Force = !opts.ContainsKey("force") || opts["force"] is true,
                ExpectedHolder = ExpectedHolder(opts.GetValueOrDefault("expectedHolder")),
                LegacyLock = opts.GetValueOrDefault("legacyLock") is true,
            });
            var ok = new D { ["released"] = r.Released, ["reason"] = r.Reason };
            if (r.LockFile != null) ok["lockFile"] = Norm(r.LockFile, dir, host);
            return new D { ["ok"] = ok };
        }
        catch (DurableStateError e) { return Err(e, dir, host); }
    }

    static L Scenario(D sc)
    {
        var dir = Directory.CreateTempSubdirectory("pca-ds-oracle-").FullName;
        var host = System.Net.Dns.GetHostName();
        var o = new L();
        try
        {
            if (sc.GetValueOrDefault("files") is D files) foreach (var kv in files) Write(dir, kv.Key, Subst((string)kv.Value!, host));
            foreach (var st in ((L)sc["steps"]!).Cast<D>())
            {
                switch ((string)st["t"]!)
                {
                    case "write": Write(dir, (string)st["file"]!, st["text"] is string tx ? Subst(tx, host) : null); o.Add(null); break;
                    case "dir": o.Add(Snapshot(dir)); break;
                    case "recover": o.Add(Recover(st, dir, host)); break;
                    case "open": o.Add(Open(st, dir, host)); break;
                    default: throw new InvalidOperationException("unknown step");
                }
            }
            o.Add(Snapshot(dir));
            return o;
        }
        finally { try { Directory.Delete(dir, true); } catch (Exception) { /* best effort */ } }
    }

    [Fact]
    public void ReplaysTheReferenceScenarioTraces()
    {
        var cases = Base.Cases("ref-durable-state");
        Assert.Equal(232, cases.Count);
        Base.Covers("ref-durable-state", new[] { "scenario" });
        var bad = new List<string>();
        foreach (var c in cases)
        {
            var got = Scenario((D)((L)c["args"]!)[0]!);
            if (!Base.Eq(c["out"], got)) bad.Add((string)c["name"]!);
        }
        Assert.True(bad.Count == 0, "scenarios differing from the reference: " + string.Join(", ", bad));
    }

    static string NewDir() => Directory.CreateTempSubdirectory("pca-ds-").FullName;

    [Fact]
    public void ValuesSurviveAReopenAndAnUnchangedValueDoesNotCommit()
    {
        var dir = NewDir();
        var a = Pca.OpenDurableState(new DurableStateOptions { Dir = dir });
        a.Set("k", "{\"a\":[1,2]}");
        Assert.Equal("{\"a\":[1,2]}", Pca.OpenDurableState(new DurableStateOptions { Dir = dir }).Get("k"));
        var seq = a.Verify().Seq;
        a.Update("k", cur => cur);
        a.Update("k", cur => "{\"a\":[1,2]}");
        Assert.Equal(seq, a.Verify().Seq);
        Assert.Equal(new[] { "k" }, a.Keys());
        Assert.Null(a.Get("zz"));
    }

    [Fact]
    public void TwoHandlesOnOneDirectoryNeverLoseAnUpdate()
    {
        var dir = NewDir();
        var hs = Enumerable.Range(0, 3).Select(_ => Pca.OpenDurableState(new DurableStateOptions { Dir = dir, LockTimeoutMs = 15_000 })).ToList();
        var errs = new System.Collections.Concurrent.ConcurrentQueue<Exception>();
        // a thread hands its failure back to the test thread (an exception escaping a thread would crash the test host)
        var ts = hs.Select(h => new Thread(() =>
        {
            try { for (var i = 0; i < 8; i++) h.Update("n", cur => ((cur == null ? 0 : int.Parse(cur)) + 1).ToString()); }
            catch (Exception e) { errs.Enqueue(e); }
        })).ToList();
        ts.ForEach(t => t.Start());
        ts.ForEach(t => t.Join());
        Assert.Empty(errs);
        Assert.Equal("24", hs[0].Get("n"));
    }

    [Fact]
    public void ALiveHolderBlocksUntilTheTimeoutAndADeadOneIsTakenOver()
    {
        var dir = NewDir();
        Pca.OpenDurableState(new DurableStateOptions { Dir = dir }).Set("a", "1");
        var g = Directory.GetFileSystemEntries(dir).Select(Path.GetFileName).Where(f => Regex.IsMatch(f!, "^state\\.lock\\.[0-9]+$")).Select(f => int.Parse(f![11..])).Max();
        var host = System.Net.Dns.GetHostName();
        File.WriteAllText(Path.Combine(dir, "state.lock." + (g + 1)), "{\"st\":\"held\",\"pid\":" + Environment.ProcessId + ",\"host\":\"" + host + "\",\"nonce\":\"n1\"}");
        var e = Assert.Throws<DurableStateError>(() => Pca.OpenDurableState(new DurableStateOptions { Dir = dir, LockTimeoutMs = 100 }));
        Assert.Equal("lock-timeout", e.Code);
        File.WriteAllText(Path.Combine(dir, "state.lock." + (g + 2)), "{\"st\":\"held\",\"pid\":" + Dead + ",\"host\":\"" + host + "\",\"nonce\":\"n2\"}");
        Assert.Equal("1", Pca.OpenDurableState(new DurableStateOptions { Dir = dir, LockTimeoutMs = 2000 }).Get("a"));
    }

    [Fact]
    public void TheOperationStoreRunsOverADurableStore()
    {
        var dir = NewDir();
        var store = new KvOperationStore(Pca.OpenDurableState(new DurableStateOptions { Dir = dir }));
        var rec = new OperationRecord("op-1", OperationStates.Pending, "pay", "r/1", "dg", "irreversible", 1);
        Assert.True(store.Create(rec).Created);
        Assert.False(new KvOperationStore(Pca.OpenDurableState(new DurableStateOptions { Dir = dir })).Create(rec).Created);
        Assert.Equal("op-1", new KvOperationStore(Pca.OpenDurableState(new DurableStateOptions { Dir = dir })).Get("op-1")!.Id);
    }

    // Arms a commit hook in this (non-child) test host with the kill replaced by a recorder; returns the points the halter was called at.
    static List<string> FireHook(string point, bool asChild)
    {
        var halted = new List<string>();
        var prev = DsNative.CrashHalter;
        var prevEnv = Environment.GetEnvironmentVariable(DsNative.CrashChildEnv);
        DsNative.CrashHalter = () => { halted.Add(point); throw new InvalidOperationException("halted"); };
        try
        {
            Environment.SetEnvironmentVariable(DsNative.CrashChildEnv, asChild ? "1" : null);
            var s = Pca.OpenDurableState(new DurableStateOptions { Dir = NewDir(), TestCrashAt = point });
            var e = Assert.Throws<InvalidOperationException>(() => s.Set("a", "1"));
            Assert.Equal(asChild ? "halted" : "crash hook fired outside a crash child (" + point + ")", e.Message);
        }
        finally
        {
            DsNative.CrashHalter = prev;
            Environment.SetEnvironmentVariable(DsNative.CrashChildEnv, prevEnv);
        }
        return halted;
    }

    [Fact]
    public void ACrashHookOutsideACrashChildThrowsInsteadOfKillingTheProcess()
    {
        foreach (var point in new[] { "after-temp-write", "after-journal-rename" }) Assert.Empty(FireHook(point, false));
    }

    [Fact]
    public void ACrashHookInACrashChildKills()
    {
        foreach (var point in new[] { "after-temp-write", "after-journal-rename" }) Assert.Equal(new[] { point }, FireHook(point, true));
    }

    [Fact]
    public void TheMemoryStoreHasTheSameInterface()
    {
        var m = Pca.CreateMemoryDurableKv();
        m.SetValue("b", new Num("1"));
        Assert.True(ReferenceEquals(DurableState.Undefined, m.UpdateValue("zz", _ => DurableState.Undefined)));
        Assert.Equal("2", ((Num)m.UpdateValue("b", p => new Num((Dbl(p) + 1).ToString())))!.Raw);
        m.Update("a", _ => "[]");
        Assert.Equal(new[] { "a", "b" }, m.Keys());
        Assert.Equal(2, m.Snapshot().Count);
    }
}
