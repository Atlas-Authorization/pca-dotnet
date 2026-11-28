using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca;
using AtlasPca.Js;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// The journal load, record by record: hand-written journals, heads and fences (hashes and MACs computed here the way the format defines them)
// pin every check of the load with its exact error, plus the open-time head repair, the value encoders and operator-free quarantine.
public class DurableStateTestsJournal
{
    static readonly string G0 = Ds.Genesis;
    static readonly string Other = new('a', 64);
    static readonly byte[] Key = Enumerable.Repeat((byte)7, 32).ToArray();

    sealed class Tmp : IDisposable
    {
        public readonly string Dir = Directory.CreateTempSubdirectory("pca-dsj-").FullName;
        public string P(string f) => Path.Combine(Dir, f);
        public void Write(string f, string text) => File.WriteAllBytes(P(f), new UTF8Encoding(false).GetBytes(text));
        public string? Read(string f) => File.Exists(P(f)) ? Encoding.UTF8.GetString(File.ReadAllBytes(P(f))) : null;
        public List<string> Names() => Directory.GetFileSystemEntries(Dir).Select(p => Path.GetFileName(p)!)
            .Where(n => !n.StartsWith("state.lock.", StringComparison.Ordinal)).OrderBy(n => n, StringComparer.Ordinal).ToList();
        public void Dispose() { try { Directory.Delete(Dir, true); } catch (Exception) { /* best effort */ } }
    }

    sealed class R
    {
        public long Seq; public string Prev = ""; public string Op = "set"; public string Payload = ""; public long Ts = 7; public long? Gen; public string H = ""; public string? Mac;

        public string Json()
        {
            var d = new D { ["seq"] = Seq, ["prev"] = Prev, ["op"] = Op, ["payload"] = Payload, ["ts"] = Ts };
            if (Gen != null) d["gen"] = Gen.Value;
            d["h"] = H;
            if (Mac != null) d["mac"] = Mac;
            return JsJson.Stringify(d);
        }
    }

    // the record hash: sha256(domain + JSON [seq, prev, op, payload, ts(, gen)])
    static string Hash(long seq, string prev, string op, string payload, long ts, long? gen)
    {
        var arr = new L { seq, prev, op, payload, ts };
        if (gen != null) arr.Add(gen.Value);
        return Ds.Sha(Ds.Domain + JsJson.Stringify(arr));
    }

    static string Mac(string msg) => Convert.ToHexString(HMACSHA256.HashData(Key, Encoding.UTF8.GetBytes(msg))).ToLowerInvariant();

    static R Mk(long seq, string prev, string payload, long? gen = null, string op = "set", bool mac = false)
    {
        var r = new R { Seq = seq, Prev = prev, Op = op, Payload = payload, Gen = gen };
        r.H = Hash(seq, prev, op, payload, r.Ts, gen);
        if (mac) r.Mac = Mac(r.H);
        return r;
    }

    // records seq 1..n chained from genesis, record i sets k to i; gens[i] is record i's generation (null: none)
    static List<R> Chain(int n, long?[]? gens = null, bool mac = false)
    {
        var res = new List<R>();
        var prev = G0;
        for (var i = 0; i < n; i++)
        {
            var r = Mk(i + 1, prev, "k\n" + (i + 1), gens?[i], "set", mac);
            res.Add(r);
            prev = r.H;
        }
        return res;
    }

    static string Lines(IEnumerable<string> ls) => string.Concat(ls.Select(l => l + "\n"));
    static void Journal(Tmp t, IEnumerable<R> recs) => t.Write("state.journal", Lines(recs.Select(r => r.Json())));

    static string HeadJson(long seq, string h, long? gen = null, string? mac = null)
    {
        var d = new D { ["seq"] = seq, ["h"] = h };
        if (gen != null) d["gen"] = gen.Value;
        if (mac != null) d["mac"] = mac;
        return JsJson.Stringify(d) + "\n";
    }

    static void Head(Tmp t, long seq, string h, long? gen = null, string? mac = null) => t.Write("state.head", HeadJson(seq, h, gen, mac));

    static void Fences(Tmp t, params (long Gen, long Seq, string H)[] fs) =>
        t.Write("state.fence", JsJson.Stringify(new D { ["v"] = 1L, ["fences"] = new L(fs.Select(f => (object?)new D { ["gen"] = f.Gen, ["seq"] = f.Seq, ["h"] = f.H })) }) + "\n");

    static DurableState Open(Tmp t, bool key = false, bool recover = false, Func<long>? now = null) =>
        Pca.OpenDurableState(new DurableStateOptions { Dir = t.Dir, HmacKey = key ? Key : null, RecoverFromCorruption = recover, Now = now, LockTimeoutMs = 5000 });

    static void Fails(Tmp t, string expected, bool key = false)
    {
        var e = Assert.Throws<DurableStateError>(() => Open(t, key));
        Assert.Equal(expected, e.Message);
    }

    // ---- reading a line ----

    [Fact]
    public void ALineThatIsNotJsonIsNamedByItsNumber()
    {
        using var t = new Tmp();
        t.Write("state.journal", Lines(new[] { Chain(1)[0].Json(), "{" }));
        Fails(t, "corrupt: journal line 2 is not valid JSON");
        t.Write("state.journal", "\n");
        Fails(t, "corrupt: journal line 1 is not valid JSON");
    }

    [Fact]
    public void EveryMalformedFieldOfARecordIsAnInvalidShape()
    {
        var c = Chain(2);
        var s = c[1].Json();
        string Field(string name, string raw) => Regex.Replace(s, "\"" + name + "\":(\"[^\"]*\"|[0-9]+)", "\"" + name + "\":" + raw);
        string Drop(string name) => Regex.Replace(s, "\"" + name + "\":(\"[^\"]*\"|[0-9]+),?", "");
        var withGen = s.Replace("\"ts\":7,", "\"ts\":7,\"gen\":GEN,");
        var bad = new Dictionary<string, string>
        {
            ["array"] = "[1]", ["null"] = "null", ["number"] = "1", ["string"] = "\"x\"",
            ["seq string"] = Field("seq", "\"2\""), ["seq fraction"] = Field("seq", "2.5"), ["seq absent"] = Drop("seq"),
            ["prev upper"] = Field("prev", "\"" + c[1].Prev.ToUpperInvariant() + "\""), ["prev short"] = Field("prev", "\"" + c[1].Prev[1..] + "\""), ["prev absent"] = Drop("prev"),
            ["op absent"] = Drop("op"), ["op other"] = Field("op", "\"del\""), ["op case"] = Field("op", "\"Set\""), ["op number"] = Field("op", "1"),
            ["payload absent"] = s.Replace("\"payload\":\"k\\n2\",", ""), ["payload number"] = s.Replace("\"payload\":\"k\\n2\"", "\"payload\":5"),
            ["ts string"] = Field("ts", "\"7\""), ["ts fraction"] = Field("ts", "7.5"), ["ts negative zero"] = Field("ts", "-0"), ["ts absent"] = Drop("ts"),
            ["h upper"] = Field("h", "\"" + c[1].H.ToUpperInvariant() + "\""), ["h absent"] = s.Replace(",\"h\":\"" + c[1].H + "\"", ""), ["h number"] = Field("h", "1"),
            ["gen zero"] = withGen.Replace("GEN", "0"), ["gen negative"] = withGen.Replace("GEN", "-1"), ["gen string"] = withGen.Replace("GEN", "\"1\""), ["gen fraction"] = withGen.Replace("GEN", "1.5"),
        };
        using var t = new Tmp();
        foreach (var (name, line) in bad)
        {
            Assert.NotEqual(s, line);
            t.Write("state.journal", Lines(new[] { c[0].Json(), line }));
            var e = Assert.Throws<DurableStateError>(() => Open(t));
            Assert.True(e.Message == "corrupt: journal line 2 has an invalid shape", name + ": " + e.Message);
        }
        // the same record with valid fields loads (a generation is part of the hash, so a parsed one must be carried exactly)
        var g = Chain(2, new long?[] { 5, 6 });
        Journal(t, g);
        Head(t, 2, g[1].H, 6);
        var st = Open(t);
        Assert.Equal("2", st.Get("k"));
        Assert.Equal((2L, g[1].H), st.Position());
    }

    // ---- one record against its predecessor ----

    [Fact]
    public void TheFirstRecordStartsAtGenesisOrIsACheckpoint()
    {
        using var t = new Tmp();
        Journal(t, new[] { Mk(2, G0, "k\n1") });
        Fails(t, "corrupt: journal does not start at genesis");
        Journal(t, new[] { Mk(1, Other, "k\n1") });
        Fails(t, "corrupt: journal does not start at genesis");
        Journal(t, new[] { Mk(0, Other, "[]", null, "checkpoint") });
        Fails(t, "corrupt: bad checkpoint seq");
        Journal(t, new[] { Mk(1, Other, "[[\"a\",\"1\"]]", null, "checkpoint") });
        Assert.Equal("1", Open(t).Get("a"));
        File.Delete(t.P("state.head"));
        var cp = Mk(5, Other, "[[\"a\",\"2\"]]", null, "checkpoint");
        Journal(t, new[] { cp });
        Head(t, 5, cp.H);
        var s = Open(t);
        Assert.Equal("2", s.Get("a"));
        Assert.Equal((5L, cp.H), s.Position());
    }

    [Fact]
    public void ALaterRecordContinuesTheSequenceAndTheHashChain()
    {
        using var t = new Tmp();
        var c = Chain(1);
        Journal(t, new[] { c[0], Mk(3, c[0].H, "k\n2") });
        Fails(t, "corrupt: journal line 2: sequence gap");
        Journal(t, new[] { c[0], Mk(1, c[0].H, "k\n2") });
        Fails(t, "corrupt: journal line 2: sequence gap");
        Journal(t, new[] { c[0], Mk(2, Other, "k\n2") });
        Fails(t, "corrupt: journal line 2: hash chain broken");
        var ok = Chain(3);
        Journal(t, ok);
        Head(t, 3, ok[2].H);
        var s = Open(t);
        Assert.Equal("3", s.Get("k"));
        Assert.Equal((3L, ok[2].H), s.Position());
    }

    [Fact]
    public void AnEditedRecordFailsItsHash()
    {
        using var t = new Tmp();
        foreach (var edit in new Action<R>[] { r => r.H = Ds.Sha("edited"), r => r.Ts = 8, r => r.Gen = 1, r => r.Payload = "k\n9" })
        {
            var c = Chain(2);
            edit(c[1]);
            Journal(t, c);
            Fails(t, "corrupt: journal line 2: record hash mismatch (edited)");
        }
    }

    [Fact]
    public void WithAKeyEveryRecordCarriesItsMacAndWithoutOneNoneMay()
    {
        using var t = new Tmp();
        var c = Chain(2, null, true);
        Journal(t, c);
        Head(t, 2, c[1].H, null, Mac("head\n2\n" + c[1].H));
        Assert.Equal("2", Open(t, key: true).Get("k"));
        File.Delete(t.P("state.head"));
        foreach (var mac in new string?[] { null, "00", Mac(c[1].H + "x") })
        {
            var b = Chain(2, null, true);
            b[1].Mac = mac;
            Journal(t, b);
            Fails(t, "key-mismatch: journal line 2: MAC does not verify (wrong key or forged record)", key: true);
        }
        Journal(t, c);
        Fails(t, "key-mismatch: journal is MAC-tagged but no hmacKey was supplied");
    }

    [Fact]
    public void GenerationsNeverDecreaseAlongTheChain()
    {
        using var t = new Tmp();
        Journal(t, Chain(2, new long?[] { 3, 2 }));
        Fails(t, "corrupt: journal line 2 (seq 2) was written by lock generation 2, older than generation 3 of an earlier record: a stale writer's record (refused)");
        Journal(t, Chain(2, new long?[] { 3, null }));
        Fails(t, "corrupt: journal line 2 (seq 2) was written by lock generation 0, older than generation 3 of an earlier record: a stale writer's record (refused)");
        var ok = Chain(3, new long?[] { 2, 2, 3 });
        Journal(t, ok);
        Head(t, 3, ok[2].H, 3);
        Assert.Equal("3", Open(t).Get("k"));
    }

    [Fact]
    public void ARecordAfterARecoveryCutFromAFencedGenerationIsRefused()
    {
        using var t = new Tmp();
        var c = Chain(2, new long?[] { 1, 3 });
        Journal(t, c);
        Fences(t, (1, 0, G0), (4, 1, c[0].H));
        Head(t, 2, c[1].H, 3);
        Fails(t, "corrupt: journal line 2 (seq 2) was written by lock generation 3, but operator recovery fenced generations below 4 after seq 1: a holder paused across recoverDurableState resumed and replaced the journal late (refused; records committed after the recovery may be lost; recoverFromCorruption quarantines the files)");
        // the fenced generation itself may write after the cut
        var ok = Chain(2, new long?[] { 1, 4 });
        Journal(t, ok);
        Fences(t, (4, 1, ok[0].H));
        Head(t, 2, ok[1].H, 4);
        Assert.Equal("2", Open(t).Get("k"));
        // a low generation AT the cut is the record the operator saw
        var one = Chain(1, new long?[] { 1 });
        Journal(t, one);
        Fences(t, (4, 1, one[0].H));
        Head(t, 1, one[0].H, 1);
        Assert.Equal("1", Open(t).Get("k"));
    }

    // ---- applying a record ----

    [Fact]
    public void ACheckpointReplacesTheWholeState()
    {
        using var t = new Tmp();
        var a = Mk(1, G0, "a\n1");
        var cp = Mk(2, a.H, "[[\"b\",\"2\"],[\"c\",\"3\"]]", null, "checkpoint");
        Journal(t, new[] { a, cp });
        Head(t, 2, cp.H);
        var s = Open(t);
        Assert.Equal(new[] { "b", "c" }, s.Keys());
        Assert.Equal("2", s.Get("b"));
        Assert.Null(s.Get("a"));
    }

    [Fact]
    public void AMalformedCheckpointIsCorrupt()
    {
        using var t = new Tmp();
        void Cp(string payload, string expected)
        {
            Journal(t, new[] { Mk(1, Other, payload, null, "checkpoint") });
            var e = Assert.Throws<DurableStateError>(() => Open(t));
            Assert.True(e.Message == expected, payload + ": " + e.Message);
        }
        Cp("{", "corrupt: checkpoint payload is not JSON");
        Cp("{}", "corrupt: checkpoint payload is not an array");
        Cp("\"x\"", "corrupt: checkpoint payload is not an array");
        foreach (var p in new[] { "[[\"a\"]]", "[[\"a\",\"b\",\"c\"]]", "[[1,\"b\"]]", "[[\"a\",2]]", "[\"x\"]", "[null]", "[[\"a\",\"1\"],[]]" })
            Cp(p, "corrupt: checkpoint entry is malformed");
    }

    [Fact]
    public void ASetPayloadIsKeyNewlineValueSplitAtTheFirstNewline()
    {
        using var t = new Tmp();
        var z = Mk(1, G0, "z\n0");
        foreach (var p in new[] { "kv", "\nv" })
        {
            Journal(t, new[] { z, Mk(2, z.H, p) });
            Fails(t, "corrupt: journal line 2: malformed payload");
        }
        foreach (var (p, key, value) in new[] { ("k\nv", "k", "v"), ("ab\nx\ny", "ab", "x\ny"), ("ab\n", "ab", "") })
        {
            var r = Mk(2, z.H, p);
            Journal(t, new[] { z, r });
            Head(t, 2, r.H);
            var s = Open(t);
            Assert.Equal(value, s.Get(key));
            Assert.Equal(new[] { key, "z" }.OrderBy(x => x, StringComparer.Ordinal).ToArray(), s.Keys());
        }
    }

    // ---- the journal file ----

    [Fact]
    public void AJournalMustEndWithANewlineAndMayBeEmpty()
    {
        using var t = new Tmp();
        t.Write("state.journal", Chain(1)[0].Json());
        Fails(t, "corrupt: journal does not end with a newline (torn or truncated)");
        t.Write("state.journal", "");
        var s = Open(t);
        Assert.Empty(s.Keys());
        Assert.Equal((0L, G0), s.Position());
        Assert.Null(t.Read("state.head"));
    }

    [Fact]
    public void AMissingJournalIsOnlyAFreshDirectory()
    {
        using var t = new Tmp();
        Head(t, 3, Other);
        Fails(t, "rollback: state.journal is missing but state.head records seq 3");
        Head(t, 0, G0);
        Assert.Empty(Open(t).Keys());
        Assert.Equal(HeadJson(0, G0), t.Read("state.head"));
        File.Delete(t.P("state.head"));
        Fences(t, (2, 0, G0), (3, 2, Other));
        Fails(t, "rollback: state.journal is missing but operator recovery cut it at seq 2");
        Fences(t, (2, 0, G0));
        Assert.Empty(Open(t).Keys());
    }

    // ---- the tail against fences, the head and what this handle saw ----

    [Fact]
    public void TheJournalMustReachAndKeepEveryRecoveryCut()
    {
        using var t = new Tmp();
        var one = Chain(1, new long?[] { 1 });
        Journal(t, one);
        Fences(t, (2, 2, Other));
        Head(t, 1, one[0].H, 1);
        Fails(t, "rollback: journal is at seq 1 but operator recovery cut it at seq 2 (truncation, or a stale writer replaced it)");

        var c = Chain(2, new long?[] { 1, 1 });
        Journal(t, c);
        Fences(t, (2, 2, c[1].H));
        Head(t, 2, c[1].H, 1);
        Assert.Equal("2", Open(t).Get("k"));

        var d = Chain(2, new long?[] { 1, 2 });
        Journal(t, d);
        Fences(t, (2, 1, d[0].H));
        Head(t, 2, d[1].H, 2);
        Assert.Equal("2", Open(t).Get("k"));
        Fences(t, (2, 1, Other));
        Fails(t, "corrupt: journal record at seq 1 is not the record operator recovery cut at: a stale writer replaced the journal (refused; recoverFromCorruption quarantines the files)");

        // compacted past the cut: no record at the cut's seq is left to compare
        var cp = Mk(3, Other, "[[\"a\",\"1\"]]", 2, "checkpoint");
        Journal(t, new[] { cp });
        Head(t, 3, cp.H, 2);
        Assert.Equal("1", Open(t).Get("a"));
    }

    [Fact]
    public void TheJournalMustReachTheHead()
    {
        using var t = new Tmp();
        Journal(t, Chain(1));
        Head(t, 2, Other);
        Fails(t, "rollback: journal is at seq 1 but state.head recorded seq 2 (truncation or older copy)");
    }

    [Fact]
    public void ATailFromAGenerationOlderThanTheHeadIsAStaleWriter()
    {
        using var t = new Tmp();
        var c = Chain(2, new long?[] { 1, 1 });
        Journal(t, c);
        const string stale = "corrupt: journal tail (seq 2) was written by lock generation 1, older than generation 2 that wrote state.head: a stale writer replaced the journal (refused)";
        Head(t, 1, c[0].H, 2);
        Fails(t, stale);
        Head(t, 2, Other, 2);
        Fails(t, stale);
        Head(t, 2, Other, 1);
        Fails(t, "corrupt: journal tail does not match state.head");
        Head(t, 1, Other, 1);
        Fails(t, "corrupt: journal tail is not chained from state.head");
        // a newer generation's head at exactly the tail is a repair, not a stale write
        Head(t, 2, c[1].H, 2);
        Assert.Equal("2", Open(t).Get("k"));
        Assert.Equal(HeadJson(2, c[1].H, 2), t.Read("state.head"));
    }

    [Fact]
    public void AHeadOneRecordBehindIsRepairedAtOpen()
    {
        using var t = new Tmp();
        var c = Chain(2, new long?[] { 2, 2 });
        Journal(t, c);
        Head(t, 1, c[0].H, 2);
        var s = Open(t);
        Assert.Equal((2L, c[1].H), s.Position());
        Assert.Equal(HeadJson(2, c[1].H, 1), t.Read("state.head")); // written by this open's lock generation (1)
        var n = Chain(2);
        Journal(t, n);
        Head(t, 1, n[0].H);
        Assert.Equal("2", Open(t).Get("k"));
    }

    [Fact]
    public void AMissingHeadIsOnlyAllowedAtTheFirstRecordAndIsWrittenAtOpen()
    {
        using var t = new Tmp();
        var c = Chain(2);
        Journal(t, c);
        Fails(t, "rollback: state.head is missing but the journal is at seq 2");
        Journal(t, c.Take(1));
        var s = Open(t);
        Assert.Equal((1L, c[0].H), s.Position());
        Assert.Equal(HeadJson(1, c[0].H, 3), t.Read("state.head")); // the failed open above took lock generation 1 and released at 2
        // a current head is left alone
        Head(t, 1, c[0].H);
        Assert.Equal("1", Open(t).Get("k"));
        Assert.Equal(HeadJson(1, c[0].H), t.Read("state.head"));
    }

    // a holder paused between its journal rename and its head rename, resumed after recovery: its late head is tolerated
    static List<R> StaleHeadJournal(Tmp t, int n = 4, long?[]? gens = null, long fenceSeq = 2)
    {
        var c = Chain(n, gens ?? new long?[] { 1, 1, 3, 3 });
        Journal(t, c);
        Fences(t, (3, fenceSeq, c[(int)fenceSeq - 1].H));
        return c;
    }

    [Fact]
    public void ALateHeadOfAFencedGenerationIsTolerated()
    {
        using var t = new Tmp();
        var c = StaleHeadJournal(t);
        Head(t, 2, c[1].H, 1);
        var s = Open(t);
        Assert.Equal((4L, c[3].H), s.Position());
        Assert.Equal(HeadJson(4, c[3].H, 1), t.Read("state.head"));
    }

    [Fact]
    public void AnyOtherHeadMoreThanOneRecordBehindIsCorrupt()
    {
        using var t = new Tmp();
        const string ahead42 = "corrupt: journal (seq 4) is more than one record ahead of state.head (seq 2)";
        // no fence
        var c = Chain(4, new long?[] { 1, 1, 3, 3 });
        Journal(t, c);
        Head(t, 2, c[1].H, 1);
        Fails(t, ahead42);
        // the head's generation is not below the fence's
        c = StaleHeadJournal(t);
        Head(t, 2, c[1].H, 3);
        Fails(t, ahead42);
        // the head is past the cut
        c = StaleHeadJournal(t, 5, new long?[] { 1, 1, 3, 3, 3 });
        Head(t, 3, c[2].H, 1);
        Fails(t, "corrupt: journal (seq 5) is more than one record ahead of state.head (seq 3)");
        // nothing after the cut
        c = StaleHeadJournal(t, 4, new long?[] { 1, 1, 1, 1 }, 4);
        Head(t, 2, c[1].H, 1);
        Fails(t, ahead42);
        // the head names no record of the journal
        StaleHeadJournal(t);
        Head(t, 2, Other, 1);
        Fails(t, ahead42);
    }

    [Fact]
    public void AnOpenHandleRefusesStateThatMovedBackwardsForkedOrVanished()
    {
        using var t = new Tmp();
        var h = Open(t);
        Assert.Null(h.Get("a"));
        h.Set("a", "1");
        var (j1, h1) = (t.Read("state.journal")!, t.Read("state.head")!);
        h.Set("a", "2");
        t.Write("state.journal", j1);
        t.Write("state.head", h1);
        var e = Assert.Throws<DurableStateError>(() => h.Get("a"));
        Assert.Equal("rollback: state moved backwards from seq 2 to 1 while open", e.Message);

        var f = Open(t);
        var c = Chain(1);
        Journal(t, c);
        Head(t, 1, c[0].H);
        e = Assert.Throws<DurableStateError>(() => f.Get("a"));
        Assert.Equal("rollback: state forked at seq 1 while open", e.Message);

        t.Write("state.journal", "");
        File.Delete(t.P("state.head"));
        e = Assert.Throws<DurableStateError>(() => f.Get("a"));
        Assert.Equal("rollback: state was emptied while open", e.Message);

        File.Delete(t.P("state.journal"));
        e = Assert.Throws<DurableStateError>(() => f.Keys());
        Assert.Equal("rollback: state was deleted while open", e.Message);
    }

    [Fact]
    public void AnOpenHandleFollowsAnotherWriter()
    {
        using var t = new Tmp();
        var a = Open(t);
        var b = Open(t);
        b.Set("k", "1");
        Assert.Equal("1", a.Get("k"));
        Assert.Equal(b.Position(), a.Position());
        Assert.Equal(1L, a.Position().Seq);
    }

    // ---- state.head ----

    [Fact]
    public void TheHeadMacCoversSeqHashAndGeneration()
    {
        using var t = new Tmp();
        var c = Chain(1, null, true);
        Journal(t, c);
        var h = c[0].H;
        Head(t, 1, h, null, Mac("head\n1\n" + h));
        Assert.Equal("1", Open(t, key: true).Get("k"));
        Head(t, 1, h, 2, Mac("head\n1\n" + h + "\n2"));
        Assert.Equal("1", Open(t, key: true).Get("k"));
        foreach (var bad in new[] { HeadJson(1, h, 2, Mac("head\n1\n" + h)), HeadJson(1, h, null, Mac("head\n1\n" + h + "\n2")), HeadJson(1, h), HeadJson(1, h, null, "00"), HeadJson(1, h, 2, Mac("head\n1\n" + h + "\n3")) })
        {
            t.Write("state.head", bad);
            Fails(t, "key-mismatch: state.head MAC does not verify (wrong key or forged head)", key: true);
        }
    }

    [Fact]
    public void AMalformedHeadIsCorrupt()
    {
        using var t = new Tmp();
        t.Write("state.head", "{");
        Fails(t, "corrupt: state.head is not valid JSON");
        var ok = HeadJson(0, G0);
        foreach (var bad in new[] { "[]", "null", "{\"h\":\"" + G0 + "\"}", ok.Replace("\"seq\":0", "\"seq\":-1"), ok.Replace("\"seq\":0", "\"seq\":-0"), ok.Replace("\"seq\":0", "\"seq\":\"0\""),
                     ok.Replace(G0, G0[1..]), HeadJson(0, G0.Replace('0', 'A')), HeadJson(0, G0, 0), ok.Replace("}", ",\"gen\":\"1\"}") })
        {
            t.Write("state.head", bad);
            var e = Assert.Throws<DurableStateError>(() => Open(t));
            Assert.True(e.Message == "corrupt: state.head has an invalid shape", bad + ": " + e.Message);
        }
    }

    // ---- values ----

    [Fact]
    public void ValuesAreNormalisedJsonWithinTheSizeLimit()
    {
        var e = Assert.Throws<DurableStateError>(() => DurableState.Normalise("{"));
        Assert.Equal("invalid: value is not JSON-serialisable", e.Message);
        Assert.Equal("[1,2]", DurableState.Normalise(" [1, 2] "));
        e = Assert.Throws<DurableStateError>(() => DurableState.EncodeTree(new object(), 100));
        Assert.Equal("invalid: value is not JSON-serialisable", e.Message);
        Assert.Equal("[1]", DurableState.EncodeTree(new L { 1L }, 3));
        e = Assert.Throws<DurableStateError>(() => DurableState.EncodeTree(new L { 10L }, 3));
        Assert.Equal("too-large: value exceeds maxValueBytes=3", e.Message);

        using var t = new Tmp();
        var s = Pca.OpenDurableState(new DurableStateOptions { Dir = t.Dir, MaxValueBytes = 3 });
        s.Set("k", " [ 1 ] ");
        Assert.Equal("[1]", s.Get("k"));
        e = Assert.Throws<DurableStateError>(() => s.Set("k", "[10]"));
        Assert.Equal("too-large: value exceeds maxValueBytes=3", e.Message);
        e = Assert.Throws<DurableStateError>(() => s.Set("k", "{"));
        Assert.Equal("invalid: value is not JSON-serialisable", e.Message);
        e = Assert.Throws<DurableStateError>(() => s.SetValue("k", new object()));
        Assert.Equal("invalid: value is not JSON-serialisable", e.Message);
        Assert.Equal("[1]", s.Get("k"));
    }

    // ---- opening the directory ----

    [Fact]
    public void ADirectoryThatCannotBeCreatedFailsWithTheFilesystemError()
    {
        using var t = new Tmp();
        t.Write("plain", "x");
        var e = Record.Exception(() => Pca.OpenDurableState(new DurableStateOptions { Dir = Path.Combine(t.P("plain"), "sub") }));
        Assert.NotNull(e);
        Assert.IsNotType<DurableStateError>(e);
    }

    [Fact]
    public void ADirectoryWithoutWorkingLinksFailsTheProbeAtOpen()
    {
        if (!OperatingSystem.IsLinux()) return; // procfs: an existing directory nobody can create files in
        var e = Assert.Throws<DurableStateError>(() => Pca.OpenDurableState(new DurableStateOptions { Dir = "/proc/self" }));
        Assert.Equal("link-unsupported", e.Code);
    }

    // ---- recovery from corruption ----

    [Fact]
    public void WithoutTheOptionCorruptionIsAnError()
    {
        using var t = new Tmp();
        t.Write("state.journal", "torn");
        Fails(t, "corrupt: journal does not end with a newline (torn or truncated)");
        Assert.Equal(new[] { "state.journal" }, t.Names());
    }

    [Fact]
    public void QuarantineMovesEverythingAsideAndFencesFromGenesis()
    {
        using var t = new Tmp();
        t.Write("state.journal", "torn");
        t.Write("state.head", "{");
        const string oldList = "{\"v\":1,\"fences\":[]}\n";
        t.Write("state.fence", oldList);
        var entry = "{\"v\":1,\"fence\":{\"gen\":2,\"seq\":0,\"h\":\"" + G0 + "\"}}\n";
        t.Write("state.fence.2-ab", entry);
        var s = Open(t, recover: true, now: () => 5000);
        Assert.True(s.Recovered);
        var tag = t.Names().Select(n => Regex.Match(n, "^state\\.journal\\.quarantine-(5000-[0-9a-f]{6})$")).Single(m => m.Success).Groups[1].Value;
        Assert.Equal(new[] { "state.fence", "state.fence.2-ab.quarantine-" + tag, "state.fence.quarantine-" + tag, "state.head.quarantine-" + tag, "state.journal.quarantine-" + tag }, t.Names());
        Assert.Equal("torn", t.Read("state.journal.quarantine-" + tag));
        Assert.Equal("{", t.Read("state.head.quarantine-" + tag));
        Assert.Equal(oldList, t.Read("state.fence.quarantine-" + tag));
        Assert.Equal(entry, t.Read("state.fence.2-ab.quarantine-" + tag));
        Assert.Equal("{\"v\":1,\"fences\":[{\"gen\":1,\"seq\":0,\"h\":\"" + G0 + "\",\"from\":0,\"t\":5000}]}\n", t.Read("state.fence"));
        Assert.Equal((0L, G0), s.Position());
        Assert.Empty(s.Keys());
        s.Set("k", "1");
        Assert.Equal("1", Open(t).Get("k"));
    }

    [Fact]
    public void QuarantineWithoutFencesWritesNone()
    {
        using var t = new Tmp();
        t.Write("state.journal", "torn");
        Assert.True(Open(t, recover: true).Recovered);
        Assert.Matches("^state\\.journal\\.quarantine-[0-9]+-[0-9a-f]{6}$", Assert.Single(t.Names()));
    }

    [Fact]
    public void QuarantineRefusesWhenTheLockWasLost()
    {
        using var t = new Tmp();
        t.Write("state.journal", "torn");
        var stolen = false;
        var e = Assert.Throws<DurableStateError>(() => Open(t, recover: true, now: () =>
        {
            if (!stolen)
            {
                stolen = true;
                t.Write("state.lock.2", "{\"st\":\"held\",\"pid\":" + Environment.ProcessId + ",\"host\":\"elsewhere\",\"nonce\":\"other\"}");
            }
            return 5000;
        }));
        Assert.Equal("lock-lost: the state lock is no longer held by this writer (generation 1, highest 2 held); nothing was written", e.Message);
        Assert.Equal(new[] { "state.journal" }, t.Names());
        Assert.Equal("torn", t.Read("state.journal"));
    }

    [Fact]
    public void AFenceListThatCannotBeLinkedAsideStopsTheQuarantine()
    {
        using var t = new Tmp();
        Directory.CreateDirectory(t.P("state.fence"));
        Fails(t, "corrupt: state.fence is not valid JSON");
        var e = Assert.Throws<IOException>(() => Open(t, recover: true));
        Assert.StartsWith("link: ", e.Message);
        Assert.True(Directory.Exists(t.P("state.fence")));
    }
}
