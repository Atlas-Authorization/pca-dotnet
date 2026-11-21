using System.Reflection;
using System.Text;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Small, exact pins for the support modules: verdict defaults, key disposal, the OID size cap, the blueprint store's keys and epoch rule,
/// the regex budget's refusal count, the attestation size caps and the NVIDIA CRL-coverage policy messages.</summary>
public class SupportSurvivorKillTests
{
    const BindingFlags NP = BindingFlags.NonPublic | BindingFlags.Static;

    // ---- Verdict

    [Fact]
    public void ANewVerdictHasNoPlanRootStatus() => Assert.Equal("", new Verdict().PlanRootAuthorized);

    // ---- PqKey

    [Fact]
    public void ADisposedPostQuantumKeyCannotSign()
    {
        var k = PqKey.Generate(Pq.Prim.MlDsa65);
        Assert.NotEmpty(k.Sign(new byte[] { 1 }));
        k.Dispose();
        Assert.Throws<ObjectDisposedException>(() => k.Sign(new byte[] { 1 }));
    }

    // ---- Sigstore OID size cap (the helper is private)

    static string SigstoreOid(byte[] content)
    {
        var n = content.Length;
        var head = n < 0x80 ? new byte[] { 0x06, (byte)n } : new byte[] { 0x06, 0x82, (byte)(n >> 8), (byte)n };
        var der = head.Concat(content).ToArray();
        var t = typeof(Sigstore).GetMethod("T", NP)!.Invoke(null, new object?[] { der, 0, -1 })!;
        var oid = typeof(Sigstore).GetMethods(NP).Single(m => m.Name == "Oid" && m.GetParameters().Length == 2);
        try { return (string)oid.Invoke(null, new[] { der, t })!; }
        catch (TargetInvocationException e) { return e.InnerException!.GetType().Name + ":" + e.InnerException.Message; }
    }

    static byte[] OidContent(int length)
    {
        // 1.2 then 17-byte arcs (119 bits each): within the platform decoder's 64-arc / 128-bit-arc limits and the
        // reference's 64-group arc limit, so only the total size is in question
        var c = new byte[length];
        c[0] = 0x2a;
        for (int i = 1; i < length; i++) c[i] = (i % 17 == 0 || i == length - 1) ? (byte)0x01 : (byte)0x81;
        return c;
    }

    [Fact]
    public void AnOidOfExactly256ContentBytesDecodesAndOneMoreIsRefused()
    {
        Assert.StartsWith("1.2.", SigstoreOid(OidContent(256)));
        Assert.Equal("Bad:OID is too long", SigstoreOid(OidContent(257)));
    }

    // ---- AtomicKvBlueprintStore

    sealed class RecordingKv : IAtomicKv
    {
        public readonly MemoryAtomicKv Inner = new();
        public readonly List<(string Key, bool Wrote)> Updates = new();
        public string? Get(string key) => Inner.Get(key);
        public void Update(string key, Func<string?, string?> fn) => Inner.Update(key, prev => { var r = fn(prev); Updates.Add((key, r != null)); return r; });
    }

    static JD Rec(string key, int epoch) => new() { ["key"] = key, ["epoch"] = new Num(epoch.ToString()) };

    [Fact]
    public void TheBlueprintStoreKeepsOneRecordPerKeyAndRaisesTheEpochOnlyUpward()
    {
        Assert.Equal("kv", Assert.Throws<ArgumentNullException>(() => new AtomicKvBlueprintStore(null!)).ParamName);
        var kv = new RecordingKv();
        var store = new AtomicKvBlueprintStore(kv);
        store.Put(Rec("k1", 5));
        Assert.NotNull(kv.Inner.Get("blueprint/rec/k1"));
        Assert.Equal(new[] { ("blueprint/rec/k1", true), ("blueprint/max_epoch", true) }, kv.Updates.ToArray());
        kv.Updates.Clear();
        store.Put(Rec("k2", 5)); // the same epoch again: the maximum is left alone
        Assert.Equal(("blueprint/max_epoch", false), kv.Updates[1]);
        store.Put(Rec("k3", 4));
        Assert.Equal(("blueprint/max_epoch", false), kv.Updates[3]);
        store.Put(Rec("k4", 6));
        Assert.Equal(("blueprint/max_epoch", true), kv.Updates[5]);
        Assert.Equal(6, store.MaxEpoch());
        Assert.Equal("5", ((Num)store.Get("k1")!["epoch"]!).Raw);
    }

    // ---- SafeRegex refusal count

    [Fact]
    public void EveryRefusedChargeCountsOnceInTheOpenBudget()
    {
        Assert.Equal(0, SafeRegex.RefusalCount);
        var seen = SafeRegex.WithBudget(() =>
        {
            var o = new List<int> { SafeRegex.RefusalCount };
            Assert.True(SafeRegex.Charge("a", 1));
            o.Add(SafeRegex.RefusalCount);
            Assert.False(SafeRegex.Charge("(", 1)); // does not compile
            o.Add(SafeRegex.RefusalCount);
            Assert.False(SafeRegex.Charge("a", 10_000_000)); // over the step budget
            o.Add(SafeRegex.RefusalCount);
            Assert.False(SafeRegex.Charge("a", 1)); // the budget is poisoned: every later charge is refused
            o.Add(SafeRegex.RefusalCount);
            return o;
        });
        Assert.Equal(new[] { 0, 0, 1, 2, 3 }, seen);
        Assert.Equal(0, SafeRegex.RefusalCount);
    }

    // ---- attestation size caps

    static string Token(byte[] header, byte[] payload) => Pca.B64u(header) + "." + Pca.B64u(payload) + ".c2ln";

    [Fact]
    public void AJwsHeaderOfExactlySixteenMiBIsStillParsed()
    {
        var exact = new byte[AttestJws.MaxAttestJsonBytes];
        Array.Fill(exact, (byte)' ');
        var json = Encoding.UTF8.GetBytes("{\"alg\":\"RS256\"}");
        json.CopyTo(exact, 0);
        Assert.Equal("RS256", AttestJws.ParseJwt(Token(exact, Encoding.UTF8.GetBytes("{}")), "p").Alg);
    }

    [Fact]
    public void ASignedJsonDocumentIsCappedAtSixteenMiBOfText()
    {
        Assert.Equal("tcbInfo: malformed JSON segment: input too large", AttestIntelCollateral.VerifySignedJson(new string(' ', AttestJws.MaxAttestJsonBytes + 1), "tcbInfo", new CertKey()).Why);
        Assert.Equal("tcbInfo not found / malformed", AttestIntelCollateral.VerifySignedJson(new string(' ', AttestJws.MaxAttestJsonBytes), "tcbInfo", new CertKey()).Why);
    }

    // ---- NVIDIA CRL-coverage policy

    static NvidiaHook Hook(object? requireCrlFor, bool include = true)
    {
        var col = new JD { ["rimRootSpkiSha256"] = new JL { "pin" } };
        if (include) col["requireCrlFor"] = requireCrlFor;
        return NvidiaHook.Create(col);
    }

    [Fact]
    public void ANullCoveragePolicyIsTheDefault()
    {
        Hook(null);
        Hook(null, include: false);
    }

    [Fact]
    public void AMalformedCoveragePolicyNamesWhatWasGiven()
    {
        string Msg(object? v) => Assert.Throws<ArgumentException>(() => Hook(v)).Message;
        Assert.Equal("nvidiaCollateralHook: malformed requireCrlFor 'none'", Msg("none"));
        Assert.Equal("nvidiaCollateralHook: malformed requireCrlFor '[...]'", Msg(new JL { new Num("-1") }));
        Assert.Equal("nvidiaCollateralHook: malformed requireCrlFor 'Boolean'", Msg(true));
        Assert.Equal("nvidiaCollateralHook: malformed requireCrlFor 'Num'", Msg(new Num("1")));
    }
}
