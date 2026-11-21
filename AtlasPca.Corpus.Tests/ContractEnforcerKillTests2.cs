using System.Text;
using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.ContractsKillSupport;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Exact-output kills for <see cref="ContractEnforcer"/>: construction guards, the durable document shape, every admit / deny / latch path of check, the read-only peek, state and the
/// signed reset, with a recording clock and failing stores.</summary>
public class ContractEnforcerKillTests2
{
    const string Clauses = "[{'id':'no-send','kind':'never','p':{'verb':'send'}},{'id':'order','kind':'precedes','p':{'verb':'review'},'q':{'verb':'deploy'}}]";
    const string Corrupt = "<state>: stored state is corrupt or belongs to another contract";
    const string NoSend = "no-send: never-invariant violated (forbidden action)";
    const string Order = "order: precedence violated (prerequisite p not yet admitted before q)";
    const double T0 = 1_800_000_000_000.0;
    static readonly string[] None = Array.Empty<string>();

    static EdKey Principal => Key(7);

    static JD Signed() => Contracts.Sign(M("{'version':1,'principal':'" + Principal.Id + "','clauses':" + Clauses + "}"), Principal);

    static JD Act(string verb) => M("{'action':{'verb':'" + verb + "','resource':'/r'}}");

    sealed class Fx
    {
        internal readonly ContractsKillFaultKv Kv = new();
        internal double Wall = T0;
        internal int Calls;
        internal readonly JD Contract = Signed();
        internal readonly ContractEnforcer En;

        internal Fx(bool latch = true) => En = ContractEnforcer.Open(Kv, Contract, Principal.Id, "k", () => { Calls++; return Wall; }, latch);

        internal string Id => (string)Contract["id"]!;
        internal string? Text => Kv.Inner.Get("k");
        internal JD Doc => (JD)Pca.ParseJson(Text!)!;
        internal JD StateOf => (JD)Doc["state"]!;
    }

    static void Expect(EnforceResult r, bool allow, string reason, string[] violated, string[] reasons, long seq)
    {
        Assert.Equal(allow, r.Allow);
        Assert.Equal(reason, r.Reason);
        Assert.Equal(violated, r.Violated.ToArray());
        Assert.Equal(reasons, r.Reasons.ToArray());
        Assert.Equal(seq, r.Seq);
    }

    // ---- open / signReset --------------------------------------------------------------------------------------------------

    [Fact]
    public void OpenRefusesWhatItCannotPin()
    {
        var c = Signed();
        foreach (var p in new string?[] { null, "" })
            Assert.Equal("ContractEnforcer: a pinned principal is required", Assert.Throws<ContractEnforcerError>(() => ContractEnforcer.Open(new MemoryAtomicKv(), c, p!)).Message);
        Assert.Equal("ContractEnforcer: contract refused: principal mismatch", Assert.Throws<ContractEnforcerError>(() => ContractEnforcer.Open(new MemoryAtomicKv(), c, "someone-else")).Message);
        var unsigned = new JD(c); unsigned.Remove("id"); unsigned.Remove("sig");
        Assert.Equal("ContractEnforcer: contract refused: id does not match content", Assert.Throws<ContractEnforcerError>(() => ContractEnforcer.Open(new MemoryAtomicKv(), unsigned, Principal.Id)).Message);
        Assert.NotNull(ContractEnforcer.Open(new MemoryAtomicKv(), c, Principal.Id));
    }

    [Fact]
    public void TheKeyDefaultsToTheContractIdAndTheClockToTheWallClock()
    {
        var kv = new MemoryAtomicKv();
        var c = Signed();
        var en = ContractEnforcer.Open(kv, c, Principal.Id);
        var before = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        Assert.True(en.Check(Act("read")).Allow);
        var after = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        Assert.Null(kv.Get("k"));
        var doc = (JD)Pca.ParseJson(kv.Get("contract/" + (string)c["id"]!)!)!;
        Assert.Equal((string)c["id"]!, doc["contract_id"]);
        var now = Nv(((JD)doc["state"]!)["now"]);
        Assert.True(now >= before && now <= after, $"now {now} not in [{before}, {after}]");
        Assert.True(en.Peek(Act("read")).Allow);
        // an explicit key is used as given
        var kv2 = new MemoryAtomicKv();
        Assert.True(ContractEnforcer.Open(kv2, c, Principal.Id, "mine").Check(Act("read")).Allow);
        Assert.NotNull(kv2.Get("mine"));
        Assert.Null(kv2.Get("contract/" + (string)c["id"]!));
    }

    [Fact]
    public void SignResetIsTheSignatureOverTheDomainedHashOfIdAndSeq()
    {
        var sig = ContractEnforcer.SignReset(Principal, "id1", 1);
        Assert.Equal(86, sig.Length);
        Assert.Equal(sig, ContractEnforcer.SignReset(Principal, "id1", 1));
        Assert.NotEqual(sig, ContractEnforcer.SignReset(Principal, "id1", 2));
        Assert.NotEqual(sig, ContractEnforcer.SignReset(Principal, "id2", 1));
        Assert.NotEqual(sig, ContractEnforcer.SignReset(Key(8), "id1", 1));
        byte[] Msg(string text) => Encoding.UTF8.GetBytes(ContractEnforcer.ResetDomain).Concat(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToArray();
        Assert.True(Pca.VerifyEdInternal(Principal.Id, Msg("id1:1"), sig));
        Assert.False(Pca.VerifyEdInternal(Principal.Id, Msg("id1:2"), sig));
    }

    // ---- check -------------------------------------------------------------------------------------------------------------

    [Fact]
    public void AnAdmittedActionCreatesAndThenAdvancesTheDocument()
    {
        var fx = new Fx();
        Assert.Null(fx.Text);
        Assert.Null(fx.En.State());
        Expect(fx.En.Check(Act("read")), true, "ok", None, None, 1);
        var doc = fx.Doc;
        Assert.Equal(new[] { "contract_id", "state", "v" }, doc.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray());
        Assert.Equal(1d, Nv(doc["v"]));
        Assert.Equal(fx.Id, doc["contract_id"]);
        Assert.Equal(1d, Nv(fx.StateOf["seq"]));
        Assert.Equal(T0, Nv(fx.StateOf["now"]));
        Assert.Empty((JD)fx.StateOf["latched"]!);
        Assert.Equal(1, fx.Calls);
        Expect(fx.En.Check(Act("review")), true, "ok", None, None, 2);
        Assert.Equal(new[] { "order" }, ((JD)fx.StateOf["latched"]!).Keys.ToArray());
        Assert.Equal(T0, Nv(((JD)fx.StateOf["latched"]!)["order"]));
        Assert.Equal(2, fx.Calls);
        Expect(fx.En.Check(Act("deploy")), true, "ok", None, None, 3);
        var st = fx.En.State();
        Assert.NotNull(st);
        Assert.False(st!.Value.Latched);
        Assert.Equal(3d, Nv(st.Value.State["seq"]));
        Assert.Null(Prohibitions.StateProblem(st.Value.State));
    }

    [Fact]
    public void TheStoredClockNeverMovesBackwardsAndFollowsAForwardWallClock()
    {
        var fx = new Fx();
        fx.Wall = 2000;
        Expect(fx.En.Check(Act("read")), true, "ok", None, None, 1);
        Assert.Equal(2000d, Nv(fx.StateOf["now"]));
        fx.Wall = 1500;
        Expect(fx.En.Check(Act("read")), true, "ok", None, None, 2);
        Assert.Equal(2000d, Nv(fx.StateOf["now"]));
        fx.Wall = 3000;
        Expect(fx.En.Check(Act("read")), true, "ok", None, None, 3);
        Assert.Equal(3000d, Nv(fx.StateOf["now"]));
    }

    [Fact]
    public void AClockThatIsNotFiniteIsAStateErrorOnAStoredDocument()
    {
        foreach (var bad in new[] { double.NaN, double.PositiveInfinity, double.NegativeInfinity })
        {
            var fx = new Fx();
            Expect(fx.En.Check(Act("read")), true, "ok", None, None, 1);
            var before = fx.Text;
            fx.Wall = bad;
            Expect(fx.En.Check(Act("read")), false, "state-error", None, new[] { "<state>: clock is not finite" }, 1);
            Assert.Equal(before, fx.Text);
        }
    }

    [Fact]
    public void AClockThatIsNotFiniteOnTheFirstCallStoresNothing()
    {
        foreach (var bad in new[] { double.NaN, double.PositiveInfinity })
        {
            var fx = new Fx();
            fx.Wall = bad;
            Expect(fx.En.Check(Act("read")), false, "state-error", None, new[] { "<state>: advance failed: clock regression" }, 0);
            Assert.Null(fx.Text);
        }
        // minus infinity falls back to the genesis clock 0 and the first action is admitted at 0
        var neg = new Fx();
        neg.Wall = double.NegativeInfinity;
        Expect(neg.En.Check(Act("read")), true, "ok", None, None, 1);
        Assert.Equal(0d, Nv(neg.StateOf["now"]));
    }

    [Fact]
    public void NotPermittedDeniesWithoutLatchingOrStoring()
    {
        var fx = new Fx();
        Expect(fx.En.Check(Act("read"), false), false, "permission", None, new[] { "<permission>: not permitted" }, 0);
        Assert.Null(fx.Text);
        Expect(fx.En.Check(Act("read")), true, "ok", None, None, 1);
        var before = fx.Text;
        Expect(fx.En.Check(Act("read"), false), false, "permission", None, new[] { "<permission>: not permitted" }, 1);
        Assert.Equal(before, fx.Text);
        Assert.False(fx.En.State()!.Value.Latched);
    }

    [Fact]
    public void ARealViolationLatchesAndEverythingAfterItIsDeniedUntilAReset()
    {
        var fx = new Fx();
        Expect(fx.En.Check(Act("read")), true, "ok", None, None, 1);
        Expect(fx.En.Check(Act("read")), true, "ok", None, None, 2);
        Expect(fx.En.Check(Act("send")), false, "violated", new[] { "no-send" }, new[] { NoSend }, 2);
        var doc = fx.Doc;
        Assert.Equal(new[] { "contract_id", "latched", "state", "v" }, doc.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray());
        Assert.Equal("{\"seq\":2,\"violated\":[\"no-send\"]}", Pca.Canonicalize(doc["latched"]));
        Assert.Equal(2d, Nv(((JD)doc["state"]!)["seq"]));
        Assert.True(fx.En.State()!.Value.Latched);
        var text = fx.Text;
        foreach (var permitted in new[] { true, false })
        {
            Expect(fx.En.Check(Act("read"), permitted), false, "latched", new[] { "no-send" }, new[] { "<latched>: contract violated at seq 2" }, 2);
            Assert.Equal(text, fx.Text);
        }
        Expect(fx.En.Peek(Act("read")), false, "latched", new[] { "no-send" }, new[] { "<latched>: contract violated at seq 2" }, 2);
        // a wrong or foreign reset does not clear it
        Assert.False(fx.En.Reset(null!));
        Assert.False(fx.En.Reset("garbage"));
        Assert.False(fx.En.Reset(ContractEnforcer.SignReset(Principal, fx.Id, 1)));
        Assert.False(fx.En.Reset(ContractEnforcer.SignReset(Principal, fx.Id, 3)));
        Assert.False(fx.En.Reset(ContractEnforcer.SignReset(Principal, "other-contract", 2)));
        Assert.False(fx.En.Reset(ContractEnforcer.SignReset(Key(8), fx.Id, 2)));
        Assert.Equal(text, fx.Text);
        Assert.True(fx.En.State()!.Value.Latched);
        // the principal's reset at the latched sequence clears it and the chain goes on
        Assert.True(fx.En.Reset(ContractEnforcer.SignReset(Principal, fx.Id, 2)));
        Assert.Equal(new[] { "contract_id", "state", "v" }, fx.Doc.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray());
        Assert.False(fx.En.State()!.Value.Latched);
        Expect(fx.En.Check(Act("read")), true, "ok", None, None, 3);
        Assert.False(fx.En.Reset(ContractEnforcer.SignReset(Principal, fx.Id, 3)));
    }

    [Fact]
    public void TheFirstEverViolationLatchesAtSequenceZero()
    {
        var fx = new Fx();
        Expect(fx.En.Check(Act("deploy")), false, "violated", new[] { "order" }, new[] { Order }, 0);
        Assert.Equal("{\"seq\":0,\"violated\":[\"order\"]}", Pca.Canonicalize(fx.Doc["latched"]));
        Expect(fx.En.Check(Act("review")), false, "latched", new[] { "order" }, new[] { "<latched>: contract violated at seq 0" }, 0);
        Assert.True(fx.En.Reset(ContractEnforcer.SignReset(Principal, fx.Id, 0)));
        Expect(fx.En.Check(Act("review")), true, "ok", None, None, 1);
        Expect(fx.En.Check(Act("deploy")), true, "ok", None, None, 2);
    }

    [Fact]
    public void AViolationWithoutLatchingLeavesTheStateAlone()
    {
        var fx = new Fx(false);
        Expect(fx.En.Check(Act("send")), false, "violated", new[] { "no-send" }, new[] { NoSend }, 0);
        Assert.Null(fx.Text);
        Expect(fx.En.Check(Act("read")), true, "ok", None, None, 1);
        var before = fx.Text;
        Expect(fx.En.Check(Act("send")), false, "violated", new[] { "no-send" }, new[] { NoSend }, 1);
        Assert.Equal(before, fx.Text);
        Assert.False(fx.En.State()!.Value.Latched);
        Expect(fx.En.Check(Act("read")), true, "ok", None, None, 2);
    }

    [Fact]
    public void AViolationIsAViolationEvenWhenThePermissionAlsoDenies()
    {
        var fx = new Fx();
        Expect(fx.En.Check(Act("send"), false), false, "violated", new[] { "no-send" }, new[] { NoSend }, 0);
        Assert.True(fx.Doc.ContainsKey("latched"));
    }

    // ---- stores that fail --------------------------------------------------------------------------------------------------

    [Fact]
    public void AStoreThatFailsOrDoesNothingIsAStoreErrorNeverAnAdmission()
    {
        var down = new ContractsKillFaultKv();
        var en = ContractEnforcer.Open(down, Signed(), Principal.Id, "k", () => T0);
        down.UpdateThrows = true;
        Expect(en.Check(Act("read")), false, "store-error", None, new[] { "store error (fail closed)" }, 0);
        down.UpdateThrows = false;
        down.UpdateSkips = true;
        Expect(en.Check(Act("read")), false, "store-error", None, new[] { "store unavailable" }, 0);
        down.UpdateSkips = false;
        down.GetThrows = true;
        Expect(en.Peek(Act("read")), false, "store-error", None, new[] { "store error (fail closed)" }, 0);
        // the clock failing is the same refusal
        var broken = ContractEnforcer.Open(new MemoryAtomicKv(), Signed(), Principal.Id, "k", () => throw new InvalidOperationException("clock"));
        Expect(broken.Check(Act("read")), false, "store-error", None, new[] { "store error (fail closed)" }, 0);
        Expect(broken.Peek(Act("read")), false, "store-error", None, new[] { "store error (fail closed)" }, 0);
        // a reset on a failing store is a refusal
        var rk = new ContractsKillFaultKv();
        var contract = Signed();
        var en2 = ContractEnforcer.Open(rk, contract, Principal.Id, "k", () => T0);
        Expect(en2.Check(Act("send")), false, "violated", new[] { "no-send" }, new[] { NoSend }, 0);
        var sig = ContractEnforcer.SignReset(Principal, (string)contract["id"]!, 0);
        rk.UpdateThrows = true;
        Assert.False(en2.Reset(sig));
        rk.UpdateThrows = false;
        Assert.True(en2.Reset(sig));
    }

    // ---- corrupt documents -------------------------------------------------------------------------------------------------

    /// <summary>A stored document built from the real contract id and the first admitted state; a member is left out with null.</summary>
    static string DocText(string id, string stateText, string? v = "1", string? contractId = "", string? state = "", string? latched = null)
    {
        var parts = new List<string>();
        if (v != null) parts.Add("\"v\":" + v);
        if (contractId != null) parts.Add("\"contract_id\":" + (contractId.Length == 0 ? "\"" + id + "\"" : contractId));
        if (state != null) parts.Add("\"state\":" + (state.Length == 0 ? stateText : state));
        if (latched != null) parts.Add("\"latched\":" + latched);
        return "{" + string.Join(",", parts) + "}";
    }

    static void ExpectCorrupt(Fx fx, string stored)
    {
        fx.Kv.Inner.Update("k", _ => stored);
        Assert.Equal("ContractEnforcer: stored state is corrupt or belongs to another contract", Assert.Throws<ContractEnforcerError>(() => fx.En.State()).Message);
        Expect(fx.En.Peek(Act("read")), false, "state-error", None, new[] { Corrupt }, 0);
        Expect(fx.En.Check(Act("read")), false, "state-error", None, new[] { Corrupt }, 0);
        Assert.Equal(stored, fx.Text);
        Assert.False(fx.En.Reset(ContractEnforcer.SignReset(Principal, fx.Id, 1)));
        Assert.Equal(stored, fx.Text);
    }

    [Fact]
    public void EveryMalformedDocumentIsCorruptNotAdmitted()
    {
        var fx = new Fx();
        Assert.True(fx.En.Check(Act("read")).Allow);
        var st = Pca.Canonicalize(fx.StateOf);
        string T(string? v = "1", string? contractId = "", string? state = "", string? latched = null) => DocText(fx.Id, st, v, contractId, state, latched);
        ExpectCorrupt(fx, "x");
        ExpectCorrupt(fx, "[]");
        ExpectCorrupt(fx, T(v: "2"));
        ExpectCorrupt(fx, T(v: "1.5"));
        ExpectCorrupt(fx, T(v: "\"1\""));
        ExpectCorrupt(fx, T(v: null));
        ExpectCorrupt(fx, T(contractId: "\"another\""));
        ExpectCorrupt(fx, T(contractId: null));
        ExpectCorrupt(fx, T(state: "{\"now\":1}"));
        ExpectCorrupt(fx, T(state: null));
        foreach (var bad in new[]
        {
            "\"x\"", "5", "null", "[]", "{\"violated\":[]}", "{\"seq\":1}", "{\"seq\":1.5,\"violated\":[]}", "{\"seq\":\"1\",\"violated\":[]}", "{\"seq\":-0,\"violated\":[]}",
            "{\"seq\":1,\"violated\":\"a\"}", "{\"seq\":1,\"violated\":[5]}", "{\"seq\":1,\"violated\":[\"a\",null]}",
        })
            ExpectCorrupt(fx, T(latched: bad));
    }

    [Fact]
    public void WellFormedLatchesAreServedBack()
    {
        var fx = new Fx();
        Assert.True(fx.En.Check(Act("read")).Allow);
        var st = Pca.Canonicalize(fx.StateOf);
        fx.Kv.Inner.Update("k", _ => DocText(fx.Id, st, latched: "{\"seq\":0,\"violated\":[]}"));
        Assert.True(fx.En.State()!.Value.Latched);
        Expect(fx.En.Peek(Act("read")), false, "latched", None, new[] { "<latched>: contract violated at seq 0" }, 1);
        fx.Kv.Inner.Update("k", _ => DocText(fx.Id, st, latched: "{\"seq\":7,\"violated\":[\"a\",\"b\"]}"));
        Expect(fx.En.Peek(Act("read")), false, "latched", new[] { "a", "b" }, new[] { "<latched>: contract violated at seq 7" }, 1);
        Expect(fx.En.Check(Act("read")), false, "latched", new[] { "a", "b" }, new[] { "<latched>: contract violated at seq 7" }, 1);
        Assert.True(fx.En.Reset(ContractEnforcer.SignReset(Principal, fx.Id, 7)));
        Assert.False(fx.Doc.ContainsKey("latched"));
    }

    // ---- peek --------------------------------------------------------------------------------------------------------------

    [Fact]
    public void PeekEvaluatesWithoutAdvancingAndReadsTheClockOnce()
    {
        var fx = new Fx();
        Expect(fx.En.Peek(Act("read")), true, "ok", None, None, 0);
        Assert.Equal(1, fx.Calls);
        Assert.Null(fx.Text);
        Expect(fx.En.Peek(Act("send")), false, "violated", new[] { "no-send" }, new[] { NoSend }, 0);
        Assert.Null(fx.Text);
        Expect(fx.En.Check(Act("read")), true, "ok", None, None, 1);
        Expect(fx.En.Check(Act("review")), true, "ok", None, None, 2);
        var before = fx.Text;
        fx.Calls = 0;
        // the stored state, not an empty one, is evaluated: the prerequisite is latched in it
        Expect(fx.En.Peek(Act("deploy")), true, "ok", None, None, 2);
        Assert.Equal(1, fx.Calls);
        Expect(fx.En.Peek(Act("send")), false, "violated", new[] { "no-send" }, new[] { NoSend }, 2);
        Assert.Equal(before, fx.Text);
        // a corrupt document answers before the clock is read
        fx.Calls = 0;
        fx.Kv.Inner.Update("k", _ => "x");
        Expect(fx.En.Peek(Act("read")), false, "state-error", None, new[] { Corrupt }, 0);
        Assert.Equal(0, fx.Calls);
    }

    [Fact]
    public void PeekToleratesANonFiniteClockOnAnEmptyStore()
    {
        foreach (var bad in new[] { double.NaN, double.PositiveInfinity, double.NegativeInfinity })
        {
            var fx = new Fx();
            fx.Wall = bad;
            Expect(fx.En.Peek(Act("read")), true, "ok", None, None, 0);
            Expect(fx.En.Peek(Act("send")), false, "violated", new[] { "no-send" }, new[] { NoSend }, 0);
        }
    }

    [Fact]
    public void PeekOnAViolatingPrerequisiteReportsTheContractsOwnViolations()
    {
        var fx = new Fx();
        Expect(fx.En.Peek(Act("deploy")), false, "violated", new[] { "order" }, new[] { Order }, 0);
        Expect(fx.En.Peek(Act("deploy")), false, "violated", new[] { "order" }, new[] { Order }, 0);
    }
}
