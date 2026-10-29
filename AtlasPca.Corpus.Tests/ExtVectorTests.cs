using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// The extension layer of the conformance corpus (optimistic-vectors.json, ledger-vectors.json, mesh-vectors.json): every vector must
// reproduce the reference verdict exactly. Nothing is skipped; each table's size must equal the file's `counts`.
public class ExtVectorTests
{
    // The row counts of the committed corpus: asserted against the REAL table sizes (not only the file's own `counts`), so a truncated
    // or regenerated file that is not re-pinned here fails.
    static readonly Dictionary<string, int> Expected = new()
    {
        ["optimistic_claim"] = 52, ["optimistic_window"] = 25, ["optimistic_fraud_proof"] = 37, ["optimistic_settlement"] = 102,
        ["ledger_inclusion"] = 96, ["ledger_consistency"] = 149, ["ledger_tree_head"] = 64, ["ledger_cosign"] = 56, ["ledger_head_consistency"] = 26,
        ["ledger_checkpoint_chain"] = 23, ["ledger_witnessed_head"] = 30, ["ledger_equivocation"] = 7,
    };

    static List<D> Rows(D doc, string table)
    {
        Assert.True(doc.ContainsKey(table), $"{table}: missing table");
        var arr = L(doc[table]);
        Assert.True(D(doc["counts"]).TryGetValue(table, out var want) && N(want) == arr.Count, $"{table}: {arr.Count} vectors, counts says {D(doc["counts"]).GetValueOrDefault(table)}");
        Assert.True(!Expected.TryGetValue(table, out var exp) || exp == arr.Count, $"{table}: {arr.Count} vectors, this runner pins {exp}");
        return arr.Cast<D>().ToList();
    }

    /// <summary>`requires_suite` names a registered suite beyond the core ones: an SDK that cannot verify it must refuse (false / check `suite`).</summary>
    static bool Lacks(D v) => v.GetValueOrDefault("requires_suite") is string s && !Pq.Suites.ContainsKey(s);

    static double F(object? v) => IntentJs.NumOf(v) ?? double.NaN;
    static D? PolicyOf(object? v) => v as D;
    static string S(object? v) => (string)v!;
    /// <summary>The optional vector `pins` (identity b64u to ML-DSA-65 key b64u); absent = no pin. ledger_cosign carries its pins in policy.pqPins.</summary>
    static IReadOnlyDictionary<string, string>? PinsOf(D v) =>
        v.GetValueOrDefault("pins") is D p ? p.ToDictionary(e => e.Key, e => (string)e.Value!) : null;

    [Fact]
    public void OptimisticVectors()
    {
        var doc = Load("optimistic-vectors.json");
        var wp = D(doc["window_policy"]);
        var pol = new ChallengeWindowPolicy(F(wp["minWindowMs"]), F(wp["maxWindowMs"]), F(wp["maxSkewMs"]));
        foreach (var v in Rows(doc, "optimistic_claim"))
        {
            var got = Optimistic.ClaimCheck(v["claim"], S(v["pcactn_digest"]), S(v["signer_public"]), F(v["server_now"]), pol);
            var exp = D(v["expect"]);
            Assert.True(got == (string)exp["check"]! && (got == "ok") == (bool)exp["ok"]!, $"claim/{v["name"]}: got {got} want {exp["check"]}");
        }
        foreach (var v in Rows(doc, "optimistic_window"))
        {
            double i = F(v["issued_at"]), w = F(v["challenge_window_ms"]), now = F(v["now"]);
            var exp = D(v["expect"]);
            Assert.True(Optimistic.ChallengeWindowEnd(i, w) == F(exp["end"]) && Optimistic.WithinChallengeWindow(i, w, now) == (bool)exp["within"]! && Optimistic.ClaimStatus(i, w, now) == (string)exp["phase"]!, $"window/{v["name"]}");
        }
        foreach (var v in Rows(doc, "optimistic_fraud_proof"))
        {
            var got = Optimistic.FraudProofWireCheck(v["claim"], v["proof"]);
            Assert.True(got == (string)D(v["expect"])["check"]!, $"fraud/{v["name"]}: got {got} want {D(v["expect"])["check"]}");
        }
        foreach (var v in Rows(doc, "optimistic_settlement"))
        {
            var got = Optimistic.SettlementWireCheck(v["record"], S(v["guardian_public"]), PinsOf(v));
            var want = Lacks(v) ? "suite" : (string)D(v["expect"])["check"]!;
            Assert.True(got == want, $"settlement/{v["name"]}: got {got} want {want}");
        }
    }

    [Fact]
    public void LedgerVectors()
    {
        var doc = Load("ledger-vectors.json");
        Assert.Equal(doc["empty_tree_root"], Ledger.EmptyTreeRoot);
        var doms = D(doc["domains"]);
        Assert.True((string)doms["sth"]! == Ledger.SthDomain && (string)doms["sth_witness"]! == Ledger.SthWitnessDomain && (string)doms["ledger_head"]! == Ledger.LedgerHeadDomain
            && (string)doms["optimistic_claim"]! == Optimistic.ClaimDomain && (string)doms["settlement"]! == Optimistic.SettlementDomain, "domain separators differ from the corpus");
        bool OkOf(D v) => (bool)D(v["expect"])["ok"]!;
        void Chk(string table, D v, bool got, bool want) => Assert.True(got == (want && !Lacks(v)), $"{table}/{v["name"]}: got {got} want {want}");
        foreach (var v in Rows(doc, "ledger_inclusion")) Chk("inclusion", v, Ledger.VerifyLedgerInclusion(S(v["root"]), v["proof"], v["leaf"]), OkOf(v));
        foreach (var v in Rows(doc, "ledger_consistency")) Chk("consistency", v, Ledger.VerifyLedgerConsistency(v["old_root"], v["new_root"], v["proof"]), OkOf(v));
        foreach (var v in Rows(doc, "ledger_tree_head")) Chk("tree_head", v, Ledger.VerifyTreeHead(v["sth"], S(v["guardian_public"]), null, PinsOf(v)), OkOf(v));
        foreach (var v in Rows(doc, "ledger_cosign")) Chk("cosign", v, Ledger.VerifyTreeHead(v["sth"], S(v["guardian_public"]), PolicyOf(v["policy"]), PinsOf(v)), OkOf(v));
        foreach (var v in Rows(doc, "ledger_head_consistency")) Chk("head_consistency", v, Ledger.VerifyHeadConsistency(v["older"], v["newer"], v["proof"], S(v["guardian_public"]), null, PinsOf(v)), OkOf(v));
        foreach (var v in Rows(doc, "ledger_checkpoint_chain"))
        {
            var got = Ledger.VerifyCheckpointChain(v["chain"], S(v["guardian_public"]), PolicyOf(v["policy"]), PinsOf(v));
            var exp = D(v["expect"]);
            Assert.True(got.Ok == (bool)exp["ok"]! && (got.Ok || got.At == N(exp["at"])), $"chain/{v["name"]}: got {got} want ok={exp["ok"]} at={exp.GetValueOrDefault("at")}");
        }
        foreach (var v in Rows(doc, "ledger_witnessed_head")) Chk("witnessed_head", v, Ledger.VerifyWitnessedHead(v["head"], S(v["witness_public"]), PinsOf(v)), OkOf(v));
        foreach (var v in Rows(doc, "ledger_equivocation")) Chk("equivocation", v, Ledger.DetectEquivocation(v["a"], v["b"], S(v["witness_public"]), PinsOf(v)), (bool)D(v["expect"])["equivocation"]!);
    }

    [Fact]
    public void MeshVectors()
    {
        var vecs = L(Load("mesh-vectors.json")["mesh"]);
        Assert.True(vecs.Count >= 100, $"expected at least 100 mesh vectors, got {vecs.Count}");
        foreach (var raw in vecs)
        {
            var v = D(raw);
            var name = (string)v["name"]!;
            var expect = D(v["expect"]);
            bool wantOk = (bool)expect["ok"]!;
            var got = Mesh.Verify(v["proof"], v["trust"]);
            Assert.True(got.Ok == wantOk, $"{name}: ok = {got.Ok} (reason '{got.Reason}'), want {wantOk} (reason '{expect.GetValueOrDefault("reason")}')");
            if (wantOk) continue;
            var wantReason = expect.GetValueOrDefault("reason") as string ?? "";
            if (wantReason.StartsWith("chain:", StringComparison.Ordinal))
            {
                Assert.True(got.Reason.StartsWith("chain:", StringComparison.Ordinal), $"{name}: reason '{got.Reason}', want a chain refusal ('{wantReason}')");
                continue;
            }
            Assert.True(got.Reason == wantReason, $"{name}: reason '{got.Reason}', want '{wantReason}'");
            int wantHop = expect.TryGetValue("hop", out var h) ? (int)N(h) : -1;
            Assert.True(got.Hop == wantHop, $"{name}: hop {got.Hop}, want {wantHop}");
        }
    }

    // Units beyond the corpus: hostile shapes never throw and are never accepted; the window edge is inclusive; JS number text.
    [Fact]
    public void HostileInputsNeverThrowAndAreRefused()
    {
        var bad = new[] { "null", "1", "\"x\"", "[]", "{}", "{\"size\":1e999}", "[null]", "{\"sth\":null,\"proof\":null}" }.Select(Pca.ParseJson).ToList();
        foreach (var v in bad)
        {
            Assert.False(Ledger.VerifyLedgerConsistency(v, v, v));
            Assert.False(Ledger.VerifyTreeHead(v, "k", null));
            Assert.False(Ledger.VerifyTreeHead(v, "k", new D { ["threshold"] = new Num("0") }));
            Assert.False(Ledger.VerifyWitnessedHead(v, "k"));
            Assert.False(Ledger.VerifyWitnessCosignature(v, v, "k"));
            Assert.False(Ledger.VerifyHeadConsistency(v, v, v, "k", null));
            Assert.False(Ledger.DetectEquivocation(v, v, "k"));
            Assert.False(Ledger.VerifyCheckpointChain(v, "k", null).Ok);
            Assert.False(Ledger.VerifyLedgerInclusion("r", v, v));
            Assert.NotEqual("ok", Optimistic.FraudProofWireCheck(v, v));
            Assert.NotEqual("ok", Optimistic.SettlementWireCheck(v, "k"));
            Assert.NotEqual("ok", Optimistic.ClaimCheck(v, "d", "k", 0, ChallengeWindowPolicy.Default));
            Assert.False(Mesh.Verify(v, v).Ok);
        }
    }

    [Fact]
    public void WindowBoundaryAndNonFinite()
    {
        Assert.True(Optimistic.WithinChallengeWindow(100, 50, 150));
        Assert.False(Optimistic.WithinChallengeWindow(100, 50, 151));
        Assert.Equal("finalized", Optimistic.ClaimStatus(100, 50, 151));
        Assert.Equal("open", Optimistic.ClaimStatus(100, 50, 150));
        Assert.False(Optimistic.WithinChallengeWindow(100, 50, double.PositiveInfinity));
        Assert.False(Optimistic.WithinChallengeWindow(100, 50, double.NaN));
    }

    [Fact]
    public void LenientCanonicalFollowsNumberToString()
    {
        foreach (var (d, s) in new (double, string)[] { (0, "0"), (-0.0, "0"), (1, "1"), (1.5, "1.5"), (100, "100"), (1e21, "1e+21"), (123456789012345680000.0, "123456789012345680000"),
            (1e-6, "0.000001"), (1e-7, "1e-7"), (-0.00001234, "-0.00001234"), (0.1 + 0.2, "0.30000000000000004"), (9007199254740991, "9007199254740991") })
            Assert.Equal(s, JsCanon.NumberString(d));
        Assert.Equal("{\"a\":[1,\"\\ud800\"],\"b\":null}", JsCanon.Lenient(new D { ["b"] = null, ["a"] = new L { new Num("1.0"), "\ud800" } }));
        Assert.Null(JsCanon.Lenient(new D { ["x"] = new Num("1e999") }));
    }
}
