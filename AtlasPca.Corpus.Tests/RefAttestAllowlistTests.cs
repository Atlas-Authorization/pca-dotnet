using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the measurement-allowlist manifests and their transparency anchor (test-data/ref-attest-allowlist.json.gz, 959 cases): verify (every suite, every window and version rule), durable verify over one
/// in-memory key/value store, create / sign / revoke, the driver version slot, the projection and the per-vendor policy fields, the anchor commit and entry, the operator log (anchor, refresh, evidence) and verify-anchored.
/// Every fn has a handler and the totals are asserted. A refused result is compared by its <c>code</c> (the reason text is not part of the contract); a refused op inside a result list is {"$throws": message}: the native
/// must refuse there too.</summary>
public class RefAttestAllowlistTests
{
    const string M = "ref-attest-allowlist";

    static object? Nums(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m => m.ToDictionary(e => e.Key, e => Nums(e.Value)),
        L l => l.Select(Nums).ToList(),
        _ => v,
    };

    static byte[] B64(object? s) => Pca.B64uDecode(s) ?? throw new InvalidDataException("bad base64url");

    static SuiteSecretKeys Secrets(D spec)
    {
        var k = new SuiteSecretKeys();
        if (spec.GetValueOrDefault("edSecret") is { } ed) k.EdSecret = B64(ed);
        if (spec.GetValueOrDefault("seed") is { } seed && Pq.Suites.TryGetValue((string)spec["alg"]!, out var suite))
        {
            if (suite.Pq == Pq.Prim.MlDsa65) k.MlDsa = PqSuites.MlDsa65Keygen(B64(seed));
            else if (suite.Pq == Pq.Prim.MlDsa87) k.MlDsa87 = PqSuites.MlDsa87Keygen(B64(seed));
        }
        return k;
    }

    static object? Durable(L a)
    {
        var args = (D)a[0]!;
        var kv = new MemoryDurableKv();
        if (args.GetValueOrDefault("initial") is D init) foreach (var (k, v) in init) kv.SetValue(k, v);
        var results = ((L)args["steps"]!).Select(step => (object?)AttestAllowlist.VerifyAllowlistDurable(step, (D)args["opts"]!, kv)).ToList();
        return new D { ["results"] = results, ["kv"] = kv.Snapshot() };
    }

    static object? Sign(L a)
    {
        var o = (D)a[1]!;
        var spec = (D)o["keySpec"]!;
        return AttestAllowlist.SignAllowlistManifest(a[0], (string)o["issuer"]!, (string)o["alg"]!, Secrets(spec));
    }

    static object? Policy(L a)
    {
        var p = (D)a[1]!;
        return (string)a[0]! switch
        {
            "azureMaaPolicyFields" => AttestAllowlist.AzureMaaPolicyFields(p),
            "intelDcapPolicyFields" => AttestAllowlist.IntelDcapPolicyFields(p),
            "sevSnpPolicyFields" => AttestAllowlist.SevSnpPolicyFields(p),
            "gcpCsPolicyFields" => AttestAllowlist.GcpCsPolicyFields(p),
            "nvidiaCcPolicyFields" => AttestAllowlist.NvidiaCcPolicyFields(p),
            var other => throw new ArgumentException("unknown policy fn " + other),
        };
    }

    static object? AnchorOps(L a)
    {
        var args = (D)a[0]!;
        var log = AttestAllowlist.CreateAllowlistAnchorLog((string)args["instanceId"]!, (string)args["principal"]!);
        var secret = B64(args["secret"]);
        var outp = new L();
        foreach (var opO in (L)args["ops"]!)
        {
            var op = (D)opO!;
            try
            {
                if (op.ContainsKey("anchor")) outp.Add(AttestAllowlist.AnchorAllowlistHead(log, op["anchor"], secret, op["nowMs"]));
                else if (op.ContainsKey("refresh")) outp.Add(AttestAllowlist.RefreshAnchorHead(log, secret, op["refresh"]));
                else if (op.ContainsKey("evidenceFor")) outp.Add(AttestAllowlist.EvidenceFor(log, Base.Long(op["evidenceFor"]), op.GetValueOrDefault("cached") as D));
                else if (op.GetValueOrDefault("latest") is true) outp.Add(log.Latest());
                else if (op.GetValueOrDefault("entries") is true) outp.Add(log.Entries().Cast<object?>().ToList());
                else throw new ArgumentException("bad op");
            }
            catch (Exception e) { outp.Add(new D { ["$throws"] = e.Message }); }
        }
        return outp;
    }

    static bool Same(object? got, object? want)
    {
        if (want is D w && w.GetValueOrDefault("ok") is false && w.ContainsKey("code")) return got is D g0 && g0.GetValueOrDefault("ok") is false && Equals(g0.GetValueOrDefault("code"), w["code"]);
        if (want is D t && t.Count == 1 && t.ContainsKey("$throws")) return got is D g1 && g1.Count == 1 && g1.ContainsKey("$throws");
        if (want is D wd && got is D gd) return wd.Count == gd.Count && wd.All(e => gd.TryGetValue(e.Key, out var x) && Same(x, e.Value));
        if (want is L wl && got is L gl) return wl.Count == gl.Count && wl.Zip(gl).All(p => Same(p.Second, p.First));
        return Base.Show(want) == Base.Show(got);
    }

    static void Fn(string fn, Func<L, object?> run, int min) => Base.Check(M, fn, a => Base.Json(run(a)), (c, have) => Same(have, c["out"]), null, min);

    [Fact] public void Constants() => Fn("constants", _ => AttestAllowlist.Constants(), 1);
    [Fact] public void VerifyAllowlistManifest() => Fn("verifyAllowlistManifest", a => AttestAllowlist.VerifyAllowlistManifest(Nums(a[0]), Nums(a[1])), 744);
    [Fact] public void VerifyAllowlistDurable() => Fn("verifyAllowlistDurable", Durable, 23);
    [Fact] public void CreateAllowlistManifest() => Fn("createAllowlistManifest", a => AttestAllowlist.CreateAllowlistManifest(a[0]), 6);
    [Fact] public void SignAllowlistManifest() => Fn("signAllowlistManifest", Sign, 10);
    [Fact] public void RevokeAllowlistEntry() => Fn("revokeAllowlistEntry", a => AttestAllowlist.RevokeAllowlistEntry((D)a[0]!, (D)a[1]!, (D)a[2]!), 11);
    [Fact] public void DriverVersionSlotHex() => Fn("driverVersionSlotHex", a => AttestAllowlist.DriverVersionSlotHex(a[0]), 13);
    [Fact] public void ProjectAllowlist() => Fn("projectAllowlist", a => AttestAllowlist.ProjectAllowlist((D)a[0]!, ((D)a[1]!)["nowMs"]), 9);
    [Fact] public void PolicyFields() => Fn("policyFields", Policy, 45);
    [Fact] public void AnchorCommit() => Fn("anchorCommit", a => AttestAllowlist.AllowlistAnchorCommit((D)a[0]!), 4);
    [Fact] public void AnchorEntryOf() => Fn("anchorEntryOf", a => AttestAllowlist.AnchorEntryOf((D)a[0]!), 1);
    [Fact] public void AnchorOpsOnOneLog() => Fn("anchorOps", AnchorOps, 20);
    [Fact] public void VerifyAnchored() => Fn("verifyAnchored", a => { var x = (D)Nums(a[0])!; return AttestAllowlist.VerifyAllowlistAnchored(x["verified"], x["evidence"], (D)x["opts"]!); }, 72);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[]
        {
            "constants", "verifyAllowlistManifest", "verifyAllowlistDurable", "createAllowlistManifest", "signAllowlistManifest", "revokeAllowlistEntry", "driverVersionSlotHex", "projectAllowlist",
            "policyFields", "anchorCommit", "anchorEntryOf", "anchorOps", "verifyAnchored",
        });
        Assert.Equal(959, Base.Total(M));
        var counts = Base.Cases(M).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(new Dictionary<string, int>
        {
            ["constants"] = 1, ["verifyAllowlistManifest"] = 744, ["verifyAllowlistDurable"] = 23, ["createAllowlistManifest"] = 6, ["signAllowlistManifest"] = 10, ["revokeAllowlistEntry"] = 11,
            ["driverVersionSlotHex"] = 13, ["projectAllowlist"] = 9, ["policyFields"] = 45, ["anchorCommit"] = 4, ["anchorEntryOf"] = 1, ["anchorOps"] = 20, ["verifyAnchored"] = 72,
        }, counts);
        Assert.Equal(17, Base.Cases(M).Count(c => c["out"] is D o && o.Count == 1 && o.ContainsKey("$throws")));
    }
}
