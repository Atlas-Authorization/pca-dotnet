using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the rest of the mesh module (test-data/ref-mesh-issue.json.gz): key revocation ids, the public effective authority, the size and latency
/// models, the worked example, the fork demonstration, the witness and domain scripts, cross-domain capability translation, the federated budget tree and the
/// cross-reference commitments. A non-finite number is {"$num": text}; a seed is the 32-byte seed as base64url. One op of a script that is refused is
/// {"$err": message}: the refusal is compared, its text is not.</summary>
public class RefMeshIssueTests
{
    const string M = "ref-mesh-issue";

    static object? Nums(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m => m.ToDictionary(e => e.Key, e => Nums(e.Value)),
        L l => l.Select(Nums).ToList(),
        _ => v,
    };

    /// <summary>A non-finite double back to the oracle's {"$num": text}.</summary>
    static object? Out(object? v) => v switch
    {
        double d when double.IsNaN(d) => new D { ["$num"] = "NaN" },
        double d when double.IsPositiveInfinity(d) => new D { ["$num"] = "Infinity" },
        double d when double.IsNegativeInfinity(d) => new D { ["$num"] = "-Infinity" },
        D m => m.ToDictionary(e => e.Key, e => Out(e.Value)),
        L l => l.Select(Out).ToList(),
        _ => v,
    };

    static double Dbl(object? o) => IntentJs.NumOf(o) ?? throw new ArgumentException("not a number");

    [Fact] public void Constants() => Base.Check(M, "constants", _ => Mesh.Constants());
    [Fact] public void KeyRevocationId() => Base.Check(M, "keyRevocationId", a => Mesh.KeyRevocationId(a[0]), min: 13);
    [Fact] public void EffectiveAuthority() => Base.Check(M, "effectiveAuthority", a => Mesh.EffectiveAuthority(a[0]), min: 33);
    [Fact] public void BuildMeshExample() => Base.Check(M, "buildMeshExample", a => Mesh.BuildMeshExample(a[0] == null ? null : Dbl(a[0])), min: 5);
    [Fact] public void DemonstrateForkRejection() => Base.Check(M, "demonstrateForkRejection", _ => Mesh.DemonstrateForkRejection());
    [Fact] public void MeshProofSize() => Base.Check(M, "meshProofSize", a => Mesh.MeshProofSize(a[0]), min: 27);
    [Fact] public void RevocationLatencyBound() => Base.Check(M, "revocationLatencyBound", a => Out(Mesh.RevocationLatencyBound(Nums(a[0]))), min: 239);
    [Fact] public void TranslateCapability() => Base.Check(M, "translateCapability", a => Mesh.TranslateCapability(a[0], a[1]), min: 35);
    [Fact] public void VerifyTranslatedCapability() => Base.Check(M, "verifyTranslatedCapability", a => Mesh.VerifyTranslatedCapability(a[0], a.Count > 1 ? a[1] : new D()), min: 132);
    [Fact] public void TranslatedEffectiveAuthority() => Base.Check(M, "translatedEffectiveAuthority", a => Mesh.TranslatedEffectiveAuthority(a[0]), min: 14);
    [Fact] public void CreateFederatedBudget() => Base.Check(M, "createFederatedBudget", a => Mesh.CreateFederatedBudget(a[0]), min: 28);
    [Fact] public void AllocateSub() => Base.Check(M, "allocateSub", a => Mesh.AllocateSub(a[0], a[1]), min: 37);
    [Fact] public void SpendFederated() => Base.Check(M, "spendFederated", a => Mesh.SpendFederated(a[0], a[1], a[2]), min: 43);
    [Fact] public void FederatedSafetyBound() => Base.Check(M, "federatedSafetyBound", a => Out(Mesh.FederatedSafetyBound(a[0])), min: 19);
    [Fact] public void MeshActionDigest() => Base.Check(M, "meshActionDigest", a => Mesh.MeshActionDigest(a[0]), min: 16);
    [Fact] public void CrossReferenceCommit() => Base.Check(M, "crossReferenceCommit", a => Mesh.CrossReferenceCommit(a[0]), min: 15);
    [Fact] public void AnchorCrossReference() => Base.Check(M, "anchorCrossReference", a => Mesh.AnchorCrossReference(a[0], a[1], a[2]), min: 13);
    [Fact] public void VerifyCrossReference() => Base.Check(M, "verifyCrossReference", a => Mesh.VerifyCrossReference(a[0], a[1]), min: 93);

    // ---- the domain / witness scripts

    static EdKey Key(string scope, object? label) => EdKey.FromSeed(SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/mesh-issue/" + scope + "/" + (string)label!)));

    static D Cap(object? label) => new()
    {
        ["id"] = (string)label!, ["issuer"] = "iss-" + (string)label!, ["holder"] = "h",
        ["caveats"] = new L { new D { ["type"] = "scope", ["actions"] = new L { label } } },
    };

    static T Need<T>(Dictionary<string, T> m, object? name) where T : class => m.TryGetValue((string)name!, out var v) ? v : throw new InvalidOperationException("unknown name " + name);

    /// <summary>A store whose save throws once <c>failAfter</c> saves have happened.</summary>
    sealed class FailingStore(double failAfter) : IMeshWitnessStore
    {
        readonly MemoryMeshWitnessStore _inner = new();
        double _saves;
        public D? Load() => _inner.Load();
        public void Save(D state)
        {
            if (_saves++ >= failAfter) throw new InvalidOperationException("disk");
            _inner.Save(state);
        }
    }

    static object? ErrOnly(object? v) => v switch
    {
        D m when m.Count == 1 && m.ContainsKey("$err") => new D { ["$err"] = true },
        D m => m.ToDictionary(e => e.Key, e => ErrOnly(e.Value)),
        L l => l.Select(ErrOnly).ToList(),
        _ => v,
    };

    static L Script(L ops)
    {
        var doms = new Dictionary<string, MeshDomain>();
        var ws = new Dictionary<string, MeshWitness>();
        var heads = new Dictionary<string, D>();
        var binds = new Dictionary<string, D>();
        var stores = new Dictionary<string, IMeshWitnessStore>();
        var res = new L();
        foreach (var o in ops)
        {
            var op = (L)o!;
            try
            {
                res.Add((op[0] as string) switch
                {
                    "domain" => Reg(doms, (string)op[1]!, new MeshDomain((string)op[1]!, Key("d", op[2]))).Id,
                    "witness" => Reg(ws, (string)op[1]!, new MeshWitness(Key("w", op[2]))).Id,
                    "witnessOpts" => Reg(ws, (string)op[1]!, new MeshWitness(Key("w", op[2]), WitnessOptions(op[3] as D ?? new D(), stores))).Id,
                    "store" => Put(stores, (string)op[1]!, new MemoryMeshWitnessStore()),
                    "failStore" => Put(stores, (string)op[1]!, new FailingStore(Dbl(op[2]))),
                    "storeLoad" => Need(stores, op[1]).Load(),
                    "record" => Need(doms, op[1]).Record(Cap(op[2])),
                    "revoke" => Revoke(Need(doms, op[1]), (string)op[2]!),
                    "publish" => Reg(heads, (string)op[2]!, Need(doms, op[1]).PublishHead(((L)op[4]!).Select(w => Need(ws, w)).ToList(), Dbl(op[3]), op[5] == null ? null : (int)Dbl(op[5]))),
                    "fork" => Fork(heads, op),
                    "forkHead" => ForkHead(heads, op),
                    "cosign" => Cosign(doms, ws, heads, op),
                    "lastSeen" => Need(ws, op[1]).LastSeen(op[2] is string n && doms.TryGetValue(n, out var dm) ? dm.Id : (string)op[2]!),
                    "export" => Need(ws, op[1]).ExportState(),
                    "import" => Import(ws, op),
                    "restart" => Reg(ws, (string)op[1]!, new MeshWitness(Key("w", op[3]), new MeshWitness.Options { Store = Need(stores, op[2]) })).ExportState(),
                    "consistency" => op[3] == null ? Need(doms, op[1]).ConsistencyProof(IntentJs.Lng(op[2])) : Need(doms, op[1]).ConsistencyProof(IntentJs.Lng(op[2]), IntentJs.Lng(op[3])),
                    "enroll" => Reg(binds, (string)op[2]!, Need(doms, op[1]).Enroll((string)op[3]!, (string)op[4]!)),
                    "evidence" => Need(doms, op[1]).Evidence(Cap(op[2]), Need(heads, op[3]), op[4] == null ? null : Need(binds, op[4])),
                    _ => throw new InvalidOperationException("op"),
                });
            }
            catch (Exception) { res.Add(new D { ["$err"] = "refused" }); }
        }
        return res;
    }

    static T Reg<T>(Dictionary<string, T> m, string name, T v) { m[name] = v; return v; }
    static object Put(Dictionary<string, IMeshWitnessStore> m, string name, IMeshWitnessStore s) { m[name] = s; return true; }
    static object? Revoke(MeshDomain d, string id) { d.Revoke(id); return null; }

    static MeshWitness.Options WitnessOptions(D x, Dictionary<string, IMeshWitnessStore> stores)
    {
        var o = new MeshWitness.Options();
        if (x.GetValueOrDefault("store") is string s) o.Store = Need(stores, s);
        if (x.GetValueOrDefault("clock") is { } clock) { var ms = Dbl(clock); o.Clock = () => ms; }
        if (x.GetValueOrDefault("skew") is { } skew) o.MaxClockSkewMs = Dbl(skew);
        return o;
    }

    static object? Fork(Dictionary<string, D> heads, L op) { heads[(string)op[1]!] = new D(Need(heads, op[2])) { [(string)op[3]!] = op[4] }; return null; }

    static object? ForkHead(Dictionary<string, D> heads, L op)
    {
        var h = Need(heads, op[2]);
        heads[(string)op[1]!] = new D(h) { ["head"] = new D((D)h["head"]!) { [(string)op[3]!] = op[4] } };
        return null;
    }

    static D Cosign(Dictionary<string, MeshDomain> doms, Dictionary<string, MeshWitness> ws, Dictionary<string, D> heads, L op)
    {
        var w = Need(ws, op[1]);
        var h = Need(heads, op[2]);
        var domainId = (h.GetValueOrDefault("head") as D)?.GetValueOrDefault("domain") as string;
        var d = doms.Values.FirstOrDefault(x => x.Id == domainId) ?? throw new InvalidOperationException("no such domain");
        D? consistency = null;
        if (op[3] is "domain")
        {
            var prev = w.LastSeen(domainId!);
            if (prev != null) consistency = d.ConsistencyProof(IntentJs.Lng(prev["size"]), IntentJs.Lng(((D)h["head"]!)["size"]));
        }
        else if (op[3] != null) consistency = (D)op[3]!;
        var req = new D { ["head"] = h };
        if (consistency != null) req["consistency"] = consistency;
        req["rev_ids"] = op[4] is "domain" ? d.RevocationSetCopy().List().Cast<object?>().ToList() : op[4];
        return w.Cosign(req);
    }

    static object? Import(Dictionary<string, MeshWitness> ws, L op)
    {
        var state = op[2] is D m && m.ContainsKey("$export") ? Need(ws, m["$export"]).ExportState() : (D?)op[2];
        Need(ws, op[1]).ImportState(state!);
        return null;
    }

    [Fact]
    public void MeshIssue() => Base.Check(M, "meshIssue", a => Script((L)a[0]!), eq: (c, have) => Base.Eq(ErrOnly(c["out"]), ErrOnly(have)), min: 23);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[]
        {
            "constants", "keyRevocationId", "effectiveAuthority", "buildMeshExample", "demonstrateForkRejection", "meshProofSize", "revocationLatencyBound", "meshIssue",
            "translateCapability", "verifyTranslatedCapability", "translatedEffectiveAuthority", "createFederatedBudget", "allocateSub", "spendFederated", "federatedSafetyBound",
            "meshActionDigest", "crossReferenceCommit", "anchorCrossReference", "verifyCrossReference",
        });
        Assert.Equal(787, Base.Total(M));
    }
}
