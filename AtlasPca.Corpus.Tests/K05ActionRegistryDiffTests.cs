using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 differential oracle of the action-kit registry layer (test-data/k05-actionregistry.json.gz, TS reference
/// packages/pca/src/action-pin.ts + packages/pca-actions/src/{pack,registry,rule22,digest}.ts). A case with <c>textPrefix</c> ends its
/// message in engine-specific text: every string that starts with the prefix compares by the prefix only.</summary>
public class K05ActionRegistryDiffTests
{
    const string M = "actionregistry";

    // a JS property read of a non-object yields undefined (an empty map); of null, a TypeError
    static D Obj(object? a) => a is D d ? d : a == null ? null! : new D();

    static object? Cut(object? v, string p) => v switch
    {
        string s when s.StartsWith(p, StringComparison.Ordinal) => p,
        D m => m.ToDictionary(e => e.Key, e => Cut(e.Value, p)),
        L l => l.Select(x => Cut(x, p)).ToList(),
        _ => v,
    };
    static bool PrefixEq(D c, object? have) => c.GetValueOrDefault("textPrefix") is string p
        ? K05.Show(Cut(c["out"], p)) == K05.Show(Cut(K05.Json(have), p))
        : K05.Eq(c["out"], have);

    /// <summary>ALLKEYS of the generator (Ed25519, ML-DSA-65 and hybrid registry keys): the key list of its first verifyPack case.</summary>
    static object? AllKeys => K05.Args(K05.Of(M, "verifyPack").First(c => (string)c["name"]! == "verifyPack/p1"))[1];

    [Fact] public void CompareVersions() => K05.Check(M, "compareVersions", a => Math.Sign(Actions.CompareVersions((string)a[0]!, (string)a[1]!)));
    [Fact] public void EvolutionRecordError() => K05.Check(M, "evolutionRecordError", a => Actions.EvolutionRecordError(a[0], a[1] is true), eq: PrefixEq);
    [Fact] public void EvolutionDiffDigest() => K05.Check(M, "evolutionDiffDigest", a => Actions.EvolutionDiffDigest((D)a[0]!));

    // typed (string, map, map, keys) port: a non-object body cannot be passed
    [Fact]
    public void VerifyRegistrySig() => K05.Check(M, "verifyRegistrySig", a => Actions.VerifyRegistrySig((string)a[0]!, (D)a[1]!, (D)a[2]!, a[3]), eq: PrefixEq,
        skip: c => K05.Args(c)[1] is D && K05.Args(c)[2] is D ? null : "non-object body (typed port)");

    [Fact] public void VerifyEvolutionRecord() => K05.Check(M, "verifyEvolutionRecord", a => Actions.VerifyEvolutionRecord(a[0], a[1]), eq: PrefixEq);
    [Fact] public void ReapprovalValid() => K05.Check(M, "reapprovalValid", a => Actions.ReapprovalValid(a[0], a[1], a[2], a[3], a[4]));
    [Fact] public void ActionPinError() => K05.Check(M, "actionPinError", a => Actions.ActionPinError(a[0]));
    [Fact] public void DecidePin() => K05.Check(M, "decidePin", a => Actions.DecidePin((D)a[0]!), eq: PrefixEq);
    [Fact] public void PackShapeError() => K05.Check(M, "packShapeError", a => Actions.PackShapeError(a[0], a[1] is true), eq: PrefixEq, min: 12000);

    [Fact]
    public void PackDefs() => K05.Check(M, "packDefs", a => Actions.PackDefs((D)a[0]!, a[1] as D).Select(d => ((D)d!)["verb"]).ToList());

    [Fact]
    public void VerifyPack() => K05.Check(M, "verifyPack", a =>
    {
        var r = Actions.VerifyPack(a[0], a[1], a[2] as D);
        return r["ok"] is true ? new D { ["ok"] = true, ["digest"] = r["digest"], ["verbs"] = ((L)r["defs"]!).Select(d => ((D)d!)["verb"]).ToList() } : r;
    }, eq: PrefixEq);

    // keepContent: false (natives do not recompute the semantic upgrade diff): ok / status / code compare, reason only when code = bad_pack
    static object? Steps(object? v) => K05.Json(v) is L l
        ? l.Select(x => { var m = new D((D)x!); if (m.GetValueOrDefault("code") as string != "bad_pack") m.Remove("reason"); return (object?)m; }).ToList()
        : v;

    [Fact]
    public void PackTracker() => K05.Check(M, "packTracker", a =>
    {
        var t = new Actions.PackTracker(AllKeys);
        return ((L)a[0]!).Select(st => { var s = (L)st!; return (object?)t.Accept((D)s[0]!, s[1] as D); }).ToList();
    }, eq: (c, h) => K05.Show(Steps(c["out"])) == K05.Show(Steps(h)));

    [Fact]
    public void Rule22Decide() => K05.Check(M, "rule22Decide", a => Actions.Rule22Decide((D)a[0]!, (string)a[1]!, Obj(a[2]), (L)a[3]!));
    [Fact] public void VerifyPackProof() => K05.Check(M, "verifyPackProof", a => Actions.VerifyPackProof((string)a[0]!, Obj(a[1]), (string)a[2]!));

    [Fact]
    public void EveryFn() => K05.Covers(M, new[]
    {
        "compareVersions", "evolutionRecordError", "evolutionDiffDigest", "verifyRegistrySig", "verifyEvolutionRecord", "reapprovalValid",
        "actionPinError", "decidePin", "packShapeError", "packDefs", "verifyPack", "packTracker", "rule22Decide", "verifyPackProof",
    });
}
