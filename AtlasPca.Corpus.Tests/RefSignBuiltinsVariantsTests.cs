using System.Security.Cryptography;
using System.Text;
using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Release signing of the built-in defs over the three other corpora of the same function. Each carries its arguments its own way (a seed label under
/// <c>seed</c> or <c>secret.$seed</c>, an explicit def list or a slice of the built-ins) and its result its own way (the signed defs, or verb / state /
/// attestation triples); the reviewer key is always SHA-256 of the conformance prefix and the label.</summary>
public class RefSignBuiltinsVariantsTests
{
    static byte[] Secret(object? label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + (string)label!));

    static L Signed(D a, L? defs) => ActionBuiltin.SignBuiltins((string)a["kid"]!, Secret(a["seed"]), a["ts"], null, defs);

    // {seed, kid, ts, defs?} -> the signed defs
    [Fact]
    public void DefsInDefsOut()
    {
        const string M = "ref-actions-signbuiltins";
        Assert.Equal(8, Base.Check(M, "signBuiltins", a => Signed((D)a[0]!, ((D)a[0]!).GetValueOrDefault("defs") as L), min: 8));
        Base.Covers(M, new[] { "signBuiltins" }); Assert.Equal(8, Base.Total(M));
    }

    // {seed, kid, ts} -> the signed built-ins; and the built-in defs themselves
    [Fact]
    public void TheBuiltIns()
    {
        const string M = "ref-signbuiltins-go";
        Assert.Equal(4, Base.Check(M, "signBuiltins", a => Signed((D)a[0]!, null), min: 4));
        Assert.Equal(1, Base.Check(M, "builtinDefs", _ => ActionBuiltin.BuiltinDefs()));
        Base.Covers(M, new[] { "signBuiltins", "builtinDefs" }); Assert.Equal(5, Base.Total(M));
    }

    // {secret: {$seed}, kid, ts, from, to} -> [verb, review state, attestation] of the built-ins from..to
    [Fact]
    public void ASliceAsTriples()
    {
        const string M = "ref-actions-signbuiltins-py";
        Assert.Equal(4, Base.Check(M, "signBuiltins", a =>
        {
            var o = (D)a[0]!;
            int from = (int)Base.Long(o["from"]), to = (int)Base.Long(o["to"]);
            var all = ActionBuiltin.BuiltinDefs();
            var slice = all.GetRange(from, Math.Min(to, all.Count) - from);
            return ActionBuiltin.SignBuiltins((string)o["kid"]!, Secret(((D)o["secret"]!)["$seed"]), o["ts"], null, slice)
                .Select(x => (D)x!).Select(d => (object?)new L { d["verb"], ((D)d["review"]!)["state"], ((D)d["review"]!)["attestation"] }).ToList();
        }, min: 4));
        Base.Covers(M, new[] { "signBuiltins" }); Assert.Equal(4, Base.Total(M));
    }
}
