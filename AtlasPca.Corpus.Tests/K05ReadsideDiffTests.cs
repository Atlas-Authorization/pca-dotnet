using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 differential oracle of the read side and the vault / aggregate layer (test-data/k05-readside.json.gz, TS reference
/// packages/pca/src/readside.ts + read-vault.ts). Every result compares by JSON value with the reference's whole result.</summary>
public class K05ReadsideDiffTests
{
    const string M = "readside";

    static ReadInput Read(object? grant, L r) => new(grant, r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9]);

    [Fact] public void ValidReadGrantBody() => K05.Check(M, "validReadGrantBody", a => ReadSide.ValidReadGrantBody(a[0]), min: 1380);
    [Fact] public void RedactRead() => K05.Check(M, "redactRead", a => ReadSide.RedactRead(new ReadInput(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10])).ToJson(), min: 3670);

    // the typed port takes a string signer: a non-string one (JS: never === a receipt's signer) maps to "", which no valid receipt carries
    [Fact]
    public void ReadChainLabels() => K05.Check(M, "readChainLabels", a =>
    {
        var c = ReadSide.ReadChainLabels(a[0], a[1] as string ?? "", (string)a[2]!, K05.Long(a[3]));
        return c.Labels != null ? new D { ["labels"] = c.Labels } : new D { ["code"] = c.Code, ["at"] = c.At };
    }, min: 1660);

    [Fact] public void CheckSink() => K05.Check(M, "checkSink", a => ReadSide.CheckSink(new SinkInput(a[0], a[1], a[2], a[3], a[4], a[5])).ToJson(), min: 380);
    [Fact] public void ReadGrantDigest() => K05.Check(M, "readGrantDigest", a => ReadSide.ReadGrantDigest((D)a[0]!), min: 2);
    [Fact] public void ReadReceiptRef() => K05.Check(M, "readReceiptRef", a => ReadSide.ReadReceiptRef((D)a[0]!), min: 1);
    [Fact] public void ValidAggregateGrantBody() => K05.Check(M, "validAggregateGrantBody", a => ReadVault.ValidAggregateGrantBody(a[0]), min: 910);
    [Fact] public void AggregateRead() => K05.Check(M, "aggregateRead", a => ReadVault.AggregateRead(new AggregateInput(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10])).ToJson(), min: 1870);

    /// <summary>RedactReadWithVault into a fresh vault, then detokenize the given token (or the one minted for path a[5]).</summary>
    [Fact]
    public void Vault() => K05.Check(M, "vault", a =>
    {
        var ra = (L)a[1]!; var da = (L)a[3]!;
        var store = new MemoryVault();
        var red = ReadVault.RedactReadWithVault(Read(a[0], ra), store);
        var token = a[4] ?? (a[5] is string p ? red.View.GetValueOrDefault(p) : null);
        var det = ReadVault.Detokenize(new DetokenizeInput(a[2], da[0], da[1], da[2], token, store));
        return new D { ["redact"] = red.ToJson(), ["detok"] = det.ToJson() };
    }, min: 400);

    [Fact]
    public void Uniform() => K05.Check(M, "uniform", a =>
    {
        var d = ReadVault.SeededDraws((string)a[0]!);
        return ((L)a[1]!).Select(b => d.Uniform(K05.Long(b))).ToList();
    }, min: 7);

    [Fact]
    public void Laplace() => K05.Check(M, "laplace", a =>
    {
        var d = ReadVault.SeededDraws((string)a[0]!);
        long s = K05.Long(a[1]), t = K05.Long(a[2]);
        var o = new List<long>();
        for (var i = K05.Long(a[3]); i > 0; i--) o.Add(ReadVault.DiscreteLaplace(d, s, t));
        return o;
    }, min: 50);

    [Fact]
    public void EveryFn() => K05.Covers(M, new[]
    {
        "validReadGrantBody", "redactRead", "readChainLabels", "checkSink", "readGrantDigest", "readReceiptRef", "validAggregateGrantBody",
        "aggregateRead", "vault", "uniform", "laplace",
    });
}
