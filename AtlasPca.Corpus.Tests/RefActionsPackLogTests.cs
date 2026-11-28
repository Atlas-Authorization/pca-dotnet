using AtlasPca.ActionsKit;
using AtlasPca.Scitt;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using ScittApi = AtlasPca.Scitt.Scitt;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of appending an action pack to a transparency log and verifying the entry against the TypeScript reference.</summary>
public class RefActionsPackLogTests
{
    const string M = "ref-actions-pack-log";

    [Fact]
    public void AppendPackToLog() => Base.Check(M, "appendPackToLog", a =>
    {
        var spec = (D)a[1]!;
        var svc = new TransparencyService("EdDSA", CoseKey.Ed25519Private(Pca.B64uDecode(spec["tsSeed"])!), "ts");
        var other = CoseKey.Ed25519Private(SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/ref-actions-pack-log/other")));
        for (int i = 0; i < int.Parse(((Num)spec["preload"]!).Raw); i++)
            svc.Register(ScittApi.SignStatement(new D { ["i"] = (long)i }, new SignStatementOpts("EdDSA", other, "other", $"s{i}")));
        var r = ActionTransparency.AppendPackToLog((D)a[0]!, svc, "EdDSA", CoseKey.Ed25519Private(Pca.B64uDecode(spec["regSeed"])!), (string)spec["issuer"]!);
        return new D { ["statement"] = r.Statement, ["receipt"] = r.Receipt, ["index"] = r.Index, ["root"] = r.Root };
    });

    [Fact]
    public void VerifyPackLogEntry() => Base.Check(M, "verifyPackLogEntry", a =>
    {
        var e = (D)a[1]!; var k = (D)a[2]!;
        return ActionTransparency.VerifyPackLogEntry((D)a[0]!, Base.Bytes(e["statement"]), Base.Bytes(e["receipt"]),
            CoseKey.Ed25519Public(Pca.B64uDecode(k["registry"])!), CoseKey.Ed25519Public(Pca.B64uDecode(k["log"])!), a[3] as string);
    });

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "appendPackToLog", "verifyPackLogEntry" }); Assert.Equal(108, Base.Total(M)); }
}
