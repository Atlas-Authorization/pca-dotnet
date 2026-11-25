using System.Security.Cryptography;
using System.Text;
using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Release signing of the built-in defs: the reviewer key derives from a seed label, the output is {verb: attestation}.</summary>
public class RefSignBuiltinsTests
{
    const string M = "ref-sign-builtins";

    [Fact]
    public void SignBuiltins() => Base.Check(M, "signBuiltins", a =>
    {
        var secret = SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + (string)a[0]!));
        var o = new D();
        foreach (var x in ActionBuiltin.SignBuiltins((string)a[1]!, secret, a[2]))
        {
            var d = (D)x!;
            o[(string)d["verb"]!] = ((D)d["review"]!)["attestation"];
        }
        return o;
    });

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "signBuiltins" }); Assert.Equal(3, Base.Total(M)); }
}
