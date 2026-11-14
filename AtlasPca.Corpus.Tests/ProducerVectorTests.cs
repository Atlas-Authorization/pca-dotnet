using System.Text.RegularExpressions;
using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Replays producer-vectors.json and producer-pq-vectors.json through the public producer entry point (the one the conformance driver
// calls): every producer must reproduce the TypeScript reference's output byte for byte, and every refusal with the reference's text.
public class ProducerVectorTests
{
    static JD Doc => Load("producer-vectors.json"); // re-parsed per access; each test takes one local snapshot
    static JD PqDoc => Load("producer-pq-vectors.json");

    static string Canon(object? o) => Pca.Canonicalize(o);

    static string Refusal(Func<object?> f)
    {
        var e = Assert.Throws<ArgumentException>(() => f());
        return e.Message;
    }

    [Fact]
    public void EveryCaseIsReproducedByteForByte()
    {
        var doc = Doc;
        var keys = D(doc["keys"]);
        var cases = L(doc["cases"]);
        Assert.True(cases.Count >= 89, $"the corpus shrank: {cases.Count}");
        var refusals = 0;
        foreach (var c in cases)
        {
            var v = D(c);
            var name = (string)v["name"]!;
            var want = D(v["expect"]);
            Func<object?> run = () => ProducerVectors.Produce((string)v["op"]!, D(v["args"]), keys);
            if (want.Count == 1 && want.TryGetValue("error", out var err))
            {
                // the canonical profile's wording is per-language: a reference canonicalize refusal needs a canonicalize refusal
                if (((string)err!).StartsWith("canonicalize: ", StringComparison.Ordinal)) Assert.StartsWith("canonicalize: ", Assert.ThrowsAny<Exception>(() => run()).Message);
                else Assert.True((string)err! == Refusal(run), name);
                refusals++;
            }
            else Assert.True(Canon(want) == Canon(run()), name);
        }
        Assert.True(refusals >= 10, $"the refusal cases shrank: {refusals}");
    }

    [Fact]
    public void EveryPqCaseIsReproducedWhereExact()
    {
        var doc = PqDoc;
        var keys = D(doc["ed_keys"]);
        var pq = D(doc["pq_keys"]);
        int exact = 0, refused = 0;
        foreach (var c in L(doc["cases"]))
        {
            var v = D(c);
            var name = (string)v["name"]!;
            Func<object?> run = () => ProducerVectors.Produce((string)v["op"]!, D(v["args"]), keys, pq);
            if (L(v["exact"]).Contains("dotnet"))
            {
                Assert.True(Canon(v["expect"]) == Canon(run()), name);
                exact++;
            }
            else
            {
                // only a suite this SDK does not sign (FN-DSA) is left out, and it is refused as such
                Assert.Contains("unsupported_suite: fn-dsa-", Refusal(run));
                refused++;
            }
        }
        Assert.True(exact >= 70, $"exact cases: {exact}");
        Assert.True(refused >= 10, $"refused cases: {refused}");
    }

    [Fact]
    public void UnknownOpsAndSuitesAreRefusedAsUnsupported()
    {
        var keys = D(Doc["keys"]);
        Assert.Equal("unsupported_op: sign_everything", Refusal(() => ProducerVectors.Produce("sign_everything", new JD(), keys)));
        Assert.Equal("unsupported_suite: fn-dsa-512", Refusal(() => ProducerVectors.Produce("pq_keygen", new JD { ["family"] = "fn-dsa-512", ["seed"] = Pca.B64u(new byte[32]) }, keys)));
        Assert.Equal("unsupported_suite: fn-dsa-1024",
            Refusal(() => ProducerVectors.Produce("suite_sign", new JD { ["alg"] = "fn-dsa-1024", ["ed"] = "agent", ["message_utf8"] = "m" }, keys)));
        Assert.StartsWith("produce: no Ed25519 key 'nobody'", Refusal(() => ProducerVectors.Produce("sign_contract_reset", new JD { ["signer"] = "nobody", ["contract_id"] = "c", ["seq"] = new Num("1") }, keys)));
        Assert.Equal("produce: seq must be an integer",
            Refusal(() => ProducerVectors.Produce("sign_contract_reset", new JD { ["signer"] = "agent", ["contract_id"] = "c", ["seq"] = new Num("1.5") }, keys)));
        Assert.StartsWith("produce: the ml-dsa-65 seed must be canonical base64url of 32 bytes",
            Refusal(() => ProducerVectors.Produce("pq_keygen", new JD { ["family"] = "ml-dsa-65", ["seed"] = Pca.B64u(new byte[31]) }, keys)));
    }

    [Fact]
    public void SeededPqKeysAreDeterministicAndSizeChecked()
    {
        var seed = Enumerable.Range(0, 48).Select(i => (byte)i).ToArray();
        Assert.Equal(PqKey.FromSeed(Pq.Prim.Slh128f, seed).PkB64u, PqKey.FromSeed(Pq.Prim.Slh128f, seed).PkB64u);
        Assert.NotEqual(PqKey.FromSeed(Pq.Prim.MlDsa65, seed[..32]).PkB64u, PqKey.FromSeed(Pq.Prim.MlDsa65, seed[1..33]).PkB64u);
        Assert.Throws<ArgumentException>(() => PqKey.FromSeed(Pq.Prim.MlDsa65, seed));
        Assert.Throws<ArgumentException>(() => PqKey.FromSeed(Pq.Prim.Slh256s, seed));
    }

    // Cross-verification: the TS-produced PCActns pass THIS SDK's verifier.
    [Fact]
    public void ReferenceActionsVerify()
    {
        var n = 0;
        foreach (var c in L(Doc["cases"]))
        {
            var v = D(c);
            var a = D(v["args"]);
            if ((string)v["op"]! != "act" || a.ContainsKey("fresh_at")) continue; // fresh_at is refused without a fresh_at policy (fail closed)
            var d = Pca.VerifyPcactnCore(D(D(v["expect"])["pcactn"]), D(a["grant"]), N(a["iat"]) + 1000, (string)a["aud"]!, planRoots: PlanRootPolicy.Skip);
            Assert.True(d.Allow, $"{v["name"]}: {d.Reason}");
            n++;
        }
        Assert.True(n >= 4);
    }

    // The built-in catalog is generated from the reference's; this pins it entry by entry. The reference source is in the flagship
    // layout (packages/pca/src); CI lays it out beside this SDK. A missing file fails: the comparison is never skipped.
    [Fact]
    public void CatalogMatchesReference()
    {
        string? path = null;
        for (var d = AppContext.BaseDirectory; d != null && path == null; d = Path.GetDirectoryName(d))
        {
            var p = Path.Combine(d, "packages", "pca", "src", "catalog-builtin.generated.ts");
            if (File.Exists(p)) path = p;
        }
        Assert.True(path != null, "packages/pca/src/catalog-builtin.generated.ts not found above " + AppContext.BaseDirectory);
        var text = File.ReadAllText(path!);
        text = text[(text.IndexOf("= [", StringComparison.Ordinal) + 2)..(text.LastIndexOf("];", StringComparison.Ordinal) + 1)];
        // quote the object keys outside string literals, then drop trailing commas: the literals become JSON
        var json = Regex.Replace(text, "\"(?:[^\"\\\\]|\\\\.)*\"|([A-Za-z_][A-Za-z0-9_]*)\\s*:", m => m.Groups[1].Success ? $"\"{m.Groups[1].Value}\":" : m.Value);
        json = Regex.Replace(json, @",\s*\]", "]");
        var refs = L(Pca.ParseJson(json));
        Assert.Equal(refs.Count, Catalog.Builtin.Count);
        for (var i = 0; i < refs.Count; i++)
        {
            var r = D(refs[i]);
            var g = Catalog.Builtin[i];
            List<string> Strs(string k) => r.GetValueOrDefault(k) is JL l ? l.Cast<string>().ToList() : new List<string>();
            Assert.Equal((string)r["verb"]!, g.Verb);
            Assert.Equal((string)r["connector"]!, g.Connector);
            Assert.Equal((string)r["action"]!, g.Action);
            Assert.Equal((string)r["reversibility"]!, g.Reversibility);
            Assert.Equal(double.Parse(((Num)r["blastRadius"]!).Raw, System.Globalization.CultureInfo.InvariantCulture), g.BlastRadius);
            Assert.Equal(r.GetValueOrDefault("amountField") as string, g.AmountField);
            Assert.Equal((string)r["description"]!, g.Description);
            Assert.Equal(Strs("aliases"), g.Aliases.ToList());
            Assert.Equal(Strs("traits"), g.Traits.ToList());
        }
    }
}
