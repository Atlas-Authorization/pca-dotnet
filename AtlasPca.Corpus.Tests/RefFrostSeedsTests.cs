using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;
using static AtlasPca.Frost;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Core FROST over the corpus that carries no key material (test-data/ref-frost.json.gz). A secret in an argument is a descriptor resolved here:
/// <c>{"$seed": label}</c> is sha256("atlas-pca-conformance/" + label); <c>{"$share": {t, n, secret, coefficients, identifiers, id}}</c> is that
/// participant's dealer share, recomputed with the native key generation; <c>{"$nonce": {r, share}}</c> is the commit nonce H3(r || share). A secret in an
/// expected result is <c>{"$sha256": digest}</c>, and the native bytes are hashed the same way before the comparison.</summary>
public class RefFrostSeedsTests
{
    const string M = "ref-frost";

    static D B(byte[] b) => new() { ["$bytes"] = Pca.B64u(b) };

    sealed class Restorer
    {
        readonly Dictionary<string, FrostKeygenResult> _keygens = new();

        byte[] Bytes(object? v)
        {
            if (Base.IsBytes(v)) return Base.Bytes(v);
            if (v is not D o || o.Count != 1) throw new ArgumentException("not a descriptor");
            var (k, x) = o.First();
            switch (k)
            {
                case "$seed": return SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + (string)x!));
                case "$share":
                {
                    var d = (D)x!;
                    var body = new D(d);
                    body.Remove("id");
                    var key = Base.Show(body);
                    if (!_keygens.TryGetValue(key, out var kg))
                    {
                        var opts = new FrostKeygenOpts { Secret = d.GetValueOrDefault("secret") == null ? null : Bytes(d["secret"]) };
                        if (d.GetValueOrDefault("coefficients") is L cs) opts.Coefficients = cs.Select(Bytes).ToList();
                        if (d.GetValueOrDefault("identifiers") is L ids) opts.Identifiers = ids.Select(Base.Long).ToArray();
                        _keygens[key] = kg = TrustedDealerKeygen((int)Base.Long(d["t"]), (int)Base.Long(d["n"]), opts);
                    }
                    long id = Base.Long(d["id"]);
                    return kg.ParticipantShares.First(s => s.Identifier == id).Share;
                }
                case "$nonce":
                {
                    var d = (D)x!;
                    var r = Bytes(d["r"]);
                    if (r.Length != 32) throw new ArgumentException("nonce randomness must be 32 bytes");
                    return ScalarToBytes(H3(r.Concat(ScalarToBytes(BytesToScalar(Bytes(d["share"])))).ToArray()));
                }
                default: throw new ArgumentException("unknown descriptor " + k);
            }
        }

        public object? Restore(object? v) => v switch
        {
            L l => l.Select(Restore).ToList(),
            D o when o.Count == 1 && o.Keys.First() is "$seed" or "$share" or "$nonce" => B(Bytes(o)),
            D o => o.ToDictionary(e => e.Key, e => Restore(e.Value)),
            _ => v,
        };
    }

    // the native result with every value the expected result hides behind {"$sha256"} hashed the same way
    static object? Mask(object? want, object? have)
    {
        if (want is D w && w.Count == 1 && w.GetValueOrDefault("$sha256") is string && Base.IsBytes(have))
            return new D { ["$sha256"] = Pca.B64u(SHA256.HashData(Base.Bytes(have))) };
        return have switch
        {
            L l => l.Select((x, i) => Mask(want is L wl && i < wl.Count ? wl[i] : null, x)).ToList(),
            D o => o.ToDictionary(e => e.Key, e => Mask((want as D)?.GetValueOrDefault(e.Key), e.Value)),
            _ => have,
        };
    }

    [Fact]
    public void EveryCase()
    {
        var restorer = new Restorer();
        var bad = new List<string>();
        int n = 0;
        foreach (var c in Base.Cases(M))
        {
            n++;
            var fn = (string)c["fn"]!;
            var name = (string)c["name"]!;
            Assert.True(RefFrostTests.Fns.TryGetValue(fn, out var run), $"{M}: fn with no test: {fn}");
            bool wantThrow = Base.Throws(c, out _);
            object? have;
            try
            {
                // the flow cases give their one argument bare, the others an argument list
                var args = restorer.Restore(c["args"]);
                have = Base.Json(run!(args as L ?? new L { args }));
            }
            catch (Exception e)
            {
                if (!wantThrow) bad.Add($"{name}\n   want {Base.Show(c["out"])}\n   threw {e.GetType().Name}: {e.Message}");
                continue;
            }
            if (wantThrow) bad.Add($"{name}\n   want throw {Base.Show(c["out"])}\n   have {Base.Show(have)}");
            else if (Base.Show(c["out"]) != Base.Show(Mask(c["out"], have))) bad.Add($"{name}\n   want {Base.Show(c["out"])}\n   have {Base.Show(Mask(c["out"], have))}");
        }
        Assert.True(bad.Count == 0, $"{M}: {bad.Count} of {n} divergent:\n" + string.Join("\n", bad.Take(40)));
        Assert.Equal(260, n);
    }
}
