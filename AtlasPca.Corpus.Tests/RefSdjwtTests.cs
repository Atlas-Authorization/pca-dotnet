using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using AtlasPca.Jose;
using AtlasPca.Sdjwt;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using J = AtlasPca.Jose.Jose;
using L = System.Collections.Generic.List<object?>;
using S = AtlasPca.Sdjwt.Sdjwt;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the pca-sdjwt oracle. Issuance is compared in a normalized form (salts are random in a native); presentation exactly (Ed25519 key-binding
/// signatures are deterministic); a verification refusal reason is compared exactly only when it is this package's own (or the canonical gate's), a reason in
/// the JOSE library's wording only has to be a refusal; verifyRecovered compares allow, and the reason when it is this package's own.</summary>
public class RefSdjwtTests
{
    const string M = "ref-sdjwt";

    /// <summary>{"$bytes": b64u} members (at any depth) become byte[].</summary>
    static object? Rev(object? v) => v switch
    {
        L l => l.Select(Rev).ToList(),
        D m when m.Count == 1 && m.ContainsKey("$bytes") => Base.Bytes(m),
        D m => m.ToDictionary(e => e.Key, e => Rev(e.Value)),
        _ => v,
    };

    static string Sha(string ascii) => Pca.B64u(SHA256.HashData(ascii.Select(c => (byte)c).ToArray()));

    static readonly (string Snake, string Camel)[] Camel =
    {
        ("required_disclosures", "requiredDisclosures"), ("expected_audience", "expectedAudience"), ("expected_kb_audience", "expectedKbAudience"),
        ("expected_nonce", "expectedNonce"), ("require_key_binding", "requireKeyBinding"), ("algorithms", "algorithms"), ("kb_algorithms", "kbAlgorithms"),
        ("now", "now"), ("kb_max_age_sec", "kbMaxAgeSec"), ("clock_tolerance_sec", "clockToleranceSec"), ("key_binding_key", "keyBindingKey"),
    };

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D
    {
        ["SD_ALG"] = S.SdAlg, ["PCA_SD_JWT_TYP"] = S.PcaSdJwtTyp, ["KB_JWT_TYP"] = S.KbJwtTyp, ["DEFAULT_SIGNING_ALG"] = S.DefaultSigningAlg,
        ["PCA_CAPABILITY_CLAIMS"] = S.PcaCapabilityClaims.Cast<object?>().ToList(),
    });

    [Fact]
    public void Ed25519PublicJwk() => Base.Check(M, "ed25519PublicJwk", a => S.Ed25519PublicJwk(Base.Bytes(a[0])));

    [Fact]
    public void ImportEd25519PrivateKey() => Base.Check(M, "importEd25519PrivateKey", a => { S.ImportEd25519PrivateKey(Base.Bytes(a[0])); return "ok"; });

    [Fact]
    public void ImportEd25519PublicKey() => Base.Check(M, "importEd25519PublicKey", a => { S.ImportEd25519PublicKey(Base.Bytes(a[0])); return "ok"; });

    /// <summary>The reference's normalized view of an issued SD-JWT (salts are random).</summary>
    static D NormalizeIssued(string sd, byte[] seed)
    {
        var parts = sd.Split('~');
        var ds = parts.Skip(1).Take(parts.Length - 2).ToList();
        object? Dec(string x) => Pca.ParseJson(Encoding.UTF8.GetString(Pca.B64uDecode(x)!));
        var hp = parts[0].Split('.');
        var h = Dec(hp[0]); var p = (D)Dec(hp[1])!;
        var disc = ds.Select(d => (L)Dec(d)!).Select(t => new L { t[1], t[2] }).OrderBy(x => (string)x[0]!, StringComparer.Ordinal).Cast<object?>().ToList();
        var dig = ds.Select(Sha).OrderBy(x => x, StringComparer.Ordinal).ToList();
        var sdl = (p.GetValueOrDefault("_sd") as L ?? new L()).Cast<string>().OrderBy(x => x, StringComparer.Ordinal).ToList();
        var rest = new D(p); rest.Remove("_sd");
        var ver = S.VerifyPcaSdJwt(sd, new D { ["issuerKey"] = S.ImportEd25519PublicKey(EdKey.FromSeed(seed).Pub), ["now"] = IntentJs.NumOf(p["iat"])!.Value * 1000 });
        return new D
        {
            ["end"] = parts[^1], ["header"] = h, ["payload"] = rest, ["n"] = ds.Count, ["digestsOk"] = dig.SequenceEqual(sdl),
            ["disclosures"] = disc, ["verified"] = ver["ok"],
        };
    }

    [Fact]
    public void IssuePcaSdJwt() => Base.Check(M, "issuePcaSdJwt", a =>
    {
        var pc = a[0] as D;
        var opt = (D)a[1]!;
        var seed = Base.Bytes(opt["issuer_seed"]);
        var o2 = new D { ["issuerKey"] = S.ImportEd25519PrivateKey(seed) };
        foreach (var k in new[] { "disclosable", "iss", "sub", "typ" }) if (opt.ContainsKey(k)) o2[k] = opt[k];
        if (opt.ContainsKey("signing_alg")) o2["signingAlg"] = opt["signing_alg"];
        if (opt.ContainsKey("key_binding"))
        {
            var kb = opt["key_binding"];
            o2["keyBinding"] = kb is D kbm && kbm.ContainsKey("holder_public_key") ? new D { ["holderPublicKey"] = Rev(kbm["holder_public_key"]) } : Rev(kb);
        }
        return NormalizeIssued(S.IssuePcaSdJwt(pc, o2), seed);
    });

    [Fact]
    public void Present() => Base.Check(M, "present", a =>
    {
        var options = new D();
        if (a.Count > 2 && a[2] is D opt && opt.ContainsKey("key_binding"))
        {
            var kb = (D)opt["key_binding"]!;
            var k = new D { ["holderKey"] = S.ImportEd25519PrivateKey(Base.Bytes(kb["holder_seed"])) };
            foreach (var n in new[] { "audience", "nonce", "iat", "alg" }) if (kb.ContainsKey(n)) k[n] = kb[n];
            options["keyBinding"] = k;
        }
        return S.Present(a[0], a[1], options);
    });

    static readonly string[] Own =
    {
        "pca-sdjwt:", "non-canonical compact JWS", "required disclosure", "KB-JWT ", "cnf key does not", "key binding required", "duplicate disclosure",
        "unsupported _sd_alg", "a presented disclosure", "a digest appears", "an array", "an object-property", "disclosure claim", "_sd must be", "'",
    };

    static string Clip(string r) => r.StartsWith("non-canonical compact JWS: bad-json", StringComparison.Ordinal) ? r.Split(" (")[0] : r;

    static bool CmpVerify(D c, object? have)
    {
        var want = (D)c["out"]!;
        var g = (D)have!;
        if (want["ok"] is false)
        {
            if (g["ok"] is not false) return false;
            var r = (string)want["reason"]!; var gr = (string)g["reason"]!;
            if (r.StartsWith("KB-JWT signature/claims invalid", StringComparison.Ordinal)) return gr.StartsWith("KB-JWT signature/claims invalid", StringComparison.Ordinal);
            foreach (var p in Own) if (r.StartsWith(p, StringComparison.Ordinal)) return Clip(gr) == Clip(r);
            return true;
        }
        return Base.Eq(want, have);
    }

    [Fact]
    public void VerifyPcaSdJwt() => Base.Check(M, "verifyPcaSdJwt", a =>
    {
        var opt = (D)a[1]!;
        var ik = Rev(opt["issuer_key"]);
        var o2 = new D { ["issuerKey"] = ik is byte[] raw ? S.ImportEd25519PublicKey(raw) : J.ImportJwk((D)ik!, opt.GetValueOrDefault("issuer_jwk_alg") as string ?? "ES256") };
        foreach (var (snake, camel) in Camel) if (opt.ContainsKey(snake)) o2[camel] = Rev(opt[snake]);
        return S.VerifyPcaSdJwt(a[0], o2);
    }, eq: CmpVerify);

    [Fact]
    public void VerifyRecovered() => Base.Check(M, "verifyRecovered", a =>
    {
        var opt = (D)a[1]!;
        double? now = opt.ContainsKey("now") ? IntentJs.NumOf(opt["now"]) : null;
        var r = S.VerifyRecovered((D)a[0]!, (D)opt["grant"]!, opt.ContainsKey("audience"), opt.GetValueOrDefault("audience") as string, now == null ? null : (long)now.Value,
            opt.GetValueOrDefault("insecure_skip_plan_root_check") is true);
        var o = new D { ["allow"] = r.Allow };
        if (r.Reason != null) o["reason"] = r.Reason;
        return o;
    }, eq: (c, have) =>
    {
        var want = (D)c["out"]!; var g = (D)have!;
        if (!Equals(g["allow"], want["allow"])) return false;
        return !(want.GetValueOrDefault("reason") is string r && r.StartsWith("pca-sdjwt:", StringComparison.Ordinal)) || r == g.GetValueOrDefault("reason") as string;
    });

    [Fact]
    public void EveryFnIsHandled() { Base.Covers(M, new[]
    {
        "constants", "ed25519PublicJwk", "importEd25519PrivateKey", "importEd25519PublicKey", "issuePcaSdJwt", "present", "verifyPcaSdJwt", "verifyRecovered",
    }); Assert.Equal(353, Base.Total(M)); }
}
