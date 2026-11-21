using AtlasPca;
using AtlasPca.Dpop;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using DP = AtlasPca.Dpop.Dpop;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the pca-dpop oracle. Function-valued options travel as JSON specs: <c>seenJti</c> is a list of seen jti values (the result carries
/// the set's final contents as <c>seen</c>), <c>replayStore</c> {kind: memory | true | false | throws, maxEntries?, preload?}, <c>nonceIssuer</c> {secret, ttl?}.
/// Randomized signatures (RSA-PSS, ECDSA) never reach the corpus as tokens: createThenVerify records only the verification outcome.</summary>
public class RefDpopTests
{
    const string M = "ref-dpop";
    const double T0 = 1_800_000_000;

    static double? Num(object? v) => IntentJs.NumOf(v);

    sealed class SeenSet : IJtiSeenSet
    {
        public readonly List<string> Order = new();
        readonly HashSet<string> _set = new();
        public SeenSet(IEnumerable<string> init) { foreach (var s in init) Add(s); }
        public bool Has(string jti) => _set.Contains(jti);
        public void Add(string jti) { if (_set.Add(jti)) Order.Add(jti); }
    }

    sealed class FixedStore : IDpopReplayStore
    {
        readonly Func<string, bool> _f;
        public FixedStore(Func<string, bool> f) { _f = f; }
        public bool AddIfAbsent(string key, double expiresAtSec, double nowSec) => _f(key);
    }

    static IDpopReplayStore MakeStore(D s)
    {
        switch (s["kind"])
        {
            case "memory":
                {
                    var st = DP.CreateInMemoryDpopReplayStore(Num(s.GetValueOrDefault("maxEntries")));
                    if (s.GetValueOrDefault("preload") is L pre)
                        foreach (var e in pre) { var t = (L)e!; st.AddIfAbsent((string)t[0]!, Num(t[1])!.Value, Num(t[2])!.Value); }
                    return st;
                }
            case "true": return new FixedStore(_ => true);
            case "false": return new FixedStore(_ => false);
            default: return new FixedStore(_ => throw new InvalidOperationException("boom"));
        }
    }

    static (VerifyDpopProofOptions Opts, SeenSet? Seen) VerifyOpts(D o)
    {
        SeenSet? seen = o.GetValueOrDefault("seenJti") is L ids ? new SeenSet(ids.OfType<string>()) : null;
        var opts = new VerifyDpopProofOptions
        {
            Method = o.GetValueOrDefault("method") as string,
            Url = o.GetValueOrDefault("url") as string,
            MaxAgeSec = Num(o.GetValueOrDefault("maxAgeSec")) ?? 0,
            ExpectedJkt = o.GetValueOrDefault("expectedJkt") as string,
            SeenJti = seen,
            ReplayStore = o.GetValueOrDefault("replayStore") is D rs ? MakeStore(rs) : null,
            RequireReplayStore = o.GetValueOrDefault("requireReplayStore") as bool?,
            NonceIssuer = o.GetValueOrDefault("nonceIssuer") is D ni ? DP.CreateDpopNonceIssuer(Pca.B64uDecode(ni["secret"]), Num(ni.GetValueOrDefault("ttl"))) : null,
            NowSec = Num(o.GetValueOrDefault("nowSec")),
            ExpectedNonce = o.GetValueOrDefault("expectedNonce") as string,
            AccessToken = o.GetValueOrDefault("accessToken") as string,
        };
        return (opts, seen);
    }

    static D WithSeen(DpopVerifyResult r, SeenSet? seen)
    {
        var o = new D { ["claims"] = r.Claims, ["jwk"] = r.Jwk, ["jkt"] = r.Jkt };
        if (seen != null) o["seen"] = seen.Order.Cast<object?>().ToList();
        return o;
    }

    static CreateDpopProofInput CreateInput(D i) => new()
    {
        Method = i.GetValueOrDefault("method") as string,
        Url = i.GetValueOrDefault("url") as string,
        PrivateKey = i.GetValueOrDefault("privateKey"),
        PublicJwk = i.GetValueOrDefault("publicJwk") as D,
        Nonce = i.GetValueOrDefault("nonce") as string,
        Ath = i.GetValueOrDefault("ath") as string,
        Iat = Num(i.GetValueOrDefault("iat")),
        Jti = i.GetValueOrDefault("jti") as string,
        NowMs = () => (long)(T0 * 1000),
    };

    /// <summary>A non-finite MaxAgeSec would disable the stale check and a non-finite NowSec would void the window: both are refused.</summary>
    [Fact]
    public void NonFiniteMaxAgeAndNowRefused()
    {
        var seed = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("dpop-non-finite"));
        string B64(byte[] b) => System.Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var x = B64(EdKey.FromSeed(seed).Pub);
        const string url = "https://rs.example/r";
        var proof = DP.CreateDpopProof(new CreateDpopProofInput
        {
            Method = "GET", Url = url, Iat = 1800000000,
            PrivateKey = new D { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = x, ["d"] = B64(seed) },
            PublicJwk = new D { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = x },
        });
        string Code(double maxAge, double now)
        {
            try { DP.VerifyDpopProof(proof, new VerifyDpopProofOptions { Method = "GET", Url = url, MaxAgeSec = maxAge, NowSec = now, RequireReplayStore = false }); return "ok"; }
            catch (DpopVerificationException e) { return e.Code; }
        }
        Assert.Equal("ok", Code(300, 1800000001));
        foreach (var v in new[] { double.NaN, double.PositiveInfinity, double.NegativeInfinity })
        {
            Assert.Equal("max_age", Code(v, 1800000001));
            Assert.Equal("now", Code(300, v));
        }
    }

    /// <summary>ref-dpop-rsa.json.gz is generated by CI (.github/scripts/dpop-rsa-corpus.sh), never committed: required when CI is set; locally the replay is skipped (xunit 2 has no dynamic skip, so it only reports).</summary>
    [Fact]
    public void RsaCorpusIsPresent()
    {
        if (Base.RsaCorpusExists()) return;
        const string msg = "RSA DPoP corpus missing (generate with .github/scripts/dpop-rsa-corpus.sh or set PCA_DPOP_RSA_CORPUS)";
        var ci = Environment.GetEnvironmentVariable("CI");
        if (ci is "true" or "1") Assert.Fail(msg);
        Console.Error.WriteLine("SKIPPED: " + msg);
    }

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D
    {
        ["allowedAlgs"] = DP.DpopAllowedAlgs.Cast<object?>().ToList(),
        ["typ"] = DP.DpopJwtTyp,
        ["defaultMaxAgeSec"] = DP.DpopDefaultMaxAgeSec,
        ["clockSkewSec"] = DP.DpopClockSkewSec,
        ["maxProofBytes"] = DP.DpopMaxProofBytes,
        ["inMemoryMaxEntries"] = DP.DpopInmemoryMaxEntries,
    });

    [Fact]
    public void JwkThumbprint() => Base.Check(M, "jwkThumbprint", a => DP.JwkThumbprint(a[0], a.Count > 1 ? a[1] as string : null));

    [Fact]
    public void DpopAlgForJwk() => Base.Check(M, "dpopAlgForJwk", a => DP.DpopAlgForJwk(a[0]));

    [Fact]
    public void DpopAlgMatchesJwk() => Base.Check(M, "dpopAlgMatchesJwk", a => DP.DpopAlgMatchesJwk(a[0] as string, a[1]));

    [Fact]
    public void NormalizeHtu() => Base.Check(M, "normalizeHtu", a => DP.NormalizeHtu(a[0] as string));

    [Fact]
    public void AthFor() => Base.Check(M, "athFor", a => DP.AthFor((string)a[0]!));

    [Fact]
    public void NonceIssuer() => Base.Check(M, "nonceIssuer", a =>
    {
        var iss = DP.CreateDpopNonceIssuer(a[0] == null ? null : Pca.B64uDecode(a[0]), Num(a[1]));
        var issued = new List<string>();
        var outp = new L();
        foreach (var opx in (L)a[2]!)
        {
            var op = (D)opx!;
            double? now = Num(op.GetValueOrDefault("now"));
            if ((string)op["op"]! == "issue") { var n = iss.Issue(now); issued.Add(n); outp.Add(n); }
            else
            {
                var raw = op.GetValueOrDefault("nonce");
                object? nonce = raw is D d && d.ContainsKey("$issued") ? issued[(int)Num(d["$issued"])!.Value] : raw;
                outp.Add(iss.Check(nonce, now));
            }
        }
        return outp;
    });

    [Fact]
    public void ReplayStore() => Base.Check(M, "replayStore", a =>
    {
        // a maxEntries that is not a number is the reference's misconfigured refusal
        if (a[0] != null && Num(a[0]) == null) throw new DpopVerificationException("misconfigured", "maxEntries must be a positive integer");
        var st = DP.CreateInMemoryDpopReplayStore(Num(a[0]));
        var outp = new L();
        foreach (var opx in (L)a[1]!)
        {
            var op = (D)opx!;
            try { outp.Add(st.AddIfAbsent((string)op["key"]!, Num(op["exp"])!.Value, Num(op["now"])!.Value)); }
            catch (Exception) { outp.Add("throws"); }
        }
        return outp;
    });

    [Fact]
    public void ReplayConformance() => Base.Check(M, "replayConformance", a =>
    {
        var kind = (string)a[0]!;
        Func<IDpopReplayStore> make = kind switch
        {
            "memory" => () => DP.CreateInMemoryDpopReplayStore(),
            "alwaysTrue" => () => new FixedStore(_ => true),
            "alwaysFalse" => () => new FixedStore(_ => false),
            _ => () => { var seen = new HashSet<string>(); return new FixedStore(k => { lock (seen) return seen.Add(k); }); },
        };
        return DP.RunDpopReplayStoreConformance(make).Cast<object?>().ToList();
    });

    [Fact]
    public void CreateDpopProof() => Base.Check(M, "createDpopProof", a => DP.CreateDpopProof(CreateInput((D)a[0]!)));

    [Fact]
    public void CreateThenVerify() => Base.Check(M, "createThenVerify", a =>
    {
        var input = (D)a[0]!;
        var proof = DP.CreateDpopProof(CreateInput(input));
        var o = new D
        {
            ["method"] = input["method"], ["url"] = input["url"], ["maxAgeSec"] = 300.0,
            ["nowSec"] = (Num(input.GetValueOrDefault("iat")) ?? T0) + 1, ["seenJti"] = new L(),
        };
        foreach (var (k, v) in (D)a[1]!) o[k] = v;
        var (opts, seen) = VerifyOpts(o);
        return WithSeen(DP.VerifyDpopProof(proof, opts), seen);
    });

    [Fact]
    public void VerifyDpopProof() => Base.Check(M, "verifyDpopProof", a =>
    {
        var (opts, seen) = VerifyOpts((D)a[1]!);
        return WithSeen(DP.VerifyDpopProof(a[0], opts), seen);
    });

    static object? Cert(object? v) => Base.IsBytes(v) ? Base.Bytes(v) : v;

    [Fact]
    public void MtlsCnf() => Base.Check(M, "mtlsCnf", a => Cert(a[0]) switch
    {
        byte[] der => DP.MtlsCnf(der),
        string pem => DP.MtlsCnf(pem),
        _ => throw new ArgumentException("certificate must be bytes or PEM text"),
    });

    [Fact]
    public void MtlsThumbprint() => Base.Check(M, "mtlsThumbprint", a => Cert(a[0]) switch
    {
        byte[] der => DP.MtlsThumbprint(der),
        string pem => DP.MtlsThumbprint(pem),
        _ => throw new ArgumentException("certificate must be bytes or PEM text"),
    });

    [Fact]
    public void AssertMtlsBound() => Base.Check(M, "assertMtlsBound", a => Cert(a[0]) switch
    {
        byte[] der => DP.AssertMtlsBound(der, a[1]),
        string pem => DP.AssertMtlsBound(pem, a[1]),
        _ => throw new ArgumentException("certificate must be bytes or PEM text"),
    });

    [Fact]
    public void LeafHolderJwk() => Base.Check(M, "leafHolderJwk", a => DP.LeafHolderJwk(a[0]));

    [Fact]
    public void BindPcaToDpop() => Base.Check(M, "bindPcaToDpop", a => DP.BindPcaToDpop(a[0]));

    [Fact]
    public void AssertPcaDpop() => Base.Check(M, "assertPcaDpop", a =>
    {
        var o = (D)a[2]!;
        var (v, seen) = VerifyOpts(o);
        var r = DP.AssertPcaDpop(a[0], a[1], new AssertPcaDpopOptions
        {
            Method = v.Method, Url = v.Url, MaxAgeSec = Num(o.GetValueOrDefault("maxAgeSec")), SeenJti = v.SeenJti, ReplayStore = v.ReplayStore,
            RequireReplayStore = v.RequireReplayStore, NonceIssuer = v.NonceIssuer, NowSec = v.NowSec, ExpectedNonce = v.ExpectedNonce, AccessToken = v.AccessToken,
        });
        return WithSeen(r, seen);
    });

    [Fact]
    public void EveryFnIsHandled() { Base.Covers(M, new[]
    {
        "constants", "jwkThumbprint", "dpopAlgForJwk", "dpopAlgMatchesJwk", "normalizeHtu", "athFor", "nonceIssuer", "replayStore", "replayConformance",
        "createDpopProof", "createThenVerify", "verifyDpopProof", "mtlsCnf", "mtlsThumbprint", "assertMtlsBound", "leafHolderJwk", "bindPcaToDpop", "assertPcaDpop",
    }); Assert.Equal(1040, Base.Total(M)); }
}
