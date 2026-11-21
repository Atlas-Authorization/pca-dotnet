using System.Globalization;
using AtlasPca;
using AtlasPca.Jose;
using AtlasPca.Spiffe;
using Xunit;
using J = AtlasPca.Jose.Jose;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using K = AtlasPca.Corpus.Tests.RefSpiffeKit;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the second SPIFFE oracle (test-data/ref-spiffe-svid.json.gz, TS reference @atlasauth/pca-spiffe): hostile SPIFFE ids, parsed and
/// built certificates, X.509 chains, hand-assembled JWT-SVIDs, SVID to holder binding, scripted caches and admission evidence. A throw with a code needs that
/// code (a SpiffeError code or a JOSE code); an option of the wrong JSON type is refused without one, as the reference does.</summary>
public class RefSpiffeSvidTests
{
    const string M = "ref-spiffe-svid";

    static D Obj(params (string, object?)[] kv) { var d = new D(); foreach (var (k, v) in kv) d[k] = v; return d; }
    static D Dd(object? o) => (D)o!;
    static L Ll(object? o) => (L)o!;

    static object? Hk(object? v) => K.Unbytes(v);

    [Fact] public void Constants() => Base.Check(M, "constants", _ => Obj(("jwtSvidAlgorithms", new L(SpiffeBridge.JwtSvidAlgorithms.Select(x => (object?)x)))));
    [Fact] public void ParseSpiffeId() => Base.Check(M, "parseSpiffeId", a => SpiffeBridge.ParseSpiffeId(a[0]).ToJson());

    [Fact]
    public void ParseX509Svid() => Base.Check(M, "parseX509Svid", a =>
    {
        var s = SpiffeBridge.ParseX509Svid(K.Unbytes(a[0]));
        return Obj(("spiffeId", s.SpiffeId.ToJson()), ("publicKeyDer", s.PublicKeyDer));
    });

    static X509Svid X509Verified(object? chain, object? vo) => SpiffeBridge.VerifyX509Svid(K.Chain(chain), K.X509Opts(Dd(vo), new L(), true));

    [Fact]
    public void VerifyX509Svid() => Base.Check(M, "verifyX509Svid", a =>
    {
        var calls = new L();
        var r = SpiffeBridge.VerifyX509Svid(K.Chain(a[0]), K.X509Opts(Dd(a[1]), calls, true));
        return Obj(("id", r.SpiffeId.Id), ("trustDomain", r.SpiffeId.TrustDomain), ("path", r.SpiffeId.Path), ("publicKeyDer", r.PublicKeyDer), ("calls", calls));
    });

    static object? KeyOf(object? spec)
    {
        if (spec is not D k) return null;
        if (k.GetValueOrDefault("jwk") != null) return k["jwk"];
        if (k.GetValueOrDefault("jwks") != null) return J.CreateLocalJwkSet(k["jwks"]);
        return null;
    }

    static VerifyJwtSvidOptions JwtVo(object? vo, L calls)
    {
        var v = Dd(vo);
        return K.JwtOpts(v, KeyOf(v.GetValueOrDefault("key")), calls, true);
    }

    static JwtSvid JwtVerified(object? token, object? vo) => SpiffeBridge.VerifyJwtSvid(token, JwtVo(vo, new L()));

    [Fact]
    public void VerifyJwtSvid() => Base.Check(M, "verifyJwtSvid", a =>
    {
        var calls = new L();
        var r = SpiffeBridge.VerifyJwtSvid(a[0], JwtVo(a[1], calls));
        return Obj(("spiffeId", r.SpiffeId.ToJson()), ("claims", r.Claims), ("audience", r.Audience), ("expiresAt", r.ExpiresAt), ("calls", calls));
    });

    static object? BindArg(object? b) => b;

    [Fact]
    public void SvidToHolderX509() => Base.Check(M, "svidToHolderX509", a =>
        SpiffeBridge.SvidToHolder(X509Verified(a[0], a[1]), Hk(a[2]), K.Bind(BindArg(a[3]) as D)).ToJson());

    [Fact]
    public void SvidToHolderJwt() => Base.Check(M, "svidToHolderJwt", a =>
        SpiffeBridge.SvidToHolder(JwtVerified(a[0], a[1]), Hk(a[2]), K.Bind(BindArg(a[3]) as D)).ToJson());

    [Fact]
    public void SvidToHolderUnverified() => Base.Check(M, "svidToHolderUnverified", a =>
    {
        var kind = (string)a[0]!;
        object? svid = kind switch
        {
            "string" => "spiffe://example.org/workload/db",
            "object" => Obj(("spiffeId", SpiffeBridge.ParseSpiffeId("spiffe://example.org/workload/db").ToJson()), ("certificate", Obj()), ("publicKeyDer", "x")),
            "null" => null,
            "number" => new Num("5"),
            "parsed jwt-like" => Obj(("spiffeId", SpiffeBridge.ParseSpiffeId("spiffe://example.org/workload/db").ToJson()), ("claims", Obj()), ("audience", new L()), ("expiresAt", new Num("1"))),
            _ => SpiffeBridge.ParseX509Svid(a[1]),
        };
        return SpiffeBridge.SvidToHolder(svid, "x", new SvidToHolderOptions()).ToJson();
    });

    [Fact]
    public void SpiffeIdForHolder() => Base.Check(M, "spiffeIdForHolder", a =>
        SpiffeBridge.SpiffeIdForHolder(X509Verified(a[0], a[1]), a[2] as string, K.Bind(BindArg(a[3]) as D)));

    [Fact]
    public void WorkloadDischargePin() => Base.Check(M, "workloadDischargePin", a => SpiffeBridge.WorkloadDischargePin((string)a[0]!, X509Verified(a[1], a[2])));

    [Fact]
    public void HolderToSpiffeId() => Base.Check(M, "holderToSpiffeId", a =>
        SpiffeBridge.HolderToSpiffeId(new SpiffeHolder("", Dd(a[0]).GetValueOrDefault("spiffeId") as string ?? "", "", "")));

    [Fact] public void HolderBindingMessage() => Base.Check(M, "holderBindingMessage", a => SpiffeBridge.HolderBindingMessage((string)a[0]!, (string)a[1]!));

    [Fact]
    public void SpiffeAdmissionEvidence() => Base.Check(M, "spiffeAdmissionEvidence", a =>
    {
        var e = Dd(a[0]);
        var ev = new SpiffeEvidence { Kind = (string)e["kind"]! };
        if (ev.Kind == "x509")
        {
            ev.Chain = K.Chain(e["chain"]);
            ev.VerifyX509 = K.X509Opts(Dd(e["verify"]), new L(), true);
        }
        else
        {
            ev.Token = e["token"];
            ev.VerifyJwt = JwtVo(e["verify"], new L());
        }
        if (e.GetValueOrDefault("bind") is D b) ev.Bind = K.Bind(b);
        return SpiffeBridge.SpiffeAdmissionEvidence(ev, a[1] as string).ToJson();
    });

    // ---- scripted caches

    static string? CodeOf(Exception e) => e switch { SpiffeError s => s.Code, JoseException j => j.Code, _ => null };

    /// <summary>Runs the scenario the way the oracle does: a scripted clock, the fetch scripted per step, one {ok | code, fetches} result per step.</summary>
    static D Scenario(bool revocation, D opts, L steps)
    {
        long t = 0; object? cur = null; int fetches = 0;
        Fetch fetch = () =>
        {
            fetches++;
            if (cur is D c && c.ContainsKey("$throw")) throw new InvalidOperationException(c["$throw"] as string ?? "");
            if (cur is D c2 && c2.ContainsKey("$spiffe")) throw new SpiffeError((string)c2["$spiffe"]!, "x");
            return cur;
        };
        double refreshMs = K.Ms(opts.GetValueOrDefault("refreshMs")), maxStaleMs = K.Ms(opts.GetValueOrDefault("maxStaleMs"));
        SpiffeBridge.RevocationSource? rs = null;
        SpiffeBridge.TrustBundleSource? bs = null;
        try
        {
            if (revocation) rs = SpiffeBridge.CreateRevocationSource(fetch, refreshMs, maxStaleMs, () => t);
            else bs = SpiffeBridge.CreateTrustBundleSource(fetch, refreshMs, maxStaleMs, () => t);
        }
        catch (SpiffeError e) { return Obj(("ctor", e.Code)); }
        var outp = new L();
        foreach (var so in steps)
        {
            var s = Dd(so);
            t = K.N(s["at"]);
            cur = s.GetValueOrDefault("fetch");
            fetches = 0;
            var op = (string)s["op"]!;
            try
            {
                object? v = null;
                if (revocation)
                {
                    if (op == "ensureFresh") rs!.EnsureFresh();
                    else if (op == "refresh") rs!.Refresh();
                    else if (op == "x509")
                    {
                        var x = Dd(s["subject"]);
                        v = rs!.X509(new X509RevocationSubject((string)x["spiffeId"]!, (string)x["serialNumber"]!, (string)x["fingerprint256"]!, (int)K.N(x["position"]), x.GetValueOrDefault("isLeaf") is true));
                    }
                    else
                    {
                        var x = Dd(s["subject"]);
                        v = rs!.Jwt(new JwtRevocationSubject((string)x["spiffeId"]!, x.GetValueOrDefault("jti") as string, x.GetValueOrDefault("expiresAt"), (string)x["tokenHash"]!));
                    }
                }
                else if (op == "x509Roots") v = bs!.X509Roots();
                else
                {
                    bs!.JwtKey(s.GetValueOrDefault("header") as D ?? Obj(("alg", "ES256")));
                    v = "key";
                }
                outp.Add(Obj(("ok", v), ("fetches", new Num(fetches.ToString(CultureInfo.InvariantCulture)))));
            }
            catch (Exception e) { outp.Add(Obj(("code", CodeOf(e)), ("fetches", new Num(fetches.ToString(CultureInfo.InvariantCulture))))); }
        }
        return Obj(("steps", outp));
    }

    [Fact] public void TrustBundleScenario() => Base.Check(M, "trustBundleScenario", a => Scenario(false, Dd(a[0]), Ll(a[1])));
    [Fact] public void RevocationScenario() => Base.Check(M, "revocationScenario", a => Scenario(true, Dd(a[0]), Ll(a[1])));

    [Fact]
    public void AllFnsCovered() { Base.Covers(M, new[]
    {
        "constants", "parseSpiffeId", "parseX509Svid", "verifyX509Svid", "verifyJwtSvid", "svidToHolderX509", "svidToHolderJwt", "svidToHolderUnverified", "spiffeIdForHolder",
        "workloadDischargePin", "holderToSpiffeId", "holderBindingMessage", "spiffeAdmissionEvidence", "trustBundleScenario", "revocationScenario",
    }); Assert.Equal(1157, Base.Total(M)); }
}
