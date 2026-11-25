using AtlasPca;
using AtlasPca.Spiffe;
using Xunit;
using J = AtlasPca.Jose.Jose;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using K = AtlasPca.Corpus.Tests.RefSpiffeKit;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the SPIFFE oracle (test-data/ref-spiffe.json.gz, TS reference @atlasauth/pca-spiffe): SPIFFE ids, the DER facts reader,
/// X.509-SVID parsing and verification, JWT-SVID sessions, holder binding, the two fail-closed caches and admission evidence.</summary>
public class RefSpiffeTests
{
    const string M = "ref-spiffe";
    const string Sub = "spiffe://example.org/workload/db";
    const long NowMs = 1_800_000_060_000L;

    static D Obj(params (string, object?)[] kv) { var d = new D(); foreach (var (k, v) in kv) d[k] = v; return d; }
    static D Dd(object? o) => (D)o!;
    static L Ll(object? o) => (L)o!;

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => Obj(("JWT_SVID_ALGORITHMS", new L(SpiffeBridge.JwtSvidAlgorithms.Select(x => (object?)x)))));

    [Fact] public void ParseSpiffeId() => Base.Check(M, "parseSpiffeId", a => K.W(() => SpiffeBridge.ParseSpiffeId(a[0]).ToJson()));
    [Fact] public void HolderBindingMessage() => Base.Check(M, "holderBindingMessage", a => SpiffeBridge.HolderBindingMessage((string)a[0]!, (string)a[1]!));

    [Fact]
    public void HolderToSpiffeId() => Base.Check(M, "holderToSpiffeId", a =>
    {
        var h = Dd(a[0]);
        return K.W(() => SpiffeBridge.HolderToSpiffeId(new SpiffeHolder((string)h["holder"]!, h.GetValueOrDefault("spiffeId") as string ?? "", (string)h["trustDomain"]!, (string)h["path"]!)));
    });

    [Fact] public void ReadCertFacts() => Base.Check(M, "readCertFacts", a => SpiffeDer.ReadCertFacts(Pca.B64uDecode(a[0]) ?? throw new InvalidDataException("bad base64url")).ToJson());

    [Fact]
    public void ParseX509Svid() => Base.Check(M, "parseX509Svid", a => K.W(() =>
    {
        var s = SpiffeBridge.ParseX509Svid(K.Unbytes(a[0]));
        return Obj(("spiffeId", s.SpiffeId.ToJson()), ("publicKeyDer", s.PublicKeyDer));
    }));

    [Fact]
    public void VerifyX509Svid() => Base.Check(M, "verifyX509Svid", a => K.W(() =>
    {
        var calls = new L();
        var r = SpiffeBridge.VerifyX509Svid(K.Chain(a[0]), K.X509Opts(Dd(a[1]), calls, false));
        return Obj(("spiffeId", r.SpiffeId.ToJson()), ("publicKeyDer", r.PublicKeyDer), ("calls", calls));
    }));

    static object? JwtKeyOf(D keySpec)
    {
        if (keySpec.GetValueOrDefault("jwk") != null) return keySpec["jwk"];
        var jwks = Dd(Dd(keySpec["bundle"])["jwks"]);
        return SpiffeBridge.CreateTrustBundleSource(() => Obj(("jwks", jwks)), 1000, 5000, () => NowMs).JwtKey;
    }

    [Fact]
    public void JwtSession() => Base.Check(M, "jwtSession", a => K.W(() =>
    {
        var s = Dd(a[0]);
        var calls = new L();
        var r = SpiffeBridge.VerifyJwtSvid(s["token"], K.JwtOpts(s, JwtKeyOf(Dd(s["key"])), calls, false));
        return Obj(("spiffeId", r.SpiffeId.ToJson()), ("claims", r.Claims), ("audience", r.Audience), ("expiresAt", r.ExpiresAt), ("calls", calls));
    }));

    [Fact]
    public void HolderSession() => Base.Check(M, "holderSession", a => K.W(() =>
    {
        var s = Dd(a[0]);
        var kind = s.GetValueOrDefault("svid") as string;
        object? svid;
        if (kind == "x509")
        {
            var v = new VerifyX509SvidOptions { TrustDomain = "example.org", NowMs = K.N(s["nowMs"]) };
            foreach (var r in Ll(s["roots"])) v.Roots.Add(r);
            svid = SpiffeBridge.VerifyX509Svid(s["chain"], v);
        }
        else if (kind == "x509-parsed") svid = SpiffeBridge.ParseX509Svid(s["chain"]);
        else if (kind == "jwt")
        {
            var j = Dd(s["jwt"]);
            svid = SpiffeBridge.VerifyJwtSvid(j["token"], K.JwtOpts(j, j["jwk"], new L(), false));
        }
        else if (kind == "string") svid = Sub;
        else if (kind == "parsed-id") svid = SpiffeBridge.ParseSpiffeId(Sub);
        else if (kind == "hand-built") svid = Obj(("claims", Obj()));
        else svid = null;
        var o = K.Bind(s);
        var op = (string)s["op"]!;
        // an explicit JSON null holder key is not an absent one (the reference refuses it), and the oracle hands forHolder the {"$bytes"} object as it is, not as bytes
        var hk = !s.ContainsKey("holderKey") ? null : s["holderKey"] == null ? new object() : op == "forHolder" ? s["holderKey"] : K.Unbytes(s["holderKey"]);
        if (op == "holder") return Obj(("holder", SpiffeBridge.SvidToHolder(svid, hk, o).ToJson()));
        if (op == "forHolder")
        {
            if (hk == null || hk is string) return Obj(("spiffeId", SpiffeBridge.SpiffeIdForHolder(svid, (string?)hk, o)));
            SpiffeBridge.SvidToHolder(svid, hk, o); // a non-string key is refused (a raw object is not a key)
            throw new InvalidOperationException("unreachable: a non-string holder key was accepted");
        }
        return Obj(("pin", SpiffeBridge.WorkloadDischargePin((string)s["label"]!, svid)));
    }));

    // ---- caches (manual clock)

    static D CacheSession(bool revocation, D s)
    {
        long[] t = { K.N(s["start"]) };
        int[] fetchCalls = { 0 };
        var fetches = Ll(s["fetches"]);
        Fetch fetch = () =>
        {
            var f = Dd(fetches[Math.Min(fetchCalls[0], fetches.Count - 1)]);
            fetchCalls[0]++;
            if (f.GetValueOrDefault("throw") is true) throw new InvalidOperationException("fetch failed");
            return f.GetValueOrDefault("list");
        };
        double refreshMs = K.Ms(s["refreshMs"]), maxStaleMs = K.Ms(s["maxStaleMs"]);
        var rs = revocation ? SpiffeBridge.CreateRevocationSource(fetch, refreshMs, maxStaleMs, () => t[0]) : null;
        var bs = revocation ? null : SpiffeBridge.CreateTrustBundleSource(fetch, refreshMs, maxStaleMs, () => t[0]);
        var outp = new L();
        foreach (var so in Ll(s["steps"]))
        {
            var st = Dd(so);
            var op = (string)st["op"]!;
            try
            {
                object? v = null;
                if (op == "adv") { t[0] += K.N(st["ms"]); outp.Add(Obj(("v", new Num(t[0].ToString(System.Globalization.CultureInfo.InvariantCulture))))); continue; }
                if (op == "x509")
                {
                    var x = Dd(st["subject"]);
                    v = rs!.X509(new X509RevocationSubject((string)x["spiffeId"]!, (string)x["serialNumber"]!, (string)x["fingerprint256"]!, (int)K.N(x["position"]), x.GetValueOrDefault("isLeaf") is true));
                }
                else if (op == "jwt")
                {
                    var x = Dd(st["subject"]);
                    v = rs!.Jwt(new JwtRevocationSubject((string)x["spiffeId"]!, x.GetValueOrDefault("jti") as string, x.GetValueOrDefault("expiresAt"), (string)x["tokenHash"]!));
                }
                else if (op == "refresh") rs!.Refresh();
                else if (op == "ensureFresh") rs!.EnsureFresh();
                else if (op == "x509Roots") v = bs!.X509Roots();
                else
                {
                    var k = bs!.JwtKey(Dd(st["header"]))!;
                    var jwk = ((AtlasPca.Jose.JoseKey)k).ExportJwk();
                    var proj = new D { ["kty"] = jwk["kty"] };
                    foreach (var f in new[] { "crv", "x", "n" }) if (jwk.GetValueOrDefault(f) != null) proj[f] = jwk[f];
                    v = proj;
                }
                outp.Add(Obj(("v", v)));
            }
            catch (SpiffeError e) { outp.Add(Obj(("code", e.Code))); }
            catch (Exception) { outp.Add(Obj(("code", "jose"))); }
        }
        return Obj(("steps", outp), ("fetchCalls", new Num(fetchCalls[0].ToString(System.Globalization.CultureInfo.InvariantCulture))));
    }

    [Fact] public void RevocationSession() => Base.Check(M, "revocationSession", a => K.W(() => CacheSession(true, Dd(a[0]))));
    [Fact] public void BundleSession() => Base.Check(M, "bundleSession", a => K.W(() => CacheSession(false, Dd(a[0]))));

    // ---- admission

    static readonly HashSet<string> Known = new()
    {
        "malformed_spiffe_id", "empty_trust_domain", "trust_domain_too_long", "invalid_trust_domain", "invalid_path", "id_too_long", "missing_audience", "missing_exp",
        "malformed_token", "invalid_subject", "trust_domain_mismatch", "no_uri_san", "multiple_uri_san", "invalid_holder_key", "unverified_svid", "missing_trust_domain", "holder_binding_failed", "malformed_certificate",
        "leaf_is_ca", "leaf_no_digital_signature", "leaf_cert_sign", "leaf_crl_sign", "leaf_root_path", "unsupported_critical_extension", "forbidden_algorithm", "invalid_typ", "chain_empty", "chain_trust_domain_mismatch",
        "chain_signature", "chain_not_ca", "chain_no_key_cert_sign", "chain_path_len", "chain_expired", "chain_untrusted_root", "chain_too_long", "trust_bundle_unavailable", "trust_bundle_invalid", "svid_revoked", "chain_revoked",
        "revocation_unavailable", "SVID is bound to a different key",
    };

    [Fact]
    public void Admission() => Base.Check(M, "admission", a =>
    {
        var s = Dd(a[0]);
        var e = new SpiffeEvidence { Kind = (string)s["kind"]! };
        if (s.GetValueOrDefault("bind") != null) e.Bind = K.Bind(Dd(s["bind"]));
        if (e.Kind == "x509")
        {
            e.Chain = s["chain"];
            e.VerifyX509 = new VerifyX509SvidOptions { TrustDomain = "example.org", NowMs = K.N(s["nowMs"]) };
            foreach (var r in Ll(s["roots"])) e.VerifyX509.Roots.Add(r);
        }
        else
        {
            e.Token = s["token"];
            e.VerifyJwt = new VerifyJwtSvidOptions { TrustDomain = "example.org", CurrentDateMs = NowMs, Key = s["jwk"] };
            e.VerifyJwt.Audience.Add("api");
        }
        var r2 = SpiffeBridge.SpiffeAdmissionEvidence(e, (string?)s["instanceKey"]).ToJson();
        if (r2.GetValueOrDefault("reason") is string reason && !Known.Contains(reason)) r2["reason"] = "other";
        return r2;
    });

    [Fact]
    public void AllFnsCovered() { Base.Covers(M, new[]
    {
        "constants", "parseSpiffeId", "holderBindingMessage", "holderToSpiffeId", "readCertFacts", "parseX509Svid", "verifyX509Svid", "jwtSession", "holderSession", "revocationSession", "bundleSession", "admission",
    }); Assert.Equal(3346, Base.Total(M)); }
}
