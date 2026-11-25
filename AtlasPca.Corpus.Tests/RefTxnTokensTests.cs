using AtlasPca;
using AtlasPca.TxnTokens;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using T = AtlasPca.TxnTokens.TxnTokens;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the pca-txn-tokens oracle. Issue is random in the reference (iat, exp, jti / txn): the oracle compares {header, claims} of the issued
/// token with iat removed, exp replaced by <c>ttl</c> (= exp - iat) and a generated jti / txn replaced by <c>true</c>; this file pins the clock and the id
/// generator and reduces the token the same way. fromTransactionToken's <c>seen</c> option is the list of ids the replay store answers "already seen" for.</summary>
public class RefTxnTokensTests
{
    const string M = "ref-txn-tokens";

    static double? Num(object? v) => v is AtlasPca.Num ? IntentJs.NumOf(v) : null;

    [Fact]
    public void SubActChain() => Base.Check(M, "subActChain", a => T.SubActChain(a[0]));

    [Fact]
    public void ActDepth() => Base.Check(M, "actDepth", a => T.ActDepth(a[0]));

    [Fact]
    public void ToRfc8693Act() => Base.Check(M, "toRfc8693Act", a => T.ToRfc8693Act(a[0]));

    // the other language lanes' corpus (ref-txn-tokens-java) names its keys by seed label and answers {header, payload, verified[, token]} and {ok, result | code, consumed}
    static byte[] SeedOf(string label) => System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label));

    static byte[] PubOf(string label) => EdKey.FromSeed(SeedOf(label)).Pub;

    static byte[]? JavaKey(object? k, bool pub) => k is D d
        ? d.GetValueOrDefault(pub ? "pubLabel" : "label") is string l ? (pub ? PubOf(l) : SeedOf(l)) : d.GetValueOrDefault("len") is { } n ? new byte[(int)IntentJs.NumOf(n)!.Value] : null
        : null;

    static readonly System.Text.RegularExpressions.Regex Uuid = new("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");

    static string? JavaToSkip(D c)
    {
        if (Base.Args(c)[0] is not D o || o.ContainsKey("seed")) return null;
        foreach (var k in new[] { "profile", "scope", "reqWl", "txn", "trustDomain", "issuer" })
            if (k != "issuer" && o.GetValueOrDefault(k) is { } v && v is not string) return k + " of another JS type";
        if (o.GetValueOrDefault("ttlSec") is { } t && t is not AtlasPca.Num) return "ttlSec of another JS type";
        return null;
    }

    static object? ToJava(D o)
    {
        var args = new ToTransactionTokenArgs
        {
            Profile = o.GetValueOrDefault("profile") as string,
            Scope = o.GetValueOrDefault("scope") as string,
            ReqWl = o.GetValueOrDefault("reqWl") as string,
            Txn = o.GetValueOrDefault("txn") as string,
            TrustDomain = o.GetValueOrDefault("trustDomain") as string,
            Chain = o.GetValueOrDefault("chain"),
            Action = o.GetValueOrDefault("action"),
            IssuerKey = JavaKey(o.GetValueOrDefault("issuerKey"), false),
            Issuer = o.GetValueOrDefault("issuer") as string,
            TtlSec = Num(o.GetValueOrDefault("ttlSec")),
            NowMs = () => Base.OracleT0,
        };
        var token = T.ToTransactionToken(args);
        var parts = token.Split('.');
        object? Dec(string seg) => Pca.ParseJson(System.Text.Encoding.UTF8.GetString(Pca.B64uDecode(seg)!));
        var payload = (D)Dec(parts[1])!;
        // the issued id is random: it prints as <uuid>
        foreach (var k in new[] { "txn", "jti" }) if (payload.GetValueOrDefault(k) is string id && Uuid.IsMatch(id) && !(o.GetValueOrDefault("txn") is string t && t == id)) payload[k] = "<uuid>";
        bool verified;
        try
        {
            // the oracle's own check: the signature and the time claims under the label's public key at T0 (not the whole transaction-token profile)
            AtlasPca.Jose.Jose.JwtVerify(token, AtlasPca.Jose.Jose.ImportJwk(AtlasPca.Jose.Jose.Ed25519PublicJwk(EdKey.FromSeed(JavaKey(o["issuerKey"], false)!).Pub), "EdDSA"),
                new AtlasPca.Jose.JwtVerifyOptions { Algorithms = new[] { "EdDSA" }, CurrentDateMs = Base.OracleT0 });
            verified = true;
        }
        catch (Exception) { verified = false; }
        return new D { ["header"] = Dec(parts[0]), ["payload"] = payload, ["verified"] = verified, ["token"] = token };
    }

    [Fact]
    public void ToTransactionToken() => Base.Check(M, "toTransactionToken", a =>
    {
        var o = (D)a[0]!;
        if (!o.ContainsKey("seed")) return ToJava(o);
        var token = T.ToTransactionToken(new ToTransactionTokenArgs
        {
            Profile = o.GetValueOrDefault("profile") as string,
            Scope = o.GetValueOrDefault("scope") as string,
            ReqWl = o.GetValueOrDefault("reqWl") as string,
            Txn = o.GetValueOrDefault("txn") as string,
            TrustDomain = o.GetValueOrDefault("trustDomain") as string,
            Chain = o.GetValueOrDefault("chain"),
            Action = o.GetValueOrDefault("action"),
            IssuerKey = (o.TryGetValue("seed", out var sd) ? Pca.B64uDecode(sd) : System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("atlas-pca-conformance/" + (string)o["label"]!))),
            Issuer = o.GetValueOrDefault("issuer") as string,
            TtlSec = Num(o.GetValueOrDefault("ttlSec")),
            NowMs = () => Base.OracleT0,
            NewId = () => "00000000-0000-4000-8000-000000000000",
        });
        var parts = token.Split('.');
        object? Dec(string seg) => Pca.ParseJson(System.Text.Encoding.UTF8.GetString(Pca.B64uDecode(seg)!));
        var header = Dec(parts[0]);
        var c = (D)Dec(parts[1])!;
        var claims = new D();
        foreach (var (k, v) in c) if (k is not ("iat" or "exp" or "jti" or "txn")) claims[k] = v;
        claims["ttl"] = IntentJs.NumOf(c["exp"])!.Value - IntentJs.NumOf(c["iat"])!.Value;
        if (c.ContainsKey("jti")) claims["jti"] = true;
        if (c.ContainsKey("txn")) claims["txn"] = o.ContainsKey("txn") ? c["txn"] : true;
        return new D { ["header"] = header, ["claims"] = claims };
    }, eq: (c, have) =>
    {
        // the token text is only compared where the oracle recorded it
        if (have is D h && c["out"] is D w && !w.ContainsKey("token")) { h = new D(h); h.Remove("token"); have = h; }
        return Base.Eq(c["out"], have);
    }, skip: JavaToSkip);

    static object? FromJava(object? token, D key, D w)
    {
        var consumed = new L();
        var seenMode = w.GetValueOrDefault("seen") as string;
        try
        {
            var result = T.FromTransactionToken(token, JavaKey(key, true), new FromTransactionTokenOptions
            {
                Profile = w.GetValueOrDefault("profile") as string,
                Audience = w.GetValueOrDefault("audience") is { } au ? au as string ?? "\0audience of another type" : null, // a non-text audience never matches
                ClockToleranceSec = Num(w.GetValueOrDefault("clockToleranceSec")),
                NowMs = Num(w.GetValueOrDefault("nowMs")),
                SeenTxn = seenMode == null ? null : (id, exp) =>
                {
                    consumed.Add(new L { id, new AtlasPca.Num(AtlasPca.Js.JsJson.NumberToString(exp)) });
                    if (seenMode == "throws") throw new InvalidOperationException("store down");
                    return seenMode is "seen" or "truthy";
                },
                ReplayCheck = w.GetValueOrDefault("replayCheck") as string,
            });
            return new D { ["ok"] = true, ["result"] = result, ["consumed"] = consumed };
        }
        catch (Exception e) { return new D { ["ok"] = false, ["code"] = (e as TxnTokenException)?.Code ?? "other", ["consumed"] = consumed }; }
    }

    [Fact]
    public void FromTransactionToken() => Base.Check(M, "fromTransactionToken", a =>
    {
        if (a[1] is D key) return FromJava(a[0], key, (D)a[2]!);
        var w = (D)a[2]!;
        var seen = w.GetValueOrDefault("seen") is L ids ? ids.OfType<string>().ToHashSet() : null;
        return T.FromTransactionToken(a[0], Pca.B64uDecode(a[1]), new FromTransactionTokenOptions
        {
            Profile = w.GetValueOrDefault("profile") as string,
            Audience = w.GetValueOrDefault("audience") is { } au ? au as string ?? "\0audience of another type" : null, // a non-text audience never matches
            ClockToleranceSec = Num(w.GetValueOrDefault("clockToleranceSec")),
            NowMs = Num(w.GetValueOrDefault("nowMs")),
            SeenTxn = seen == null ? null : (id, _) => seen.Contains(id),
            ReplayCheck = w.GetValueOrDefault("unchecked") is true ? "unchecked" : null,
        });
    });

    [Fact]
    public void EveryFnIsHandled() { Base.Covers(M, new[] { "subActChain", "actDepth", "toRfc8693Act", "toTransactionToken", "fromTransactionToken" }); Assert.Equal(641, Base.Total(M)); }
}
