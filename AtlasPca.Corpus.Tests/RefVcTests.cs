using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using AtlasPca.Vc;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using V = AtlasPca.Vc.Vc;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the pca-vc oracle: base58btc and did:key, the bundled JSON-LD context, the agent-passport SD-JWT VC (issuance compared in a normalized form:
/// random salts) and RFC 9421 / Web Bot Auth request signatures. The reference ran under a pinned clock; the same instant is passed here as <c>now</c>.</summary>
public class RefVcTests
{
    const string M = "ref-vc";
    const double Now = 1_700_000_100_000d;

    static string Str(object? o) => o as string ?? throw new ArgumentException("not a string");

    static string Sha(string ascii) => Pca.B64u(SHA256.HashData(ascii.Select(c => (byte)c).ToArray()));

    static object? Json(string b64) => Pca.ParseJson(Encoding.UTF8.GetString(Pca.B64uDecode(b64)!));

    [Fact]
    public void Base58btcEncode() => Base.Check(M, "base58btcEncode", a => V.Base58btcEncode(Base.Bytes(a[0])));

    [Fact]
    public void Base58btcDecode() => Base.Check(M, "base58btcDecode", a => V.Base58btcDecode(Str(a[0])));

    [Fact]
    public void DidKeyFromEd25519() => Base.Check(M, "didKeyFromEd25519", a => V.DidKeyFromEd25519(Base.Bytes(a[0])));

    [Fact]
    public void Ed25519FromDidKey() => Base.Check(M, "ed25519FromDidKey", a => V.Ed25519FromDidKey(Str(a[0])));

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D
    {
        ["VC_CONTEXT"] = V.VcContext, ["AGENT_PASSPORT_CONTEXT"] = V.AgentPassportContext, ["AGENT_PASSPORT_VC_TYPE"] = V.AgentPassportVcType,
        ["AGENT_PASSPORT_CONTEXT_DIGEST"] = V.AgentPassportContextDigest, ["AGENT_PASSPORT_CONTEXT_DOC"] = V.AgentPassportContextDoc,
    });

    [Fact]
    public void ResolveAgentPassportContext() => Base.Check(M, "resolveAgentPassportContext", a => V.ResolveAgentPassportContext(a[0]));

    /// <summary>The reference's normalized view of an issued credential (salts are random).</summary>
    static D NormVc(string sd)
    {
        var parts = sd.Split('~');
        var ds = parts.Skip(1).Take(parts.Length - 2).ToList();
        var hp = parts[0].Split('.');
        var h = Json(hp[0]); var p = (D)Json(hp[1])!;
        var cs = (p.GetValueOrDefault("vc") as D)?.GetValueOrDefault("credentialSubject") as D;
        var sdl = ((cs?.GetValueOrDefault("_sd") as L) ?? new L()).Cast<string>().OrderBy(x => x, StringComparer.Ordinal).ToList();
        cs?.Remove("_sd");
        bool verified;
        try { V.VerifyPassportVC(sd, EdKey.FromSeed(Enumerable.Repeat((byte)1, 32).ToArray()).Pub, new D { ["now"] = Now }); verified = true; }
        catch (Exception) { verified = false; }
        var dig = ds.Select(Sha).OrderBy(x => x, StringComparer.Ordinal).ToList();
        var disc = ds.Select(d => (L)Json(d)!).Select(t => new L { t[1], t[2] }).OrderBy(x => (x[0] as string) ?? "", StringComparer.Ordinal).Cast<object?>().ToList();
        return new D
        {
            ["end"] = parts[^1], ["header"] = h, ["payload"] = p, ["n"] = ds.Count, ["digestsOk"] = dig.SequenceEqual(sdl), ["disclosures"] = disc, ["verified"] = verified,
        };
    }

    [Fact]
    public void PassportToVC() => Base.Check(M, "passportToVC", a =>
    {
        // a null passport is the reference's TypeError; any other non-object reads as an object with no members
        if (a[0] == null) throw new ArgumentException("Cannot read properties of null");
        var passport = a[0] as D ?? new D();
        var o = (D)a[1]!;
        var args = new D { ["issuerKey"] = Base.Bytes(o["issuer_seed"]) };
        if (o.ContainsKey("issuer_did")) args["issuerDid"] = o["issuer_did"];
        if (o.ContainsKey("subject_did")) args["subjectDid"] = o["subject_did"];
        if (o.ContainsKey("ttl_sec")) args["ttlSec"] = o["ttl_sec"];
        args["now"] = Now;
        return NormVc(V.PassportToVC(passport, args));
    });

    [Fact]
    public void VerifyPassportVC() => Base.Check(M, "verifyPassportVC", a =>
    {
        var o = new D { ["now"] = Now };
        if (a.Count > 2 && a[2] is D opts && opts.ContainsKey("expectedIssuerDid")) o["expectedIssuerDid"] = opts["expectedIssuerDid"];
        return V.VerifyPassportVC(a[0], Base.Bytes(a[1]), o);
    });

    [Fact]
    public void SignRequestMessage() => Base.Check(M, "signRequestMessage", a =>
    {
        var i = (D)a[0]!;
        var args = new D { ["method"] = i["method"], ["url"] = i["url"], ["headers"] = i["headers"], ["key"] = Base.Bytes(i["key"]), ["keyid"] = i["keyid"] };
        if (i.ContainsKey("created")) args["created"] = i["created"];
        if (i.ContainsKey("signature_agent")) args["signatureAgent"] = i["signature_agent"];
        args["now"] = Now;
        return V.SignRequestMessage(args);
    });

    static readonly (string Snake, string Camel)[] ReqNames =
    {
        ("method", "method"), ("url", "url"), ("headers", "headers"), ("signature_input", "signatureInput"), ("signature", "signature"),
        ("signature_agent", "signatureAgent"), ("required_components", "requiredComponents"), ("max_age_sec", "maxAgeSec"), ("now_sec", "nowSec"),
    };

    [Fact]
    public void VerifyRequestSignature() => Base.Check(M, "verifyRequestSignature", a =>
    {
        var i = (D)a[0]!;
        var args = new D();
        foreach (var (snake, camel) in ReqNames) if (i.ContainsKey(snake)) args[camel] = i[snake];
        args["now"] = Now;
        return V.VerifyRequestSignature(args, Base.Bytes(a[1]));
    });

    [Fact]
    public void EveryFnIsHandled() { Base.Covers(M, new[]
    {
        "base58btcEncode", "base58btcDecode", "didKeyFromEd25519", "ed25519FromDidKey", "constants", "resolveAgentPassportContext", "passportToVC",
        "verifyPassportVC", "signRequestMessage", "verifyRequestSignature",
    }); Assert.Equal(338, Base.Total(M)); }
}
