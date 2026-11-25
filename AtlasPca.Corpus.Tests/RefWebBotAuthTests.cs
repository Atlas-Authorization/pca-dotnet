using System.Text.RegularExpressions;
using AtlasPca;
using AtlasPca.WebBotAuth;
using Xunit;
using Wba = AtlasPca.WebBotAuth.WebBotAuth;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of Web Bot Auth (RFC 9421 message signatures, signed directory, Content-Digest, proof binding) against the TypeScript reference
/// (test-data/ref-webbotauth.json.gz).</summary>
public class RefWebBotAuthTests
{
    const string M = "ref-webbotauth";

    static List<string> Strs(object? o) => ((L)o!).Select(e => (string)e!).ToList();

    static object? Body(object? o) => Base.IsBytes(o) ? Base.Bytes(o) : o;

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D
    {
        ["tag"] = Wba.WebBotAuthTag, ["alg"] = Wba.WebBotAuthAlg, ["path"] = Wba.WellKnownDirectoryPath, ["ct"] = Wba.DirectoryContentType,
        ["label"] = Wba.DefaultSignatureLabel, ["exp"] = new Num(Wba.DefaultExpiresSec.ToString()), ["agent"] = Wba.SignatureAgentHeader, ["pca"] = Wba.PcaHeader,
        ["comp"] = Wba.PcaProofComponent, ["cd"] = ContentDigest.ContentDigestHeaderName, ["algs"] = ContentDigest.ContentDigestAlgs.Cast<object?>().ToList(),
        ["dtag"] = SignedDirectory.DirectorySignatureTag,
    });

    [Fact] public void JwkThumbprint() => Base.Check(M, "jwkThumbprint", a => Wba.JwkThumbprint(Base.Bytes(a[0])));
    [Fact] public void SignRequest() => Base.Check(M, "signRequest", a => Wba.SignRequest(a[0] == null ? (D)null! : a[0] as D ?? new D()));

    // ---- verify

    /// <summary>The oracle's key-resolver spec: keyid to {"$bytes"} | JWK | null | {"$throw": true}; an unlisted keyid resolves to null.</summary>
    static Wba.KeyResolver Resolver(D spec) => kid =>
    {
        var v = spec.GetValueOrDefault(kid);
        if (v is D vd && vd.GetValueOrDefault("$throw") is true) throw new InvalidOperationException("resolver down");
        return Base.IsBytes(v) ? Base.Bytes(v) : v;
    };

    static Wba.ReplayCache Cache(object? spec) => spec switch
    {
        "always" => (k, e, n) => true,
        "never" => (k, e, n) => false,
        "throw" => (k, e, n) => throw new InvalidOperationException("cache down"),
        "memory" => Wba.MemoryReplayCache(),
        string s when s.StartsWith("memory:", StringComparison.Ordinal) => Wba.MemoryReplayCache(int.Parse(s[7..])),
        _ => throw new ArgumentException("unknown cache spec " + spec),
    };

    static D VOpts(D op)
    {
        var o = new D(op);
        if (o.GetValueOrDefault("resolveKey") is D rk) o["resolveKey"] = Resolver(rk);
        if (o.GetValueOrDefault("maxLifetimeSec") is "Infinity") o["maxLifetimeSec"] = double.PositiveInfinity;
        if (o.ContainsKey("replayCache")) o["replayCache"] = Cache(o["replayCache"]);
        return o;
    }

    static D Norm(D r)
    {
        var o = new D(r);
        if (o.GetValueOrDefault("reason") is string reason) o["reason"] = Regex.Replace(reason, "^(invalid PCActn in PCA-Action): .*$", "$1", RegexOptions.Singleline);
        return o;
    }

    [Fact]
    public void VerifySignedRequest() => Base.Check(M, "verifySignedRequest", a =>
    {
        int times = a.Count > 2 ? (int)IntentJs.NumOf(a[2])! : 1;
        var vo = VOpts((D)a[1]!);
        var rs = new L();
        for (int i = 0; i < times; i++) rs.Add(Norm(Wba.VerifySignedRequest((D)a[0]!, vo)));
        return times == 1 ? rs[0] : rs;
    });

    [Fact] public void VerifySignedRequestWithProof() => Base.Check(M, "verifySignedRequestWithProof", a => Norm(Wba.VerifySignedRequestWithProof((D)a[0]!, VOpts((D)a[1]!))));

    // ---- directory + replay cache

    static List<D> DirKeys(object? o) => ((L)o!).Select(k => { var e = new D((D)k!); e["publicKey"] = Base.Bytes(e["publicKey"]); return e; }).ToList();

    [Fact] public void BuildKeyDirectory() => Base.Check(M, "buildKeyDirectory", a => Wba.BuildKeyDirectory(DirKeys(a[0])));
    [Fact] public void ResolveFromDirectory() => Base.Check(M, "resolveFromDirectory", a => Wba.ResolveFromDirectory((D)a[0]!, (string)a[1]!));

    [Fact]
    public void DirectoryHandler() => Base.Check(M, "directoryHandler", a =>
    {
        var h = Wba.DirectoryHandler(DirKeys(a[0]));
        return ((L)a[1]!).Select(p => (object?)h((string)p!)).ToList();
    });

    [Fact]
    public void MemoryReplayCache() => Base.Check(M, "memoryReplayCache", a =>
    {
        var c = a[0] == null ? Wba.MemoryReplayCache() : Wba.MemoryReplayCache((int)IntentJs.NumOf(a[0])!);
        var o = new L();
        foreach (var op in (L)a[1]!)
        {
            var x = (L)op!;
            try { o.Add(c((string)x[0]!, IntentJs.NumOf(x[1])!.Value, IntentJs.NumOf(x[2])!.Value)); }
            catch (Exception) { o.Add("throw"); }
        }
        return o;
    });

    // ---- proof binding

    [Fact] public void ProofHeaders() => Base.Check(M, "proofHeaders", a => Wba.ProofHeaders(a[0]));
    [Fact] public void DecodeProofHeader() => Base.Check(M, "decodeProofHeader", a => Wba.DecodeProofHeader((string)a[0]!));
    [Fact] public void SignRequestWithProof() => Base.Check(M, "signRequestWithProof", a => Wba.SignRequestWithProof((D)a[0]!));

    // ---- Content-Digest

    [Fact] public void ContentDigestBytes() => Base.Check(M, "contentDigestBytes", a => ContentDigest.ContentDigestBytes(Body(a[0]), (string)a[1]!));
    [Fact] public void ContentDigestHeader() => Base.Check(M, "contentDigestHeader", a => ContentDigest.ContentDigestHeader(Body(a[0]), a.Count > 1 ? Strs(a[1]) : null));
    [Fact] public void ParseContentDigest() => Base.Check(M, "parseContentDigest", a => ContentDigest.ParseContentDigest((string)a[0]!));

    [Fact]
    public void VerifyContentDigest() => Base.Check(M, "verifyContentDigest", a =>
    {
        var req = a.Count > 2 && a[2] is D o && o.GetValueOrDefault("require") != null ? Strs(o["require"]) : null;
        return ContentDigest.VerifyContentDigest(a[0] as string, Body(a[1]), req);
    });

    // ---- signed directory

    [Fact] public void ParseKeyDirectory() => Base.Check(M, "parseKeyDirectory", a => SignedDirectory.ParseKeyDirectory((string)a[0]!));
    [Fact] public void SignDirectoryResponse() => Base.Check(M, "signDirectoryResponse", a => SignedDirectory.SignDirectoryResponse((D)a[0]!));
    [Fact] public void VerifyDirectoryResponse() => Base.Check(M, "verifyDirectoryResponse", a => SignedDirectory.VerifyDirectoryResponse((D)a[0]!));

    /// <summary>The oracle's scripted fetch: records the URL and headers, answers {status, headers, body} (or throws for "throw").</summary>
    [Fact]
    public void FetchKeyDirectory() => Base.Check(M, "fetchKeyDirectory", a =>
    {
        var spec = (D)a[1]!;
        var res = spec.GetValueOrDefault("response");
        D? called = null;
        DirectoryFetch.Fetcher fetcher = (url, headers, timeout) =>
        {
            called = new D { ["url"] = url, ["headers"] = headers.ToDictionary(e => e.Key, e => (object?)e.Value), ["redirect"] = "error" };
            if (res is "throw") throw new InvalidOperationException("network down");
            var r = (D)res!;
            var hs = r.GetValueOrDefault("headers") as D ?? new D();
            return new FetchResponse((int)IntentJs.NumOf(r["status"])!, name => hs.GetValueOrDefault(name.ToLowerInvariant()) as string, () => (string)r["body"]!);
        };
        var options = new D();
        if (spec.GetValueOrDefault("options") is D so) foreach (var (k, v) in so) options[k] = v;
        options["fetch"] = fetcher;
        var o = new D();
        try { o["directory"] = DirectoryFetch.FetchKeyDirectory((string)a[0]!, options); }
        catch (Exception e)
        {
            o["error"] = true;
            var msg = e.Message ?? "";
            o["message"] = msg.StartsWith("directory ", StringComparison.Ordinal) || msg.StartsWith("Invalid URL", StringComparison.Ordinal)
                ? Regex.Replace(msg, "^(directory signature): .*$", "$1", RegexOptions.Singleline) : "other";
        }
        o["called"] = called;
        return o;
    });

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "constants", "jwkThumbprint", "signRequest", "verifySignedRequest", "verifySignedRequestWithProof", "buildKeyDirectory", "resolveFromDirectory", "directoryHandler",
        "memoryReplayCache", "proofHeaders", "decodeProofHeader", "signRequestWithProof", "contentDigestBytes", "contentDigestHeader", "parseContentDigest", "verifyContentDigest",
        "parseKeyDirectory", "signDirectoryResponse", "verifyDirectoryResponse", "fetchKeyDirectory",
    }); Assert.Equal(1253, Base.Total(M)); }
}
