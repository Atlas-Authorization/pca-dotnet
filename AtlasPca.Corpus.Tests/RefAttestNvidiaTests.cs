using System.Text;
using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.FrostReplay;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the NVIDIA GPU confidential-computing attestation modules over the real public hardware captures (H100, a second H100, two GB100 GPUs: their RIMs, CRLs and OCSP pairs) with byte-level mutations and a
/// forged PKI (test-data/ref-attest-nvidia.json.gz, 467 cases: the SPDM transcript parse, device chain, report signature, challenge, RIM ids and golden comparison, CRL and OCSP revocation, OCSP request building, the fetch
/// helpers over a scripted transport and the ASN.1 time check; test-data/ref-attest-nvidia-rim.json.gz, 163 cases: RIM XMLDSig verification and the collateral hook). Every string over 400 characters is {"$blob": id} (args and out are
/// hydrated). A reference throw requires a refusal; a reason that is library text (an OpenSSL "error:", the ASN.1 schema message, "OCSP response rejected:", the XML parser's) is compared for presence only. Every fn has a handler
/// and both totals are asserted.</summary>
public class RefAttestNvidiaTests
{
    const string M = "ref-attest-nvidia", R = "ref-attest-nvidia-rim";

    static byte[] B(object? o) => o as byte[] ?? throw new ArgumentException("bytes expected");
    static string S(object? o) => o as string ?? throw new ArgumentException("string expected");
    static List<string> Strs(object? o) => ((L)o!).Select(x => (string)x!).ToList();

    static bool LibText(string s) =>
        s.StartsWith("OCSP response rejected:", StringComparison.Ordinal) || s.StartsWith("RIM: verification error (fail closed):", StringComparison.Ordinal) || (s.Contains("error:", StringComparison.Ordinal) && s.Contains("routines", StringComparison.Ordinal))
        || s.Contains("Object's schema was not verified", StringComparison.Ordinal);

    static bool Same(object? want, object? have)
    {
        if (want is D w)
        {
            if (have is not D h) return false;
            if (w.ContainsKey("$throws")) return h.ContainsKey("$throws");
            return w.Count == h.Count && w.All(e => h.TryGetValue(e.Key, out var x) && Same(e.Value, x));
        }
        if (want is L wl) return have is L hl && wl.Count == hl.Count && wl.Zip(hl).All(p => Same(p.First, p.Second));
        if (want is string ws && LibText(ws)) return have is string hs && hs.Length > 0;
        return Base.Show(want) == Base.Show(have);
    }

    static int Replay(string module, string fn, Func<L, object?> run, int min)
    {
        var blobs = BlobCorpus.Blobs(module);
        var bad = new List<string>();
        int n = 0;
        foreach (var c in Base.Of(module, fn))
        {
            n++;
            var args = (L)Un(BlobCorpus.Hydrate(Base.Args(c), blobs))!;
            var want = BlobCorpus.Hydrate(c["out"], blobs);
            object? have;
            try { have = Base.Json(run(args)); }
            catch (Exception e) { have = new D { ["$throws"] = e.Message }; }
            if (!Same(want, have)) bad.Add($"{c["name"]}\n   want {Trim(Base.Show(want))}\n   have {Trim(Base.Show(have))}");
        }
        Assert.True(bad.Count == 0, $"{module}/{fn}: {bad.Count} of {n} divergent:\n" + string.Join("\n", bad.Take(25)));
        Assert.True(n >= min, $"{module}/{fn}: only {n} cases compared");
        return n;
    }

    static string Trim(string s) => s.Length > 600 ? s[..600] + "..." : s;

    // ---- the injected transport of the fetch helpers ----
    static (Func<NvidiaFetchRequest, NvidiaFetchResponse> Fetch, L Requests) Transport(object? response)
    {
        var requests = new L();
        NvidiaFetchResponse Fetch(NvidiaFetchRequest r)
        {
            var q = new D { ["url"] = r.Url, ["method"] = r.Method, ["contentType"] = r.ContentType };
            if (r.Body != null) q["bodyBytes"] = r.Body.Length;
            requests.Add(q);
            var d = (D)response!;
            if (d.TryGetValue("$throws", out var m)) throw new InvalidOperationException((string)m!);
            var status = d.TryGetValue("status", out var st) ? (int)Base.Long(st) : 200;
            var body = d.ContainsKey("bodyBytes") ? B(d["bodyBytes"]) : Encoding.UTF8.GetBytes(AtlasPca.Js.JsJson.Stringify(d.GetValueOrDefault("body")));
            return new NvidiaFetchResponse(status, body);
        }
        return (Fetch, requests);
    }

    static object? Fetched(Func<Func<NvidiaFetchRequest, NvidiaFetchResponse>, object?> call, object? response)
    {
        var (fetch, requests) = Transport(response);
        var o = new D();
        try { o["ok"] = true; o["value"] = call(fetch); }
        catch (Exception e) { o.Remove("value"); o["ok"] = false; o["error"] = e.Message; }
        o["requests"] = requests;
        return o;
    }

    static object? FetchRim(L a)
    {
        var c = (D)a[0]!;
        return Fetched(f => NvidiaAttest.FetchRim((string)c["id"]!, f, c.GetValueOrDefault("baseUrl") as string), c["response"]);
    }

    static object? FetchCrl(L a)
    {
        var c = (D)a[0]!;
        return Fetched(f => NvidiaAttest.FetchCrl((string)c["url"]!, f), c["response"]);
    }

    static object? FetchOcsp(L a)
    {
        var c = (D)a[0]!;
        var (fetch, requests) = Transport(c["response"]);
        var o = new D();
        try
        {
            var opts = c.GetValueOrDefault("opts") as D;
            var (req, res) = NvidiaAttest.FetchOcsp(S(c["certPem"]), S(c["issuerPem"]), fetch, opts?.GetValueOrDefault("url") as string, opts?.GetValueOrDefault("nonce") as byte[]);
            o["ok"] = true; o["request"] = req; o["response"] = res;
        }
        catch (Exception e) { o["ok"] = false; o["error"] = e.Message; }
        o["requests"] = requests;
        return o;
    }

    static object? Revocation(L a)
    {
        object? rf = a.Count > 4 ? a[4] : null;
        if (rf is L l) rf = l.Select(x => IntentJs.NumOf(x) ?? throw new ArgumentException("a number was expected")).ToList();
        return NvidiaAttest.CheckChainRevocation(S(a[0]), ((L)a[1]!).Select(x => B(x)).ToList(), Dbl(a[2]), a.Count > 3 ? Strs(a[3]) : null, rf);
    }

    static object? OcspVerify(L a)
    {
        var o = (D)a[1]!;
        return NvidiaAttest.VerifyOcspResponse(B(a[0]), new NvidiaAttest.OcspVerifyOptions
        {
            ChainPem = S(o["chainPem"]), CertIndex = (int)Lng(o["certIndex"]), IssuerIndex = o.GetValueOrDefault("issuerIndex") is { } ii ? (int)Lng(ii) : null, NowMs = Dbl(o["nowMs"]),
            MaxAgeMs = DblOpt(o.GetValueOrDefault("maxAgeMs")), ClockSkewMs = DblOpt(o.GetValueOrDefault("clockSkewMs")), ExpectedNonce = o.GetValueOrDefault("expectedNonce") as byte[],
        });
    }

    static object? OcspChain(L a)
    {
        var o = a.Count > 3 ? a[3] as D : null;
        var rg = o?.GetValueOrDefault("requireGood");
        if (rg is L l) rg = l.Select(x => IntentJs.NumOf(x) ?? throw new ArgumentException("a number was expected")).ToList();
        return NvidiaAttest.CheckChainOcsp(S(a[0]), ((L)a[1]!).Select(x => B(x)).ToList(), Dbl(a[2]), new NvidiaAttest.ChainOcspOptions
        {
            RequireGood = rg, MaxAgeMs = DblOpt(o?.GetValueOrDefault("maxAgeMs")), ClockSkewMs = DblOpt(o?.GetValueOrDefault("clockSkewMs")),
            ExpectedNonces = (o?.GetValueOrDefault("expectedNonces") as L)?.Select(x => x as byte[]).ToList(),
        });
    }

    static object? Hook(L a)
    {
        var c = (D)a[0]!;
        return new D { ["value"] = NvidiaAttest.CollateralHook((D)c["opts"]!, c.GetValueOrDefault("bundle") as D, B(c["evidence"]), S(c["chainPem"]), Dbl(c["nowMs"])) };
    }

    static Dictionary<string, Func<L, object?>> Fns => new()
    {
        ["constants"] = _ => new D
        {
            ["NVIDIA_SPDM_SUITE"] = NvidiaAttest.SpdmSuite, ["NVIDIA_OPAQUE"] = NvidiaAttest.Opaque.ToDictionary(kv => kv.Key, kv => (object?)kv.Value), ["NVIDIA_RIM_BASE_URL"] = NvidiaAttest.RimBaseUrl,
            ["NVIDIA_GH100_CRL_URLS"] = NvidiaAttest.Gh100CrlUrls.ToList(), ["NVIDIA_GB100_CRL_URLS"] = NvidiaAttest.Gb100CrlUrls.ToList(), ["NVIDIA_OCSP_URL"] = NvidiaAttest.OcspUrl, ["NVIDIA_OCSP_DEFAULT_MAX_AGE_MS"] = NvidiaAttest.OcspDefaultMaxAgeMs,
        },
        ["parseReport"] = a => NvidiaAttest.ParseEvidence(a[0] as byte[]),
        ["formatVbiosVersion"] = a => NvidiaAttest.FormatVbiosVersion(B(a[0])),
        ["spkiSha256Hex"] = a => NvidiaAttest.SpkiSha256Hex(S(a[0])),
        ["parsePemChain"] = a => NvidiaAttest.ParsePemChain(S(a[0])),
        ["verifyDeviceChain"] = a => NvidiaAttest.VerifyDeviceChain(S(a[0]), Strs(a[1]), Dbl(a[2])),
        ["verifySpdmSignature"] = a => NvidiaAttest.VerifySpdmSignature(B(a[0]), S(a[1])),
        ["spdmChallenge"] = a => NvidiaAttest.SpdmChallenge(a[0]),
        ["rimIds"] = a => NvidiaAttest.RimIdsForReport(B(a[0])),
        ["compareReport"] = a => NvidiaAttest.CompareReportToRims(B(a[0]), a[1], a[2]),
        ["checkRevocation"] = Revocation,
        ["fetchRim"] = FetchRim,
        ["fetchCrl"] = FetchCrl,
        ["ocspRequest"] = a => NvidiaAttest.BuildOcspRequest(S(a[0]), S(a[1]), ((D)a[2]!).GetValueOrDefault("nonce") as byte[], ((D)a[2]!).GetValueOrDefault("hash") as string),
        ["ocspUrls"] = a => NvidiaAttest.CertOcspUrls(S(a[0])),
        ["ocspVerify"] = OcspVerify,
        ["ocspChain"] = OcspChain,
        ["fetchOcsp"] = FetchOcsp,
        ["asn1TimesWellFormed"] = a => NvidiaAttest.AllAsn1TimesWellFormed(B(a[0])),
    };

    static void Fn(string fn, int min) => Replay(M, fn, Fns[fn], min);

    [Fact] public void Constants() => Fn("constants", 1);
    [Fact] public void SpdmReport() { foreach (var (f, n) in new[] { ("parseReport", 66), ("formatVbiosVersion", 9), ("spdmChallenge", 10), ("verifySpdmSignature", 15) }) Fn(f, n); }
    [Fact] public void DeviceChain() { foreach (var (f, n) in new[] { ("spkiSha256Hex", 3), ("parsePemChain", 12), ("verifyDeviceChain", 63) }) Fn(f, n); }
    [Fact] public void RimIdsAndComparison() { foreach (var (f, n) in new[] { ("rimIds", 26), ("compareReport", 26) }) Fn(f, n); }
    [Fact] public void CrlRevocation() => Fn("checkRevocation", 39);
    [Fact] public void FetchHelpers() { foreach (var (f, n) in new[] { ("fetchRim", 12), ("fetchCrl", 4), ("fetchOcsp", 5) }) Fn(f, n); }
    [Fact] public void OcspRequests() { foreach (var (f, n) in new[] { ("ocspRequest", 20), ("ocspUrls", 8), ("asn1TimesWellFormed", 37) }) Fn(f, n); }
    [Fact] public void OcspResponses() => Fn("ocspVerify", 81);
    [Fact] public void OcspChains() => Fn("ocspChain", 30);

    [Fact] public void RimSignatures() => Replay(R, "verifyRim", a => NvidiaAttest.VerifyRim(a[0], Strs(((D)a[1]!)["rimRootSpkiSha256"]), Dbl(((D)a[1]!)["nowMs"])), 108);
    [Fact] public void CollateralHook() => Replay(R, "collateralHook", Hook, 55);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, Fns.Keys);
        Base.Covers(R, ["verifyRim", "collateralHook"]);
        Assert.Equal(467, Base.Total(M));
        Assert.Equal(163, Base.Total(R));
        Assert.Equal(Fns.Count, Base.Cases(M).Select(c => (string)c["fn"]!).Distinct().Count());
    }
}
