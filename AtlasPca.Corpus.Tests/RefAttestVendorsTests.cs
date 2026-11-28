using System.Text;
using System.Text.RegularExpressions;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the vendor attestation facades (test-data/ref-attest-vendors.json.gz, 758 cases, 22 functions) through the reference-named members of <see cref="AttestVendors"/>:
/// constants, the DCAP quote / TD report parsers, the PCK extension reader and chain, the genuine-quote and collateral verifiers, CRL / signed JSON, the Azure binding, the MAA / Confidential Space
/// token parsers, the x5c chain checks, the hardware-model mapper and both JWKS fetchers over a scripted transport (every requested URL is compared). Strings over 400 characters are
/// {"$blob": id}; {"$bytes": ...} is a byte string. A reason or throw text that comes from a library (OpenSSL "error:" text, JSON.parse messages, the P-256 library's point errors,
/// "URI malformed") is compared by its fixed prefix and presence; a case whose certificate bytes are not DER at all only requires a refusal. No input is outside the typed API, so no case is skipped.
/// Every fn has a handler and the totals are asserted.</summary>
public class RefAttestVendorsTests
{
    const string M = "ref-attest-vendors";
    static D Blobs => BlobCorpus.Blobs(M);
    static object? H(object? x) => BlobCorpus.Hydrate(x, Blobs);

    static readonly Regex Lib = new(@"error:[0-9A-Fa-f]{8}:|Unexpected token|Unexpected end of JSON input|bad point:|invalid Point, expected length|URI malformed|is not valid JSON", RegexOptions.CultureInvariant);
    static readonly string[] NotDer = { "malformed-certificate", "pem-malformed-block", "garbage" };

    static object? Dec(object? v) => v switch
    {
        L l => l.Select(Dec).ToList(),
        D m when Base.IsBytes(m) => Base.Bytes(m),
        D m => m.ToDictionary(e => e.Key, e => Dec(e.Value)),
        _ => v,
    };

    static string JsonText(object? v) => Pca.Canonicalize(Base.Json(v));

    static bool SameText(string want, string got)
    {
        var m = Lib.Match(want);
        return !m.Success ? want == got : got.Length > 0 && got.StartsWith(want[..m.Index], StringComparison.Ordinal);
    }

    static bool Same(object? got, object? want)
    {
        if (want is string w && Lib.IsMatch(w)) return got is string g && SameText(w, g);
        if (want is D wd && got is D gd) return wd.Count == gd.Count && wd.All(e => gd.TryGetValue(e.Key, out var x) && Same(x, e.Value));
        if (want is L wl && got is L gl) return wl.Count == gl.Count && wl.Zip(gl).All(p => Same(p.Second, p.First));
        return Base.Show(want) == Base.Show(got);
    }

    static bool Judge(string name, object? want, object? got, string? thrown)
    {
        if (want is D w && w.Count == 1 && w.TryGetValue("$throws", out var m)) return thrown != null && SameText((string)m!, thrown);
        if (thrown != null) return false;
        if (NotDer.Any(x => name.Contains(x, StringComparison.Ordinal)) && want is D wd && wd.GetValueOrDefault("ok") is false) return got is D g && g.GetValueOrDefault("ok") is false;
        return Same(got, want);
    }

    static AttestationBinding BindingOf(object? e)
    {
        var d = (D)e!;
        return new AttestationBinding((string)d["holderPub"]!, (string)d["grantRef"]!, IntentJs.NumOf(d["epoch"])!.Value, (string)d["nonce"]!);
    }

    static string? Anchor(D o) => o.GetValueOrDefault("trustAnchorRootCaSpkiSha256") as string;
    static long Now(object? v) => Base.Long(v);

    static object? Crl(L a)
    {
        var (ok, revoked, reason) = AttestVendors.IntelPcsCollateral.VerifyCrl((byte[])a[0]!, (byte[])((D)a[1]!)["spkiDer"]!, Now(a[2]));
        return ok ? new D { ["ok"] = true, ["revoked"] = revoked!.OrderBy(x => x, StringComparer.Ordinal).Cast<object?>().ToList() } : new D { ["ok"] = false, ["reason"] = reason };
    }

    static object? Fetch(L a, bool maa)
    {
        var c = (D)a[0]!;
        var script = (L)c["script"]!;
        var log = new L();
        int i = 0;
        KdsResponse Transport(string url)
        {
            log.Add(url);
            var r = (D)script[Math.Min(i++, script.Count - 1)]!;
            if (r.TryGetValue("$throws", out var msg)) throw new InvalidOperationException((string)msg!);
            int status = r.TryGetValue("status", out var st) ? (int)Base.Long(st) : 200;
            var body = r.GetValueOrDefault("body");
            var text = body is D t && t.Count == 1 && t.TryGetValue("$text", out var tx) ? (string)tx! : JsonText(body);
            return new KdsResponse(status is >= 200 and < 300, status, Encoding.UTF8.GetBytes(text));
        }
        var o = new D();
        try
        {
            var opts = c.GetValueOrDefault("opts") as D;
            o["jwks"] = maa
                ? AttestVendors.AzureMaa.FetchMaaJwks((string)c["issuer"]!, Transport, opts?.GetValueOrDefault("certsPath") as string ?? "/certs")
                : AttestVendors.GcpConfidentialSpace.FetchGcpConfidentialSpaceJwks((string)c["issuer"]!, Transport, opts?.GetValueOrDefault("jwksUri") as string);
            o["ok"] = true;
        }
        catch (Exception e) { o["ok"] = false; o["error"] = e.Message; }
        o["requests"] = log;
        return o;
    }

    static readonly Dictionary<string, Func<L, object?>> Handlers = new()
    {
        ["constants"] = _ => AttestVendors.Constants(),
        ["toHex"] = a => AttestVendors.ToHex((byte[])a[0]!),
        ["pemToDer"] = a => AttestVendors.PemToDer((string)a[0]!),
        ["ecdsaP256PublicKey"] = a => AttestVendors.EcdsaP256PublicKey((byte[])a[0]!),
        ["parseDcapTdReport"] = a => AttestVendors.IntelTdx.ParseDcapTdReport((byte[])a[0]!),
        ["parseDcapQuote"] = a => AttestVendors.IntelTdx.ParseDcapQuote((byte[])a[0]!),
        ["extractPckFmspcAndTcb"] = a => AttestVendors.IntelTdx.ExtractPckFmspcAndTcb((byte[])a[0]!),
        ["verifyIntelPckChainX509"] = a => { var o = (D)a[0]!; return AttestVendors.IntelTdx.VerifyIntelPckChainX509((string)o["pckChainPem"]!, Anchor(o), Now(o["nowMs"])); },
        ["verifyGenuineTdxQuote"] = a =>
        {
            var o = (D)a[0]!;
            return AttestVendors.IntelTdx.VerifyGenuineTdxQuote((byte[])o["quote"]!, Anchor(o), o.GetValueOrDefault("expected") is { } e ? BindingOf(e) : null, o.GetValueOrDefault("policy") as D, Now(o["nowMs"]));
        },
        ["verifyCrl"] = Crl,
        ["serialIsRevoked"] = a => AttestVendors.IntelPcsCollateral.SerialIsRevoked(new HashSet<string>(((L)a[0]!).Cast<string>(), StringComparer.Ordinal), (string)a[1]!),
        ["verifySignedJson"] = a => AttestVendors.IntelPcsCollateral.VerifySignedJson((string)a[0]!, (string)a[1]!, (byte[])((D)a[2]!)["spkiDer"]!),
        ["decodeIssuerChainHeader"] = a => AttestVendors.IntelPcsCollateral.DecodeIssuerChainHeader((string)a[0]!),
        ["verifyIntelTdxCollateral"] = a =>
        {
            var o = (D)a[0]!;
            return AttestVendors.IntelPcsCollateral.VerifyIntelTdxCollateral((byte[])o["quote"]!, o.GetValueOrDefault("collateral") as D, Now(o["nowMs"]), o.GetValueOrDefault("policy") as D, Anchor(o),
                o.GetValueOrDefault("allowDebug") is true);
        },
        ["checkAzureRuntimeDataBinding"] = a => AttestVendors.CheckAzureRuntimeDataBinding((byte[])a[0]!, (byte[])a[1]!, BindingOf(a[2])),
        ["parseMaaJwt"] = a => AttestVendors.AzureMaa.ParseMaaJwt((string)a[0]!),
        ["parseGcpCsJwt"] = a => AttestVendors.GcpConfidentialSpace.ParseGcpCsJwt((string)a[0]!),
        ["verifyX5cChain"] = a =>
        {
            var o = (D)a[2]!;
            return AttestVendors.AzureMaa.VerifyX5cChain(a[0] as L ?? new L(), (D)a[1]!, Now(o["nowMs"]), o.TryGetValue("clockSkewMs", out var sk) ? IntentJs.NumOf(sk)!.Value : 0);
        },
        ["verifyJwkX5cChain"] = a =>
        {
            var o = (D)a[2]!;
            return AttestVendors.GcpConfidentialSpace.VerifyJwkX5cChain((L)a[0]!, (D)a[1]!, Now(o["nowMs"]), o.TryGetValue("skewMs", out var sk) ? IntentJs.NumOf(sk)!.Value : 0);
        },
        ["teeTypeOfHwModel"] = a => AttestVendors.GcpConfidentialSpace.TeeTypeOfHwModel((string)a[0]!),
        ["fetchMaaJwks"] = a => Fetch(a, true),
        ["fetchGcpConfidentialSpaceJwks"] = a => Fetch(a, false),
    };

    static readonly Dictionary<string, int> Totals = new()
    {
        ["constants"] = 1, ["toHex"] = 8, ["pemToDer"] = 10, ["ecdsaP256PublicKey"] = 12, ["parseDcapTdReport"] = 11, ["parseDcapQuote"] = 45, ["extractPckFmspcAndTcb"] = 25,
        ["verifyIntelPckChainX509"] = 46, ["verifyGenuineTdxQuote"] = 64, ["verifyCrl"] = 34, ["serialIsRevoked"] = 10, ["verifySignedJson"] = 31, ["decodeIssuerChainHeader"] = 13,
        ["verifyIntelTdxCollateral"] = 159, ["checkAzureRuntimeDataBinding"] = 24, ["parseMaaJwt"] = 57, ["parseGcpCsJwt"] = 57, ["verifyX5cChain"] = 61,
        ["verifyJwkX5cChain"] = 27, ["teeTypeOfHwModel"] = 15, ["fetchMaaJwks"] = 22, ["fetchGcpConfidentialSpaceJwks"] = 26,
    };

    static void Replay(string fn)
    {
        var bad = new List<string>();
        int n = 0;
        foreach (var c in Base.Of(M, fn))
        {
            n++;
            var name = (string)c["name"]!;
            var args = (L)Dec(H(c["args"]))!;
            var want = H(c["out"]);
            object? got = null;
            string? thrown = null;
            try { got = Base.Json(Handlers[fn](args)); }
            catch (Exception e) { thrown = e.Message; }
            bool ok;
            try { ok = Judge(name, want, got, thrown); }
            catch (Exception e) { ok = false; thrown = "compare threw " + e.Message; }
            if (!ok) bad.Add($"{name}\n   want {Base.Show(want)}\n   have {(thrown != null ? "threw " + thrown : Base.Show(got))}");
        }
        Assert.True(bad.Count == 0, $"{M}/{fn}: {bad.Count} of {n} divergent:\n" + string.Join("\n", bad.Take(30).Select(b => b.Length > 600 ? b[..600] : b)));
        Assert.Equal(Totals[fn], n);
    }

    [Fact] public void Constants() => Replay("constants");
    [Fact] public void ToHex() => Replay("toHex");
    [Fact] public void PemToDer() => Replay("pemToDer");
    [Fact] public void EcdsaP256PublicKey() => Replay("ecdsaP256PublicKey");
    [Fact] public void ParseDcapTdReport() => Replay("parseDcapTdReport");
    [Fact] public void ParseDcapQuote() => Replay("parseDcapQuote");
    [Fact] public void ExtractPckFmspcAndTcb() => Replay("extractPckFmspcAndTcb");
    [Fact] public void VerifyIntelPckChainX509() => Replay("verifyIntelPckChainX509");
    [Fact] public void VerifyGenuineTdxQuote() => Replay("verifyGenuineTdxQuote");
    [Fact] public void VerifyCrl() => Replay("verifyCrl");
    [Fact] public void SerialIsRevoked() => Replay("serialIsRevoked");
    [Fact] public void VerifySignedJson() => Replay("verifySignedJson");
    [Fact] public void DecodeIssuerChainHeader() => Replay("decodeIssuerChainHeader");
    [Fact] public void VerifyIntelTdxCollateral() => Replay("verifyIntelTdxCollateral");
    [Fact] public void CheckAzureRuntimeDataBinding() => Replay("checkAzureRuntimeDataBinding");
    [Fact] public void ParseMaaJwt() => Replay("parseMaaJwt");
    [Fact] public void ParseGcpCsJwt() => Replay("parseGcpCsJwt");
    [Fact] public void VerifyX5cChain() => Replay("verifyX5cChain");
    [Fact] public void VerifyJwkX5cChain() => Replay("verifyJwkX5cChain");
    [Fact] public void TeeTypeOfHwModel() => Replay("teeTypeOfHwModel");
    [Fact] public void FetchMaaJwks() => Replay("fetchMaaJwks");
    [Fact] public void FetchGcpConfidentialSpaceJwks() => Replay("fetchGcpConfidentialSpaceJwks");

    [Fact]
    public void Covers()
    {
        Base.Covers(M, Handlers.Keys);
        Assert.Equal(758, Base.Total(M));
        Assert.Equal(Totals.Keys.OrderBy(k => k), Base.Cases(M).Select(c => (string)c["fn"]!).Distinct().OrderBy(k => k));
        Assert.Equal(Totals, Base.Cases(M).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count()));
    }
}
