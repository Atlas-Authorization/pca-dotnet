using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the Azure MAA key trust (test-data/ref-attest-maa.json.gz, 261 cases): JWKS evaluation over the real public certificate sets and forged certificates, the built-in release-signed pins,
/// multi-vantage corroboration, the guarded certs fetch over a scripted transport, the rotation-safe trust store (scripted fetches, persisted state, signed re-pin), the durable state store and the construction checks.
/// Every string over 400 characters is {"$blob": id} in the corpus (args and out are hydrated). A rejection reason that starts with "error:" (library text) or "The first argument" is compared for presence only.
/// Every fn has a handler and the totals are asserted.</summary>
public class RefAttestMaaTests
{
    const string M = "ref-attest-maa";
    static D Blobs => BlobCorpus.Blobs(M);
    static object? H(object? x) => BlobCorpus.Hydrate(x, Blobs);

    static bool LibText(string s) => s.StartsWith("error:", StringComparison.Ordinal) || s.StartsWith("The first argument", StringComparison.Ordinal);

    static bool Same(object? got, object? want)
    {
        if (want is string w && LibText(w)) return got is string g && g.Length > 0;
        if (want is D wd && got is D gd) return wd.Count == gd.Count && wd.All(e => gd.TryGetValue(e.Key, out var x) && Same(x, e.Value));
        if (want is L wl && got is L gl) return wl.Count == gl.Count && wl.Zip(gl).All(p => Same(p.Second, p.First));
        return Base.Show(want) == Base.Show(got);
    }

    static string Json(object? v) => JsCanonText(v);
    static string JsCanonText(object? v) => Pca.Canonicalize(Base.Json(v));

    static MaaFetchResponse ToResponse(object? r)
    {
        if (r is D d && d.TryGetValue("$throws", out var m)) throw new InvalidOperationException((string)m!);
        var rd = (D)r!;
        // a bare JWKS ({keys}) is the body of a 200 answer; otherwise {status?, url?, contentLength?, body | bodyBytes}
        if (rd.ContainsKey("keys")) return new MaaFetchResponse(true, 200, null, null, Encoding.UTF8.GetBytes(Json(rd)));
        int status = rd.TryGetValue("status", out var st) ? (int)Base.Long(st) : 200;
        byte[] body = rd.ContainsKey("bodyBytes") ? Base.Bytes(rd["bodyBytes"])
            : rd.GetValueOrDefault("body") is D t && t.Count == 1 && t.TryGetValue("$text", out var tx) ? Encoding.UTF8.GetBytes((string)tx!)
            : Encoding.UTF8.GetBytes(Json(rd.GetValueOrDefault("body")));
        return new MaaFetchResponse(status is >= 200 and < 300, status, rd.GetValueOrDefault("url") as string, rd.TryGetValue("contentLength", out var cl) ? JsJsonText(cl) : null, body);
    }

    static string JsJsonText(object? cl) => AtlasPca.Js.JsJson.ToJsString(cl);

    static object? FetchCerts(L a)
    {
        var c = (D)a[0]!;
        var requests = new L();
        var o = new D();
        try
        {
            var opts = c.GetValueOrDefault("opts") as D;
            var jwks = AttestMaaKeys.FetchMaaCerts((string)c["issuer"]!, url => { requests.Add(url + " [redirect:error]"); return ToResponse(c["response"]); }, opts?.GetValueOrDefault("timeoutMs"), opts?.GetValueOrDefault("maxBytes"));
            o["ok"] = true; o["jwks"] = jwks;
        }
        catch (Exception e) { o["ok"] = false; o["error"] = e.Message; }
        o["requests"] = requests;
        return o;
    }

    static object? Trust(L a)
    {
        var sc = (D)a[0]!;
        var store = new MemoryMaaKeyStateStore();
        if (sc.GetValueOrDefault("initial") is D init) foreach (var (k, v) in init) store.Set(k, v);
        var fetches = (L)sc["fetches"]!;
        var requests = new L();
        int i = 0;
        var trust = AttestMaaKeys.CreateMaaKeyTrust((D)sc["policy"]!, store, url =>
        {
            requests.Add(url + " [redirect:error]");
            return ToResponse(fetches[Math.Min(i++, fetches.Count - 1)]);
        });
        var results = new L();
        foreach (var co in (L)sc["calls"]!)
        {
            var call = (D)co!;
            results.Add(trust.GetTrustAnchors((string)call["issuer"]!, call["nowMs"], call.GetValueOrDefault("repin") as D));
        }
        return new D { ["results"] = results, ["store"] = store.Snapshot(), ["fetches"] = requests };
    }

    static object? KvStore(L a)
    {
        var kv = new MemoryDurableKv();
        var store = AttestMaaKeys.DurableMaaKeyStateStore(kv);
        var results = new L();
        foreach (var so in (L)((D)a[0]!)["steps"]!)
        {
            var step = (D)so!;
            if (step.TryGetValue("set", out var set)) { var sl = (L)set!; store.Set((string)sl[0]!, sl[1]); results.Add(null); }
            else results.Add(store.Get((string)step["get"]!));
        }
        return new D { ["results"] = results, ["kv"] = kv.Snapshot() };
    }

    static object? BuildTrust(L a)
    {
        var c = (D)a[0]!;
        AttestMaaKeys.CreateMaaKeyTrust((D)c["policy"]!, new MemoryMaaKeyStateStore(), c.GetValueOrDefault("noFetch") is true ? null : (MaaFetch)(_ => throw new InvalidOperationException("no fetch in a build case")));
        return new D { ["built"] = true };
    }

    static void Fn(string fn, Func<L, object?> run, int min) =>
        Base.Check(M, fn, a => Base.Json(run((L)H(a)!)), (c, have) => Same(have, H(c["out"])), null, min);

    [Fact] public void Constants() => Fn("constants", _ => AttestMaaKeys.Constants(), 1);
    [Fact] public void EvaluateMaaJwks() => Fn("evaluateMaaJwks", a => AttestMaaKeys.EvaluateMaaJwks(a[0], (string)a[1]!, (D)a[2]!, a[3]), 92);
    [Fact] public void LoadBuiltinMaaPins() => Fn("loadBuiltinMaaPins", a => AttestMaaKeys.LoadBuiltinMaaPins((D)a[0]!), 32);
    [Fact] public void Corroborate() => Fn("corroborate", a => AttestMaaKeys.CorroborateMaaKeySets(a[0], a[1], (D)a[2]!), 26);
    [Fact] public void FetchCertsGuarded() => Fn("fetchCerts", FetchCerts, 36);
    [Fact] public void TrustStoreScenarios() => Fn("trust", Trust, 60);
    [Fact] public void KvStoreSteps() => Fn("kvStore", KvStore, 5);
    [Fact] public void BuildTrustCases() => Fn("buildTrust", BuildTrust, 9);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "constants", "evaluateMaaJwks", "loadBuiltinMaaPins", "corroborate", "fetchCerts", "trust", "kvStore", "buildTrust" });
        Assert.Equal(261, Base.Total(M));
        Assert.Equal(49, Blobs.Count);
        var counts = Base.Cases(M).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(new Dictionary<string, int>
        {
            ["evaluateMaaJwks"] = 92, ["trust"] = 60, ["fetchCerts"] = 36, ["loadBuiltinMaaPins"] = 32, ["corroborate"] = 26, ["buildTrust"] = 9, ["kvStore"] = 5, ["constants"] = 1,
        }, counts);
    }
}
