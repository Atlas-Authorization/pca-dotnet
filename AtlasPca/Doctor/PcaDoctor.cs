// Checks a live PCA deployment's assumptions: clock skew, replay store, trusted-proxy settings, signature-suite policy, root-caveat enforcement and the
// verifier's required checks. Every check returns a CheckResult (pass / warn / fail / skip, what was observed and what to do); RunDoctor merges them,
// VerdictOf reduces them, FormatResults prints them, and nothing printed carries a credential (ScrubText). Configuration is a plain JSON object (sections
// url, clock, store, proxy, verifier); checks that cannot be observed from here say so instead of passing.
using System.Globalization;
using System.Text.RegularExpressions;
using AtlasPca.Js;
using JS = AtlasPca.Doctor.DoctorJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Doctor;

/// <summary>One check's result: id, status, detail, optional remediation and observed.</summary>
public sealed class CheckResult
{
    public D Json { get; }
    CheckResult(D json) { Json = json; }

    public static CheckResult Of(string id, string status, string detail) => new(new D { ["id"] = id, ["status"] = status, ["detail"] = detail });
    public static CheckResult FromJson(D m) => new(m);

    internal CheckResult Fix(string remediation) { Json["remediation"] = remediation; return this; }
    internal CheckResult Observed(D o) { Json["observed"] = o; return this; }
    public string Id => JS.Str(Json.GetValueOrDefault("id"));
    public string Status => JS.Str(Json.GetValueOrDefault("status"));
    public string Detail => JS.Str(Json.GetValueOrDefault("detail"));
    public string? Remediation { get { var r = Json.GetValueOrDefault("remediation"); return JS.Truthy(r) ? JS.Str(r) : null; } }
    public D ToJson() => Json;
}

/// <summary>One HTTP response: the status and a header by lower-case name (null when absent).</summary>
public sealed record DoctorResponse(int Status, Func<string, string?> Header);

/// <summary>The doctor's HTTP client: method is HEAD or GET; redirects are not followed.</summary>
public delegate DoctorResponse DoctorFetch(string method, string url, IReadOnlyDictionary<string, string> headers, long timeoutMs);

/// <summary>The decision of one probe: whether the payment was allowed, and the reasons given.</summary>
public sealed record DoctorDecision(bool Allowed, IReadOnlyList<string> Reasons)
{
    internal D ToJson() => new() { ["allowed"] = Allowed, ["reasons"] = Reasons.Select(r => (object?)r).ToList() };
}

/// <summary>Decide a payment of <paramref name="amount"/> USD under a root grant carrying <paramref name="rootCaveat"/>, through the library under test.</summary>
public delegate DoctorDecision DoctorProbe(D rootCaveat, double amount);

/// <summary>The library under test: its version, where it was found, and how to probe it.</summary>
public sealed record LoadedPca(string Version, string Path, DoctorProbe Probe);

/// <summary>One reading of a server's clock relative to the local one: remote minus local (ms) and its uncertainty, or an error.</summary>
public sealed record DateReading(double OffsetMs, double UncertaintyMs, string? Error)
{
    public D ToJson() => Error != null ? new D { ["error"] = Error } : new D { ["offsetMs"] = OffsetMs, ["uncertaintyMs"] = UncertaintyMs };
}

/// <summary>Collaborators of RunDoctor; every member is optional (real HTTP, the wall clock, no library loader).</summary>
public sealed class DoctorDeps
{
    public DoctorFetch? Fetch;
    public Func<long>? Now;
    public Func<string?, LoadedPca>? LoadPca;
    public Func<double>? Rand;
}

public static class PcaDoctor
{
    // ---- results ----

    /// <summary>A deep copy of a config / result tree with absent (undefined) members dropped, the form the reference serialises.</summary>
    public static object? Json(object? v) => v switch
    {
        D m => m.Where(e => !JS.IsUndef(e.Value)).ToDictionary(e => e.Key, e => Json(e.Value)),
        L l => l.Select(x => JS.IsUndef(x) ? null : Json(x)).ToList(),
        _ => v,
    };

    // ---- scrub ----

    const string S = @"\t\n\u000B\f\r    - \u2028\u2029  　﻿";
    const RegexOptions CI = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
    static readonly Regex ScrubJwt = new(@"(?<![A-Za-z0-9_])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*", RegexOptions.CultureInvariant);
    static readonly Regex ScrubAuth = new(@"(?<![A-Za-z0-9_])(authorization[""']?[" + S + @"]*[:=][" + S + @"]*)[^\n""']*", CI);
    static readonly Regex ScrubBearer = new(@"(?<![A-Za-z0-9_])(Bearer|Basic|Token)[" + S + @"]+[A-Za-z0-9_.~+/=-]{6,}", CI);
    static readonly Regex ScrubUrl = new(@"([a-z][a-z0-9+.-]*://)[^" + S + @"/@]*:[^" + S + @"/@]*@", CI);
    static readonly Regex ScrubPair = new(@"(?<![A-Za-z0-9_])((?:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|auth|sslpassword)[""']?[" + S + @"]*[:=][" + S + @"]*)(""[^""]*""|'[^']*'|[^" + S + @"""'&,;]+)", CI);
    static readonly Regex ScrubLong = new(@"[A-Za-z0-9_-]{40,}", RegexOptions.CultureInvariant);

    /// <summary>Remove credentials from text the doctor prints: URL userinfo, token= / password= pairs, bearer credentials, JWTs and long token runs.</summary>
    public static string ScrubText(object? text)
    {
        var t = JS.Str(text);
        t = ScrubJwt.Replace(t, "[redacted]");
        t = ScrubAuth.Replace(t, "${1}[redacted]");
        t = ScrubBearer.Replace(t, "${1} [redacted]");
        t = ScrubUrl.Replace(t, "${1}[redacted]@");
        t = ScrubPair.Replace(t, "${1}[redacted]");
        t = ScrubLong.Replace(t, "[redacted]");
        return t.Length > 600 ? t.Substring(0, 600) + "..." : t;
    }

    /// <summary>Scrub every string inside a JSON-like value (nesting deeper than 8 is left as it is, as the reference does).</summary>
    public static object? ScrubDeep(object? v) => ScrubDeep(v, 0);

    static object? ScrubDeep(object? v, int depth)
    {
        if (v is string) return ScrubText(v);
        if (depth > 8 || v == null || !(v is D || v is L)) return v;
        if (v is L l) return l.Select(x => ScrubDeep(x, depth + 1)).ToList();
        var o = new D();
        foreach (var (k, val) in (D)v) o[k] = ScrubDeep(val, depth + 1);
        return o;
    }

    // ---- fetch ----

    /// <summary>The default client over HttpClient: redirects are not followed.</summary>
    public static DoctorFetch HttpFetch { get; } = (method, url, headers, timeoutMs) =>
    {
        using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromMilliseconds(timeoutMs) };
        using var req = new HttpRequestMessage(new HttpMethod(method), url);
        foreach (var (k, v) in headers) req.Headers.TryAddWithoutValidation(k, v);
        using var res = client.Send(req, HttpCompletionOption.ResponseHeadersRead);
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in res.Headers) map[h.Key] = string.Join(", ", h.Value);
        foreach (var h in res.Content.Headers) map[h.Key] = string.Join(", ", h.Value);
        return new DoctorResponse((int)res.StatusCode, n => map.GetValueOrDefault(n));
    };

    // ---- clock ----

    public const string DefaultReferenceUrl = "https://www.google.com/generate_204";
    public const string ClockRemediation =
        "Synchronise every verifier, issuer and replay-store host with NTP (chrony or systemd-timesyncd) and alert on drift. PCA tolerates at most 60 s between any two clocks (PCACTN_MAX_SKEW_MS); replay retention is exp + skew, so a clock outside that bound can free a nonce early or reject fresh actions.";

    /// <summary>One reading of the server's clock from its Date header (one-second resolution: +-0.5 s plus half the round trip).</summary>
    public static DateReading ReadDate(string url, DoctorFetch fetch, Func<long> now, long timeoutMs)
    {
        double t0 = now();
        DoctorResponse res;
        try { res = fetch("HEAD", url, new Dictionary<string, string>(), timeoutMs); }
        catch (Exception e) { return new DateReading(0, 0, "request failed: " + e.Message); }
        double t1 = now();
        var date = res.Header("date");
        double d = date == null ? double.NaN : JS.ParseDate(date);
        if (double.IsNaN(d) || double.IsInfinity(d)) return new DateReading(0, 0, date == null ? "no Date header" : "unparseable Date header '" + date + "'");
        return new DateReading(d + 500 - (t0 + t1) / 2, 500 + (t1 - t0) / 2, null);
    }

    static string Signed(double ms) => (ms >= 0 ? "+" : "-") + JS.ToFixed1(Math.Abs(ms) / 1000) + " s";

    /// <summary>Clock skew of the deployment against a reference (the Date headers of both, or this machine's clock).</summary>
    public static CheckResult CheckClock(D cfg, DoctorFetch fetch, Func<long>? now = null)
    {
        Func<long> clock = now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        var url = JS.G(cfg, "url");
        if (!JS.Truthy(url)) return CheckResult.Of("clock", "skip", "no deployment URL given (--url)");
        var clockCfg = JS.G(cfg, "clock");
        double max = JS.ToNumber(JS.Or(JS.G(clockCfg, "maxSkewMs"), (double)Pca.MaxSkewMs));
        double warnAt = max * JS.ToNumber(JS.Or(JS.G(clockCfg, "warnFraction"), 0.25));
        long timeout = (long)JS.ToNumber(JS.Or(JS.G(clockCfg, "timeoutMs"), 10_000.0));
        var dep = ReadDate(JS.Str(url), fetch, clock, timeout);
        if (dep.Error != null)
            return CheckResult.Of("clock", "warn", "cannot observe the deployment's clock at " + JS.Str(url) + ": " + dep.Error)
                .Fix("Make the deployment answer with a Date header (RFC 9110 requires one from an origin with a clock), or check its clock on the host. " + ClockRemediation);
        var refUrl = JS.Str(JS.Or(JS.G(clockCfg, "referenceUrl"), DefaultReferenceUrl));
        var refR = new DateReading(0, 0, null);
        var refName = "this machine's clock";
        var refNote = "";
        if (refUrl != "local")
        {
            var r = ReadDate(refUrl, fetch, clock, timeout);
            if (r.Error != null) refNote = " (reference " + refUrl + " unusable: " + r.Error + "; compared with this machine's clock instead)";
            else { refR = r; refName = refUrl; }
        }
        double skew = dep.OffsetMs - refR.OffsetMs;
        double unc = dep.UncertaintyMs + refR.UncertaintyMs;
        double lower = Math.Abs(skew) - unc;
        double upper = Math.Abs(skew) + unc;
        // a skew, uncertainty or threshold that is not a number can show nothing: fail, never pass
        var measurable = double.IsFinite(lower) && double.IsFinite(upper) && !double.IsNaN(max) && !double.IsNaN(warnAt);
        var status = !measurable ? "fail" : lower > max ? "fail" : Math.Abs(skew) > warnAt || upper > max ? "warn" : "pass";
        var detail = "deployment clock " + Signed(skew) + " relative to " + refName + refNote + " (+-" + JS.ToFixed1(unc / 1000) + " s: Date has 1 s resolution, plus round trips); "
            + "fail beyond " + JS.NumStr(max / 1000) + " s, warn above " + JS.NumStr(warnAt / 1000) + " s. The Date header is written by whatever answers the request (a CDN or proxy may set it).";
        var res2 = CheckResult.Of("clock", status, detail);
        if (status != "pass") res2.Fix(ClockRemediation);
        return res2.Observed(new D { ["skewMs"] = skew, ["uncertaintyMs"] = unc, ["maxSkewMs"] = max, ["warnAtMs"] = warnAt, ["reference"] = refName });
    }

    // ---- proxy ----

    public const string ProxyRemediation =
        "Set TRUSTED_PROXY_COUNT to exactly the number of reverse proxies in front of the API that APPEND to the trusted header (1 behind one load balancer / ingress; 0 when clients connect directly), and TRUSTED_PROXY_HEADER to the header they write. Too high lets a client pick its own rate-limit bucket with extra X-Forwarded-For entries; too low merges every client into the proxy's bucket.";

    static CheckResult Fail(string id, string detail, string remediation) => CheckResult.Of(id, "fail", detail).Fix(remediation);

    /// <summary>The stated TRUSTED_PROXY_COUNT / TRUSTED_PROXY_HEADER against the stated number of appending proxies.</summary>
    public static CheckResult CheckProxyConfig(D cfg)
    {
        var p = JS.G(cfg, "proxy");
        var n = JS.G(p, "trustedProxyCount");
        if (JS.IsUndef(n)) return CheckResult.Of("proxy.config", "skip", "TRUSTED_PROXY_COUNT not given (config proxy.trustedProxyCount or env TRUSTED_PROXY_COUNT)");
        var header = JS.Or(JS.G(p, "header"), "x-forwarded-for");
        var hs = JS.Str(header);
        var ns = JS.Str(n);
        if (!JS.IsInteger(n) || JS.Num(n) < 0 || JS.IsNegZero(n) || JS.Num(n) > 16) return Fail("proxy.config", "TRUSTED_PROXY_COUNT=" + ns + " is not an integer in 0..16", ProxyRemediation);
        double nv = JS.Num(n)!.Value;
        if (header is "x-real-ip" && nv == 0) return Fail("proxy.config", "TRUSTED_PROXY_HEADER=x-real-ip needs TRUSTED_PROXY_COUNT >= 1 (with 0 every forwarding header is ignored)", ProxyRemediation);
        var hops = JS.G(p, "hops");
        if (JS.IsUndef(hops))
        {
            var r = CheckResult.Of("proxy.config", nv == 0 ? "pass" : "warn", "TRUSTED_PROXY_COUNT=" + ns + " (" + hs + "); the real number of appending proxies was not stated (proxy.hops / PCA_TRUSTED_PROXY_HOPS), so it cannot be compared");
            return nv == 0 ? r : r.Fix(ProxyRemediation);
        }
        double h = JS.ToNumber(hops);
        var hp = JS.Str(hops);
        if (nv > h) return Fail("proxy.config", "TRUSTED_PROXY_COUNT=" + ns + " is larger than the " + hp + " proxies in front of the API: a client chooses its own address (and rate-limit bucket) with extra " + hs + " entries", ProxyRemediation);
        if (nv < h) return CheckResult.Of("proxy.config", "warn", "TRUSTED_PROXY_COUNT=" + ns + " is smaller than the " + hp + " proxies in front of the API: clients are keyed by a proxy's address and share its bucket").Fix(ProxyRemediation);
        return CheckResult.Of("proxy.config", "pass", "TRUSTED_PROXY_COUNT=" + ns + " (" + hs + ") matches the stated " + hp + " appending proxies");
    }

    /// <summary>mulberry32: the seeded PRNG the reference vectors use (returns values in [0, 1)).</summary>
    public static Func<double> Mulberry32(long seed)
    {
        int a = unchecked((int)seed);
        return () =>
        {
            unchecked
            {
                a += 0x6d2b79f5;
                int t = a;
                t = (t ^ (int)((uint)t >> 15)) * (t | 1);
                t ^= t + (t ^ (int)((uint)t >> 7)) * (t | 61);
                return (uint)(t ^ (int)((uint)t >> 14)) / 4294967296.0;
            }
        };
    }

    /// <summary>A random documentation address (RFC 5737 TEST-NET-2 / -3): never a real client.</summary>
    public static string TestNetIp(Func<double>? rand = null)
    {
        var r = rand ?? Random.Shared.NextDouble;
        var net = r() < 0.5 ? "198.51.100" : "203.0.113";
        return net + "." + (1 + (int)Math.Floor(r() * 254)).ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>Forged values for all three forwarding headers at once (the server trusts at most one of them).</summary>
    public static Dictionary<string, string> ForgedHeaders(Func<double>? rand = null)
    {
        var r = rand ?? Random.Shared.NextDouble;
        var chain = new List<string>();
        for (int i = 0; i < 17; i++) chain.Add(TestNetIp(r));
        return new Dictionary<string, string>
        {
            ["x-forwarded-for"] = string.Join(", ", chain),
            ["forwarded"] = string.Join(", ", chain.Select(ip => "for=" + ip)),
            ["x-real-ip"] = TestNetIp(r),
        };
    }

    static double? Remaining(DoctorFetch fetch, string url, IReadOnlyDictionary<string, string> headers, long timeoutMs)
    {
        var r = fetch("GET", url, headers, timeoutMs);
        var v = r.Header("ratelimit-remaining");
        double n = v == null ? double.NaN : JS.ToNumber(v);
        return double.IsNaN(n) || double.IsInfinity(n) ? null : n;
    }

    /// <summary>new URL(path, base).href for the shapes a probe path takes (absolute URL, rooted path, relative path).</summary>
    static string ResolveHref(string path, string baseUrl)
    {
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var b) || b.Host.Length == 0) throw new AtlasPca.Jose.InvalidUrlException();
        if (!Uri.TryCreate(b, path, out var r)) throw new AtlasPca.Jose.InvalidUrlException();
        return r.AbsoluteUri;
    }

    /// <summary>Forged forwarding headers sent to a public rate-limited path: a forged request landing in a FRESH bucket means client-written entries are trusted.</summary>
    public static CheckResult CheckProxyProbe(D cfg, DoctorFetch fetch, Func<double>? rand = null)
    {
        const string id = "proxy.probe";
        var url = JS.G(cfg, "url");
        if (!JS.Truthy(url)) return CheckResult.Of(id, "skip", "no deployment URL given (--url)");
        var proxy = JS.G(cfg, "proxy");
        if (JS.G(proxy, "probe") is false) return CheckResult.Of(id, "skip", "disabled (--no-probe)");
        var target = ResolveHref(JS.Str(JS.Or(JS.G(proxy, "probePath"), "/v1/pca/suites")), JS.Str(url));
        long t = (long)JS.ToNumber(JS.Or(JS.G(JS.G(cfg, "clock"), "timeoutMs"), 10_000.0));
        double? a, b, f, c;
        try
        {
            var none = new Dictionary<string, string>();
            a = Remaining(fetch, target, none, t);
            b = Remaining(fetch, target, none, t);
            f = Remaining(fetch, target, ForgedHeaders(rand), t);
            c = Remaining(fetch, target, none, t);
        }
        catch (Exception e)
        {
            return CheckResult.Of(id, "warn", "probe request to " + target + " failed: " + e.Message).Fix("Set proxy.probePath to a public, rate-limited path of the deployment, or run with --no-probe.");
        }
        var observed = new D { ["url"] = target, ["remaining"] = new L { a, b, f, c } };
        if (a == null || b == null || f == null || c == null)
            return CheckResult.Of(id, "skip", "not observable remotely: " + target + " does not return a RateLimit-Remaining header on every response").Observed(observed);
        string sa = JS.NumStr(a.Value), sb = JS.NumStr(b.Value), sf = JS.NumStr(f.Value), sc = JS.NumStr(c.Value);
        if (!(b < a && c < b))
            return CheckResult.Of(id, "warn", "inconclusive: the plain requests' bucket did not drain monotonically (" + sa + ", " + sb + ", then " + sc
                + "): a window rollover, a shared bucket or concurrent traffic. Re-run.").Observed(observed);
        if (f > b)
            return CheckResult.Of(id, "fail", "a request with FORGED forwarding headers got a fresh rate-limit bucket (remaining " + sf + ", while the plain requests' bucket was at " + sb
                + "): the deployment trusts client-written forwarding entries").Fix(ProxyRemediation).Observed(observed);
        return CheckResult.Of(id, "pass", "forged X-Forwarded-For / Forwarded / X-Real-IP did not move the client to another bucket (remaining " + sa + ", " + sb + ", forged " + sf + ", " + sc
            + "). A count that is too LOW is not observable from one client.").Observed(observed);
    }

    // ---- suites ----

    public const string SuitesRemediation =
        "Set the verifier's allowedSuites to exactly the suites your issuers sign with (names from SIG_SUITES), e.g. ['ed25519'] or ['hybrid-ed25519-ml-dsa-65'].";
    public const string PqRemediation =
        "Never set allowUnboundPq. For pure-PQ or hybrid roots, configure pqPins (issuer Ed25519 identity -> PQ public key, from pqPinFor) or verify against your stored root grant (trustedRoot; requirePCA / verifyPCActnCore do this).";

    static readonly Regex B64U = new(@"\A[A-Za-z0-9_-]+\z", RegexOptions.CultureInvariant);
    static readonly Regex Ed25519Id = new(@"\A[A-Za-z0-9_-]{43}\z", RegexOptions.CultureInvariant);

    /// <summary>The closed signature-suite registry (SIG_SUITES), in registry order.</summary>
    public static readonly IReadOnlyList<string> RegisteredSuites = new[]
    {
        "ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65", "slh-dsa-sha2-128f", "hybrid-ed25519-slh-dsa-sha2-128f", "ml-dsa-87",
        "hybrid-ed25519-ml-dsa-87", "slh-dsa-sha2-256s", "hybrid-ed25519-slh-dsa-sha2-256s", "fn-dsa-512", "less-cat1", "hybrid-ed25519-less-cat1", "fn-dsa-1024",
    };

    static bool IsPq(object? alg) => alg is string s && s != "ed25519" && RegisteredSuites.Contains(s);

    /// <summary>allowedSuites against the closed suite registry (the library's registered suite names, in registry order).</summary>
    public static CheckResult CheckAllowedSuites(D cfg, IReadOnlyList<string>? registry = null)
    {
        registry ??= RegisteredSuites;
        const string id = "suites.allowed";
        var v = JS.G(cfg, "verifier");
        if (!JS.Truthy(v)) return CheckResult.Of(id, "skip", "no verifier configuration given (config verifier.*)");
        var list = JS.G(v, "allowedSuites");
        var known = string.Join(", ", registry);
        if (JS.IsUndef(list))
            return CheckResult.Of(id, "warn", "allowedSuites is unset: every registered suite is accepted (" + registry.Count + ": " + known + ")").Fix(SuitesRemediation);
        if (list is not L l || l.Count == 0)
            return CheckResult.Of(id, "fail", "allowedSuites is empty or not a list: no PCActn can verify").Fix(SuitesRemediation);
        var unknown = l.Where(s => !(s is string ss && registry.Contains(ss))).Select(JS.Str).ToList();
        if (unknown.Count > 0)
            return CheckResult.Of(id, "fail", "allowedSuites names suite(s) outside the registry: " + string.Join(", ", unknown) + " (known: " + known + ")").Fix(SuitesRemediation);
        return CheckResult.Of(id, "pass", "allowedSuites = " + string.Join(", ", l.Select(JS.Str)));
    }

    /// <summary>allowUnboundPq / pqPins / trustedRoot sanity.</summary>
    public static CheckResult CheckPqBinding(D cfg)
    {
        const string id = "suites.pq-binding";
        var v = JS.G(cfg, "verifier");
        if (!JS.Truthy(v)) return CheckResult.Of(id, "skip", "no verifier configuration given (config verifier.*)");
        if (JS.G(v, "allowUnboundPq") is true)
            return Fail(id, "allowUnboundPq is set: PQ keys are read from the artifact, so a hybrid gives no protection against an Ed25519 forger and a pure-PQ hop can be signed by any key", PqRemediation);
        var pins = JS.G(v, "pqPins");
        if (!JS.IsUndef(pins))
        {
            if (!JS.Truthy(pins) || pins is not D pd) return Fail(id, "pqPins is not an object of { ed25519 identity: pq public key }", PqRemediation);
            var bad = pd.Where(e => !Ed25519Id.IsMatch(e.Key) || !(e.Value is string val && B64U.IsMatch(val))).Select(e => e.Key).ToList();
            if (bad.Count > 0)
                return Fail(id, "pqPins has malformed entries (key must be a 43-char base64url Ed25519 identity, value a base64url PQ key): " + string.Join(", ", bad), PqRemediation);
        }
        var allowed = JS.Or(JS.G(v, "allowedSuites"), RegisteredSuites.Select(s => (object?)s).ToList());
        if (allowed is not L al) throw new InvalidOperationException("allowedSuites is not a list");
        var pq = al.Where(IsPq).Select(s => (string)s!).ToList();
        if (pq.Count == 0) return CheckResult.Of(id, "pass", "no post-quantum suite is accepted (Ed25519 only: no PQ binding needed, and no PQ protection)");
        bool pinned = !JS.IsUndef(pins) && ((D)pins!).Count > 0;
        if (!pinned && JS.G(v, "trustedRoot") is not true)
            return CheckResult.Of(id, "warn", "post-quantum suite(s) accepted (" + string.Join(", ", pq)
                + ") with neither pqPins nor a stored trustedRoot: a non-Ed25519 root is refused (fail closed) or its PQ key is not pinned").Fix(PqRemediation);
        return CheckResult.Of(id, "pass", "PQ suites (" + string.Join(", ", pq) + ") are bound: " + (pinned ? ((D)pins!).Count.ToString(CultureInfo.InvariantCulture) + " pin(s)" : "stored trustedRoot") + "; allowUnboundPq off");
    }

    // ---- replay store remediation texts ----

    public const string AtomicityRemediation =
        "Make consumeOnce / advance one atomic operation on the shared store, e.g. Postgres INSERT .. ON CONFLICT (key) DO UPDATE .. WHERE until < $now RETURNING and UPDATE .. WHERE counter < $n RETURNING, Redis SET key NX PX or a Lua compare-and-set; never read, then write. Then run the full kit: pca-store-conformance --adapter <your adapter>.";
    public const string DurabilityRemediation =
        "Keep consumed keys and counters in a store with synchronous, persistent commits (Postgres synchronous_commit=on; Redis appendfsync always and maxmemory-policy noeviction), shared by every verifier instance. An in-memory store is only correct for a single process whose lifetime covers the action lifetime.";

    /// <summary>Without a store adapter the replay store cannot be exercised remotely: both checks are skipped. shortcut: an adapter module path cannot be
    /// loaded here (the reference imports a JS module); naming one is a failed check, upgrade by supplying an adapter factory through the store conformance kit.</summary>
    public static List<CheckResult> CheckStore(D cfg)
    {
        var store = JS.G(cfg, "store");
        var spec = JS.G(store, "adapter");
        if (!JS.Truthy(spec))
        {
            const string detail = "no store adapter given (--store ./adapter.mjs); the replay store cannot be exercised remotely";
            return new List<CheckResult> { CheckResult.Of("store.atomicity", "skip", detail), CheckResult.Of("store.durability", "skip", detail) };
        }
        return new List<CheckResult>
        {
            CheckResult.Of("store.atomicity", "fail", "cannot load the store adapter " + JS.Str(spec) + ": adapter modules cannot be loaded by this SDK").Fix("Point --store at a store adapter class (see the store conformance kit guide)."),
        };
    }

    // ---- root caveats and enforcement ----

    public const string RootCaveatMinVersion = "0.4.1";
    public const string CaveatRemediation =
        "Upgrade @atlasauth/pca to >= 0.4.1 in the deployed application (root caveats outside the envelope are enforced from 0.4.1), redeploy, and re-run pca-doctor with --pca-dir pointing at the application.";
    public static readonly IReadOnlyList<string> DefaultRequired = new[] { "counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound" };

    /// <summary>-1 / 0 / 1 for a &lt; b / = / &gt; over major.minor.patch (pre-release tags ignored); NaN parts compare as -1.</summary>
    public static int CompareVersion(string a, string b)
    {
        var pa = Regex.Split(a, "[.+-]"); var pb = Regex.Split(b, "[.+-]");
        for (int i = 0; i < 3; i++)
        {
            double x = i < pa.Length ? JS.ToNumber(pa[i]) : double.NaN;
            double y = i < pb.Length ? JS.ToNumber(pb[i]) : double.NaN;
            if (double.IsNaN(x) || double.IsInfinity(x)) x = -1;
            if (double.IsNaN(y) || double.IsInfinity(y)) y = -1;
            if (x != y) return x < y ? -1 : 1;
        }
        return 0;
    }

    /// <summary>Root-caveat enforcement of the deployed library: version >= 0.4.1, and a probe (max_spend 100 denies 150 and allows 50; an unknown caveat type denies).</summary>
    public static CheckResult CheckRootCaveats(D cfg, Func<string?, LoadedPca>? loadPca = null)
    {
        const string id = "caveats.root";
        var dir = JS.G(JS.G(cfg, "verifier"), "pcaDir");
        var pcaDir = JS.Truthy(dir) ? JS.Str(dir) : null;
        LoadedPca pca;
        try { pca = (loadPca ?? NoLoader)(pcaDir); }
        catch (Exception e) { return CheckResult.Of(id, "fail", "cannot load @atlasauth/pca" + (pcaDir != null ? " from " + pcaDir : "") + ": " + e.Message).Fix(CaveatRemediation); }
        var where = "@atlasauth/pca " + pca.Version + " at " + pca.Path;
        if (CompareVersion(pca.Version, RootCaveatMinVersion) < 0)
            return CheckResult.Of(id, "fail", where + ": root caveats outside the envelope are NOT enforced before " + RootCaveatMinVersion + " (legacy behaviour)").Fix(CaveatRemediation);
        DoctorDecision over, under, unknown;
        try
        {
            over = pca.Probe(new D { ["type"] = "max_spend", ["usd"] = 100L }, 150);
            under = pca.Probe(new D { ["type"] = "max_spend", ["usd"] = 100L }, 50);
            unknown = pca.Probe(new D { ["type"] = "pca-doctor-unknown-caveat" }, 50);
        }
        catch (Exception e) { return CheckResult.Of(id, "fail", where + ": the enforcement probe could not run: " + e.Message).Fix(CaveatRemediation); }
        var observed = new D { ["version"] = pca.Version, ["over"] = over.ToJson(), ["under"] = under.ToJson(), ["unknown"] = unknown.ToJson() };
        if (over.Allowed || unknown.Allowed)
            return CheckResult.Of(id, "fail", where + ": a root caveat was NOT enforced (" + (over.Allowed ? "max_spend 100 allowed a 150 payment" : "an unknown root caveat type was allowed") + ")")
                .Fix(CaveatRemediation).Observed(observed);
        if (!under.Allowed)
            return CheckResult.Of(id, "warn", where + ": inconclusive: the control payment within the root max_spend was denied too (" + string.Join("; ", under.Reasons) + ")").Observed(observed);
        return CheckResult.Of(id, "pass", where + ": root caveats enforced (max_spend 100 denies 150, allows 50; an unknown root caveat type denies)").Observed(observed);
    }

    /// <summary>The in-process probe (also a <see cref="DoctorProbe"/>): a payment of <paramref name="amount"/> USD under the root caveat, decided by THIS library's caveat
    /// evaluation (<c>now</c> defaults to the wall clock). Pass <c>PcaDoctor.ProbeDecision</c> as the probe of a <see cref="LoadedPca"/> that describes this library.</summary>
    public static DoctorDecision ProbeDecision(D rootCaveat, double amount, long? now = null)
    {
        var at = now ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var ctx = new D
        {
            ["now"] = at,
            ["action"] = new D { ["verb"] = "pay", ["resource"] = "invoice:42", ["reversibility_class"] = "reversible", ["params"] = new D { ["amount"] = amount, ["currency"] = "usd" } },
        };
        var r = Caveats.EvaluateCaveats(new List<object?> { rootCaveat }, ctx);
        return new DoctorDecision(r.Ok, r.Failed.ToList());
    }

    static LoadedPca NoLoader(string? dir) =>
        throw new InvalidOperationException("no @atlasauth/pca loader is configured (the .NET SDK cannot load the deployed library; supply a loader that probes it)");

    /// <summary>requirePCA must not run with insecureAllowUnenforced, and a custom require list should keep the defaults.</summary>
    public static CheckResult CheckEnforcement(D cfg)
    {
        const string id = "verifier.enforcement";
        var v = JS.G(cfg, "verifier");
        if (!JS.Truthy(v)) return CheckResult.Of(id, "skip", "no verifier configuration given (config verifier.*)");
        if (JS.G(v, "insecureAllowUnenforced") is true)
            return Fail(id, "requirePCA runs with insecureAllowUnenforced: required checks that are not enforced do not deny", "Remove insecureAllowUnenforced and supply the stores the required checks need (counter / revocation / budget).");
        var req = JS.G(v, "require");
        if (!JS.IsUndef(req))
        {
            if (req == null) throw new InvalidOperationException("Cannot read properties of null (reading 'includes')");
            var missing = new List<string>();
            foreach (var c in DefaultRequired)
            {
                bool has;
                if (req is L rl) has = rl.Any(x => x is string xs && xs == c);
                else if (req is string rs) has = rs.Contains(c, StringComparison.Ordinal);
                else throw new InvalidOperationException("require.includes is not a function");
                if (!has) missing.Add(c);
            }
            if (missing.Count > 0)
                return CheckResult.Of(id, "warn", "the require list drops default check(s): " + string.Join(", ", missing)).Fix("Keep every default required check (" + string.Join(", ", DefaultRequired) + ") and add to it.");
        }
        if (JS.Truthy(req))
        {
            if (req is not L rl2) throw new InvalidOperationException("require.join is not a function");
            return CheckResult.Of(id, "pass", "require = " + string.Join(", ", rl2.Select(x => JS.Nullish(x) ? "" : JS.Str(x))));
        }
        return CheckResult.Of(id, "pass", "default required checks; insecureAllowUnenforced off");
    }

    // ---- runDoctor ----

    public static readonly IReadOnlyList<string> CheckGroups = new[] { "clock", "store", "proxy", "suites", "caveats" };

    /// <summary>One check group that throws is a failed check, not a crashed run and not a skipped one.</summary>
    static List<CheckResult> Guarded(string id, Func<List<CheckResult>> run)
    {
        try { return run(); }
        catch (Exception e)
        {
            return new List<CheckResult> { CheckResult.Of(id, "fail", id + " could not run: " + ScrubText(e.Message)).Fix("Fix the configuration or the dependency named above and run the doctor again.") };
        }
    }

    static List<CheckResult> One(CheckResult r) => new() { r };

    /// <summary>Numeric settings that would make a check meaningless (NaN, negative, zero where a duration is needed) are configuration errors.</summary>
    public static List<string> ConfigProblems(D cfg)
    {
        var o = new List<string>();
        var clock = JS.G(cfg, "clock"); var store = JS.G(cfg, "store"); var proxy = JS.G(cfg, "proxy");
        Pos(o, "clock.maxSkewMs", JS.G(clock, "maxSkewMs"), false);
        Pos(o, "clock.timeoutMs", JS.G(clock, "timeoutMs"), false);
        var wf = JS.G(clock, "warnFraction");
        if (!JS.IsUndef(wf))
        {
            var d = JS.Num(wf);
            if (!(d != null && d > 0 && d <= 1)) o.Add("clock.warnFraction must be a number in (0, 1]");
        }
        Pos(o, "store.concurrency", JS.G(store, "concurrency"), true);
        Pos(o, "store.rounds", JS.G(store, "rounds"), true);
        NonNeg(o, "proxy.trustedProxyCount", JS.G(proxy, "trustedProxyCount"));
        NonNeg(o, "proxy.hops", JS.G(proxy, "hops"));
        var url = JS.G(cfg, "url");
        if (!JS.IsUndef(url))
        {
            if (!(url is string us) || !Uri.TryCreate(us, UriKind.Absolute, out var u) || (u.Scheme is "http" or "https" && u.Host.Length == 0)) o.Add("url is not a valid URL");
            else if (u.Scheme is not ("http" or "https")) o.Add("url must be an http(s) URL");
        }
        return o;
    }

    static void Pos(List<string> o, string name, object? v, bool integer)
    {
        if (JS.IsUndef(v)) return;
        var d = JS.Num(v);
        if (d == null || double.IsNaN(d.Value) || double.IsInfinity(d.Value) || d <= 0 || (integer && !JS.IsInteger(v))) o.Add(name + " must be a positive " + (integer ? "integer" : "number"));
    }

    static void NonNeg(List<string> o, string name, object? v)
    {
        if (JS.IsUndef(v)) return;
        if (!JS.IsInteger(v) || JS.Num(v) < 0 || JS.IsNegZero(v)) o.Add(name + " must be a non-negative integer");
    }

    /// <summary>Run the selected check groups (all by default) and scrub everything they report.</summary>
    public static List<CheckResult> RunDoctor(D cfg, IReadOnlyList<string>? only = null, DoctorDeps? deps = null)
    {
        var d = deps ?? new DoctorDeps();
        var sel = only ?? CheckGroups;
        var problems = ConfigProblems(cfg);
        if (problems.Count > 0)
            return problems.Select(p => CheckResult.Of("config", "fail", ScrubText("invalid configuration: " + p)).Fix("Correct the setting; no check was run.")).ToList();
        var fetch = d.Fetch ?? HttpFetch;
        var o = new List<CheckResult>();
        if (sel.Contains("clock")) o.AddRange(Guarded("clock", () => One(CheckClock(cfg, fetch, d.Now))));
        if (sel.Contains("store")) o.AddRange(Guarded("store", () => CheckStore(cfg)));
        if (sel.Contains("proxy"))
        {
            o.AddRange(Guarded("proxy.config", () => One(CheckProxyConfig(cfg))));
            o.AddRange(Guarded("proxy.probe", () => One(CheckProxyProbe(cfg, fetch, d.Rand))));
        }
        if (sel.Contains("suites"))
        {
            o.AddRange(Guarded("suites.allowed", () => One(CheckAllowedSuites(cfg))));
            o.AddRange(Guarded("suites.pq", () => One(CheckPqBinding(cfg))));
        }
        if (sel.Contains("caveats"))
        {
            o.AddRange(Guarded("caveats.root", () => One(CheckRootCaveats(cfg, d.LoadPca))));
            o.AddRange(Guarded("caveats.enforcement", () => One(CheckEnforcement(cfg))));
        }
        return o.Select(r => CheckResult.FromJson((D)ScrubDeep(r.Json)!)).ToList();
    }

    /// <summary>fail if any check failed; warn if any warned (fail under strict); else pass. A run in which nothing was checked is a fail.</summary>
    public static string VerdictOf(IReadOnlyList<CheckResult> results, bool strict = false)
    {
        bool any = false, fail = false, warn = false;
        foreach (var r in results)
        {
            var s = r.Status;
            if (s != "skip") any = true;
            if (s == "fail") fail = true;
            if (s == "warn") warn = true;
        }
        if (!any) return "fail";
        if (fail) return "fail";
        if (warn) return strict ? "fail" : "warn";
        return "pass";
    }

    public static string FormatResults(IReadOnlyList<CheckResult> results, string? target, bool strict = false)
    {
        var lines = new List<string> { "pca-doctor" + (!string.IsNullOrEmpty(target) ? ": " + target : "") };
        foreach (var r in results)
        {
            lines.Add("  " + JS.PadEnd(r.Status.ToUpperInvariant(), 4) + "  " + JS.PadEnd(r.Id, 20) + " " + r.Detail);
            if (r.Remediation != null) lines.Add("  " + JS.PadEnd("", 4) + "  " + JS.PadEnd("", 20) + " fix: " + r.Remediation);
        }
        bool anyChecked = results.Any(r => r.Status != "skip");
        int N(string s) => results.Count(r => r.Status == s);
        if (!anyChecked) lines.Add("  FAIL  nothing checked        no check produced a result: nothing about this deployment was verified");
        lines.Add("Summary: " + N("pass") + " pass, " + N("warn") + " warn, " + N("fail") + " fail, " + N("skip") + " skip -> " + VerdictOf(results, strict).ToUpperInvariant());
        return string.Join("\n", lines);
    }

    // ---- configuration ----

    static readonly Regex Truthy = new(@"\A(?:1|true|yes|on)\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    static readonly IReadOnlyList<string> ProxyHeaders = new[] { "x-forwarded-for", "forwarded", "x-real-ip" };

    static object? EnvInt(string name, string? v)
    {
        if (string.IsNullOrEmpty(v)) return JS.Undef;
        double n = JS.ToNumber(v);
        if (double.IsNaN(n) || double.IsInfinity(n) || n != Math.Round(n) || n < 0 || IntentJs.IsNegZero(n)) throw new ArgumentException(name + " must be a non-negative integer");
        return n;
    }

    static bool Has(string? v) => !string.IsNullOrEmpty(v);

    /// <summary>The deployment's own environment variable names (as the API and the guides use them).</summary>
    public static D ConfigFromEnv(IReadOnlyDictionary<string, string> env)
    {
        string? E(string k) => env.TryGetValue(k, out var v) ? v : null;
        var c = new D();
        if (Has(E("PCA_DOCTOR_URL"))) c["url"] = E("PCA_DOCTOR_URL");
        if (Has(E("PCA_DOCTOR_REFERENCE_URL"))) c["clock"] = new D { ["referenceUrl"] = E("PCA_DOCTOR_REFERENCE_URL") };
        if (Has(E("PCA_DOCTOR_STORE"))) c["store"] = new D { ["adapter"] = E("PCA_DOCTOR_STORE") };
        var proxy = new D();
        if (E("TRUSTED_PROXY_COUNT") != null) proxy["trustedProxyCount"] = EnvInt("TRUSTED_PROXY_COUNT", E("TRUSTED_PROXY_COUNT"));
        if (Has(E("TRUSTED_PROXY_HEADER")))
        {
            var h = E("TRUSTED_PROXY_HEADER")!.ToLowerInvariant();
            if (!ProxyHeaders.Contains(h)) throw new ArgumentException("TRUSTED_PROXY_HEADER must be one of " + string.Join(", ", ProxyHeaders));
            proxy["header"] = h;
        }
        if (E("PCA_TRUSTED_PROXY_HOPS") != null) proxy["hops"] = EnvInt("PCA_TRUSTED_PROXY_HOPS", E("PCA_TRUSTED_PROXY_HOPS"));
        if (proxy.Count > 0) c["proxy"] = proxy;
        var v2 = new D();
        if (E("PCA_ALLOWED_SUITES") != null)
        {
            var suites = new L();
            foreach (var s in E("PCA_ALLOWED_SUITES")!.Split(',')) { var t = JS.Trim(s); if (t.Length > 0) suites.Add(t); }
            v2["allowedSuites"] = suites;
        }
        if (Has(E("PCA_PQ_PINS")))
        {
            object? pins;
            try { pins = Pca.ParseJson(E("PCA_PQ_PINS")!); }
            catch (Exception) { throw new ArgumentException("PCA_PQ_PINS is not valid JSON"); } // never echo the value
            if (!(pins is D pd && pd.Values.All(x => x is string))) throw new ArgumentException("PCA_PQ_PINS must be a JSON object of issuer -> public key strings");
            v2["pqPins"] = pins;
        }
        if (E("PCA_ALLOW_UNBOUND_PQ") != null) v2["allowUnboundPq"] = Truthy.IsMatch(E("PCA_ALLOW_UNBOUND_PQ")!);
        if (v2.Count > 0) c["verifier"] = v2;
        return c;
    }

    static void SpreadInto(D into, object? b)
    {
        if (b is D m) foreach (var (k, v) in m) into[k] = v;
        else if (b is L l) for (int i = 0; i < l.Count; i++) into[i.ToString(CultureInfo.InvariantCulture)] = l[i];
        else if (b is string s) for (int i = 0; i < s.Length; i++) into[i.ToString(CultureInfo.InvariantCulture)] = s.Substring(i, 1);
    }

    /// <summary>Two-level merge: later sources win per field inside each section.</summary>
    public static D MergeConfig(IEnumerable<D> cs)
    {
        var o = new D();
        foreach (var c in cs)
        {
            foreach (var (k, val) in c)
            {
                if (k is "__proto__" or "constructor" or "prototype") throw new ArgumentException("config key \"" + k + "\" is not allowed");
                if (JS.IsUndef(val)) continue;
                if (JS.Truthy(val) && val is D vd)
                {
                    var merged = new D();
                    if (o.TryGetValue(k, out var prev) && prev != null && !JS.IsUndef(prev)) SpreadInto(merged, prev);
                    foreach (var (k2, v2) in vd) merged[k2] = v2;
                    o[k] = merged;
                }
                else o[k] = val;
            }
        }
        return o;
    }

    /// <summary>A JSON file. shortcut: the reference also loads a JS module exporting the config; that has no .NET counterpart.</summary>
    public static D LoadConfigFile(string path)
    {
        if (!path.EndsWith(".json", StringComparison.Ordinal)) throw new NotSupportedException("only a .json config file can be loaded: " + path);
        return Pca.ParseJson(File.ReadAllText(path)) as D ?? throw new ArgumentException("config file is not a JSON object: " + path);
    }

    // ---- CLI ----

    public static readonly string Usage = "pca-doctor [--url <deployment>] [options]\n\n"
        + "  --url URL              the live deployment (base URL of the API that verifies PCActns)\n"
        + "  --config FILE          JSON or JS config (see the pca-doctor guide); env and flags override it\n"
        + "  --store MODULE         replay-store adapter module (store conformance kit interface) for the atomicity / durability checks\n"
        + "  --store-option k=v     passed to the adapter factory (repeatable)\n"
        + "  --reference URL|local  clock reference (default https://www.google.com/generate_204)\n"
        + "  --max-skew-ms N        clock fail threshold (default 60000)\n"
        + "  --trusted-proxy-count N, --proxy-header H, --proxy-hops N   the deployment's proxy settings and the real hop count\n"
        + "  --pca-dir DIR          the deployed application's directory (its installed @atlasauth/pca is probed)\n"
        + "  --only a,b | --skip a,b   check groups: " + string.Join(", ", CheckGroups) + "\n"
        + "  --no-probe             do not send forged forwarding headers to the deployment\n"
        + "  --strict               warnings fail too\n"
        + "  --json                 machine-readable output\n\n"
        + "Env: PCA_DOCTOR_URL, PCA_DOCTOR_REFERENCE_URL, PCA_DOCTOR_STORE, TRUSTED_PROXY_COUNT, TRUSTED_PROXY_HEADER, PCA_TRUSTED_PROXY_HOPS,\n"
        + "     PCA_ALLOWED_SUITES (comma list), PCA_PQ_PINS (JSON), PCA_ALLOW_UNBOUND_PQ.";

    static List<string> Groups(string flag, string? v)
    {
        var g = (v ?? "").Split(',').Where(x => x.Length > 0).ToList();
        var bad = g.Where(x => !CheckGroups.Contains(x)).ToList();
        if (bad.Count > 0 || g.Count == 0) throw new ArgumentException(flag + ": unknown check group(s) " + (bad.Count == 0 ? "(none given)" : string.Join(", ", bad)));
        return g;
    }

    static double NumArg(string flag, string? v)
    {
        double n = string.IsNullOrEmpty(v) ? double.NaN : JS.ToNumber(v);
        if (double.IsNaN(n) || double.IsInfinity(n)) throw new ArgumentException(flag + " needs a number");
        return n;
    }

    static D Sub(D flags, string k)
    {
        var m = new D();
        if (flags.GetValueOrDefault(k) is D cur) foreach (var (a, b) in cur) m[a] = b;
        flags[k] = m;
        return m;
    }

    /// <summary>The parsed command line: flags (a config), only, json, strict, help and an optional config path.</summary>
    public static D ParseDoctorArgs(IReadOnlyList<string> argv)
    {
        var flags = new D();
        var only = CheckGroups.ToList();
        bool json = false, strict = false, help = false;
        string? config = null;
        for (int i = 0; i < argv.Count; i++)
        {
            var k = argv[i];
            string? nx = i + 1 < argv.Count ? argv[i + 1] : null; // next() consumes even when absent
            object? NxOrUndef() => nx == null ? JS.Undef : nx;
            switch (k)
            {
                case "--url": i++; flags["url"] = NxOrUndef(); break;
                case "--config": i++; config = nx; break;
                case "--store": i++; Sub(flags, "store")["adapter"] = NxOrUndef(); break;
                case "--store-option":
                {
                    i++;
                    var kv = nx ?? "";
                    int eq = kv.IndexOf('=');
                    if (eq < 1) throw new ArgumentException("--store-option needs k=v");
                    var st = Sub(flags, "store");
                    var opts = new D();
                    if (st.GetValueOrDefault("options") is D cm) foreach (var (a, b) in cm) opts[a] = b;
                    opts[kv.Substring(0, eq)] = kv.Substring(eq + 1);
                    st["options"] = opts;
                    break;
                }
                case "--reference": i++; Sub(flags, "clock")["referenceUrl"] = NxOrUndef(); break;
                case "--max-skew-ms": i++; Sub(flags, "clock")["maxSkewMs"] = NumArg(k, nx); break;
                case "--trusted-proxy-count": i++; Sub(flags, "proxy")["trustedProxyCount"] = NumArg(k, nx); break;
                case "--proxy-header":
                {
                    i++;
                    var h = (nx ?? "").ToLowerInvariant();
                    if (!ProxyHeaders.Contains(h)) throw new ArgumentException("--proxy-header must be x-forwarded-for, forwarded or x-real-ip");
                    Sub(flags, "proxy")["header"] = h;
                    break;
                }
                case "--proxy-hops": i++; Sub(flags, "proxy")["hops"] = NumArg(k, nx); break;
                case "--no-probe": Sub(flags, "proxy")["probe"] = false; break;
                case "--pca-dir": i++; Sub(flags, "verifier")["pcaDir"] = NxOrUndef(); break;
                case "--only": i++; only = Groups(k, nx); break;
                case "--skip":
                {
                    i++;
                    var s = Groups(k, nx);
                    only = only.Where(g => !s.Contains(g)).ToList();
                    break;
                }
                case "--strict": strict = true; break;
                case "--json": json = true; break;
                case "-h": case "--help": help = true; break;
                default: throw new ArgumentException("unknown argument " + k);
            }
        }
        var a2 = new D { ["flags"] = flags, ["only"] = only.Select(x => (object?)x).ToList(), ["json"] = json, ["strict"] = strict, ["help"] = help };
        if (config != null) a2["config"] = config;
        return a2;
    }

    /// <summary>Run the CLI: exit code 1 on any fail (and on warn under --strict), 2 on usage errors, else 0.</summary>
    public static int Main(IReadOnlyList<string> argv, IReadOnlyDictionary<string, string> env, Action<string> print, Action<string> printErr, DoctorDeps? deps = null)
    {
        D a, cfg;
        try
        {
            a = ParseDoctorArgs(argv);
            if (a["help"] is true) { print(Usage); return 0; }
            var sources = new List<D>
            {
                a.GetValueOrDefault("config") is string cp ? LoadConfigFile(cp) : new D(),
                ConfigFromEnv(env),
                (D)a["flags"]!,
            };
            cfg = MergeConfig(sources);
        }
        catch (Exception e)
        {
            printErr(ScrubText(e.Message) + "\n\n" + Usage);
            return 2;
        }
        var results = RunDoctor(cfg, ((L)a["only"]!).Select(x => (string)x!).ToList(), deps);
        bool strict = a["strict"] is true;
        var verdict = VerdictOf(results, strict);
        var url = JS.G(cfg, "url");
        if (a["json"] is true)
        {
            var doc = new D { ["target"] = JS.Nullish(url) ? null : url, ["verdict"] = verdict, ["results"] = results.Select(r => (object?)r.Json).ToList() };
            print(JS.Stringify(doc));
        }
        else print(FormatResults(results, JS.Truthy(url) ? JS.Str(url) : null, strict));
        return verdict == "fail" ? 1 : 0;
    }
}
