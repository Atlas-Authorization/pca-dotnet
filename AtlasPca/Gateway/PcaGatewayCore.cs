using System.Globalization;
using System.Text.RegularExpressions;
using AtlasPca.Adapters;
using AtlasPca.Connect;
using AtlasPca.Js;
using static AtlasPca.InteropJs.JsX;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Gateway;

/// <summary>A single-use store for presented proofs: <see cref="Claim"/> is true for the first live claim of a key.</summary>
public interface IReplayGuard
{
    /// <summary>True iff THIS call took the key; false when a live claim exists. Throws when the store cannot decide (the gateway denies).</summary>
    bool Claim(string key, double expiresAtMs, double? nowMs);
}

/// <summary>In-process single-use store. State is per process: use a shared store for more than one instance. A claim stays live through its
/// expiry inclusive. Fails closed (throws) when <c>maxEntries</c> unexpired claims are held.</summary>
public sealed class MemoryReplayGuard : IReplayGuard
{
    readonly Dictionary<string, double> seen = new(StringComparer.Ordinal);
    readonly int max;
    readonly Func<double> now;

    public MemoryReplayGuard(int maxEntries = 100_000, Func<double>? now = null)
    {
        max = maxEntries;
        this.now = now ?? (() => AtlasPca.ReplayClock.NowMs());
    }

    public bool Claim(string key, double expiresAtMs, double? nowMs = null)
    {
        lock (seen)
        {
            var t = nowMs ?? now();
            if (seen.Count >= max)
            {
                foreach (var (k, exp) in seen.ToList()) if (exp < t) seen.Remove(k);
                if (seen.Count >= max) throw new InvalidOperationException("replay guard full");
            }
            if (seen.TryGetValue(key, out var existing) && existing >= t) return false;
            seen[key] = expiresAtMs;
            return true;
        }
    }
}

/// <summary>The gateway's per-session record of untrusted content it relayed.</summary>
public interface IProvenanceLog
{
    /// <summary>A copy of the observations of a session (<c>{origin, source}</c>), oldest first.</summary>
    List<D> Seen(string session);
    void Add(string session, D observation);
}

/// <summary>At most <c>maxSessions</c> sessions (oldest dropped first), 256 distinct observations each.</summary>
public sealed class MemoryProvenanceLog : IProvenanceLog
{
    readonly Dictionary<string, List<D>> m = new(StringComparer.Ordinal);
    readonly List<string> order = new();
    readonly int max;

    public MemoryProvenanceLog(int maxSessions = 10_000) { max = maxSessions; }

    public List<D> Seen(string session)
    {
        lock (m) return m.TryGetValue(session, out var l) ? l.Select(x => new D(x)).ToList() : new List<D>();
    }

    public void Add(string session, D o)
    {
        lock (m)
        {
            var cur = new List<D>();
            if (m.Remove(session, out var prev)) { cur = prev; order.Remove(session); }
            var origin = o.TryGetValue("origin", out var ov) ? ov : Undef;
            var source = o.TryGetValue("source", out var sv) ? sv : Undef;
            if (!cur.Any(x => StrictEq(x.TryGetValue("origin", out var a) ? a : Undef, origin) && StrictEq(x.TryGetValue("source", out var b) ? b : Undef, source)) && cur.Count < 256)
            {
                var e = new D();
                if (!ReferenceEquals(origin, Undef)) e["origin"] = origin;
                if (!ReferenceEquals(source, Undef)) e["source"] = source;
                cur.Add(e);
            }
            m[session] = cur;
            order.Add(session);
            while (m.Count > max) { m.Remove(order[0]); order.RemoveAt(0); }
        }
    }
}

public static partial class PcaGateway
{
    public const string PcaHeader = "PCA-Action";
    public static readonly IReadOnlyList<string> PcaInjectedHeaders = new[] { "x-pca-verdict", "x-pca-verb", "x-pca-grant" };
    public static readonly IReadOnlyList<string> DefaultRequireChecks = new[] { "revocation" };

    /// <summary>What <see cref="PresentedProvenance"/> returns when the request presents none (a JSON null is a presented, malformed bundle).</summary>
    public static readonly object Absent = new();

    // ---- JavaScript helpers ----
    /// <summary><c>o?.[k] ?? null</c>: a member of a parsed object; null when absent, null or <paramref name="o"/> is not an object.</summary>
    internal static object? G(object? o, string k) => o is D m && m.TryGetValue(k, out var v) ? v : null;

    /// <summary>JavaScript truthiness of a parsed JSON value (an empty object or array is truthy).</summary>
    internal static bool Jt(object? v)
    {
        if (v == null || ReferenceEquals(v, Undef)) return false;
        if (v is bool b) return b;
        if (v is string s) return s.Length > 0;
        return IntentJs.NumOf(v) is double d ? !(double.IsNaN(d) || d == 0) : true;
    }

    internal static object? First(params object?[] vs)
    {
        foreach (var v in vs) if (v != null) return v;
        return null;
    }

    static string Lower(string s) => s.Replace("İ", "i̇", StringComparison.Ordinal).ToLowerInvariant();

    // ---- canonical query / binding ----
    static readonly Regex BadPercent = new(@"%(?![0-9a-fA-F]{2})", RegexOptions.CultureInvariant);
    static readonly Regex PercentPair = new(@"%([0-9a-fA-F]{2})", RegexOptions.CultureInvariant);

    /// <summary>Strip a leading '?', drop empty pairs, sort the raw pairs (UTF-16 code unit order) and join with '&amp;'. Throws on a query that is
    /// ambiguous across upstream parsers: a repeated parameter name (percent-decoded, '+' as space, case-insensitive), a ';' separator, or a
    /// malformed percent escape in a name (the gateway turns it into a request-mismatch deny).</summary>
    public static string CanonicalQuery(string? query)
    {
        if (query == null) return "";
        var q = query.StartsWith('?') ? query[1..] : query;
        if (q.Contains(';')) throw new FormatException("query contains ';' (parsers disagree on it as a separator)");
        var pairs = q.Split('&').Where(x => x.Length > 0).ToList();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pair in pairs)
        {
            var eq = pair.IndexOf('=');
            var rawKey = eq < 0 ? pair : pair[..eq];
            string key;
            try { key = Lower(ConnectJs.DecodeUriComponent(rawKey.Replace('+', ' '))); }
            catch (FormatException) { throw new FormatException("query parameter name has a malformed percent escape"); }
            if (!seen.Add(key)) throw new FormatException($"duplicate query parameter '{key}'");
        }
        pairs.Sort(StringComparer.Ordinal);
        return string.Join("&", pairs);
    }

    /// <summary>The canonical binding of a request an agent signs as its action params: upper-cased method, path, canonical query and optionally the
    /// authority and body hash. <paramref name="opts"/> is <c>{authority?, body?}</c>; an absent <c>body</c> binds the hash when the request has one.</summary>
    public static D RequestBinding(D req, D? opts = null)
    {
        opts ??= new D();
        var sha = G(req, "bodySha256") ?? G(req, "body_sha256");
        var b = new D { ["v"] = new Num("2"), ["method"] = ((string)req["method"]!).ToUpperInvariant(), ["path"] = (string)req["path"]!, ["query"] = CanonicalQuery((string?)G(req, "query")) };
        if (Jt(opts.GetValueOrDefault("authority"))) b["authority"] = Jt(G(req, "authority")) ? Lower((string)G(req, "authority")!) : "";
        var hasBody = opts.TryGetValue("body", out var body);
        if (hasBody && body is true || (!hasBody && sha != null)) b["body_sha256"] = sha != null ? Lower((string)sha) : "";
        return b;
    }

    /// <summary>The params an agent signs for a full-policy gateway: the params plus the request binding as a <c>binding</c> member (null binding: the params).</summary>
    public static D BindParams(D parameters, D? binding = null)
    {
        if (binding == null) return parameters;
        if (parameters.ContainsKey("binding")) throw new ArgumentException("params already have a 'binding' member");
        return new D(parameters) { ["binding"] = binding };
    }

    static readonly Regex Unreserved = new(@"\A[A-Za-z0-9\-._~]\z", RegexOptions.CultureInvariant);

    /// <summary>Why <paramref name="path"/> is ambiguous for route matching (the upstream may route a different path), or null when canonical.</summary>
    public static string? AmbiguousPathReason(string path)
    {
        if (path.Any(c => c <= 0x1f || c == 0x7f || c == '\\')) return "control character or backslash in path";
        if (path.Contains("//", StringComparison.Ordinal)) return "repeated slash in path";
        if (path.Contains(';')) return "path parameter (;) in path";
        if (path.Split('/').Any(seg => seg == "." || seg == "..")) return "dot segment in path";
        foreach (Match m in PercentPair.Matches(path))
        {
            var code = int.Parse(m.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            var ch = (char)code;
            if (code < 0x20 || code == 0x7f) return "percent-encoded control character in path";
            if (ch == '/' || ch == '\\') return "percent-encoded slash in path";
            if (ch == ';') return "percent-encoded path parameter delimiter in path";
            if (Unreserved.IsMatch(ch.ToString())) return "non-canonical percent-encoding in path";
        }
        if (BadPercent.IsMatch(path)) return "malformed percent-encoding in path";
        return null;
    }

    // ---- headers / extraction ----
    /// <summary>Case-insensitive single-value lookup over a header map: the first key that matches; a list reads as its first element.</summary>
    public static object? GetHeader(object? headers, string name)
    {
        if (headers is not D h) return null;
        foreach (var (key, v) in h)
        {
            if (!string.Equals(Lower(key), Lower(name), StringComparison.Ordinal)) continue;
            if (v is L l) return l.Count > 0 ? l[0] : null;
            return v;
        }
        return null;
    }

    /// <summary>The PCActn of a header text: size cap first, then strict JSON; must be an object.</summary>
    static D DecodePcactn(string text)
    {
        if (Pca.ArtifactTooLarge(text)) throw new ArgumentException(Pca.ArtifactSizeReason);
        return Pca.ParseStrict(text) as D ?? throw new InvalidCastException("decodePCActn: not an object");
    }

    static string DecodeHeaderValue(object? raw) => raw is string s ? PcaAdapters.DecodePcaHeader(s) : throw new PcaHeaderError("PCA-Action header is empty");

    static (D? Pcactn, string? Code, string? Reason) ExtractPcactn(object? headers)
    {
        var raw = GetHeader(headers, PcaHeader);
        if (raw == null || (raw is string rs && rs.Length == 0)) return (null, "no-proof", "no " + PcaHeader + " header");
        try { return (DecodePcactn(DecodeHeaderValue(raw)), null, null); }
        catch (Exception e) { return (null, "invalid-proof", "undecodable " + PcaHeader + " header: " + e.Message); }
    }

    static D? BodyObject(D req)
    {
        if (G(req, "body") is string body && body.Length > 0)
        {
            try { return Pca.ParseStrict(body) as D; }
            catch (Exception) { return null; }
        }
        return null;
    }

    /// <summary>The provenance bundle a request presents: header <c>PCA-Provenance</c> (strict base64url JSON), else body member <c>pca_provenance</c>
    /// when the body is not the signed params. <see cref="Absent"/> when none; null when presented but unreadable.</summary>
    public static object? PresentedProvenance(D req, FullPolicy? policy)
    {
        try
        {
            var h = GetHeader(G(req, "headers"), "pca-provenance");
            if (h != null && !(h is string hs && hs.Length == 0)) return Pca.ParseStrict(DecodeHeaderValue(h));
        }
        catch (Exception) { return null; }
        if (policy?.ParamsFn != null && BodyObject(req) is { } b && b.TryGetValue("pca_provenance", out var pp)) return pp;
        return Absent;
    }

    /// <summary>The discharges and narrow block a request presents (headers, then body members when the body is not the signed params).</summary>
    public static D PresentedArtifacts(D req, FullPolicy? policy)
    {
        var o = new D();
        var headers = G(req, "headers");
        try
        {
            var d = GetHeader(headers, "pca-discharges");
            if (d != null && !(d is string ds && ds.Length == 0) && Pca.ParseStrict(DecodeHeaderValue(d)) is L arr) o["discharges"] = arr;
        }
        catch (Exception) { /* unreadable: no discharges */ }
        try
        {
            var n = GetHeader(headers, "pca-narrow");
            if (n != null && !(n is string ns && ns.Length == 0)) o["narrow"] = Pca.ParseStrict(DecodeHeaderValue(n));
        }
        catch (Exception) { /* unreadable: no narrow block */ }
        if (policy?.ParamsFn != null && BodyObject(req) is { } b)
        {
            if (!o.ContainsKey("discharges") && b.GetValueOrDefault("pca_discharges") is L bd) o["discharges"] = bd;
            if (!o.ContainsKey("narrow") && b.TryGetValue("pca_narrow", out var bn)) o["narrow"] = bn;
        }
        return o;
    }
}
