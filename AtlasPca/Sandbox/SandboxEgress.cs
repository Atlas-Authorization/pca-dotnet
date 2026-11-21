// Egress admission for non-WASM tools: the one outbound request an authorized operation maps to, matched exactly (host, port, method, path, query,
// body hash). The proxy server itself (sockets, TLS tunnelling) is a runtime concern and not part of this port.
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Sandbox;

public static partial class PcaSandbox
{
    const string DomLabel = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
    static readonly Regex EgressHostRe = new(@"\A" + DomLabel + @"(?:\." + DomLabel + @")*\z", RegexOptions.CultureInvariant);
    static readonly Regex MethodRe = new(@"\A[A-Z]+\z", RegexOptions.CultureInvariant);
    static readonly Regex BadPathRe = new(@"[?#\\]|%2[eE]|%2[fF]|%5[cC]|(\A|/)\.\.?(/|\z)", RegexOptions.CultureInvariant);
    static readonly Regex EncodedPathRe = new(@"%2[eE]|%2[fF]|%5[cC]|\\", RegexOptions.CultureInvariant);
    static readonly Regex ConnectRe = new(@"\A([a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\]):([0-9]{1,5})\z", RegexOptions.CultureInvariant);
    static readonly Regex V4TailRe = new(@"\A(.*:)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\z", RegexOptions.CultureInvariant);
    static readonly Regex GroupRe = new(@"\A[0-9a-f]{1,4}\z", RegexOptions.CultureInvariant);

    // Node's net.isIPv4 / net.isIPv6 grammar.
    const string V4Seg = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])";
    const string V4 = "(?:" + V4Seg + @"\.){3}" + V4Seg;
    const string V6Seg = "(?:[0-9a-fA-F]{1,4})";
    static readonly Regex Ipv4Re = new(@"\A" + V4 + @"\z", RegexOptions.CultureInvariant);
    static readonly Regex Ipv6Re = new(@"\A(?:"
        + "(?:" + V6Seg + ":){7}(?:" + V6Seg + "|:)|"
        + "(?:" + V6Seg + ":){6}(?:" + V4 + "|:" + V6Seg + "|:)|"
        + "(?:" + V6Seg + ":){5}(?::" + V4 + "|(?::" + V6Seg + "){1,2}|:)|"
        + "(?:" + V6Seg + ":){4}(?:(?::" + V6Seg + "){0,1}:" + V4 + "|(?::" + V6Seg + "){1,3}|:)|"
        + "(?:" + V6Seg + ":){3}(?:(?::" + V6Seg + "){0,2}:" + V4 + "|(?::" + V6Seg + "){1,4}|:)|"
        + "(?:" + V6Seg + ":){2}(?:(?::" + V6Seg + "){0,3}:" + V4 + "|(?::" + V6Seg + "){1,5}|:)|"
        + "(?:" + V6Seg + ":){1}(?:(?::" + V6Seg + "){0,4}:" + V4 + "|(?::" + V6Seg + "){1,6}|:)|"
        + "(?::(?:(?::" + V6Seg + "){0,5}:" + V4 + "|(?::" + V6Seg + "){1,7}|:))"
        + @")(?:%[0-9a-zA-Z.:-]{1,})?\z", RegexOptions.CultureInvariant);

    static bool IsIPv4(string s) => Ipv4Re.IsMatch(s);
    static bool IsIPv6(string s) => Ipv6Re.IsMatch(s);

    static bool PrivateV4(int a, int b) =>
        a == 0 || a == 10 || a == 127 || (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 100 && b >= 64 && b <= 127) || a >= 224;

    static int P10(string s) => int.Parse(s, System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>The eight 16-bit groups of an IPv6 literal (any spelling Node accepts: compressed or expanded, a dotted v4 tail, any case), or null; a zone id is not parsed.</summary>
    static int[]? Ipv6Groups(string ip)
    {
        if (!IsIPv6(ip) || ip.Contains('%')) return null;
        var s = ip.ToLowerInvariant();
        var t = V4TailRe.Match(s);
        if (t.Success)
            s = t.Groups[1].Value + ((P10(t.Groups[2].Value) << 8) | P10(t.Groups[3].Value)).ToString("x") + ":" + ((P10(t.Groups[4].Value) << 8) | P10(t.Groups[5].Value)).ToString("x");
        var halves = s.Split("::");
        if (halves.Length > 2) return null;
        static List<string> Part(string h) => h.Length == 0 ? new List<string>() : h.Split(':').ToList();
        var head = Part(halves[0]);
        var rest = halves.Length > 1 ? Part(halves[1]) : new List<string>();
        var fill = 8 - head.Count - rest.Count;
        if (halves.Length == 1 ? fill != 0 : fill < 1) return null;
        var groups = new List<string>(head);
        if (halves.Length > 1) groups.AddRange(Enumerable.Repeat("0", fill));
        groups.AddRange(rest);
        if (!groups.All(g => GroupRe.IsMatch(g))) return null;
        return groups.Select(g => Convert.ToInt32(g, 16)).ToArray();
    }

    /// <summary>Loopback, link-local, private, CGNAT, multicast, reserved and unspecified addresses, classified on the parsed address, not its spelling.
    /// IPv6: only global unicast (2000::/3) is public; an IPv4-mapped, IPv4-compatible or NAT64 (64:ff9b::/96) address follows its embedded IPv4 address;
    /// a zoned address (%id) is link-scoped, so private. Anything that is not an IP literal (or not a string) counts as private.</summary>
    public static bool IsPrivateAddress(object? ipArg)
    {
        if (ipArg is not string ip) return true;
        if (IsIPv4(ip))
        {
            var p = ip.Split('.');
            return PrivateV4(P10(p[0]), P10(p[1]));
        }
        var g = Ipv6Groups(ip);
        if (g == null) return true;
        var zero80 = g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0;
        var nat64 = g[0] == 0x64 && g[1] == 0xff9b && g[2] == 0 && g[3] == 0 && g[4] == 0 && g[5] == 0;
        if ((zero80 && (g[5] == 0 || g[5] == 0xffff)) || nat64) return PrivateV4(g[6] >> 8, g[6] & 0xff);
        return g[0] < 0x2000 || g[0] >= 0x4000;
    }

    static string Sha256B64u(byte[] b) => Pca.B64u(Pca.Sha(b));

    sealed class Admission
    {
        public string OpId = "", Verb = "", Resource = "", Method = "", Scheme = "", Host = "", Path = "";
        public object? Params, Query;
        public string? BodySha256;
        public bool HasBodySha256, PathPrefix, Tunnel;
        public int Port;
        public long Uses;
        public double ExpiresAt;
    }

    sealed class Target
    {
        public string? Reason;
        public bool Connect;
        public string Scheme = "", Host = "", Path = "", Query = "";
        public int Port;
    }

    /// <summary>The set of admitted requests: one authorized operation, one request template. Default deny.</summary>
    public sealed class EgressPolicy
    {
        readonly List<Admission> _admissions = new();
        readonly Func<double> _now;
        readonly object _lock = new();

        public EgressPolicy(Func<double>? now = null) { _now = now ?? (() => (double)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()); }

        /// <summary>Admit the request that <paramref name="operation"/> maps to. Throws unless <paramref name="result"/> allows exactly the operation and the
        /// template is well formed. <paramref name="uses"/> (default 1) and <paramref name="expiresAt"/> (default never) are JSON numbers or null.</summary>
        public void Admit(AuthorizeResult result, Operation operation, Func<Operation, D?> toRequest, object? uses = null, object? expiresAt = null)
        {
            if (!Pca.IsAuthorizedFor(result, operation)) throw new ArgumentException("not_authorized: result does not allow exactly this operation");
            var t = toRequest(operation) ?? throw new ArgumentException("no_egress_for_operation");
            if (t.GetValueOrDefault("host") is not string h) throw new ArgumentException("bad_template_host");
            if (!(IsIPv4(h) || IsIPv6(h) || EgressHostRe.IsMatch(h)) || h != h.ToLowerInvariant()) throw new ArgumentException("bad_template_host");
            var scheme = t.GetValueOrDefault("scheme");
            if (scheme is not ("http" or "https")) throw new ArgumentException("bad_template_scheme");
            var portV = t.GetValueOrDefault("port") ?? (long)(scheme is "http" ? 80 : 443);
            var pd = IntOf(portV);
            if (pd == null || pd < 1 || pd > 65535) throw new ArgumentException("bad_template_port");
            if (t.GetValueOrDefault("method") is not string method || !MethodRe.IsMatch(method)) throw new ArgumentException("bad_template_method");
            if (t.GetValueOrDefault("path") is not string ps) throw new ArgumentException("path is not a string");
            if (!ps.StartsWith('/') || BadPathRe.IsMatch(ps)) throw new ArgumentException("bad_template_path");
            var ud = IntOf(uses ?? 1L);
            if (ud == null || ud < 1) throw new ArgumentException("bad_uses");
            var a = new Admission
            {
                OpId = result.Operation?.Id ?? "",
                Verb = operation.Verb,
                Resource = operation.Resource,
                Params = operation.Params,
                Method = method,
                Scheme = (string)scheme,
                Host = h,
                Port = (int)pd.Value,
                Path = ps,
                PathPrefix = JsX.Truthy(t.GetValueOrDefault("path_prefix")),
                Query = t.GetValueOrDefault("query") ?? "",
                HasBodySha256 = t.ContainsKey("body_sha256"),
                BodySha256 = t.GetValueOrDefault("body_sha256") as string,
                Tunnel = t.GetValueOrDefault("tunnel") is true,
                Uses = (long)ud.Value,
                ExpiresAt = expiresAt == null ? double.PositiveInfinity : IntentJs.NumOf(expiresAt) ?? double.PositiveInfinity,
            };
            lock (_lock) _admissions.Add(a);
        }

        /// <summary>Decide and, if allowed, spend one use of the matching admission. Anything not matched is denied with a reason. Returns
        /// {allow:true, op_id, admission:{verb, resource, params_digest}} or {allow:false, reason}.</summary>
        public D Claim(object? method, object? url, byte[]? bodyIn = null)
        {
            if (method is not string m) throw new ArgumentException("method is not a string");
            var parsed = ParseTarget(m, url is string us ? us : JsJson.ToJsString(url));
            if (parsed.Reason != null) return Deny(parsed.Reason);
            var body = bodyIn ?? Array.Empty<byte>();
            var why = "no_admission";
            lock (_lock)
            {
                foreach (var a in _admissions)
                {
                    if (parsed.Connect != a.Tunnel) continue;
                    if (a.Method != m.ToUpperInvariant() && !parsed.Connect) continue;
                    if (parsed.Scheme != a.Scheme && !parsed.Connect) continue;
                    if (parsed.Host != a.Host || parsed.Port != a.Port) continue;
                    if (!parsed.Connect)
                    {
                        bool pathOk = a.PathPrefix
                            ? parsed.Path == a.Path || parsed.Path.StartsWith(a.Path.EndsWith('/') ? a.Path : a.Path + "/", StringComparison.Ordinal)
                            : parsed.Path == a.Path;
                        if (!pathOk) continue;
                        if (!(a.Query is string q && parsed.Query == q)) { why = "query_mismatch"; continue; }
                        if (body.Length > 0 && (!a.HasBodySha256 || Sha256B64u(body) != a.BodySha256)) { why = "body_mismatch"; continue; }
                        if (body.Length == 0 && a.HasBodySha256 && Sha256B64u(body) != a.BodySha256) { why = "body_mismatch"; continue; }
                    }
                    if (a.Uses < 1 || _now() >= a.ExpiresAt) { why = "spent"; continue; } // reported only when the request would otherwise have matched
                    a.Uses -= 1;
                    return new D
                    {
                        ["allow"] = true,
                        ["op_id"] = a.OpId,
                        ["admission"] = new D { ["verb"] = a.Verb, ["resource"] = a.Resource, ["params_digest"] = Pca.HashCanonical(a.Params) },
                    };
                }
            }
            return Deny(why);
        }

        static D Deny(string reason) => new() { ["allow"] = false, ["reason"] = reason };
    }

    static Target Refuse(string r) => new() { Reason = r };

    static Target ParseTarget(string method, string url)
    {
        if (method.ToUpperInvariant() == "CONNECT")
        {
            var m = ConnectRe.Match(url);
            if (!m.Success) return Refuse("bad_connect_target");
            var h = m.Groups[1].Value;
            if (h.StartsWith('[')) h = h.Substring(1);
            if (h.EndsWith(']')) h = h.Substring(0, h.Length - 1);
            return new Target { Connect = true, Scheme = "https", Host = h.ToLowerInvariant(), Port = int.Parse(m.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture) };
        }
        var u = EgressUrl.Parse(url);
        if (u == null) return Refuse("not_absolute_url");
        if ((u.Scheme != "http" && u.Scheme != "https") || u.Credentials || u.Hash) return Refuse("bad_url");
        // encoded dots and slashes are how a prefix match is walked out of: refuse rather than decode
        if (EncodedPathRe.IsMatch(u.Path)) return Refuse("encoded_path");
        return new Target { Connect = false, Scheme = u.Scheme, Host = u.Host, Port = u.Port >= 0 ? u.Port : (u.Scheme == "http" ? 80 : 443), Path = u.Path, Query = u.Query };
    }
}
