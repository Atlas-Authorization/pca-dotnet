using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.A2aPkg;
using AtlasPca.InteropJs;
using J = AtlasPca.Jose.Jose;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.WebBotAuth;

/// <summary>Web Bot Auth for Proof-Carrying Authority: RFC 9421 HTTP Message Signatures over outbound agent requests, in the Cloudflare / AWS WAF "web-bot-auth"
/// profile, so a PCA agent passes automated-traffic bot verification AND carries its per-action proof in the SAME request. The signature base is built byte for
/// byte as the reference builds it.
/// <see cref="SignRequest"/> builds the <c>Signature-Input</c> / <c>Signature</c> header values with the agent's Ed25519 identity; <see cref="VerifySignedRequest"/>
/// rebuilds the base from the request, resolves the key by <c>keyid</c> (a <see cref="KeyResolver"/> or a JWKS directory), verifies the Ed25519 signature strictly
/// (RFC 8032: canonical S, no small-order or non-canonical points) and enforces <c>created</c> / <c>expires</c> freshness and the <c>web-bot-auth</c> tag. It FAILS
/// CLOSED: a parse error, a missing field, a stale window, a wrong tag, an unknown key or a bad signature returns <c>{valid:false, reason}</c> and never throws. A valid
/// signature proves the holder of the key signed THIS request's covered components inside the window; it does not by itself prove the action is authorized.
/// Values are parsed JSON (D, L, string, bool, Num, null); input and option bags are dictionaries keyed by the reference's names. Keys are <see cref="EdKey"/> or a map
/// with a b64u <c>secretKey</c> (the 32-byte seed).
/// shortcut: request URLs must be http(s) (ws, wss and ftp too); other schemes are refused where the reference would accept them, and a <c>@target-uri</c> covering a URL
/// with credentials or a fragment is refused. Upgrade if a non-HTTP request target is ever signed.</summary>
public static class WebBotAuth
{
    public const string WebBotAuthTag = "web-bot-auth";
    public const string WebBotAuthAlg = "ed25519";
    public const string WellKnownDirectoryPath = "/.well-known/http-message-signatures-directory";
    public const string DirectoryContentType = "application/http-message-signatures-directory+json";
    public const string DefaultSignatureLabel = "sig1";
    public const int DefaultExpiresSec = 300;
    public const string SignatureAgentHeader = "Signature-Agent";
    public const string PcaHeader = "PCA-Action";
    /// <summary>The covered-component (lowercase) name of the PCA proof header.</summary>
    public const string PcaProofComponent = "pca-action";

    /// <summary>Maps a keyid to its Ed25519 public key: a 32-byte byte[], a public JWK map, or null for unknown.</summary>
    public delegate object? KeyResolver(string keyid);

    /// <summary>Single-use store for accepted signatures: true if <c>key</c> was claimed for the first time (until <c>expiresAtSec</c>).</summary>
    public delegate bool ReplayCache(string key, double expiresAtSec, double nowSec);

    /// <summary>In-process <see cref="ReplayCache"/>. Fails CLOSED (throws) when <paramref name="maxEntries"/> unexpired claims are held.</summary>
    public static ReplayCache MemoryReplayCache(int maxEntries = 100_000)
    {
        var seen = new Dictionary<string, double>();
        return (key, expiresAtSec, nowSec) =>
        {
            lock (seen)
            {
                if (!double.IsFinite(nowSec) || !double.IsFinite(expiresAtSec)) return false;
                if (seen.Count >= maxEntries)
                {
                    foreach (var k in seen.Where(e => e.Value < nowSec).Select(e => e.Key).ToList()) seen.Remove(k);
                    if (seen.Count >= maxEntries) throw new InvalidOperationException("replay cache full");
                }
                if (seen.TryGetValue(key, out var existing) && !(existing < nowSec)) return false;
                seen[key] = expiresAtSec;
                return true;
            }
        };
    }

    // ---- keys ----

    /// <summary>An Ed25519 signing identity from an <see cref="EdKey"/> or a map with a b64u <c>secretKey</c> seed.</summary>
    internal static EdKey EdKeyOf(object? k)
    {
        if (k is EdKey e) return e;
        var sk = WbaJs.Get(k, "secretKey");
        if (sk is not string s) throw new ArgumentException("key must carry a secretKey");
        return EdKey.FromSeed(Pca.B64uDecode(s) ?? throw new ArgumentException("secretKey is not base64url"));
    }

    /// <summary>RFC 7638 JWK thumbprint of an Ed25519 public key (base64url of SHA-256 over the canonical JWK).</summary>
    public static string JwkThumbprint(byte[] publicKey) =>
        Pca.B64u(SHA256.HashData(Encoding.UTF8.GetBytes("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + Pca.B64u(publicKey) + "\"}")));

    // ---- structured-field helpers ----

    static List<string> SplitTopLevel(string s, char sep)
    {
        var o = new List<string>();
        int depth = 0, start = 0;
        bool inStr = false;
        for (int i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (inStr)
            {
                if (c == '\\') i++;
                else if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') inStr = true;
            else if (c == '(') depth++;
            else if (c == ')') depth = Math.Max(0, depth - 1);
            else if (c == sep && depth == 0) { o.Add(s[start..i]); start = i + 1; }
        }
        o.Add(s[Math.Min(start, s.Length)..]);
        return o;
    }

    static (string Value, int Next) ReadSfString(string s, int i)
    {
        if (i >= s.Length || s[i] != '"') throw new WebBotAuthParseError("expected a quoted string");
        var o = new StringBuilder();
        for (int j = i + 1; j < s.Length; j++)
        {
            var c = s[j];
            if (c == '\\')
            {
                if (j + 1 >= s.Length || (s[j + 1] != '"' && s[j + 1] != '\\')) throw new WebBotAuthParseError("invalid escape in string");
                o.Append(s[j + 1]);
                j++;
            }
            else if (c == '"') return (o.ToString(), j + 1);
            else o.Append(c);
        }
        throw new WebBotAuthParseError("unterminated string");
    }

    static Regex IntRe => WbaJs.R(@"^-?[0-9]+\z");
    static Regex DecRe => WbaJs.R(@"^-?[0-9]+\.[0-9]+\z");

    static object ParseParamValue(string raw)
    {
        var s = WbaJs.Trim(raw);
        if (s.Length == 0) return true;
        if (s[0] == '"')
        {
            var (value, next) = ReadSfString(s, 0);
            if (next != s.Length) throw new WebBotAuthParseError("trailing characters after string parameter");
            return value;
        }
        if (s == "?1") return true;
        if (s == "?0") return false;
        if (IntRe.IsMatch(s) || DecRe.IsMatch(s)) return double.Parse(s, CultureInfo.InvariantCulture);
        return s;
    }

    static D ParseParams(string paramStr)
    {
        var prms = new D();
        var trimmed = WbaJs.Trim(paramStr);
        if (trimmed.Length == 0) return prms;
        if (trimmed[0] != ';') throw new WebBotAuthParseError("expected parameters to start with \";\"");
        foreach (var part in SplitTopLevel(trimmed[1..], ';'))
        {
            var seg = WbaJs.Trim(part);
            if (seg.Length == 0) continue;
            int eq = IndexOfTopLevel(seg, '=');
            if (eq == -1) prms[seg] = true;
            else prms[WbaJs.Trim(seg[..eq])] = ParseParamValue(seg[(eq + 1)..]);
        }
        return prms;
    }

    static int MatchingParen(string s, int open)
    {
        if (open >= s.Length || s[open] != '(') return -1;
        int depth = 0;
        bool inStr = false;
        for (int i = open; i < s.Length; i++)
        {
            var c = s[i];
            if (inStr)
            {
                if (c == '\\') i++;
                else if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') inStr = true;
            else if (c == '(') depth++;
            else if (c == ')') { depth--; if (depth == 0) return i; }
        }
        return -1;
    }

    static int IndexOfTopLevel(string s, char ch)
    {
        int depth = 0;
        bool inStr = false;
        for (int i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (inStr)
            {
                if (c == '\\') i++;
                else if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') inStr = true;
            else if (c == '(') depth++;
            else if (c == ')') depth = Math.Max(0, depth - 1);
            else if (c == ch && depth == 0) return i;
        }
        return -1;
    }

    sealed record Comp(string Id, string Raw, string? Key);

    sealed record SigInput(string Label, List<Comp> Components, string ParamsRaw, D Params);

    static Regex KeyParamRe => WbaJs.R(@"^;key=(""(?:[^""\\]|\\[^\n\r\u2028\u2029])*"")\z");

    static List<SigInput> ParseSignatureInput(string value)
    {
        var entries = new List<SigInput>();
        foreach (var memberRaw in SplitTopLevel(value, ','))
        {
            var member = WbaJs.Trim(memberRaw);
            if (member.Length == 0) continue;
            int eq = IndexOfTopLevel(member, '=');
            if (eq == -1) throw new WebBotAuthParseError("malformed Signature-Input member");
            var label = WbaJs.Trim(member[..eq]);
            var paramsRaw = WbaJs.Trim(member[(eq + 1)..]);
            if (paramsRaw.Length == 0 || paramsRaw[0] != '(') throw new WebBotAuthParseError("Signature-Input value must be an inner list");
            int close = MatchingParen(paramsRaw, 0);
            if (close == -1) throw new WebBotAuthParseError("unterminated inner list");
            var inner = paramsRaw[1..close];
            var components = new List<Comp>();
            foreach (var chunkRaw in SplitTopLevel(inner, ' '))
            {
                var chunk = WbaJs.Trim(chunkRaw);
                if (chunk.Length == 0) continue;
                var (sfValue, next) = ReadSfString(chunk, 0);
                var lowered = WbaJs.Lower(sfValue);
                var rest = WbaJs.Trim(chunk[next..]);
                if (rest.Length == 0) { components.Add(new Comp(lowered, "\"" + lowered + "\"", null)); continue; }
                // The only component parameter supported is `key` (dictionary member), on header components.
                var m = KeyParamRe.Match(rest);
                if (!m.Success || lowered.StartsWith('@')) throw new WebBotAuthParseError($"unsupported component parameters on \"{sfValue}\"");
                var key = ReadSfString(m.Groups[1].Value, 0).Value;
                components.Add(new Comp(lowered, "\"" + lowered + "\";key=" + WbaJs.SfString(key), key));
            }
            entries.Add(new SigInput(label, components, paramsRaw, ParseParams(paramsRaw[(close + 1)..])));
        }
        return entries;
    }

    static Dictionary<string, byte[]> ParseSignature(string value)
    {
        var o = new Dictionary<string, byte[]>();
        foreach (var memberRaw in SplitTopLevel(value, ','))
        {
            var member = WbaJs.Trim(memberRaw);
            if (member.Length == 0) continue;
            int eq = IndexOfTopLevel(member, '=');
            if (eq == -1) throw new WebBotAuthParseError("malformed Signature member");
            var label = WbaJs.Trim(member[..eq]);
            var v = WbaJs.Trim(member[(eq + 1)..]);
            if (v.Length < 2 || v[0] != ':' || v[^1] != ':') throw new WebBotAuthParseError("Signature value must be a byte sequence (:base64:)");
            o[label] = WbaJs.NodeBase64(v[1..^1]);
        }
        return o;
    }

    // ---- signature base (RFC 9421 section 2.5) ----

    sealed class Ctx
    {
        public string Method = "", Authority = "", Path = "", Scheme = "", Query = "", RequestTarget = "";
        public string? TargetUri;
        public Dictionary<string, string> Headers = new();
    }

    static Dictionary<string, string> NormalizeHeaders(object? h)
    {
        var m = new Dictionary<string, string>();
        if (h is not D hd) return m;
        foreach (var (key, v) in hd)
        {
            var name = WbaJs.Lower(key);
            string value;
            if (v is L list)
            {
                var parts = new List<string>();
                foreach (var x in list)
                {
                    if (x is not string xs) throw new InvalidOperationException("x.trim is not a function");
                    parts.Add(WbaJs.Trim(xs));
                }
                value = string.Join(", ", parts);
            }
            else if (v is string vs) value = WbaJs.Trim(vs);
            else throw new InvalidOperationException("v.trim is not a function");
            m[name] = m.TryGetValue(name, out var prev) ? prev + ", " + value : value;
        }
        return m;
    }

    /// <summary>The query of a URL as the WHATWG parser reports it in <c>search</c>: empty when there is none or it is empty, else <c>?</c> + the percent-encoded query
    /// (special-query set). Tabs and newlines are removed and the ends trimmed of C0 controls and spaces first.</summary>
    internal static string SearchOfUrl(string url)
    {
        var s = url.Replace("\t", "").Replace("\n", "").Replace("\r", "").Trim(Enumerable.Range(0, 0x21).Select(i => (char)i).ToArray());
        int hash = s.IndexOf('#');
        if (hash >= 0) s = s[..hash];
        int q = s.IndexOf('?');
        if (q < 0 || q == s.Length - 1) return "";
        var sb = new StringBuilder("?");
        foreach (var b in Encoding.UTF8.GetBytes(s[(q + 1)..]))
        {
            if (b <= 0x20 || b > 0x7e || "\"#<>'".IndexOf((char)b) >= 0) sb.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
            else sb.Append((char)b);
        }
        return sb.ToString();
    }

    static Ctx BuildContext(object? methodValue, string url, Dictionary<string, string> headers)
    {
        var u = AtlasPca.Jose.WhatwgUrl.TryParse(url) ?? throw new AtlasPca.Jose.InvalidUrlException();
        if (!(u.Protocol is "http:" or "https:" or "ws:" or "wss:" or "ftp:")) throw new ArgumentException("unsupported URL scheme");
        var hostport = u.Host;
        var search = SearchOfUrl(url);
        int hash = url.IndexOf('#');
        var noFrag = hash >= 0 ? url[..hash] : url;
        int slashes = noFrag.IndexOf("//", StringComparison.Ordinal);
        int authEnd = noFrag.Length;
        for (int k = slashes + 2; k < noFrag.Length; k++) { var ch = noFrag[k]; if (ch == '/' || ch == '\\' || ch == '?') { authEnd = k; break; } }
        bool plain = hash < 0 && !(slashes >= 0 && noFrag[(slashes + 2)..authEnd].Contains('@'));
        var c = new Ctx
        {
            Method = WbaJs.RequireString(methodValue, "method").ToUpperInvariant(), // after the URL parse, as in the reference
            Authority = WbaJs.Lower(hostport),
            Path = u.Pathname.Length == 0 ? "/" : u.Pathname,
            Scheme = WbaJs.Lower(u.Protocol.TrimEnd(':')),
            Query = search.Length == 0 ? "?" : search,
            Headers = headers,
        };
        c.TargetUri = plain ? u.Protocol + "//" + hostport + u.Pathname + search + (search.Length == 0 && noFrag.Contains('?') ? "?" : "") : null;
        c.RequestTarget = c.Path + search;
        return c;
    }

    static Regex CanonParamsRe => WbaJs.R(@"^(;[a-z*][a-z0-9_.*\-]*(=(""(?:[^""\\]|\\[^\n\r\u2028\u2029])*""|[A-Za-z0-9_.:/*+%\-]+))?)*\z");

    static string DeriveComponentValue(Comp component, Ctx ctx)
    {
        var id = component.Id;
        switch (id)
        {
            case "@method": return ctx.Method;
            case "@authority": return ctx.Authority;
            case "@path": return ctx.Path;
            case "@target-uri":
                return ctx.TargetUri ?? throw new WebBotAuthParseError("@target-uri is not supported for a URL with credentials or a fragment");
            case "@scheme": return ctx.Scheme;
            case "@query": return ctx.Query;
            case "@request-target": return ctx.RequestTarget;
            default:
                {
                    if (id.StartsWith('@')) throw new WebBotAuthParseError($"unsupported derived component \"{id}\"");
                    if (!ctx.Headers.TryGetValue(id, out var v)) throw new WebBotAuthParseError($"covered header \"{id}\" is absent from the request");
                    return component.Key != null ? DictionaryMember(v, component.Key, id) : v;
                }
        }
    }

    /// <summary>RFC 9421 section 2.1.2: the serialized value of dictionary member <paramref name="key"/> of a Structured Field dictionary header (string members only).</summary>
    static string DictionaryMember(string header, string key, string headerName)
    {
        foreach (var memberRaw in SplitTopLevel(header, ','))
        {
            var member = WbaJs.Trim(memberRaw);
            int eq = IndexOfTopLevel(member, '=');
            if (eq == -1 || WbaJs.Trim(member[..eq]) != key) continue;
            var value = WbaJs.Trim(member[(eq + 1)..]);
            var (_, next) = ReadSfString(value, 0);
            // Parameters are allowed only in compact canonical form, so the verbatim text IS the serialization.
            if (!CanonParamsRe.IsMatch(value[next..])) throw new WebBotAuthParseError($"member \"{key}\" of \"{headerName}\" is not in canonical form");
            return value;
        }
        throw new WebBotAuthParseError($"\"{headerName}\" has no dictionary member \"{key}\"");
    }

    static string BuildSignatureBase(List<Comp> components, string paramsRaw, Ctx ctx)
    {
        var lines = new List<string>();
        foreach (var c in components) lines.Add(c.Raw + ": " + DeriveComponentValue(c, ctx));
        lines.Add("\"@signature-params\": " + paramsRaw);
        return string.Join("\n", lines);
    }

    // ---- signRequest ----

    static Regex HasQueryRe => WbaJs.R(@"\?[^#]");

    static double NowSec() => Math.Floor(AtlasPca.ReplayClock.NowMs() / 1000.0);

    /// <summary>Build the <c>Signature-Input</c> + <c>Signature</c> header values over the RFC 9421 signature base. <paramref name="input"/>: method, url, headers?, key
    /// (signing identity), keyid, created? (epoch seconds, default now), expiresInSec? (default 300), agentDirectoryUrl? (also emits and covers <c>Signature-Agent</c>),
    /// agentDirectoryKey? (dictionary form, requires agentDirectoryUrl), components? (derived components replacing the default <c>@authority @method @path</c>;
    /// <c>@authority</c> required), coverHeaders?, nonce?, label?. Returns <c>{signatureInput, signature, signatureAgent?, covered, headers}</c>.</summary>
    public static D SignRequest(D input)
    {
        var label = input.GetValueOrDefault("label") != null ? WbaJs.AnyStr(input["label"]) : DefaultSignatureLabel;
        double created = input.GetValueOrDefault("created") != null ? WbaJs.Number(input["created"]) : NowSec();
        double expires = created + (input.GetValueOrDefault("expiresInSec") != null ? WbaJs.Number(input["expiresInSec"]) : DefaultExpiresSec);

        var working = NormalizeHeaders(input.GetValueOrDefault("headers"));
        var emitted = new D();

        var components = new List<Comp>();
        var derived = new List<string>();
        if (input.GetValueOrDefault("components") != null)
        {
            foreach (var c in A2aPca.SpreadList(input["components"])) derived.Add(WbaJs.RequireString(c, "component"));
        }
        else derived.AddRange(new[] { "@authority", "@method", "@path" });
        var url = WbaJs.AnyStr(input.GetValueOrDefault("url")); // the reference coerces it to text; a non-URL then fails in new URL(): ERR_INVALID_URL
        // by default a URL with a query string also covers @query (the verifier requires it)
        if (input.GetValueOrDefault("components") == null && HasQueryRe.IsMatch(url)) derived.Add("@query");
        if (!derived.Contains("@authority")) throw new ArgumentException("signRequest: the web-bot-auth profile requires @authority to be covered");
        foreach (var id in derived)
        {
            var lower = WbaJs.Lower(id);
            if (!lower.StartsWith('@')) throw new ArgumentException($"signRequest: components must be derived components, got \"{id}\" (use coverHeaders for headers)");
            components.Add(new Comp(lower, "\"" + lower + "\"", null));
        }

        string? signatureAgent = null;
        if (WbaJs.Def(input, "agentDirectoryUrl"))
        {
            bool hasKey = WbaJs.Def(input, "agentDirectoryKey");
            if (hasKey && input["agentDirectoryKey"] is not string) throw new ArgumentException("signRequest: agentDirectoryKey must be a string");
            var key = hasKey ? (string)input["agentDirectoryKey"]! : null;
            var agentUrl = WbaJs.RequireString(input["agentDirectoryUrl"], "agentDirectoryUrl");
            signatureAgent = key == null ? WbaJs.SfString(agentUrl) : key + "=" + WbaJs.SfString(agentUrl);
            working["signature-agent"] = signatureAgent;
            emitted[SignatureAgentHeader] = signatureAgent;
            components.Add(key == null ? new Comp("signature-agent", "\"signature-agent\"", null) : new Comp("signature-agent", "\"signature-agent\";key=" + WbaJs.SfString(key), key));
        }
        else if (WbaJs.Def(input, "agentDirectoryKey")) throw new ArgumentException("signRequest: agentDirectoryKey requires agentDirectoryUrl");

        if (input.GetValueOrDefault("coverHeaders") != null)
        {
            foreach (var n in A2aPca.SpreadList(input["coverHeaders"]))
            {
                var name = WbaJs.RequireString(n, "covered header name");
                var lower = WbaJs.Lower(name);
                if (!working.ContainsKey(lower)) throw new ArgumentException($"signRequest: covered header \"{name}\" is not present in headers");
                if (!components.Any(c => c.Id == lower)) components.Add(new Comp(lower, "\"" + lower + "\"", null));
            }
        }

        var ctx = BuildContext(input.GetValueOrDefault("method"), url, working);

        // The parameter order follows the examples in the Web Bot Auth architecture draft: created, keyid, alg, expires, nonce, tag.
        var paramsRaw = "(" + string.Join(" ", components.Select(c => c.Raw)) + ");created=" + WbaJs.NumStr(created)
            + ";keyid=" + WbaJs.SfString(WbaJs.RequireString(input.GetValueOrDefault("keyid"), "keyid"))
            + ";alg=" + WbaJs.SfString(WebBotAuthAlg) + ";expires=" + WbaJs.NumStr(expires);
        if (WbaJs.Def(input, "nonce")) paramsRaw += ";nonce=" + WbaJs.SfString(WbaJs.RequireString(input["nonce"], "nonce"));
        paramsRaw += ";tag=" + WbaJs.SfString(WebBotAuthTag);

        var bas = BuildSignatureBase(components, paramsRaw, ctx);
        var sig = EdKeyOf(input.GetValueOrDefault("key")).Sign(Encoding.UTF8.GetBytes(bas));

        var signatureInput = label + "=" + paramsRaw;
        var signature = label + "=:" + WbaJs.B64(sig) + ":";
        emitted["Signature-Input"] = signatureInput;
        emitted["Signature"] = signature;

        var o = new D { ["signatureInput"] = signatureInput, ["signature"] = signature };
        if (signatureAgent != null) o["signatureAgent"] = signatureAgent;
        o["covered"] = components.Select(c => (object?)c.Id).ToList();
        o["headers"] = emitted;
        return o;
    }

    // ---- verifySignedRequest ----

    static string? XFromResolved(object? k)
    {
        if (k == null) return null;
        if (k is byte[] b) return b.Length == 32 ? Pca.B64u(b) : null;
        if (k is D m && m.GetValueOrDefault("x") is string x && m.GetValueOrDefault("crv") is "Ed25519" && m.GetValueOrDefault("kty") is "OKP") return x;
        return null;
    }

    static string? ResolvePublicKeyX(string keyid, D opts, double now, double skew)
    {
        if (opts.GetValueOrDefault("resolveKey") != null) return XFromResolved(((KeyResolver)opts["resolveKey"]!)(keyid));
        if (opts.GetValueOrDefault("jwks") != null)
        {
            D? match = null;
            foreach (var j in WbaJs.ListOf(WbaJs.Get(opts["jwks"], "keys"))) if (j is D jd && jd.GetValueOrDefault("kid") is string kid && kid == keyid) { match = jd; break; }
            if (match == null) return null;
            // A published validity window is enforced; a bound that is present but not a finite number cannot be checked, so the key resolves to nothing.
            foreach (var b in new[] { "nbf", "exp" })
                if (match.ContainsKey(b) && !(IntentJs.NumOf(match[b]) is double d && double.IsFinite(d))) return null;
            if (match.ContainsKey("nbf") && !(double.IsFinite(now) && double.IsFinite(skew) && now + skew >= WbaJs.Number(match["nbf"]))) return null;
            if (match.ContainsKey("exp") && !(double.IsFinite(now) && double.IsFinite(skew) && now - skew <= WbaJs.Number(match["exp"]))) return null;
            return XFromResolved(match);
        }
        return null;
    }

    static bool Ed25519VerifyX(string x, byte[] message, byte[] sig)
    {
        try
        {
            if (sig.Length != 64) return false;
            var pk = Pca.B64uDecode(x, 32);
            return pk != null && Pca.VerifyEd25519Strict(pk, message, sig);
        }
        catch (Exception) { return false; }
    }

    static D Invalid(string reason) => new() { ["valid"] = false, ["reason"] = reason };

    static object? NumVal(double d) => new Num(WbaJs.NumStr(d));

    /// <summary>Verify the HTTP Message Signature of <paramref name="req"/> (<c>{method, url, headers}</c>). <paramref name="opts"/>: resolveKey (<see cref="KeyResolver"/>, takes
    /// precedence) or jwks (a key directory), now (epoch seconds), clockSkewSec (0), maxAgeSec, requireExpires (default true), requiredTag (default web-bot-auth; null = not
    /// enforced), label, requiredComponents (default <c>@authority @method @path</c>, plus <c>@query</c> when the URL has a query), maxLifetimeSec (default 300; Infinity
    /// disables), replayCache (<see cref="ReplayCache"/>). Returns <c>{valid, reason?, label?, keyid?, covered?, created?, expires?, tag?, nonce?}</c>; never throws.</summary>
    public static D VerifySignedRequest(D req, D opts)
    {
        try
        {
            if (opts.GetValueOrDefault("resolveKey") == null && opts.GetValueOrDefault("jwks") == null) return Invalid("verifySignedRequest: provide resolveKey or jwks");
            var headers = NormalizeHeaders(req.GetValueOrDefault("headers"));
            if (!headers.TryGetValue("signature-input", out var sigInputHeader) || !headers.TryGetValue("signature", out var sigHeader)) return Invalid("missing Signature-Input or Signature header");

            var inputs = ParseSignatureInput(sigInputHeader);
            var sigs = ParseSignature(sigHeader);
            var requiredTag = WbaJs.Def(opts, "requiredTag") ? opts["requiredTag"] : WebBotAuthTag;

            SigInput? chosen = null;
            if (WbaJs.Def(opts, "label")) { foreach (var e in inputs) if (Equals(e.Label, opts["label"])) { chosen = e; break; } }
            else if (requiredTag != null)
            {
                foreach (var e in inputs) if (Equals(e.Params.GetValueOrDefault("tag"), requiredTag)) { chosen = e; break; }
                if (chosen == null && inputs.Count > 0) chosen = inputs[0];
            }
            else if (inputs.Count > 0) chosen = inputs[0];
            if (chosen == null) return Invalid("no matching signature in Signature-Input");

            if (!sigs.TryGetValue(chosen.Label, out var sigBytes)) return Invalid($"no Signature entry for label \"{chosen.Label}\"");

            var tag = chosen.Params.GetValueOrDefault("tag") as string;
            if (requiredTag != null && !Equals(tag, requiredTag))
                return Invalid($"tag \"{tag ?? "undefined"}\" does not match required \"{WbaJs.AnyStr(requiredTag)}\"");

            // web-bot-auth requires @authority to be covered; @method and @path too, so a signature for one request cannot be replayed on another method or path of the same host.
            var covered = new HashSet<string>(chosen.Components.Select(c => c.Id));
            var required = opts.GetValueOrDefault("requiredComponents") != null ? A2aPca.SpreadList(opts["requiredComponents"]) : new L { "@authority", "@method", "@path" };
            foreach (var id in required) if (!(id is string ids && covered.Contains(ids))) return Invalid(WbaJs.AnyStr(id) + " is not a covered component");
            if (!WbaJs.Def(opts, "requiredComponents"))
            {
                var url = WbaJs.RequireString(req.GetValueOrDefault("url"), "url");
                int q = url.IndexOf('?');
                if (q >= 0 && url[(q + 1)..].Split('#')[0].Length != 0 && !covered.Contains("@query")) return Invalid("@query is not a covered component");
            }

            var alg = chosen.Params.GetValueOrDefault("alg");
            if (alg != null && !(alg is string a && a == WebBotAuthAlg)) return Invalid($"unsupported alg \"{WbaJs.Str(alg)}\"");

            // Freshness.
            double now = opts.GetValueOrDefault("now") != null ? WbaJs.Number(opts["now"]) : NowSec();
            double skew = opts.GetValueOrDefault("clockSkewSec") != null ? WbaJs.Number(opts["clockSkewSec"]) : 0;
            double? created = chosen.Params.GetValueOrDefault("created") is double cd ? cd : null;
            double? expires = chosen.Params.GetValueOrDefault("expires") is double ed ? ed : null;
            if (expires == null && opts.GetValueOrDefault("requireExpires") is not false) return Invalid("missing expires parameter");
            if (expires != null && !(double.IsFinite(now) && double.IsFinite(skew) && double.IsFinite(expires.Value) && now <= expires + skew)) return Invalid("signature has expired");
            if (created != null && !(double.IsFinite(now) && double.IsFinite(skew) && double.IsFinite(created.Value) && created <= now + skew)) return Invalid("signature created-time is in the future");
            if (opts.GetValueOrDefault("maxAgeSec") != null && created != null && !(double.IsFinite(now) && double.IsFinite(skew) && now - created <= WbaJs.Number(opts["maxAgeSec"]) + skew)) return Invalid("signature is older than maxAgeSec");
            double maxLifetime = opts.GetValueOrDefault("maxLifetimeSec") != null ? WbaJs.Number(opts["maxLifetimeSec"]) : 300;
            bool finite = !double.IsNaN(maxLifetime) && !double.IsInfinity(maxLifetime);
            if (finite)
            {
                if (created == null) return Invalid("missing created parameter (needed to bound the signature lifetime)");
                if (expires != null && !(expires - created <= maxLifetime)) return Invalid("signature lifetime exceeds maxLifetimeSec");
            }

            if (chosen.Params.GetValueOrDefault("keyid") is not string keyid) return Invalid("missing keyid parameter");
            var x = ResolvePublicKeyX(keyid, opts, now, skew);
            if (x == null) return Invalid($"could not resolve key \"{keyid}\"");

            var ctx = BuildContext(req.GetValueOrDefault("method"), WbaJs.RequireString(req.GetValueOrDefault("url"), "url"), headers);
            var bas = BuildSignatureBase(chosen.Components, chosen.ParamsRaw, ctx);
            if (!Ed25519VerifyX(x, Encoding.UTF8.GetBytes(bas), sigBytes)) return Invalid("signature does not verify under the resolved key");

            var nonce = chosen.Params.GetValueOrDefault("nonce") as string;
            if (opts.GetValueOrDefault("replayCache") != null)
            {
                double until = expires ?? (created != null ? created.Value + (finite ? maxLifetime : 3600) : now + 3600);
                var key = keyid + "|" + (nonce ?? Pca.B64u(sigBytes));
                if (!((ReplayCache)opts["replayCache"]!)(key, until + skew, now)) return Invalid("replayed signature");
            }
            var o = new D { ["valid"] = true, ["label"] = chosen.Label, ["keyid"] = keyid, ["covered"] = chosen.Components.Select(c => (object?)c.Id).ToList() };
            if (created != null) o["created"] = NumVal(created.Value);
            if (expires != null) o["expires"] = NumVal(expires.Value);
            if (tag != null) o["tag"] = tag;
            if (nonce != null) o["nonce"] = nonce;
            return o;
        }
        catch (Exception e)
        {
            return Invalid("verification failed (fail closed): " + e.Message);
        }
    }

    // ---- key directory (JWKS) + handler ----

    static byte[] PubOf(object? o) => o switch
    {
        byte[] b => b,
        string s => Pca.B64uDecode(s) ?? throw new ArgumentException("publicKey is not base64url"),
        _ => throw new ArgumentException("publicKey must be bytes or a b64u string"),
    };

    /// <summary>The JWKS for a list of <c>{publicKey (bytes or b64u), keyid?, use?, nbf?, exp?}</c>: <c>{keys: [{kty, crv, x, kid, use?, nbf?, exp?}]}</c>.</summary>
    public static D BuildKeyDirectory(IReadOnlyList<D> keys)
    {
        var list = new L();
        foreach (var k in keys)
        {
            var pk = PubOf(k.GetValueOrDefault("publicKey"));
            var e = new D { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = Pca.B64u(pk), ["kid"] = k.GetValueOrDefault("keyid") ?? JwkThumbprint(pk) };
            foreach (var f in new[] { "use", "nbf", "exp" }) if (k.ContainsKey(f)) e[f] = k[f];
            list.Add(e);
        }
        return new D { ["keys"] = list };
    }

    /// <summary>Resolve a public key JWK from a directory by <c>kid</c> (null when absent).</summary>
    public static D? ResolveFromDirectory(D directory, string keyid)
    {
        foreach (var j in WbaJs.ListOf(directory.GetValueOrDefault("keys"))) if (j is D jd && jd.GetValueOrDefault("kid") is string kid && kid == keyid) return jd;
        return null;
    }

    /// <summary>A framework-agnostic handler for the well-known directory path: returns <c>{status, headers, body}</c> (200 JSON) when the path (before any <c>?</c>) is
    /// <see cref="WellKnownDirectoryPath"/>, otherwise null so a caller can fall through.</summary>
    public static Func<string, D?> DirectoryHandler(IReadOnlyList<D> keys)
    {
        var body = J.Stringify(BuildKeyDirectory(keys));
        return pathname =>
        {
            int q = pathname.IndexOf('?');
            var path = q >= 0 ? pathname[..q] : pathname;
            if (path != WellKnownDirectoryPath) return null;
            return new D
            {
                ["status"] = new Num("200"),
                ["headers"] = new D { ["content-type"] = DirectoryContentType, ["cache-control"] = "max-age=86400" },
                ["body"] = body,
            };
        };
    }

    // ---- PCA proof binding ----

    /// <summary>The <c>PCA-Action</c> header carrying a PCActn (base64url of the canonical wire form).</summary>
    public static D ProofHeaders(object? pcactn) => new() { [PcaHeader] = Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(pcactn))) };

    /// <summary>Reverse <see cref="ProofHeaders"/>: the <c>PCA-Action</c> header value to the PCActn. Throws ArgumentException when the value is not a strict encoding of one.</summary>
    public static D DecodeProofHeader(string value)
    {
        var text = AtlasPca.Adapters.PcaAdapters.DecodePcaHeader(value);
        if (Pca.ArtifactTooLarge(text)) throw new ArgumentException(Pca.ArtifactSizeReason);
        return Pca.ParseStrict(text) as D ?? throw new ArgumentException("decodePCActn: not an object");
    }

    /// <summary>Sign a request AND bind it to a PCActn: the PCActn goes in the canonical <c>PCA-Action</c> header and that header is a covered component, so the single request is
    /// bot-verifiable and carries tamper-evident proof of authority. <paramref name="input"/> is the <see cref="SignRequest"/> input plus <c>pcactn</c>. Returns the sign result
    /// with the proof header merged into <c>headers</c>, plus <c>proofHeader</c>.</summary>
    public static D SignRequestWithProof(D input)
    {
        if (!WbaJs.Def(input, "pcactn")) throw new ArgumentException("signRequestWithProof: pcactn is required");
        var proof = ProofHeaders(input["pcactn"]);
        var headers = new D();
        if (input.GetValueOrDefault("headers") is D hd) foreach (var (k, v) in hd) headers[k] = v;
        foreach (var (k, v) in proof) headers[k] = v;
        var cover = new L();
        if (input.GetValueOrDefault("coverHeaders") != null) cover.AddRange(A2aPca.SpreadList(input["coverHeaders"]));
        cover.Add(PcaProofComponent);
        var rest = new D(input);
        rest.Remove("pcactn");
        rest["headers"] = headers;
        rest["coverHeaders"] = cover;
        var result = SignRequest(rest);
        var merged = new D((D)result["headers"]!);
        foreach (var (k, v) in proof) merged[k] = v;
        result["headers"] = merged;
        result["proofHeader"] = proof;
        return result;
    }

    /// <summary>Verify the HTTP Message Signature AND extract the proof: requires <c>PCA-Action</c> to be a covered component (else fail closed), decodes the PCActn from it,
    /// and, when <c>opts.expectedPCActn</c> is given, checks the carried proof equals it by canonical digest. The returned <c>pcactn</c> is bound to the verified signature.</summary>
    public static D VerifySignedRequestWithProof(D req, D opts)
    {
        var bas = VerifySignedRequest(req, opts);
        if (bas["valid"] is not true) return bas;
        if (!(bas.GetValueOrDefault("covered") is L cov && cov.Contains(PcaProofComponent))) return Invalid($"the {PcaHeader} proof header is not covered by the signature");
        string? headerValue;
        try { headerValue = NormalizeHeaders(req.GetValueOrDefault("headers")).GetValueOrDefault(PcaProofComponent); }
        catch (Exception e) { return Invalid("verification failed (fail closed): " + e.Message); }
        if (headerValue == null) return Invalid($"missing {PcaHeader} header");
        D pcactn;
        try { pcactn = DecodeProofHeader(headerValue); }
        catch (Exception e) { return Invalid($"invalid PCActn in {PcaHeader}: {e.Message}"); }
        if (opts.GetValueOrDefault("expectedPCActn") != null && Pca.HashCanonical(pcactn) != Pca.HashCanonical(opts["expectedPCActn"]))
            return Invalid("carried PCActn does not match the expected proof");
        return new D(bas) { ["pcactn"] = pcactn };
    }
}
