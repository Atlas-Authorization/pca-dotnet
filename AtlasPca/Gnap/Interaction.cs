using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Digests;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Gnap;

/// <summary>
/// GNAP interaction modes (RFC 9635 sections 2.5, 3.3, 4, 5.1): the four start modes, the two finish methods, the interaction hash,
/// one-time interaction references, and an authorization-server state machine (pending, approved, finalized). The approved interaction
/// then continues through the PCA step-up continuation (<see cref="Gnap.BeginGnapContinuation"/> / <see cref="Gnap.CompleteGnapContinuation"/>).
/// </summary>
public static class Interaction
{
    public static readonly IReadOnlyList<string> StartModes = new[] { "redirect", "app", "user_code", "user_code_uri" };
    public static readonly IReadOnlyList<string> FinishMethods = new[] { "redirect", "push" };
    /// <summary>Named Information hash names (IANA) this implementation computes.</summary>
    public static readonly IReadOnlyList<string> HashMethods = new[] { "sha-256", "sha-384", "sha-512", "sha3-256", "sha3-512" };

    /// <summary>The names JavaScript's <c>in</c> finds on a plain object besides its own keys (a hash_method of one of these passes
    /// <see cref="ValidateInteractRequest"/>).</summary>
    static readonly HashSet<string> ObjectProtoNames = new()
    {
        "constructor", "__defineGetter__", "__defineSetter__", "hasOwnProperty", "__lookupGetter__", "__lookupSetter__", "isPrototypeOf",
        "propertyIsEnumerable", "toString", "valueOf", "__proto__", "toLocaleString",
    };

    static bool InHashMethods(object? m)
    {
        var k = GnapJs.Str(m);
        return HashMethods.Contains(k) || ObjectProtoNames.Contains(k);
    }

    static string RandomB64u(int n) => Pca.B64u(RandomNumberGenerator.GetBytes(n));

    static string? StartName(object? e) => e is string s ? s : e is D m && m.GetValueOrDefault("mode") is string mode ? mode : null;

    // ---- callback URIs ----

    static readonly HashSet<string> Special = new() { "http", "https", "ftp", "ws", "wss", "file" };

    /// <summary>The text a WHATWG URL parser works on: leading and trailing C0 controls and spaces dropped, tab, LF and CR removed.</summary>
    static string UrlInput(string s)
    {
        int a = 0, b = s.Length;
        while (a < b && s[a] <= 0x20) a++;
        while (b > a && s[b - 1] <= 0x20) b--;
        var sb = new StringBuilder();
        for (int i = a; i < b; i++) { var c = s[i]; if (c != '\t' && c != '\n' && c != '\r') sb.Append(c); }
        return sb.ToString();
    }

    static bool IsHostChar(char c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_';

    static readonly Regex Digits = new(@"\A[0-9]+\z", RegexOptions.CultureInvariant);
    static readonly Regex HexLabel = new(@"\A0[xX][0-9a-fA-F]*\z", RegexOptions.CultureInvariant);
    static readonly Regex QuadPart = new(@"\A[0-9]{1,3}\z", RegexOptions.CultureInvariant);
    static readonly Regex SchemeRe = new(@"\A[A-Za-z][A-Za-z0-9+.\-]*\z", RegexOptions.CultureInvariant);

    static bool NumericLabel(string label) => label.Length > 0 && (Digits.IsMatch(label) || HexLabel.IsMatch(label));

    /// <summary>A dotted-quad IPv4 literal of four decimal parts each at most 255 (the only numeric host this check accepts).</summary>
    static bool PlainIpv4(string host)
    {
        var p = host.Split('.');
        if (p.Length != 4) return false;
        foreach (var x in p)
            if (!QuadPart.IsMatch(x) || (x.Length > 1 && x[0] == '0') || int.Parse(x, CultureInfo.InvariantCulture) > 255) return false;
        return true;
    }

    /// <summary>The parsed shape of a callback URI: lowercase scheme, host (lowercase; null when the scheme has none), the text after the authority.</summary>
    sealed class Url
    {
        public string Scheme = "";
        public string? Host; // as URL.hostname prints it ("[::1]" keeps its brackets)
        public string? Userinfo;
        public string? Port; // as given, "" when absent
        public string? Rest; // path and query (no fragment: callbackUriOk refuses those)
        public bool HasAuthority;
    }

    /// <summary>A conservative reading of what <c>new URL(uri)</c> accepts. Anything this parser is unsure about (a special scheme without <c>//</c>, an
    /// internationalized or exotic host, a short IPv4 form, an IPv6 literal other than <c>[::1]</c>) is refused: the result is never more permissive
    /// than the reference.</summary>
    static Url? ParseUrl(string uri)
    {
        var s = UrlInput(uri);
        int colon = s.IndexOf(':');
        if (colon <= 0) return null;
        var scheme = s[..colon];
        if (!SchemeRe.IsMatch(scheme)) return null;
        var u = new Url { Scheme = scheme.ToLowerInvariant() };
        var after = s[(colon + 1)..];
        bool special = Special.Contains(u.Scheme);
        if (!after.StartsWith("//", StringComparison.Ordinal))
        {
            if (special) return null;
            u.Rest = after;
            return u;
        }
        var auth = after[2..];
        int end = auth.Length;
        for (int i = 0; i < auth.Length; i++) { var c = auth[i]; if (c == '/' || c == '?' || (special && c == '\\')) { end = i; break; } }
        u.Rest = auth[end..];
        auth = auth[..end];
        u.HasAuthority = true;
        int at = auth.LastIndexOf('@');
        u.Userinfo = at >= 0 ? auth[..at] : null;
        var hostport = at >= 0 ? auth[(at + 1)..] : auth;
        int pc = hostport.LastIndexOf(':');
        string host = hostport, port = "";
        if (hostport.StartsWith('['))
        {
            int close = hostport.IndexOf(']');
            if (close < 0) return null;
            host = hostport[..(close + 1)];
            var tail = hostport[(close + 1)..];
            if (tail.Length > 0) { if (!tail.StartsWith(':')) return null; port = tail[1..]; }
            if (host != "[::1]") return null; // the only IPv6 literal this check reads
        }
        else if (pc >= 0)
        {
            host = hostport[..pc];
            port = hostport[(pc + 1)..];
        }
        if (port.Length > 0)
        {
            if (!Digits.IsMatch(port) || port.Length > 9 || long.Parse(port, CultureInfo.InvariantCulture) > 65535) return null;
        }
        u.Port = port;
        if (!host.StartsWith('['))
        {
            foreach (var ch in host) if (!IsHostChar(ch)) return null;
            if (host.Length == 0 && special && u.Scheme != "file") return null;
            var h = host.EndsWith('.') ? host[..^1] : host;
            var last = h.Contains('.') ? h[(h.LastIndexOf('.') + 1)..] : h;
            if (NumericLabel(last) && !PlainIpv4(host)) return null;
            foreach (var label in host.Split('.')) if (label.ToLowerInvariant().StartsWith("xn--", StringComparison.Ordinal)) return null;
        }
        u.Host = host.ToLowerInvariant();
        return u;
    }

    /// <summary>RFC 9635 2.5.2: absolute URI, no fragment; HTTPS, loopback, or an application-specific scheme (not plain http to a remote host).</summary>
    public static bool CallbackUriOk(object? uri)
    {
        if (uri is not string s || s.Length > 2048) return false;
        var u = ParseUrl(s);
        if (u == null) return false;
        if (s.Contains('#')) return false;
        if (u.Scheme == "https") return true;
        if (u.Scheme == "http") return u.Host != null && (u.Host == "localhost" || u.Host == "127.0.0.1" || u.Host == "[::1]");
        return u.Scheme != "javascript" && u.Scheme != "data" && u.Scheme != "file" && u.Scheme != "blob";
    }

    // ---- request validation, hashes, codes ----

    static bool PrintableAscii(string s)
    {
        foreach (var c in s) if (c < 0x21 || c > 0x7e) return false;
        return s.Length > 0;
    }

    /// <summary>Validate an <c>interact</c> request; returns the problems (empty = valid). Unknown start modes are tolerated (the registry is open).</summary>
    public static List<string> ValidateInteractRequest(object? r)
    {
        var e = new List<string>();
        if (r is not D o) return new List<string> { "interact must be an object" };
        if (o.GetValueOrDefault("start") is not L { Count: > 0 and <= 16 } start) e.Add("start must be a non-empty array of modes");
        else foreach (var s in start) if (StartName(s) == null) e.Add("each start entry is a mode name or an object with a mode");
        if (o.ContainsKey("finish"))
        {
            var f = o["finish"];
            if (!GnapJs.IsObject(f)) e.Add("finish must be an object");
            else
            {
                if (GnapJs.Member(f, "method") is not string method || !FinishMethods.Contains(method)) e.Add("finish.method must be redirect or push");
                if (!CallbackUriOk(GnapJs.Member(f, "uri"))) e.Add("finish.uri must be an absolute https, loopback or app-scheme URI without a fragment");
                if (GnapJs.Member(f, "nonce") is not string nonce || nonce.Length < 8 || nonce.Length > 256 || !PrintableAscii(nonce))
                    e.Add("finish.nonce must be 8..256 printable ASCII characters");
                if (GnapJs.Has(f, "hash_method") && !InHashMethods(((D)f!)["hash_method"])) e.Add("finish.hash_method is not a supported Named Information hash");
            }
        }
        return e;
    }

    /// <summary>Node's 'ascii' encoding keeps the low byte of each UTF-16 code unit.</summary>
    static byte[] AsciiBytes(string s)
    {
        var b = new byte[s.Length];
        for (int i = 0; i < b.Length; i++) b[i] = (byte)s[i];
        return b;
    }

    static byte[] Sha3(int bits, byte[] data)
    {
        var d = new Sha3Digest(bits);
        d.BlockUpdate(data, 0, data.Length);
        var o = new byte[d.GetDigestSize()];
        d.DoFinal(o, 0);
        return o;
    }

    static byte[] Digest(string name, byte[] data) => name switch
    {
        "sha-256" => SHA256.HashData(data),
        "sha-384" => SHA384.HashData(data),
        "sha-512" => SHA512.HashData(data),
        "sha3-256" => Sha3(256, data),
        "sha3-512" => Sha3(512, data),
        _ => throw new AtlasPca.Grants.CodedException("ERR_INVALID_ARG_TYPE", "The \"algorithm\" argument must be of type string"),
    };

    /// <summary>RFC 9635 4.2.3: base64url (no padding) of HASH(clientNonce LF asNonce LF interactRef LF grantEndpointUri). <paramref name="a"/>: clientNonce,
    /// asNonce, interactRef, grantEndpoint, hashMethod.</summary>
    public static string InteractionHash(D a)
    {
        var m = a.GetValueOrDefault("hashMethod") ?? "sha-256";
        if (!InHashMethods(m)) throw new InteractionException("unsupported_hash", "hash_method " + GnapJs.Str(m) + " is not supported");
        if (m is not string name) throw new AtlasPca.Grants.CodedException("ERR_INVALID_ARG_TYPE", "The \"algorithm\" argument must be of type string");
        var text = GnapJs.Str(GnapJs.Get(a, "clientNonce")) + "\n" + GnapJs.Str(GnapJs.Get(a, "asNonce")) + "\n" + GnapJs.Str(GnapJs.Get(a, "interactRef")) + "\n"
            + GnapJs.Str(GnapJs.Get(a, "grantEndpoint"));
        return Pca.B64u(Digest(name, AsciiBytes(text)));
    }

    /// <summary>Client side: does the callback's <c>hash</c> match? Constant time; a non-validating hash means the interact_ref MUST NOT be sent.</summary>
    public static bool VerifyInteractionHash(object? received, D a)
    {
        if (received is not string r) return false;
        var want = Encoding.UTF8.GetBytes(InteractionHash(a));
        var got = Encoding.UTF8.GetBytes(r);
        return want.Length == got.Length && CryptographicOperations.FixedTimeEquals(want, got);
    }

    const string CodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    /// <summary><paramref name="len"/> (6..12) characters from an alphabet without look-alikes; compared case-insensitively (RFC 9635 3.3.3).</summary>
    public static string NewUserCode(int len = 8)
    {
        if (len < 6 || len > 12) throw new ArgumentOutOfRangeException(nameof(len), "user code length 6..12");
        var b = RandomNumberGenerator.GetBytes(len);
        var sb = new StringBuilder();
        foreach (var x in b) sb.Append(CodeAlphabet[x % 32]); // 32 symbols, 256 % 32 == 0: no modulo bias
        return sb.ToString();
    }

    /// <summary>/[\s-]/g removed, then upper-cased (JavaScript's \s set).</summary>
    static string NormCode(string c)
    {
        var sb = new StringBuilder();
        foreach (var ch in c)
        {
            bool ws = ch == '-' || ch == ' ' || (ch >= '\t' && ch <= '\r') || ch == ' ' || ch == ' ' || (ch >= ' ' && ch <= ' ') || ch == '\u2028'
                || ch == '\u2029' || ch == ' ' || ch == ' ' || ch == '　' || ch == '﻿';
            if (!ws) sb.Append(ch);
        }
        return sb.ToString().ToUpperInvariant();
    }

    // ---- the authorization-server state machine ----

    /// <summary>One interaction: state pending, approved or finalized.</summary>
    public sealed class State
    {
        public string Id { get; }
        public string Status { get; internal set; } = "pending";
        public string GrantEndpoint { get; }
        public List<string> Modes { get; internal set; } = new();
        /// <summary>method, uri, clientNonce, asNonce, hashMethod; null without a finish method.</summary>
        public D? Finish { get; internal set; }
        public string? UserCode { get; internal set; }
        public string? InteractRef { get; internal set; }
        public bool RefUsed { get; internal set; }
        public long ExpiresAt { get; internal set; }

        internal State(string id, string grantEndpoint) { Id = id; GrantEndpoint = grantEndpoint; }

        /// <summary>The object the reference holds (members that were never set are absent).</summary>
        public D ToMap()
        {
            var m = new D { ["id"] = Id, ["state"] = Status, ["grantEndpoint"] = GrantEndpoint, ["modes"] = new L(Modes.Select(x => (object?)x)) };
            if (Finish != null) m["finish"] = Finish;
            if (UserCode != null) m["userCode"] = UserCode;
            if (InteractRef != null) m["interactRef"] = InteractRef;
            m["refUsed"] = RefUsed;
            m["expiresAt"] = ExpiresAt;
            return m;
        }
    }

    /// <summary>The authorization server's interaction endpoint. <c>supports</c>: the modes this AS supports; <c>redirectUri</c>, <c>appUri</c> build the
    /// interaction URIs; <c>userCodeUri</c> is the user-code page; <c>ttlSec</c> (default 600); <c>now</c> is the clock in seconds.</summary>
    public sealed class Server(string grantEndpoint, IReadOnlyList<string> supports, Func<string, string> redirectUri, Func<string, string>? appUri,
        string? userCodeUri, long? ttlSec, Func<long> now)
    {
        readonly Dictionary<string, State> byId = new();
        readonly Dictionary<string, string> byCode = new();
        readonly Dictionary<string, string> byRef = new();

        /// <summary>Start an interaction from an <c>interact</c> request: the interaction and the response. The response never names a mode the client did
        /// not ask for nor one the AS does not support (RFC 9635 3.3).</summary>
        public (State Interaction, D Response) Start(D req)
        {
            var problems = ValidateInteractRequest(req);
            if (problems.Count > 0) throw new InteractionException("invalid_request", string.Join("; ", problems));
            var asked = new HashSet<string?>();
            foreach (var s in (L)req["start"]!) asked.Add(StartName(s));
            var modes = new List<string>();
            foreach (var m in supports)
                if (asked.Contains(m) && (m != "app" || appUri != null) && (m != "user_code_uri" || !string.IsNullOrEmpty(userCodeUri))) modes.Add(m);
            bool hasFinish = GnapJs.Truthy(req.GetValueOrDefault("finish"));
            if (modes.Count == 0 && !hasFinish) throw new InteractionException("invalid_interaction", "no requested interaction mode is supported");
            var id = RandomB64u(16);
            long ttl = ttlSec ?? 600;
            var it = new State(id, grantEndpoint) { Modes = modes, ExpiresAt = now() + ttl };
            var res = new D { ["expires_in"] = ttl };
            if (modes.Contains("redirect")) res["redirect"] = redirectUri(id);
            if (modes.Contains("app")) res["app"] = appUri!(id);
            if (modes.Contains("user_code") || modes.Contains("user_code_uri"))
            {
                it.UserCode = NewUserCode();
                byCode[it.UserCode] = id;
                if (modes.Contains("user_code")) res["user_code"] = it.UserCode;
                if (modes.Contains("user_code_uri")) res["user_code_uri"] = new D { ["code"] = it.UserCode, ["uri"] = userCodeUri };
            }
            if (hasFinish)
            {
                var f = (D)req["finish"]!;
                var asNonce = RandomB64u(24);
                it.Finish = new D
                {
                    ["method"] = f.GetValueOrDefault("method"), ["uri"] = f.GetValueOrDefault("uri"), ["clientNonce"] = f.GetValueOrDefault("nonce"),
                    ["asNonce"] = asNonce, ["hashMethod"] = f.GetValueOrDefault("hash_method") ?? "sha-256",
                };
                res["finish"] = asNonce;
            }
            byId[id] = it;
            return (it, res);
        }

        /// <summary>The resource owner typed a code. Case-insensitive. A 32^8 code space is only safe behind a per-source rate limit on this lookup: the caller MUST apply one.</summary>
        public State? LookupUserCode(string code)
        {
            State? it = byCode.TryGetValue(NormCode(code), out var id) && byId.TryGetValue(id, out var s) ? s : null;
            if (it == null || it.Status != "pending" || now() > it.ExpiresAt) return null;
            return it;
        }

        public State? Get(string id) => byId.GetValueOrDefault(id);

        State Live(string id)
        {
            var it = byId.GetValueOrDefault(id) ?? throw new InteractionException("unknown_interaction", "no such interaction");
            if (now() > it.ExpiresAt) throw new InteractionException("expired", "the interaction expired");
            return it;
        }

        /// <summary>The resource owner approved. Returns <c>{interactRef, finish?}</c>: the finish message to deliver (redirect URL or push body), if the client asked for one.</summary>
        public D Approve(string id)
        {
            var it = Live(id);
            if (it.Status != "pending") throw new InteractionException("wrong_state", "interaction is " + it.Status);
            it.Status = "approved";
            it.InteractRef = RandomB64u(18);
            byRef[it.InteractRef] = id;
            if (it.UserCode != null) byCode.Remove(it.UserCode);
            if (it.Finish == null) return new D { ["interactRef"] = it.InteractRef };
            var hash = InteractionHash(new D
            {
                ["clientNonce"] = it.Finish["clientNonce"], ["asNonce"] = it.Finish["asNonce"], ["interactRef"] = it.InteractRef,
                ["grantEndpoint"] = it.GrantEndpoint, ["hashMethod"] = it.Finish["hashMethod"],
            });
            if (it.Finish["method"] is "push")
                return new D { ["interactRef"] = it.InteractRef, ["finish"] = new D { ["method"] = "push", ["uri"] = it.Finish["uri"], ["body"] = new D { ["hash"] = hash, ["interact_ref"] = it.InteractRef } } };
            return new D { ["interactRef"] = it.InteractRef, ["finish"] = new D { ["method"] = "redirect", ["url"] = RedirectUrl((string)it.Finish["uri"]!, hash, it.InteractRef) } };
        }

        /// <summary>Continuation (RFC 9635 5.1): present the interact_ref once. A replay finalizes the grant and is <c>too_many_attempts</c>.</summary>
        public State Consume(string interactRef)
        {
            State? it = byRef.TryGetValue(interactRef, out var id) && byId.TryGetValue(id, out var s) ? s : null;
            if (it == null) throw new InteractionException("unknown_interaction", "no such interaction reference");
            if (it.RefUsed || it.Status == "finalized")
            {
                it.Status = "finalized";
                throw new InteractionException("too_many_attempts", "the interaction reference was already used");
            }
            if (now() > it.ExpiresAt) throw new InteractionException("expired", "the interaction expired");
            if (it.Status != "approved") throw new InteractionException("wrong_state", "interaction is " + it.Status);
            it.RefUsed = true;
            return it;
        }

        public void FinalizeInteraction(string id)
        {
            if (byId.TryGetValue(id, out var it)) it.Status = "finalized";
        }
    }

    // ---- the redirect URL: the finish URI with hash and interact_ref set in its query ----

    /// <summary>application/x-www-form-urlencoded decoding of one component ('+' is a space; a '%' not followed by two hex digits stays).</summary>
    static string FormDecode(string s)
    {
        s = s.Replace('+', ' ');
        var bytes = new List<byte>();
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '%' && i + 2 < s.Length && Uri.IsHexDigit(s[i + 1]) && Uri.IsHexDigit(s[i + 2]))
            {
                bytes.Add(byte.Parse(s.AsSpan(i + 1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                i += 2;
            }
            else if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { bytes.AddRange(Encoding.UTF8.GetBytes(s.Substring(i, 2))); i++; }
            else bytes.AddRange(Encoding.UTF8.GetBytes(s[i].ToString()));
        }
        return Encoding.UTF8.GetString(bytes.ToArray());
    }

    static string FormEncode(string s)
    {
        var sb = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(s))
        {
            if ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '*' || b == '-' || b == '.' || b == '_') sb.Append((char)b);
            else if (b == ' ') sb.Append('+');
            else sb.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    /// <summary><c>new URL(uri)</c> with <c>hash</c> and <c>interact_ref</c> set via <c>searchParams.set</c>, printed. Covers the callback forms
    /// <see cref="CallbackUriOk"/> accepts: the scheme and host in lower case, the scheme's default port dropped, an empty path of a special scheme
    /// printed as <c>/</c>; the query is re-serialized as application/x-www-form-urlencoded.</summary>
    static string RedirectUrl(string uri, string hash, string reference)
    {
        var u = ParseUrl(uri) ?? throw new ArgumentException("not a URL: " + uri);
        var rest = u.Rest ?? "";
        int q = rest.IndexOf('?');
        var path = q >= 0 ? rest[..q] : rest;
        var query = q >= 0 ? rest[(q + 1)..] : "";
        var ps = new List<string[]>();
        if (query.Length > 0)
        {
            foreach (var pair in query.Split('&'))
            {
                if (pair.Length == 0) continue;
                int eq = pair.IndexOf('=');
                ps.Add(new[] { FormDecode(eq >= 0 ? pair[..eq] : pair), FormDecode(eq >= 0 ? pair[(eq + 1)..] : "") });
            }
        }
        foreach (var kv in new[] { new[] { "hash", hash }, new[] { "interact_ref", reference } })
        {
            bool set = false;
            for (int i = 0; i < ps.Count; i++)
            {
                if (ps[i][0] != kv[0]) continue;
                if (!set) { ps[i][1] = kv[1]; set = true; } else ps.RemoveAt(i--);
            }
            if (!set) ps.Add(kv);
        }
        var qs = new StringBuilder();
        foreach (var kv in ps) { if (qs.Length > 0) qs.Append('&'); qs.Append(FormEncode(kv[0])).Append('=').Append(FormEncode(kv[1])); }
        var o = new StringBuilder(u.Scheme).Append(':');
        if (u.HasAuthority)
        {
            o.Append("//");
            if (!string.IsNullOrEmpty(u.Userinfo)) o.Append(u.Userinfo).Append('@');
            o.Append(u.Host);
            var dp = u.Scheme is "https" or "wss" ? "443" : u.Scheme is "http" or "ws" ? "80" : u.Scheme == "ftp" ? "21" : "";
            var port = Regex.Replace(u.Port ?? "", "^0+(?=[0-9])", "");
            if (port.Length > 0 && port != dp) o.Append(':').Append(port);
            if (path.Length == 0 && Special.Contains(u.Scheme)) path = "/";
        }
        o.Append(path).Append('?').Append(qs);
        return o.ToString();
    }

    /// <summary>Client side: validate a finish callback (query for redirect, JSON body for push). Returns the interact_ref to send, or throws
    /// <c>unknown_interaction</c>. <paramref name="ctx"/>: clientNonce, asNonce, grantEndpoint, hashMethod.</summary>
    public static string AcceptFinish(D cb, D ctx)
    {
        if (cb.GetValueOrDefault("interact_ref") is not string { Length: > 0 } reference || cb.GetValueOrDefault("hash") is not string)
            throw new InteractionException("unknown_interaction", "hash and interact_ref are required");
        var a = new D(ctx) { ["interactRef"] = reference };
        if (!VerifyInteractionHash(cb["hash"], a)) throw new InteractionException("unknown_interaction", "the callback hash does not validate");
        return reference;
    }

    /// <summary>One need (<c>{verb, resource}</c>) per (action, location) pair, the resource namespaced as <c>gnap:&lt;type&gt;:&lt;location&gt;</c> exactly like
    /// <see cref="Gnap.GnapActionResource"/>. An access right with no <c>actions</c> or no <c>locations</c> is a wildcard and is REFUSED here.</summary>
    public static L AccessToNeeds(L access)
    {
        var o = new L();
        foreach (var ao in access)
        {
            if (ao == null) throw new ArgumentException("access entry is null");
            var actions = GnapJs.Member(ao, "actions"); var locations = GnapJs.Member(ao, "locations");
            if (actions is not L { Count: > 0 } al || locations is not L { Count: > 0 } ll)
                throw new InteractionException("invalid_request", "access \"" + GnapJs.Str(GnapJs.Get(ao, "type")) + "\" needs explicit actions and locations to become a need");
            foreach (var verb in al) foreach (var loc in ll)
                o.Add(new D { ["verb"] = verb, ["resource"] = "gnap:" + GnapJs.Str(GnapJs.Get(ao, "type")) + ":" + GnapJs.Str(loc) });
        }
        return o;
    }
}
