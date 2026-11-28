// SD-JWT serialization of a PCA PCActn (IETF SD-JWT, RFC 9901 family): the issuer-signed JWT carries salted-hash digests of the selectively
// disclosable capability claims, the holder presents a subset and appends a key-binding JWT (typ kb+jwt). A bridge: the PCActn's own signature
// (a claim) stays the source of truth (VerifyRecovered re-verifies it with the core). Maps onto the reference's pca-sdjwt exports (PascalCase).
//
// Options are JSON-shaped dictionaries with the reference's member names (a member that is absent differs from one that is JSON null, as in the
// reference). Keys are JoseKey values (ImportEd25519PrivateKey / ImportEd25519PublicKey / AtlasPca.Jose.Jose.ImportJwk), or a JWK / raw public bytes
// where the reference takes them. EdDSA is the only issuance algorithm by default; verification also accepts ES256 / RS256 / PS256 / ... keys through
// `algorithms`. Verification fails closed: every refusal is {ok:false, reason}.
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca;
using AtlasPca.Jose;
using J = AtlasPca.Jose.Jose;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Sdjwt;

/// <summary>The outcome of <see cref="Sdjwt.VerifyRecovered"/>: allow, the reason of the first failed check (this package's own, or the core's; null when allowed) and the core's checks.</summary>
public sealed record RecoveredResult(bool Allow, string? Reason, IReadOnlyDictionary<string, bool> Checks);

public static class Sdjwt
{
    public const string SdAlg = "sha-256";
    public const string PcaSdJwtTyp = "pca+sd-jwt";
    public const string KbJwtTyp = "kb+jwt";
    public const string DefaultSigningAlg = "EdDSA";

    /// <summary>The PCActn fields carried as selectively disclosable capability claims by default.</summary>
    public static readonly IReadOnlyList<string> PcaCapabilityClaims = new[]
    {
        "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter", "risk_claim", "nonce", "caution",
        "rationale_commitment", "progress_step", "prohibition_evidence", "tool_binding", "alg", "pq_pk", "sig", "pq_sig", "threshold", "zk_compliance", "bond_ref",
    };

    static readonly HashSet<string> StandardMapped = new() { "aud", "iat", "exp" };
    const string ClearDiscriminator = "ver";
    static readonly HashSet<string> CriticalClaims = new() { "iss", "aud", "exp", "nbf", "cnf", "status" };
    static readonly HashSet<string> ReservedClaims = new() { "iss", "sub", "aud", "iat", "exp", "_sd", "_sd_alg", "cnf" };

    // ===================== helpers =====================

    /// <summary>base64url(SHA-256(ASCII(input))): each UTF-16 unit contributes its low byte, as an ASCII write does.</summary>
    static string Sha256b64u(string ascii)
    {
        var b = new byte[ascii.Length];
        for (int i = 0; i < b.Length; i++) b[i] = (byte)ascii[i];
        return Pca.B64u(SHA256.HashData(b));
    }

    static bool IsJwk(object? v) => v is D m && m.GetValueOrDefault("kty") is string;
    static double? NumOf(object? o) => J.NumberOf(o);

    static bool Truthy(object? v)
    {
        if (v == null) return false;
        if (v is bool b) return b;
        if (v is string s) return s.Length > 0;
        if (NumOf(v) is double d) return d != 0 && !double.IsNaN(d);
        return true;
    }

    /// <summary>JavaScript ToNumber of a parsed JSON value (null is 0, a non-numeric string NaN).</summary>
    static double ToNumber(object? v)
    {
        if (v == null) return 0;
        if (NumOf(v) is double d) return d;
        if (v is bool b) return b ? 1 : 0;
        if (v is string s)
        {
            var t = s.Trim();
            if (t.Length == 0) return 0;
            return double.TryParse(t, NumberStyles.Float, CultureInfo.InvariantCulture, out var r) ? r : double.NaN;
        }
        return double.NaN;
    }

    /// <summary>JavaScript's <c>String(v)</c> as far as a message needs it.</summary>
    static string JsStr(object? v) => v switch
    {
        null => "null",
        string s => s,
        Num n => IntentJs.NormNum(n.Raw).Raw,
        bool b => b ? "true" : "false",
        L l => string.Join(",", l.Select(x => x == null ? "" : JsStr(x))),
        _ => "[object Object]",
    };

    static bool SameJs(object? a, object? b)
    {
        if (a == null || b == null) return a == null && b == null;
        if (a is string || b is string) return a is string x && b is string y && x == y;
        if (a is bool || b is bool) return a is bool p && b is bool q && p == q;
        return NumOf(a) is double u && NumOf(b) is double w && u == w;
    }

    // ===================== key helpers =====================

    /// <summary>A <c>{kty: OKP, crv: Ed25519, x}</c> JWK for a raw 32-byte Ed25519 public key.</summary>
    public static D Ed25519PublicJwk(byte[]? raw)
    {
        if (raw == null || raw.Length != 32) throw new InvalidOperationException("pca-sdjwt: Ed25519 public key must be 32 bytes");
        return J.Ed25519PublicJwk(raw);
    }

    /// <summary>A private key (usable to sign) for a raw 32-byte Ed25519 SEED.</summary>
    public static JoseKey ImportEd25519PrivateKey(byte[]? rawSeed)
    {
        if (rawSeed == null || rawSeed.Length != 32) throw new InvalidOperationException("pca-sdjwt: Ed25519 private seed must be 32 bytes");
        return (JoseKey)J.ImportJwk(J.Ed25519SeedJwk(rawSeed), "EdDSA");
    }

    /// <summary>A public key (usable to verify) for a raw 32-byte Ed25519 public key.</summary>
    public static JoseKey ImportEd25519PublicKey(byte[]? raw)
    {
        if (raw == null || raw.Length != 32) throw new InvalidOperationException("pca-sdjwt: Ed25519 public key must be 32 bytes");
        return (JoseKey)J.ImportJwk(J.Ed25519PublicJwk(raw), "EdDSA");
    }

    static D LeafHolderJwk(D pcActn)
    {
        var chain = pcActn.GetValueOrDefault("cap_chain") as L;
        var leaf = chain is { Count: > 0 } ? chain[^1] as D : null;
        if (leaf == null || leaf.GetValueOrDefault("holder") is not string h || h.Length == 0)
            throw new InvalidOperationException("pca-sdjwt: cannot derive holder key — cap_chain leaf holder is missing");
        byte[] raw;
        try { raw = J.DecodeB64Lenient(h); } catch (JoseException) { raw = Array.Empty<byte>(); }
        return Ed25519PublicJwk(raw);
    }

    static D ResolveCnfJwk(D pcActn, D kb)
    {
        if (!kb.ContainsKey("holderPublicKey")) return LeafHolderJwk(pcActn);
        var hp = kb["holderPublicKey"];
        if (hp is byte[] raw) return Ed25519PublicJwk(raw);
        if (IsJwk(hp)) return (D)hp!;
        throw new InvalidOperationException("pca-sdjwt: keyBinding.holderPublicKey must be a JWK or a raw Ed25519 public key");
    }

    static double NumericDate(object? ms, string label, bool ceil)
    {
        if (NumOf(ms) is not double d || !double.IsFinite(d)) throw new InvalidOperationException($"pca-sdjwt: PCActn.{label} must be a finite number (epoch ms)");
        var v = d / 1000;
        return ceil ? Math.Ceiling(v) : Math.Floor(v);
    }

    static (string Encoded, string Digest) MakeDisclosure(string name, object? value)
    {
        var salt = Pca.B64u(RandomNumberGenerator.GetBytes(16));
        var encoded = Pca.B64u(J.Utf8(J.Stringify(new L { salt, name, value })));
        return (encoded, Sha256b64u(encoded));
    }

    // ===================== issuance =====================

    /// <summary>Serializes a signed PCActn as an IETF SD-JWT: <c>&lt;issuer JWT&gt;~&lt;Disclosure 1&gt;~...~&lt;Disclosure N&gt;~</c>. Options: <c>issuerKey</c>
    /// (a private JoseKey or JWK, required), <c>disclosable</c> (claim names; null / absent = all of <see cref="PcaCapabilityClaims"/>), <c>keyBinding</c>
    /// (<c>{holderPublicKey?}</c> embeds a cnf key; absent / null / false = none), <c>iss</c>, <c>sub</c>, <c>typ</c>, <c>signingAlg</c>. No KB-JWT is attached at issuance.</summary>
    public static string IssuePcaSdJwt(D? pcActn, D options)
    {
        if (pcActn == null) throw new InvalidOperationException("pca-sdjwt: pcActn must be an object");
        if (pcActn.GetValueOrDefault("cap_chain") is not L { Count: > 0 } chain) throw new InvalidOperationException("pca-sdjwt: pcActn.cap_chain must be a non-empty array");
        var root = chain[0] as D; var leaf = chain[^1] as D;
        if (root == null || root.GetValueOrDefault("issuer") is not string) throw new InvalidOperationException("pca-sdjwt: cap_chain root issuer is missing");
        if (leaf == null || leaf.GetValueOrDefault("holder") is not string) throw new InvalidOperationException("pca-sdjwt: cap_chain leaf holder is missing");
        if (pcActn.GetValueOrDefault("aud") is not string aud || aud.Length == 0) throw new InvalidOperationException("pca-sdjwt: pcActn.aud is required");

        var iss = options.GetValueOrDefault("iss") ?? root["issuer"];
        var sub = options.GetValueOrDefault("sub") ?? leaf["holder"];
        double iat = NumericDate(pcActn.GetValueOrDefault("iat"), "iat", false);
        double exp = NumericDate(pcActn.GetValueOrDefault("exp"), "exp", true);
        if (exp <= iat) exp = iat + 1; // keep exp strictly after iat even for sub-second lifetimes

        var disclosable = new HashSet<string>();
        var dis = options.GetValueOrDefault("disclosable");
        if (dis == null) disclosable.UnionWith(PcaCapabilityClaims);
        else if (dis is L dl) { foreach (var x in dl) if (x is string xs) disclosable.Add(xs); }
        else throw new InvalidOperationException("pca-sdjwt: disclosable must be an array");

        // iat_ms / exp_ms carry the exact signed epoch-ms values so VerifyRecovered can rebuild the byte-identical PCActn
        var payload = new D { ["iss"] = iss, ["sub"] = sub, ["aud"] = aud, ["iat"] = iat, ["exp"] = exp };
        if (pcActn.ContainsKey(ClearDiscriminator)) payload[ClearDiscriminator] = pcActn[ClearDiscriminator];
        payload["iat_ms"] = pcActn["iat"]; payload["exp_ms"] = pcActn["exp"]; payload["_sd_alg"] = SdAlg;
        var disclosures = new List<string>();
        var sd = new L();
        foreach (var key in IntentJs.JsKeys(pcActn.Keys))
        {
            if (StandardMapped.Contains(key) || key == ClearDiscriminator) continue; // mapped to a standard / clear claim
            if (disclosable.Contains(key))
            {
                var (encoded, digest) = MakeDisclosure(key, pcActn[key]);
                disclosures.Add(encoded);
                sd.Add(digest);
            }
            else payload[key] = pcActn[key]; // the caller chose to keep this capability claim in the clear
        }
        if (sd.Count > 0) payload["_sd"] = sd;

        var kbO = options.GetValueOrDefault("keyBinding");
        if (Truthy(kbO)) payload["cnf"] = new D { ["jwk"] = ResolveCnfJwk(pcActn, kbO as D ?? new D()) };

        var alg = options.GetValueOrDefault("signingAlg") ?? DefaultSigningAlg;
        if (alg is not string) throw new JoseException("ERR_JWS_INVALID", "JWS \"alg\" (Algorithm) Header Parameter missing or invalid");
        var header = new D { ["alg"] = alg, ["typ"] = options.GetValueOrDefault("typ") ?? PcaSdJwtTyp };
        var jwt = J.SignJwt(header, payload, options.GetValueOrDefault("issuerKey") ?? throw new JoseTypeError("Key must be one of type CryptoKey, KeyObject, or JSON Web Key"));
        var sb = new StringBuilder(jwt).Append('~');
        foreach (var d in disclosures) sb.Append(d).Append('~');
        return sb.ToString();
    }

    // ===================== parsing =====================

    sealed class ParsedSdJwt
    {
        public string Jwt = "";
        public List<string> Disclosures = new();
        public string? KbJwt;
        public string PresentationHead = "";
    }

    static ParsedSdJwt ParseSdJwt(object? sdjwtO)
    {
        if (sdjwtO is not string sdjwt || sdjwt.Length == 0) throw new InvalidOperationException("pca-sdjwt: empty SD-JWT");
        var segments = sdjwt.Split('~');
        if (segments.Length < 2) throw new InvalidOperationException("pca-sdjwt: malformed SD-JWT (missing ~ separator)");
        var jwt = segments[0];
        if (jwt.Length == 0) throw new InvalidOperationException("pca-sdjwt: empty issuer JWT");
        var last = segments[^1];
        var disclosures = segments.Skip(1).Take(segments.Length - 2).ToList();
        // empty middle segments (a~~b) are an aliasing vector: reject rather than silently dropping them
        if (disclosures.Any(s => s.Length == 0)) throw new InvalidOperationException("pca-sdjwt: empty disclosure segment");
        // canonical-spelling gate BEFORE the JOSE layer: one accepted string form per issuer JWT / KB-JWT
        J.AssertCanonicalCompactJws(jwt);
        if (last.Length > 0) J.AssertCanonicalCompactJws(last);
        var p = new ParsedSdJwt { Jwt = jwt, Disclosures = disclosures };
        if (last.Length == 0) p.PresentationHead = sdjwt; // no KB-JWT: the whole string is the presentation head
        else { p.PresentationHead = sdjwt[..(sdjwt.Length - last.Length)]; p.KbJwt = last; }
        return p;
    }

    static L DecodeDisclosureParts(string encoded)
    {
        object? parsed;
        try { parsed = J.DecodeCanonicalJsonSegment(encoded); }
        catch (Exception) { throw new InvalidOperationException("pca-sdjwt: disclosure is not canonical base64url strict JSON"); }
        if (parsed is not L l || (l.Count != 2 && l.Count != 3)) throw new InvalidOperationException("pca-sdjwt: disclosure must be a [salt, name, value] triple or a [salt, value] pair");
        if (l[0] is not string) throw new InvalidOperationException("pca-sdjwt: disclosure salt must be a string");
        return l;
    }

    static void CollectDigests(object? node, List<string> output)
    {
        if (node is L l) { foreach (var x in l) CollectDigests(x, output); }
        else if (node is D m)
        {
            foreach (var (k, v) in m)
            {
                if (k == "_sd" && v is L sdl) output.AddRange(sdl.OfType<string>());
                else if (k == "..." && v is string sv) output.Add(sv);
                else CollectDigests(v, output);
            }
        }
    }

    static void Include(string digest, Dictionary<string, string> byDigest, HashSet<string> kept)
    {
        if (!byDigest.TryGetValue(digest, out var encoded) || kept.Contains(digest)) return;
        kept.Add(digest);
        var parts = DecodeDisclosureParts(encoded);
        var nested = new List<string>();
        CollectDigests(parts[^1], nested);
        foreach (var d in nested) Include(d, byDigest, kept);
    }

    /// <summary>The names a <c>new Set(selectClaims)</c> holds: a list's elements, a string's code points, nothing for null; anything else throws.</summary>
    static HashSet<string> KeepSet(object? select)
    {
        var keep = new HashSet<string>();
        if (select == null) return keep;
        if (select is L l) { foreach (var x in l) if (x is string s) keep.Add(s); return keep; }
        if (select is string str) { foreach (var r in str.EnumerateRunes()) keep.Add(r.ToString()); return keep; }
        throw new InvalidOperationException("object is not iterable");
    }

    // ===================== holder presentation =====================

    /// <summary>A holder presentation of an issued SD-JWT that discloses ONLY <paramref name="selectClaims"/> (claim names; a list, or null for none) and drops
    /// every other Disclosure; a selected claim is disclosed in full. Any existing KB-JWT is stripped. Options: <c>keyBinding</c>
    /// <c>{holderKey (private JoseKey / JWK), audience, nonce, iat, alg}</c> appends a fresh KB-JWT over the new presentation.</summary>
    public static string Present(object? sdjwt, object? selectClaims, D? options = null)
    {
        var parsed = ParseSdJwt(sdjwt);
        var keep = KeepSet(selectClaims);
        var byDigest = new Dictionary<string, string>();
        foreach (var e in parsed.Disclosures) byDigest[Sha256b64u(e)] = e;
        var kept = new HashSet<string>();
        object? payload;
        try
        {
            var segs = parsed.Jwt.Split('.');
            var raw = J.DecodeB64Lenient(segs.Length > 1 ? segs[1] : "");
            payload = NoDuplicateKeys.Parse(Encoding.UTF8.GetString(raw)); // a duplicate member is refused
        }
        catch (Exception) { throw new InvalidOperationException("pca-sdjwt: issuer JWT payload is not valid base64url JSON"); }
        if (payload is D pm)
        {
            // object-property Disclosures referenced from the top-level _sd, selected by claim name
            if (pm.GetValueOrDefault("_sd") is L sdl)
            {
                foreach (var digest in sdl)
                {
                    if (digest is not string ds || !byDigest.TryGetValue(ds, out var encoded)) continue;
                    var parts = DecodeDisclosureParts(encoded);
                    if (parts[1] is string name && parts.Count == 3 && keep.Contains(name)) Include(ds, byDigest, kept);
                }
            }
            // clear claims that contain selectively-disclosable parts (e.g. an array with `...` entries)
            foreach (var key in IntentJs.JsKeys(pm.Keys))
            {
                if (key != "_sd" && keep.Contains(key))
                {
                    var ds = new List<string>();
                    CollectDigests(pm[key], ds);
                    foreach (var d in ds) Include(d, byDigest, kept);
                }
            }
        }
        var head = new StringBuilder(parsed.Jwt);
        foreach (var e in parsed.Disclosures) if (kept.Contains(Sha256b64u(e))) head.Append('~').Append(e);
        head.Append('~');
        var kb = options?.GetValueOrDefault("keyBinding") as D;
        if (kb == null) return head.ToString();
        var now = kb.GetValueOrDefault("iat") ?? (object)Math.Floor(AtlasPca.ReplayClock.NowMs() / 1000.0);
        var kbPayload = new D { ["iat"] = now };
        if (kb.ContainsKey("audience")) kbPayload["aud"] = kb["audience"];
        kbPayload["sd_hash"] = Sha256b64u(head.ToString());
        if (kb.ContainsKey("nonce")) kbPayload["nonce"] = kb["nonce"];
        var alg = kb.GetValueOrDefault("alg") ?? DefaultSigningAlg;
        if (alg is not string) throw new JoseException("ERR_JWS_INVALID", "JWS \"alg\" (Algorithm) Header Parameter missing or invalid");
        var kbHeader = new D { ["alg"] = alg, ["typ"] = KbJwtTyp };
        var kbJwt = J.SignJwt(kbHeader, kbPayload, kb.GetValueOrDefault("holderKey") ?? throw new JoseTypeError("Key must be one of type CryptoKey, KeyObject, or JSON Web Key"));
        return head + kbJwt;
    }

    // ===================== verification =====================

    sealed class SdJwtProcessingError : Exception
    {
        public SdJwtProcessingError(string m) : base(m) { }
    }

    sealed class DecodedDisclosure
    {
        public readonly L Parts;
        public bool Used;
        public DecodedDisclosure(L parts) { Parts = parts; }
    }

    static DecodedDisclosure? ClaimDigest(string d, Dictionary<string, DecodedDisclosure> byDigest, HashSet<string> seen)
    {
        if (!seen.Add(d)) throw new SdJwtProcessingError("a digest appears more than once in the payload");
        return byDigest.GetValueOrDefault(d);
    }

    /// <summary>RFC 9901 s7.1 payload processing (resolve <c>_sd</c> digests and <c>{"...": digest}</c> array elements).</summary>
    static (D Processed, D DisclosedTop) ProcessDisclosures(D payload, Dictionary<string, DecodedDisclosure> byDigest)
    {
        var seen = new HashSet<string>();
        var disclosedTop = new D();
        if (Walk(payload, true, byDigest, seen, disclosedTop) is not D p) throw new SdJwtProcessingError("payload is not an object");
        p.Remove("_sd_alg");
        foreach (var d in byDigest.Values)
            if (!d.Used) throw new SdJwtProcessingError("a presented disclosure is not referenced by any digest in the payload");
        return (p, disclosedTop);
    }

    static object? Walk(object? node, bool top, Dictionary<string, DecodedDisclosure> byDigest, HashSet<string> seen, D disclosedTop)
    {
        if (node is L list)
        {
            var o = new L();
            foreach (var el in list)
            {
                if (el is D em && em.Count == 1 && em.ContainsKey("..."))
                {
                    if (em["..."] is not string digest) throw new SdJwtProcessingError("an array '...' entry must reference a string digest");
                    var d = ClaimDigest(digest, byDigest, seen);
                    if (d == null) continue; // undisclosed element or decoy: removed
                    if (d.Parts.Count != 2) throw new SdJwtProcessingError("an array-element disclosure must be [salt, value]");
                    d.Used = true;
                    o.Add(Walk(d.Parts[1], false, byDigest, seen, disclosedTop));
                }
                else o.Add(Walk(el, false, byDigest, seen, disclosedTop));
            }
            return o;
        }
        if (node is D nm)
        {
            var o = new D();
            foreach (var key in IntentJs.JsKeys(nm.Keys))
            {
                if (key == "_sd") continue;
                o[key] = Walk(nm[key], false, byDigest, seen, disclosedTop);
            }
            if (nm.TryGetValue("_sd", out var sd))
            {
                if (sd is not L sdl || !sdl.All(x => x is string)) throw new SdJwtProcessingError("_sd must be an array of strings");
                foreach (string digest in sdl)
                {
                    var d = ClaimDigest(digest, byDigest, seen);
                    if (d == null) continue; // decoy or undisclosed claim
                    if (d.Parts.Count != 3) throw new SdJwtProcessingError("an object-property disclosure must be [salt, name, value]");
                    if (d.Parts[1] is not string n) throw new SdJwtProcessingError("disclosure claim name must be a string");
                    if (n == "_sd" || n == "...") throw new SdJwtProcessingError($"disclosure claim name '{n}' is reserved");
                    if (o.ContainsKey(n)) throw new SdJwtProcessingError($"disclosure claim '{n}' collides with an existing claim");
                    if (top && CriticalClaims.Contains(n)) throw new SdJwtProcessingError($"'{n}' is security-critical and must not be selectively disclosable");
                    d.Used = true;
                    var value = Walk(d.Parts[2], false, byDigest, seen, disclosedTop);
                    o[n] = value;
                    if (top) disclosedTop[n] = value;
                }
            }
            return o;
        }
        return node;
    }

    static D Fail(string reason) => new() { ["ok"] = false, ["reason"] = reason };

    static readonly Regex Secs = new(@"^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>The JOSE library's time-period parser (a clock tolerance given as text, e.g. "10 seconds").</summary>
    static double ParseSecs(string str)
    {
        var m = Secs.Match(str);
        if (!m.Success || (m.Groups[4].Success && m.Groups[1].Success)) throw new JoseException("ERR_JOSE_GENERIC", "Invalid time period format");
        double value = double.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture);
        double n = m.Groups[3].Value.ToLowerInvariant() switch
        {
            "sec" or "secs" or "second" or "seconds" or "s" => Math.Round(value, MidpointRounding.AwayFromZero),
            "minute" or "minutes" or "min" or "mins" or "m" => Math.Round(value * 60, MidpointRounding.AwayFromZero),
            "hour" or "hours" or "hr" or "hrs" or "h" => Math.Round(value * 3600, MidpointRounding.AwayFromZero),
            "day" or "days" or "d" => Math.Round(value * 86400, MidpointRounding.AwayFromZero),
            "week" or "weeks" or "w" => Math.Round(value * 604800, MidpointRounding.AwayFromZero),
            _ => Math.Round(value * 31557600, MidpointRounding.AwayFromZero),
        };
        return m.Groups[1].Value == "-" || m.Groups[4].Value.Equals("ago", StringComparison.OrdinalIgnoreCase) ? -n : n;
    }

    /// <summary>The JWT options of an issuer or KB verification (<paramref name="hasAud"/>: whether an audience option was given at all, then its value).</summary>
    static JwtVerifyOptions JwtOptions(D options, bool hasAud, object? audValue, IReadOnlyCollection<string> algs)
    {
        string? audString = null; List<string>? audList = null;
        if (hasAud)
        {
            if (audValue is string s) audString = s;
            else if (audValue is L l) audList = l.Select(x => x as string ?? "\0not-a-string").ToList();
            else if (!Truthy(audValue)) audString = ""; // presence is required, the value is not compared
            else audString = "\0never"; // a truthy non-string, non-list option never matches
        }
        double? nowMs = null;
        if (options.ContainsKey("now"))
        {
            var nw = options["now"];
            nowMs = nw == null ? 0 : NumOf(nw) ?? double.NaN;
        }
        double? tol = null;
        if (options.ContainsKey("clockToleranceSec"))
        {
            var t = options["clockToleranceSec"];
            if (t is string ts) tol = ParseSecs(ts);
            else if (NumOf(t) is double td) tol = td;
            else throw new JoseTypeError("Invalid clockTolerance option type");
        }
        return new JwtVerifyOptions { Algorithms = algs, AudienceString = audString, AudienceList = audList, CurrentDateMs = nowMs, ClockTolerance = tol };
    }

    static List<string> AlgorithmList(object? v, string dflt)
    {
        if (v == null) return new List<string> { dflt };
        if (v is not L l) throw new JoseTypeError("\"algorithms\" option must be an array of strings");
        var o = new List<string>();
        foreach (var x in l)
        {
            if (x is not string s) throw new JoseTypeError("\"algorithms\" option must be an array of strings");
            o.Add(s);
        }
        return o;
    }

    static string? ThumbX(object? k)
    {
        if (k is byte[] b) return Pca.B64u(b);
        if (k is JoseKey jk) return jk.ExportJwk().GetValueOrDefault("x") as string;
        if (IsJwk(k)) return ((D)k!).GetValueOrDefault("x") as string;
        throw new JoseTypeError("Invalid key input");
    }

    /// <summary>Verifies a PCA SD-JWT, FAIL-CLOSED. Options: <c>issuerKey</c> (a public JoseKey / JWK, required), <c>requiredDisclosures</c>, <c>expectedAudience</c>,
    /// <c>keyBindingKey</c> (JoseKey, JWK or raw bytes; requires a KB-JWT bound to it), <c>expectedKbAudience</c>, <c>expectedNonce</c>, <c>requireKeyBinding</c>,
    /// <c>algorithms</c> (default EdDSA), <c>kbAlgorithms</c>, <c>now</c> (ms), <c>kbMaxAgeSec</c>, <c>clockToleranceSec</c>. Returns <c>{ok:true, payload, processed,
    /// protectedHeader, disclosed, claims, keyBinding}</c> or <c>{ok:false, reason}</c>.</summary>
    public static D VerifyPcaSdJwt(object? sdjwt, D options)
    {
        try
        {
            // a non-finite clock, tolerance or window would slip past the date checks (every comparison with NaN is false, and -Infinity is "before" every expiry)
            foreach (var optKey in new[] { "now", "clockToleranceSec", "kbMaxAgeSec" })
                if (options.TryGetValue(optKey, out var optVal) && !(NumOf(optVal) is double optNum && double.IsFinite(optNum))) return Fail("now, clockToleranceSec and kbMaxAgeSec must be finite");
            // a time beyond +-8.64e15 ms is an invalid Date, which the JOSE layer reads as no clock at all: it is refused like a non-finite one
            if (options.TryGetValue("now", out var nowOpt) && !(Math.Abs(NumOf(nowOpt) ?? double.NaN) <= 8.64e15)) return Fail("now is not a representable time");
            var parsed = ParseSdJwt(sdjwt);
            var algorithms = AlgorithmList(options.GetValueOrDefault("algorithms"), DefaultSigningAlg);
            var verified = J.JwtVerify(parsed.Jwt, options.GetValueOrDefault("issuerKey"),
                JwtOptions(options, options.ContainsKey("expectedAudience"), options.GetValueOrDefault("expectedAudience"), algorithms));
            var payload = verified.Payload;
            var protectedHeader = verified.ProtectedHeader;

            // _sd / Disclosure matching (RFC 9901 s7.1), recursive over nested objects and arrays; _sd_alg defaults to sha-256 when absent, any other value is unsupported
            if (payload.ContainsKey("_sd_alg") && !(payload["_sd_alg"] is string sa && sa == SdAlg)) return Fail($"unsupported _sd_alg (require \"{SdAlg}\")");
            var byDigest = new Dictionary<string, DecodedDisclosure>();
            foreach (var encoded in parsed.Disclosures)
            {
                var digest = Sha256b64u(encoded);
                if (byDigest.ContainsKey(digest)) return Fail("duplicate disclosure");
                byDigest[digest] = new DecodedDisclosure(DecodeDisclosureParts(encoded));
            }
            D processedPayload, disclosed;
            try { (processedPayload, disclosed) = ProcessDisclosures(payload, byDigest); }
            catch (SdJwtProcessingError e)
            {
                bool unmatched = e.Message.Contains("not referenced", StringComparison.Ordinal);
                return Fail(unmatched ? "a presented disclosure does not match any _sd digest (tampered)" : e.Message);
            }

            var req = options.GetValueOrDefault("requiredDisclosures");
            if (req != null)
            {
                var names = new List<object?>();
                if (req is L rl) names.AddRange(rl);
                else if (req is string rs) { foreach (var c in rs) names.Add(c.ToString()); }
                else throw new InvalidOperationException("requiredDisclosures is not iterable");
                foreach (var required in names)
                {
                    var key = required as string ?? JsStr(required);
                    if (!disclosed.ContainsKey(key)) return Fail($"required disclosure '{key}' was not presented");
                }
            }

            // key binding
            var cnfJwk = payload.GetValueOrDefault("cnf") is D cnf && IsJwk(cnf.GetValueOrDefault("jwk")) ? (D)cnf["jwk"]! : null;
            var keyBinding = new D { ["presented"] = parsed.KbJwt != null, ["verified"] = false };

            if (parsed.KbJwt != null)
            {
                if (cnfJwk == null) return Fail("KB-JWT presented but issuer JWT has no cnf key");
                if (options.ContainsKey("keyBindingKey"))
                {
                    var want = ThumbX(options["keyBindingKey"]); var have = ThumbX(cnfJwk);
                    if (want == null || have == null || want != have) return Fail("cnf key does not match the expected keyBindingKey");
                }
                var kbAlgs = AlgorithmList(options.GetValueOrDefault("kbAlgorithms"), DefaultSigningAlg);
                var kbKey = J.ImportJwk(cnfJwk, kbAlgs.Count > 0 ? kbAlgs[0] : DefaultSigningAlg); // import errors are the outer refusal, as in the reference
                JwtResult kb;
                try
                {
                    var kbAud = options.GetValueOrDefault("expectedKbAudience");
                    var aud = kbAud ?? options.GetValueOrDefault("expectedAudience");
                    bool hasAud = kbAud != null || options.ContainsKey("expectedAudience");
                    kb = J.JwtVerify(parsed.KbJwt, kbKey, JwtOptions(options, hasAud, aud, kbAlgs));
                }
                catch (Exception e) { return Fail("KB-JWT signature/claims invalid: " + e.Message); }
                if (kb.ProtectedHeader.GetValueOrDefault("typ") is not KbJwtTyp) return Fail($"KB-JWT typ must be \"{KbJwtTyp}\"");
                if (NumOf(kb.Payload.GetValueOrDefault("iat")) is not double kbIat) return Fail("KB-JWT iat is required");
                if (options.ContainsKey("kbMaxAgeSec"))
                {
                    var nw = options.GetValueOrDefault("now");
                    double nowMs = nw != null ? ToNumber(nw) : AtlasPca.ReplayClock.NowMs();
                    double nowSec = Math.Floor(nowMs / 1000);
                    if (!double.IsFinite(kbIat)) return Fail("KB-JWT iat is not a finite number");
                    if (!(nowSec - kbIat <= ToNumber(options["kbMaxAgeSec"]))) return Fail("KB-JWT is older than the accepted window");
                    var tol = options.GetValueOrDefault("clockToleranceSec");
                    if (!(kbIat - nowSec <= (tol != null ? ToNumber(tol) : 0))) return Fail("KB-JWT iat is in the future");
                }
                var kbAudClaim = kb.Payload.GetValueOrDefault("aud");
                if (kbAudClaim is not (string or L)) return Fail("KB-JWT aud is required");
                if (!(kb.Payload.GetValueOrDefault("sd_hash") is string sh && sh == Sha256b64u(parsed.PresentationHead))) return Fail("KB-JWT sd_hash does not cover this presentation");
                if (options.ContainsKey("expectedNonce"))
                {
                    if (!(kb.Payload.ContainsKey("nonce") && SameJs(kb.Payload["nonce"], options["expectedNonce"]))) return Fail("KB-JWT nonce does not match");
                }
                keyBinding["verified"] = true;
                if (kbAudClaim is string ka) keyBinding["aud"] = ka;
                if (kb.Payload.GetValueOrDefault("nonce") is string kn) keyBinding["nonce"] = kn;
            }
            else if (options.ContainsKey("keyBindingKey") || Truthy(options.GetValueOrDefault("requireKeyBinding")))
            {
                return Fail("key binding required but no KB-JWT was presented");
            }

            // recovered capability claims = clear (non-reserved) + disclosed, from the Processed SD-JWT Payload
            var claims = new D();
            foreach (var (k, v) in processedPayload) if (!ReservedClaims.Contains(k)) claims[k] = v;
            return new D
            {
                ["ok"] = true, ["payload"] = payload, ["processed"] = processedPayload, ["protectedHeader"] = protectedHeader,
                ["disclosed"] = disclosed, ["claims"] = claims, ["keyBinding"] = keyBinding,
            };
        }
        catch (Exception e) { return Fail(e.Message); }
    }

    static RecoveredResult Deny(string reason) => new(false, reason, new Dictionary<string, bool>());

    /// <summary>Re-verifies a verified SD-JWT with the PCA core: rebuilds the PCActn from the recovered claims and runs the core verification. FAIL-CLOSED: a
    /// withheld required claim, missing or inconsistent iat_ms / exp_ms, or an iss / sub that disagrees with the chain denies. <paramref name="grant"/> is the
    /// verifier's OWN stored grant. <paramref name="audienceGiven"/> with a string must equal the PCActn's aud; given with null is the explicit opt-out
    /// ("accept any audience"); not given fails closed. <paramref name="nowMs"/> null = now.</summary>
    public static RecoveredResult VerifyRecovered(D res, D grant, bool audienceGiven, string? audience, long? nowMs, bool insecureSkipPlanRootCheck)
    {
        var c = (D)res["claims"]!; var p = (D)res["processed"]!;
        var rest = new D(c);
        var iatMs = rest.GetValueOrDefault("iat_ms"); var expMs = rest.GetValueOrDefault("exp_ms");
        rest.Remove("iat_ms"); rest.Remove("exp_ms");
        if (NumOf(iatMs) is not double iatD || NumOf(expMs) is not double expD) return Deny("pca-sdjwt: iat_ms/exp_ms missing; cannot rebuild the PCActn");
        if (!(NumOf(p.GetValueOrDefault("iat")) is double pIat && Math.Floor(iatD / 1000) == pIat)) return Deny("pca-sdjwt: iat_ms disagrees with iat");
        if (!(NumOf(p.GetValueOrDefault("exp")) is double pExp && Math.Max(Math.Ceiling(expD / 1000), Math.Floor(iatD / 1000) + 1) == pExp)) return Deny("pca-sdjwt: exp_ms disagrees with exp");
        foreach (var k in new[] { "action", "cap_chain", "plan", "sig", "grant_ref", "counter" })
            if (!rest.ContainsKey(k)) return Deny($"pca-sdjwt: required claim '{k}' was not disclosed");
        if (p.GetValueOrDefault("aud") is not string pAud) return Deny("pca-sdjwt: aud must be a string");
        if (rest["cap_chain"] is not L { Count: > 0 } cl) return Deny("pca-sdjwt: cap_chain is empty");
        var first = cl[0]; var last = cl[^1];
        if (first == null) throw new InvalidOperationException("Cannot read properties of null (reading 'issuer')");
        if (!SameJs(p.GetValueOrDefault("iss"), (first as D)?.GetValueOrDefault("issuer"))) return Deny("pca-sdjwt: iss does not match the chain root issuer");
        if (last == null) throw new InvalidOperationException("Cannot read properties of null (reading 'holder')");
        if (!SameJs(p.GetValueOrDefault("sub"), (last as D)?.GetValueOrDefault("holder"))) return Deny("pca-sdjwt: sub does not match the chain leaf holder");
        var pcActn = new D(rest);
        if (p.TryGetValue("ver", out var ver)) pcActn["ver"] = ver; else pcActn.Remove("ver");
        pcActn["aud"] = pAud; pcActn["iat"] = iatMs; pcActn["exp"] = expMs;
        try
        {
            // the core takes the audience as a string: "not given" is an audience that cannot match, "given as null" is the PCActn's own (any audience)
            var coreAud = !audienceGiven ? "\0no-audience-supplied" : audience ?? pAud;
            var verdict = Pca.VerifyPcactnCore(pcActn, grant, nowMs ?? AtlasPca.ReplayClock.NowMs(), coreAud,
                planRoots: insecureSkipPlanRootCheck ? PlanRootPolicy.Skip : new PlanRootPolicy());
            return new RecoveredResult(verdict.Allow, verdict.Reason.Length == 0 ? null : verdict.Reason, new Dictionary<string, bool>(verdict.Checks));
        }
        catch (Exception e) { return Deny("pca-sdjwt: core verification threw: " + e.Message); }
    }
}
