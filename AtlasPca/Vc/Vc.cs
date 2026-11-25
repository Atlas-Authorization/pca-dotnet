// W3C Verifiable Credentials for PCA: did:key (Ed25519) with base58btc, the agent-passport credential as an SD-JWT VC, and RFC 9421 HTTP Message
// Signatures with the Web Bot Auth Signature-Agent pattern. Maps onto the reference's pca-vc exports (PascalCase). Arguments and results are the JSON
// tree (a member that is absent differs from one that is JSON null, as in the reference); keys are a 32-byte seed / public key (byte[]), a JWK
// (Dictionary) or a JoseKey. The clock is the `now` argument (epoch ms; default the system clock).
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca;
using AtlasPca.Jose;
using J = AtlasPca.Jose.Jose;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Vc;

public static class Vc
{
    public const string VcContext = "https://www.w3.org/ns/credentials/v2";
    public const string AgentPassportContext = "https://atlasauth.net/credentials/agent-passport/v1";
    public const string AgentPassportVcType = "AgentPassportCredential";
    static readonly string[] SdDigestFields = { "weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement" };

    static double? NumOf(object? o) => J.NumberOf(o);

    static string Sha256b64u(string ascii)
    {
        var b = new byte[ascii.Length];
        for (int i = 0; i < b.Length; i++) b[i] = (byte)ascii[i];
        return Pca.B64u(SHA256.HashData(b));
    }

    static string AsString(object? v, string label) => v as string ?? throw new InvalidOperationException($"pca-vc: expected string for {label}");

    // ===================== base58btc / did:key =====================

    const string B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const int MaxBase58Input = 1024;

    /// <summary>Base58 (Bitcoin alphabet) encoding, as multibase <c>z</c>.</summary>
    public static string Base58btcEncode(byte[] bytes)
    {
        int zeros = 0;
        while (zeros < bytes.Length && bytes[zeros] == 0) zeros++;
        var digits = new List<int>();
        for (int i = zeros; i < bytes.Length; i++)
        {
            int carry = bytes[i];
            for (int j = 0; j < digits.Count; j++)
            {
                carry += digits[j] << 8;
                digits[j] = carry % 58;
                carry /= 58;
            }
            while (carry > 0) { digits.Add(carry % 58); carry /= 58; }
        }
        var sb = new StringBuilder(new string('1', zeros));
        for (int i = digits.Count - 1; i >= 0; i--) sb.Append(B58[digits[i]]);
        return sb.ToString();
    }

    /// <summary>Inverse of <see cref="Base58btcEncode"/>; throws on a character outside the alphabet or an input over 1024 characters.</summary>
    public static byte[] Base58btcDecode(string str)
    {
        if (str.Length > MaxBase58Input) throw new InvalidOperationException("pca-vc: base58btc input too long");
        int zeros = 0;
        while (zeros < str.Length && str[zeros] == '1') zeros++;
        var bytes = new List<int>();
        for (int i = zeros; i < str.Length; i++)
        {
            int carry = B58.IndexOf(str[i]);
            if (carry < 0) throw new InvalidOperationException("pca-vc: invalid base58btc character");
            for (int j = 0; j < bytes.Count; j++)
            {
                carry += bytes[j] * 58;
                bytes[j] = carry & 0xff;
                carry >>= 8;
            }
            while (carry > 0) { bytes.Add(carry & 0xff); carry >>= 8; }
        }
        var o = new byte[zeros + bytes.Count];
        for (int i = 0; i < bytes.Count; i++) o[zeros + bytes.Count - 1 - i] = (byte)bytes[i];
        return o;
    }

    /// <summary>A <c>did:key</c> identifier for an Ed25519 public key (32 raw bytes).</summary>
    public static string DidKeyFromEd25519(byte[] publicKey)
    {
        if (publicKey.Length != 32) throw new InvalidOperationException("pca-vc: Ed25519 public key must be 32 bytes");
        var mc = new byte[34];
        mc[0] = 0xed; mc[1] = 0x01;
        Buffer.BlockCopy(publicKey, 0, mc, 2, 32);
        return "did:key:z" + Base58btcEncode(mc);
    }

    /// <summary>The 32-byte Ed25519 public key of an Ed25519 <c>did:key</c>. Inverse of <see cref="DidKeyFromEd25519"/>.</summary>
    public static byte[] Ed25519FromDidKey(string did)
    {
        const string prefix = "did:key:z";
        if (!did.StartsWith(prefix, StringComparison.Ordinal)) throw new InvalidOperationException("pca-vc: not a did:key:z… identifier");
        if (did.Length > prefix.Length + 64) throw new InvalidOperationException("pca-vc: did:key is not an Ed25519 (0xed01) key");
        var mc = Base58btcDecode(did[prefix.Length..]);
        if (mc.Length != 34 || mc[0] != 0xed || mc[1] != 0x01) throw new InvalidOperationException("pca-vc: did:key is not an Ed25519 (0xed01) key");
        return mc[2..];
    }

    // ===================== bundled JSON-LD context =====================

    const string V = "https://atlasauth.net/credentials/agent-passport/v1#";
    const string Xsd = "http://www.w3.org/2001/XMLSchema#";
    static D Term(string id, string type) => new() { ["@id"] = V + id, ["@type"] = Xsd + type };

    /// <summary>The JSON-LD context for AgentPassportCredential, bundled so a verifier resolves it offline. Terms are protected. Do not mutate.</summary>
    public static readonly D AgentPassportContextDoc = BuildContext();

    static D BuildContext()
    {
        var inner = new D
        {
            ["@protected"] = true, ["id"] = "@id", ["type"] = "@type",
            ["passport_id"] = Term("passportId", "string"), ["model_id"] = Term("modelId", "string"), ["operator"] = Term("operator", "string"),
            ["hardware_rooted"] = Term("hardwareRooted", "boolean"), ["weights_measured"] = Term("weightsMeasured", "boolean"), ["issued_at"] = Term("issuedAt", "integer"),
            ["weights_digest"] = Term("weightsDigest", "string"), ["system_prompt_digest"] = Term("systemPromptDigest", "string"),
            ["tool_manifest_digest"] = Term("toolManifestDigest", "string"), ["runtime_measurement"] = Term("runtimeMeasurement", "string"),
            ["_sd"] = new D { ["@id"] = V + "selectiveDisclosureDigest", ["@container"] = "@set" },
        };
        var cred = new D { ["@id"] = V + "AgentPassportCredential", ["@context"] = inner };
        return new D { ["@context"] = new D { ["@protected"] = true, ["AgentPassportCredential"] = cred } };
    }

    /// <summary>SHA-256 (hex) of the key-sorted JSON of <see cref="AgentPassportContextDoc"/>; changes whenever any term changes.</summary>
    public static readonly string AgentPassportContextDigest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Pca.Canonicalize(AgentPassportContextDoc)))).ToLowerInvariant();

    /// <summary>A document loader for JSON-LD processors: the bundled document for its IRI, null for anything else (never fetched).</summary>
    public static D? ResolveAgentPassportContext(object? iri) => iri is string s && s == AgentPassportContext ? AgentPassportContextDoc : null;

    // ===================== key plumbing =====================

    /// <summary>A signing key: a 32-byte seed, a private JWK or a private JoseKey.</summary>
    static object PrivateKey(object? key)
    {
        if (key is byte[] seed)
        {
            if (seed.Length != 32) throw new AtlasPca.Grants.CodedException("ERR_OSSL_ASN1_NOT_ENOUGH_DATA", "error:0680008E:asn1 encoding routines::not enough data");
            return J.Ed25519SeedJwk(seed);
        }
        return (key is D or JoseKey) ? key! : throw new InvalidOperationException("pca-vc: not a signing key");
    }

    /// <summary>A verification key: a 32-byte public key (imported as a key object) or a JWK / JoseKey.</summary>
    static object PublicKey(object? key)
    {
        if (key is byte[] raw)
        {
            if (raw.Length != 32) throw new InvalidOperationException("pca-vc: Ed25519 public key must be 32 bytes");
            return J.ImportJwk(J.Ed25519PublicJwk(raw), "EdDSA");
        }
        return (key is D or JoseKey) ? key! : throw new InvalidOperationException("pca-vc: not a verification key");
    }

    // ===================== W3C VC 2.0 as an SD-JWT VC =====================

    /// <summary>Emits an AgentPassport (a dictionary) as a W3C VC 2.0 secured as an SD-JWT VC (EdDSA): <c>&lt;jwt&gt;~&lt;disclosure&gt;~...~</c>. The credential
    /// subject carries a salted hash of each present passport digest in <c>_sd</c>; the model id, operator, hardware flag and passport id stay in the clear.
    /// Options: <c>issuerKey</c> (32-byte seed / private JWK), <c>issuerDid</c>, <c>subjectDid</c>, <c>ttlSec</c> (null counts as 0), <c>now</c> (ms).</summary>
    public static string PassportToVC(D passport, D args)
    {
        var disclosures = new List<string>();
        var sd = new L();
        foreach (var field in SdDigestFields)
        {
            if (!passport.ContainsKey(field)) continue;
            var salt = Pca.B64u(RandomNumberGenerator.GetBytes(16));
            var disclosure = Pca.B64u(J.Utf8(J.Stringify(new L { salt, field, passport[field] })));
            disclosures.Add(disclosure);
            sd.Add(Sha256b64u(disclosure));
        }
        var cs = new D();
        if (args.ContainsKey("subjectDid")) cs["id"] = args["subjectDid"];
        foreach (var k in new[] { "id", "model_id", "operator", "hardware_rooted", "issued_at" })
            if (passport.ContainsKey(k)) cs[k == "id" ? "passport_id" : k] = passport[k];
        if (passport.ContainsKey("weights_measured")) cs["weights_measured"] = passport["weights_measured"];
        if (sd.Count > 0) cs["_sd"] = sd;

        var vc = new D
        {
            ["@context"] = new L { VcContext, AgentPassportContext },
            ["type"] = new L { "VerifiableCredential", AgentPassportVcType },
            ["credentialSubject"] = cs,
        };
        double nowMs = args.GetValueOrDefault("now") is { } nw ? NumOf(nw) ?? double.NaN : AtlasPca.ReplayClock.NowMs();
        double now = Math.Floor(nowMs / 1000);
        var payload = new D { ["vc"] = vc };
        if (sd.Count > 0) payload["_sd_alg"] = "sha-256";
        if (args.ContainsKey("issuerDid")) payload["iss"] = args["issuerDid"];
        if (args.ContainsKey("subjectDid")) payload["sub"] = args["subjectDid"];
        payload["iat"] = now;
        if (args.ContainsKey("ttlSec"))
        {
            var t = args["ttlSec"];
            double ttl = t == null ? 0 : t is bool tb ? (tb ? 1 : 0) : NumOf(t) ?? throw new JoseException("ERR_JOSE_GENERIC", "Invalid time period format");
            payload["exp"] = now + ttl;
        }
        var header = new D { ["alg"] = "EdDSA", ["typ"] = "vc+sd-jwt" };
        var jwt = J.SignJwt(header, payload, PrivateKey(args.GetValueOrDefault("issuerKey")));
        var sb = new StringBuilder(jwt).Append('~');
        foreach (var d in disclosures) sb.Append(d).Append('~');
        return sb.ToString();
    }

    /// <summary>Verifies an SD-JWT VC produced by <see cref="PassportToVC"/> and reconstructs the passport: <c>{passport, issuerDid, subjectDid}</c>. The
    /// signature is checked under <paramref name="issuerVerifyKey"/> (EdDSA only); every presented disclosure must hash to a digest in
    /// <c>credentialSubject._sd</c>. Options: <c>expectedIssuerDid</c>, <c>now</c> (ms). Throws on any failure.</summary>
    public static D VerifyPassportVC(object? vcO, object? issuerVerifyKey, D? options = null)
    {
        if (vcO is not string vcs) throw new InvalidOperationException("vc.split is not a function");
        var parts = vcs.Split('~');
        var jwt = parts[0];
        if (jwt.Length == 0) throw new InvalidOperationException("pca-vc: empty SD-JWT");
        var disclosures = parts.Skip(1).Where(p => p.Length > 0).ToList();
        // canonical-spelling gate BEFORE the JOSE layer: one accepted string form per JWT-VC / disclosure
        J.AssertCanonicalCompactJws(jwt);
        foreach (var d in disclosures) J.DecodeCanonicalBase64Url(d);

        // pin the algorithm: a raw-bytes key must never be accepted as an HMAC secret (algorithm confusion)
        double? nowMs = options?.GetValueOrDefault("now") is { } n ? NumOf(n) : null;
        var res = J.JwtVerify(jwt, PublicKey(issuerVerifyKey), new JwtVerifyOptions { Algorithms = new[] { "EdDSA" }, CurrentDateMs = nowMs });
        var payload = res.Payload;
        if (res.ProtectedHeader.GetValueOrDefault("typ") is not "vc+sd-jwt") throw new InvalidOperationException("pca-vc: header typ must be 'vc+sd-jwt'");
        if (payload.GetValueOrDefault("vc") is not D vcClaim) throw new InvalidOperationException("pca-vc: missing vc claim");
        if (vcClaim.GetValueOrDefault("@context") is not L { Count: > 0 } ctx || ctx[0] is not VcContext) throw new InvalidOperationException($"pca-vc: @context must begin with {VcContext}");
        // exactly the two contexts this package defines terms for: an extra or unknown context could redefine the passport terms
        if (ctx.Count != 2 || ctx[1] is not AgentPassportContext) throw new InvalidOperationException($"pca-vc: @context must be exactly [{VcContext}, {AgentPassportContext}]");
        if (vcClaim.GetValueOrDefault("type") is not L types || !types.Contains("VerifiableCredential") || !types.Contains(AgentPassportVcType))
            throw new InvalidOperationException($"pca-vc: type must include VerifiableCredential and {AgentPassportVcType}");
        if (vcClaim.GetValueOrDefault("credentialSubject") is not D cs) throw new InvalidOperationException("pca-vc: missing credentialSubject");
        if (cs.ContainsKey("_sd_alg")) throw new InvalidOperationException("pca-vc: _sd_alg must be a top-level claim");
        if (payload.ContainsKey("_sd_alg") && payload["_sd_alg"] is not "sha-256") throw new InvalidOperationException("pca-vc: unsupported _sd_alg (require sha-256)");

        var sdList = (cs.GetValueOrDefault("_sd") as L)?.OfType<string>().ToList() ?? new List<string>();
        var recovered = new Dictionary<string, string>();
        var seen = new HashSet<string>();
        foreach (var disclosure in disclosures)
        {
            var digest = Sha256b64u(disclosure);
            if (!sdList.Contains(digest)) throw new InvalidOperationException("pca-vc: disclosure does not match any _sd digest");
            if (!seen.Add(digest)) throw new InvalidOperationException("pca-vc: duplicate disclosure");
            object? decoded;
            try { decoded = NoDuplicateKeys.Parse(Encoding.UTF8.GetString(J.DecodeB64Lenient(disclosure))); } // a duplicate member is refused
            catch (Exception) { throw new InvalidOperationException("pca-vc: malformed disclosure"); }
            if (decoded is not L { Count: 3 } dl) throw new InvalidOperationException("pca-vc: malformed disclosure");
            var name = AsString(dl[1], "disclosure name");
            if (!SdDigestFields.Contains(name)) throw new InvalidOperationException($"pca-vc: unexpected disclosure claim '{name}'");
            if (recovered.ContainsKey(name)) throw new InvalidOperationException($"pca-vc: disclosure claim '{name}' appears more than once");
            recovered[name] = AsString(dl[2], "disclosure value");
        }

        var passport = new D
        {
            ["id"] = AsString(cs.GetValueOrDefault("passport_id"), "passport_id"),
            ["model_id"] = AsString(cs.GetValueOrDefault("model_id"), "model_id"),
            ["operator"] = AsString(cs.GetValueOrDefault("operator"), "operator"),
        };
        if (cs.GetValueOrDefault("hardware_rooted") is not bool) throw new InvalidOperationException("pca-vc: expected boolean for hardware_rooted");
        passport["hardware_rooted"] = cs["hardware_rooted"];
        if (NumOf(cs.GetValueOrDefault("issued_at")) == null) throw new InvalidOperationException("pca-vc: expected number for issued_at");
        passport["issued_at"] = cs["issued_at"];
        if (cs.ContainsKey("weights_measured"))
        {
            if (cs["weights_measured"] is not bool) throw new InvalidOperationException("pca-vc: expected boolean for weights_measured");
            passport["weights_measured"] = cs["weights_measured"];
        }
        foreach (var field in SdDigestFields) if (recovered.TryGetValue(field, out var rv)) passport[field] = rv;

        var issuerDid = AsString(payload.GetValueOrDefault("iss"), "iss");
        var subjectDid = AsString(cs.GetValueOrDefault("id"), "credentialSubject.id");
        // the JWT sub and the VC subject id are the same identity; a disagreement is a malformed or spliced credential
        if (!(payload.GetValueOrDefault("sub") is string sub && sub == subjectDid)) throw new InvalidOperationException("pca-vc: sub does not match credentialSubject.id");
        // the verification key is the caller's; binding it to the claimed issuer is theirs unless they pin the DID here
        if (options != null && options.ContainsKey("expectedIssuerDid") && !(options["expectedIssuerDid"] is string ex && ex == issuerDid))
            throw new InvalidOperationException("pca-vc: iss does not match expectedIssuerDid");
        return new D { ["passport"] = passport, ["issuerDid"] = issuerDid, ["subjectDid"] = subjectDid };
    }

    // ===================== RFC 9421 HTTP Message Signatures + Web Bot Auth =====================

    const string SigLabel = "sig1";
    /// <summary>JavaScript's whitespace set (String.prototype.trim and the regex \s).</summary>
    const string WsClass = "[\\u0009-\\u000d\\u0020\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff]";
    static readonly char[] WsChars = { '\t', '\n', '\v', '\f', '\r', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '\u2028', '\u2029', ' ', ' ', '　', '﻿' };
    static string JsTrim(string s) => s.Trim(WsChars);

    /// <summary>JavaScript String(v) of a parsed JSON value (template-literal interpolation).</summary>
    static string JsString(object? v) => v switch
    {
        null => "null",
        string s => s,
        bool b => b ? "true" : "false",
        Num n => double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var nd) ? AtlasPca.Js.JsJson.NumberToString(nd) : n.Raw,
        double d => AtlasPca.Js.JsJson.NumberToString(d),
        L l => string.Join(",", l.Select(x => x == null ? "" : JsString(x))),
        _ => "[object Object]",
    };

    /// <summary>Lower-case header keys; a later duplicate wins.</summary>
    static Dictionary<string, string?> NormalizeHeaders(object? headers)
    {
        if (headers is not D h) throw new InvalidOperationException("Cannot convert undefined or null to object");
        var o = new Dictionary<string, string?>();
        foreach (var k in IntentJs.JsKeys(h.Keys)) o[k.ToLowerInvariant()] = h[k] as string; // a non-string value only fails when the header is covered, which every normalized header is
        return o;
    }

    static string ComponentValue(string name, string method, string url, Dictionary<string, string?> headers)
    {
        if (name == "@method") return method.ToUpperInvariant();
        if (name == "@target-uri") return url;
        if (name == "@authority") return WhatwgUrl.Require(url).Host;
        if (!headers.TryGetValue(name, out var v) || v == null) throw new InvalidOperationException($"pca-vc: covered header '{name}' absent from request");
        return JsTrim(v);
    }

    static string SignatureBase(List<string> components, string sigParamsValue, string method, string url, Dictionary<string, string?> headers)
    {
        var lines = components.Select(c => $"\"{c}\": {ComponentValue(c, method, url, headers)}").ToList();
        lines.Add($"\"@signature-params\": {sigParamsValue}");
        return string.Join("\n", lines);
    }

    /// <summary>Signs an HTTP request per RFC 9421 (EdDSA) with the Web Bot Auth Signature-Agent pattern. <paramref name="args"/>: <c>method</c>, <c>url</c>,
    /// <c>headers</c> (dictionary), <c>key</c> (32-byte seed / private JWK), <c>keyid</c>, <c>created</c> (null / absent = now), <c>signatureAgent</c> (present, even
    /// null, adds the agent header, the covered component and the web-bot-auth tag), <c>now</c> (ms). Returns <c>{signatureInput, signature, signatureAgent?}</c>.</summary>
    public static D SignRequestMessage(D args)
    {
        var method = args.GetValueOrDefault("method") as string ?? throw new InvalidOperationException("method.toUpperCase is not a function");
        var url = args.GetValueOrDefault("url") as string ?? throw new InvalidOperationException("Invalid URL");
        double nowMs = args.GetValueOrDefault("now") is { } nw ? NumOf(nw) ?? double.NaN : AtlasPca.ReplayClock.NowMs();
        var createdO = args.GetValueOrDefault("created");
        var created = createdO != null ? JsString(createdO) : JsString(Math.Floor(nowMs / 1000));
        var headers = NormalizeHeaders(args.GetValueOrDefault("headers"));
        if (!headers.ContainsKey("host")) headers["host"] = WhatwgUrl.Require(url).Host;
        bool agent = args.ContainsKey("signatureAgent");
        if (agent) headers["signature-agent"] = $"\"{JsString(args["signatureAgent"])}\"";
        var components = new List<string> { "@method", "@target-uri" };
        var names = headers.Keys.ToList();
        names.Sort(StringComparer.Ordinal);
        components.AddRange(names);
        var inner = "(" + string.Join(" ", components.Select(c => $"\"{c}\"")) + ")";
        var prms = $";created={created};keyid=\"{JsString(args.GetValueOrDefault("keyid"))}\";alg=\"ed25519\"";
        if (agent) prms += ";tag=\"web-bot-auth\"";
        var sigParamsValue = inner + prms;
        var baseStr = SignatureBase(components, sigParamsValue, method, url, headers);
        var sig = J.SignRaw("EdDSA", PrivateKey(args.GetValueOrDefault("key")), J.Utf8(baseStr));
        var result = new D { ["signatureInput"] = $"{SigLabel}={sigParamsValue}", ["signature"] = $"{SigLabel}=:{Convert.ToBase64String(sig)}:" };
        if (agent) result["signatureAgent"] = $"\"{JsString(args["signatureAgent"])}\"";
        return result;
    }

    static List<string> ParseComponents(string sigParamsValue)
    {
        int open = sigParamsValue.IndexOf('('), close = sigParamsValue.IndexOf(')');
        if (open != 0 || close < 0) throw new InvalidOperationException("pca-vc: malformed @signature-params");
        var inner = JsTrim(sigParamsValue.Substring(open + 1, close - open - 1));
        var o = new List<string>();
        if (inner.Length == 0) return o;
        foreach (var tok in Regex.Split(inner, WsClass + "+"))
        {
            var m = Regex.Match(tok, "^\"(.*)\"\\z", RegexOptions.CultureInvariant);
            if (!m.Success) throw new InvalidOperationException("pca-vc: malformed component identifier");
            o.Add(m.Groups[1].Value);
        }
        return o;
    }

    static double ToNumber(object? v)
    {
        if (v == null) return 0;
        if (NumOf(v) is double d) return d;
        if (v is bool b) return b ? 1 : 0;
        if (v is string s)
        {
            var t = JsTrim(s);
            if (t.Length == 0) return 0;
            return double.TryParse(t, NumberStyles.Float, CultureInfo.InvariantCulture, out var r) ? r : double.NaN;
        }
        return double.NaN;
    }

    /// <summary>Node-style lenient base64 (either alphabet, optional padding, stops at the first '=').</summary>
    static byte[] NodeBase64(string s)
    {
        int eq = s.IndexOf('=');
        var t = (eq >= 0 ? s[..eq] : s).Replace('-', '+').Replace('_', '/');
        if (!Regex.IsMatch(t, "^[A-Za-z0-9+/]*$") || t.Length % 4 == 1) return Array.Empty<byte>();
        var sb = new StringBuilder(t);
        while (sb.Length % 4 != 0) sb.Append('=');
        return Convert.FromBase64String(sb.ToString());
    }

    /// <summary>Verifies an RFC 9421 signature produced by <see cref="SignRequestMessage"/>. <paramref name="args"/>: <c>method</c>, <c>url</c>, <c>headers</c>,
    /// <c>signatureInput</c>, <c>signature</c>, <c>signatureAgent</c>, <c>requiredComponents</c>, <c>maxAgeSec</c>, <c>nowSec</c>, <c>now</c> (ms; the clock when
    /// <c>nowSec</c> is absent). False on any mismatch.</summary>
    public static bool VerifyRequestSignature(D args, object? verifyKey)
    {
        try
        {
            var signatureInput = (string)args["signatureInput"]!;
            int eq = signatureInput.IndexOf('=');
            if (eq < 0) return false;
            var sigParamsValue = signatureInput[(eq + 1)..];
            var components = ParseComponents(sigParamsValue);
            if (args.GetValueOrDefault("requiredComponents") is { } req)
                foreach (var need in (L)req) if (!(need is string ns && components.Contains(ns))) return false;
            var algParam = Regex.Match(sigParamsValue, ";alg=\"([^\"]*)\"");
            if (algParam.Success && algParam.Groups[1].Value != "ed25519") return false;
            if (args.ContainsKey("maxAgeSec"))
            {
                var created = Regex.Match(sigParamsValue, ";created=(\\d+)");
                if (!created.Success) return false;
                double now = args.GetValueOrDefault("nowSec") != null
                    ? NumOf(args["nowSec"]) ?? throw new InvalidOperationException("nowSec")
                    : Math.Floor((args.GetValueOrDefault("now") != null ? NumOf(args["now"])!.Value : AtlasPca.ReplayClock.NowMs()) / 1000);
                double c = double.Parse(created.Groups[1].Value, CultureInfo.InvariantCulture);
                if (!double.IsFinite(now) || !double.IsFinite(c) || !(now - c <= ToNumber(args["maxAgeSec"])) || !(c - now <= 5)) return false;
            }
            var url = (string)args["url"]!;
            var headers = NormalizeHeaders(args.GetValueOrDefault("headers"));
            if (!headers.ContainsKey("host")) headers["host"] = WhatwgUrl.Require(url).Host;
            if (components.Contains("signature-agent") && !headers.ContainsKey("signature-agent"))
            {
                if (args.GetValueOrDefault("signatureAgent") is not string sa) return false; // absent: refused; a non-string value fails when the header is read
                headers["signature-agent"] = sa;
            }
            var baseStr = SignatureBase(components, sigParamsValue, (string)args["method"]!, url, headers);
            var signature = (string)args["signature"]!;
            int sigEq = signature.IndexOf('=');
            if (sigEq < 0) return false;
            var wrapped = JsTrim(signature[(sigEq + 1)..]);
            var m = Regex.Match(wrapped, "^:(.*):\\z", RegexOptions.CultureInvariant);
            if (!m.Success) return false;
            return J.VerifyWith("EdDSA", PublicKey(verifyKey), NodeBase64(m.Groups[1].Value), J.Utf8(baseStr));
        }
        catch (Exception) { return false; }
    }
}
