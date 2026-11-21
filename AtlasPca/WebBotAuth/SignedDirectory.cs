using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using J = AtlasPca.Jose.Jose;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.WebBotAuth;

/// <summary>Signed key-directory responses (draft-meunier-http-message-signatures-directory section 5.2): the directory body is signed with RFC 9421, covering
/// <c>"@authority";req</c>, <c>tag="http-message-signatures-directory"</c>, <c>alg="ed25519"</c>, a <c>keyid</c> that is the RFC 7638 thumbprint of the signing key,
/// with <c>created</c> and <c>expires</c>. One signature per key; a client keeps only the keys that have a valid one.</summary>
public static class SignedDirectory
{
    public const string DirectorySignatureTag = "http-message-signatures-directory";
    const double DefaultLifetimeSec = 86_400;

    static Regex XRe => WbaJs.R(@"^[A-Za-z0-9_\-]{43}\z");
    static Regex AuthorityRe => WbaJs.R(@"^[a-z0-9.\-\[\]:]+\z");
    static Regex EntryRe => WbaJs.R(@"^([a-z][a-z0-9_.*\-]*)=\(""@authority"";req\)((?:;[a-z]+=(?:[0-9]+|""[A-Za-z0-9_.\-]*""))*)\z");
    static Regex SigRe => WbaJs.R(@"^([a-z][a-z0-9_.*\-]*)=:([A-Za-z0-9+/]+={0,2}):\z");
    static Regex DigitsRe => WbaJs.R(@"^[0-9]+\z");

    internal static string ThumbprintOfX(string x) =>
        Pca.B64u(SHA256.HashData(Encoding.UTF8.GetBytes("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + x + "\"}")));

    static bool FiniteNumber(object? o) => IntentJs.NumOf(o) is double d && double.IsFinite(d);

    /// <summary>Strictly parse a directory document: every key must be a well-formed Ed25519 OKP JWK with a string <c>kid</c>. Throws ArgumentException otherwise.</summary>
    public static D ParseKeyDirectory(string text)
    {
        var doc = Pca.ParseJson(text);
        var keys = doc is D dd ? dd.GetValueOrDefault("keys") : null;
        if (keys is not L kl || kl.Count == 0) throw new ArgumentException("directory has no keys");
        foreach (var k in kl)
        {
            if (k is not D j) throw new ArgumentException("directory contains a malformed key");
            if (!(j.GetValueOrDefault("kty") is "OKP") || !(j.GetValueOrDefault("crv") is "Ed25519") || !(j.GetValueOrDefault("kid") is string kid && kid.Length > 0))
                throw new ArgumentException("directory contains a malformed key");
            if (!(j.GetValueOrDefault("x") is string x && XRe.IsMatch(x))) throw new ArgumentException("directory contains a malformed key");
            foreach (var f in new[] { "nbf", "exp" })
                if (j.ContainsKey(f) && !FiniteNumber(j[f])) throw new ArgumentException("directory contains a malformed key");
        }
        return (D)doc!;
    }

    static double NowSec() => Math.Floor(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0);

    /// <summary>Sign a directory response. <paramref name="input"/>: <c>keys</c> (list of signing keys, each an <see cref="EdKey"/> or a map with a b64u <c>secretKey</c> seed),
    /// <c>directory</c> (the document to serve, as built by BuildKeyDirectory; every signing key must be in it), <c>authority</c> (lower-case host or host:port),
    /// <c>created</c>?, <c>expiresInSec</c>?. Returns <c>{body, headers}</c>.</summary>
    public static D SignDirectoryResponse(D input)
    {
        var keys = input.GetValueOrDefault("keys") as L ?? new L();
        if (keys.Count == 0) throw new ArgumentException("signDirectoryResponse: at least one signing key is required");
        if (!(input.GetValueOrDefault("authority") is string authority && AuthorityRe.IsMatch(authority)))
            throw new ArgumentException("signDirectoryResponse: authority must be a lower-case host or host:port");
        double created = input.GetValueOrDefault("created") != null ? WbaJs.Number(input["created"]) : NowSec();
        double expires = created + (input.GetValueOrDefault("expiresInSec") != null ? WbaJs.Number(input["expiresInSec"]) : DefaultLifetimeSec);
        var directory = input.GetValueOrDefault("directory");
        var body = J.Stringify(directory);
        var inputs = new List<string>();
        var sigs = new List<string>();
        int i = 0;
        foreach (var k in keys)
        {
            var key = WebBotAuth.EdKeyOf(k);
            var x = key.Id;
            bool found = false;
            if (WbaJs.Get(directory, "keys") is L dk) foreach (var j in dk) if (WbaJs.Get(j, "x") is string jx && jx == x) { found = true; break; }
            if (!found) throw new ArgumentException("signDirectoryResponse: a signing key is not in the directory");
            var keyid = ThumbprintOfX(x);
            var label = "sig" + (i + 1);
            i++;
            var prms = "(\"@authority\";req);created=" + WbaJs.NumStr(created) + ";expires=" + WbaJs.NumStr(expires) + ";keyid=\"" + keyid + "\";alg=\"ed25519\";tag=\"" + DirectorySignatureTag + "\"";
            var bas = "\"@authority\";req: " + authority + "\n\"@signature-params\": " + prms;
            inputs.Add(label + "=" + prms);
            sigs.Add(label + "=:" + WbaJs.B64(key.Sign(Encoding.UTF8.GetBytes(bas))) + ":");
        }
        return new D
        {
            ["body"] = body,
            ["headers"] = new D
            {
                ["content-type"] = "application/http-message-signatures-directory+json",
                ["signature-input"] = string.Join(", ", inputs),
                ["signature"] = string.Join(", ", sigs),
            },
        };
    }

    static D Fail(string reason) => new() { ["valid"] = false, ["reason"] = reason, ["keys"] = new L() };

    static string? StrParam(Dictionary<string, string> p, string k) => p.TryGetValue(k, out var v) && v.StartsWith('"') ? v[1..^1] : null;

    static double? NumParam(Dictionary<string, string> p, string k) =>
        p.TryGetValue(k, out var v) && DigitsRe.IsMatch(v) ? double.Parse(v, CultureInfo.InvariantCulture) : null;

    /// <summary>Verify a signed directory response. <paramref name="input"/>: <c>authority</c>, <c>headers</c> (<c>signature-input</c>, <c>signature</c>), <c>body</c>, <c>now</c>?,
    /// <c>clockSkewSec</c>?, <c>maxLifetimeSec</c>? (default 86400). Fail closed: <c>{valid:false, reason, keys:[]}</c> for a missing or malformed signature header, a body
    /// that is not a well-formed directory, or when NO signature is valid. When valid, <c>keys</c> holds only the directory keys that carry a valid signature.</summary>
    public static D VerifyDirectoryResponse(D input)
    {
        try
        {
            var hdrs = input.GetValueOrDefault("headers");
            var sigInputO = WbaJs.Get(hdrs, "signature-input");
            var sigHeaderO = WbaJs.Get(hdrs, "signature");
            if (!JsX.Truthy(sigInputO) || !JsX.Truthy(sigHeaderO)) return Fail("missing signature-input or signature header");
            var sigInput = (string)sigInputO!;
            var sigHeader = (string)sigHeaderO!;
            var dir = ParseKeyDirectory((string)input.GetValueOrDefault("body")!);
            var sigs = new Dictionary<string, byte[]>();
            foreach (var part in sigHeader.Split(", "))
            {
                var m = SigRe.Match(part);
                if (!m.Success) return Fail("malformed signature header");
                sigs[m.Groups[1].Value] = WbaJs.NodeBase64(m.Groups[2].Value);
            }
            double now = input.GetValueOrDefault("now") != null ? WbaJs.Number(input["now"]) : NowSec();
            double skew = input.GetValueOrDefault("clockSkewSec") != null ? WbaJs.Number(input["clockSkewSec"]) : 0;
            double maxLife = input.GetValueOrDefault("maxLifetimeSec") != null ? WbaJs.Number(input["maxLifetimeSec"]) : DefaultLifetimeSec;
            var good = new D();
            var lastReason = "no signature entry";
            foreach (var raw in sigInput.Split(", "))
            {
                var m = EntryRe.Match(raw);
                if (!m.Success) { lastReason = "malformed signature-input entry (must cover exactly \"@authority\";req)"; continue; }
                var label = m.Groups[1].Value;
                var prms = new Dictionary<string, string>();
                bool dup = false;
                var ps = m.Groups[2].Value.Split(';');
                for (int pi = 1; pi < ps.Length; pi++)
                {
                    int eq = ps[pi].IndexOf('=');
                    var k = ps[pi][..eq];
                    if (prms.ContainsKey(k)) dup = true;
                    prms[k] = ps[pi][(eq + 1)..];
                }
                if (dup) { lastReason = "duplicate signature parameter"; continue; }
                if (StrParam(prms, "tag") != DirectorySignatureTag) { lastReason = "wrong tag"; continue; }
                if (prms.TryGetValue("alg", out var alg) && alg != "\"ed25519\"") { lastReason = "unsupported alg"; continue; }
                var created = NumParam(prms, "created");
                var expires = NumParam(prms, "expires");
                if (created == null || expires == null) { lastReason = "created and expires are required"; continue; }
                if (!(double.IsFinite(now) && double.IsFinite(skew) && double.IsFinite(created.Value) && created <= now + skew)) { lastReason = "signature created-time is in the future"; continue; }
                if (!(double.IsFinite(expires.Value) && now <= expires + skew)) { lastReason = "signature has expired"; continue; }
                if (!(expires - created <= maxLife)) { lastReason = "signature lifetime exceeds maxLifetimeSec"; continue; }
                var keyid = StrParam(prms, "keyid");
                if (keyid == null) { lastReason = "missing keyid"; continue; }
                D? key = null;
                foreach (var j in (L)dir["keys"]!) if (ThumbprintOfX((string)((D)j!)["x"]!) == keyid) { key = (D)j!; break; }
                if (key == null) { lastReason = "keyid is not the thumbprint of any directory key"; continue; }
                var nbf = IntentJs.NumOf(key.GetValueOrDefault("nbf"));
                var exp = IntentJs.NumOf(key.GetValueOrDefault("exp"));
                if ((nbf != null && !(now + skew >= nbf)) || (exp != null && !(now - skew <= exp))) { lastReason = "directory key is outside its validity window"; continue; }
                if (!sigs.TryGetValue(label, out var sig) || sig.Length != 64) { lastReason = "no valid signature bytes for the label"; continue; }
                var bas = "\"@authority\";req: " + input.GetValueOrDefault("authority") + "\n\"@signature-params\": " + raw[(label.Length + 1)..];
                var pk = WbaJs.NodeBase64((string)key["x"]!);
                if (!Pca.VerifyEd25519Strict(pk, Encoding.UTF8.GetBytes(bas), sig)) { lastReason = "signature does not verify"; continue; }
                good[(string)key["kid"]!] = key;
            }
            if (good.Count == 0) return Fail(lastReason);
            return new D { ["valid"] = true, ["keys"] = good.Values.ToList() };
        }
        catch (Exception e)
        {
            return Fail("verification failed (fail closed): " + e.Message);
        }
    }
}
