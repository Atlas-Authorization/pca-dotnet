using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.WebBotAuth;

/// <summary>RFC 9530 Content-Digest: the dictionary field whose members are hash algorithm names with byte-sequence values over the message content.
/// Only sha-256 and sha-512 (the algorithms the RFC marks Active) are produced or accepted. Cover <c>content-digest</c> in the signature so it protects
/// the body too; <see cref="VerifyContentDigest"/> then checks the body against the covered field and FAILS CLOSED.</summary>
public static class ContentDigest
{
    public static IReadOnlyList<string> ContentDigestAlgs => new[] { "sha-256", "sha-512" };
    public const string ContentDigestHeaderName = "Content-Digest";

    static Regex MemberRe => WbaJs.R(@"^([a-z*][a-z0-9_\-.*]*)=:([A-Za-z0-9+/]*={0,2}):\z");

    static byte[] BytesOf(object? body) => body switch
    {
        string s => Encoding.UTF8.GetBytes(s),
        byte[] b => b,
        _ => throw new ArgumentException("body must be a string or bytes"),
    };

    /// <summary>The raw digest bytes of <paramref name="body"/> (a string, hashed as UTF-8, or byte[]) under <paramref name="alg"/>.</summary>
    public static byte[] ContentDigestBytes(object? body, string alg) => alg switch
    {
        "sha-256" => SHA256.HashData(BytesOf(body)),
        "sha-512" => SHA512.HashData(BytesOf(body)),
        _ => throw new NodeCodedException("ERR_INVALID_ARG_TYPE", "The \"algorithm\" argument must be of type string. Received undefined"),
    };

    /// <summary>The Content-Digest field value, e.g. <c>sha-256=:X48E9q...=:</c> (members in the given order, repeats dropped).</summary>
    public static string ContentDigestHeader(object? body, IReadOnlyList<string>? algs = null)
    {
        algs ??= new[] { "sha-256" };
        if (algs.Count == 0) throw new ArgumentException("contentDigestHeader: name at least one algorithm");
        var seen = new HashSet<string>();
        var parts = new List<string>();
        foreach (var alg in algs)
        {
            if (!ContentDigestAlgs.Contains(alg)) throw new ArgumentException("contentDigestHeader: unsupported algorithm " + alg);
            if (!seen.Add(alg)) continue;
            parts.Add(alg + "=:" + WbaJs.B64(ContentDigestBytes(body, alg)) + ":");
        }
        return string.Join(", ", parts);
    }

    /// <summary>Parse the dictionary: key to byte sequence. Throws on anything that is not <c>key=:base64:</c> (parameters refused).</summary>
    public static Dictionary<string, byte[]> ParseContentDigest(string value)
    {
        var o = new Dictionary<string, byte[]>();
        foreach (var raw in value.Split(','))
        {
            var member = WbaJs.Trim(raw);
            if (member.Length == 0) throw new ArgumentException("empty dictionary member");
            var m = MemberRe.Match(member);
            if (!m.Success) throw new ArgumentException($"malformed Content-Digest member \"{member}\"");
            string key = m.Groups[1].Value, b64 = m.Groups[2].Value;
            if (b64.Length % 4 != 0) throw new ArgumentException($"member \"{key}\" is not canonical base64");
            var bytes = WbaJs.NodeBase64(b64);
            if (WbaJs.B64(bytes) != b64) throw new ArgumentException($"member \"{key}\" is not canonical base64");
            if (o.ContainsKey(key)) throw new ArgumentException($"member \"{key}\" appears twice");
            o[key] = bytes;
        }
        return o;
    }

    static D Fail(string reason) => new() { ["valid"] = false, ["reason"] = reason };

    /// <summary>Check <paramref name="body"/> against a Content-Digest field value (<paramref name="header"/> null = absent). Every supported member present must match;
    /// unsupported members are ignored (RFC 9530 section 2); at least one supported member must be present; every algorithm in <paramref name="require"/> (null = none)
    /// must be among the matched ones. Returns <c>{valid, reason?, matched?}</c>; never throws on a bad header.</summary>
    public static D VerifyContentDigest(string? header, object? body, IReadOnlyList<string>? require = null)
    {
        try
        {
            if (header == null || WbaJs.Trim(header).Length == 0) return Fail("missing Content-Digest");
            var members = ParseContentDigest(header);
            var matched = new List<string>();
            foreach (var alg in ContentDigestAlgs)
            {
                if (!members.TryGetValue(alg, out var got)) continue;
                if (!CryptographicOperations.FixedTimeEquals(got, ContentDigestBytes(body, alg))) return Fail(alg + " digest does not match the content");
                matched.Add(alg);
            }
            if (matched.Count == 0) return Fail("no supported digest algorithm (sha-256 or sha-512)");
            if (require != null) foreach (var alg in require) if (!matched.Contains(alg)) return Fail($"required {alg} digest is absent");
            return new D { ["valid"] = true, ["matched"] = matched.Cast<object?>().ToList() };
        }
        catch (ArgumentException e) { return Fail("malformed Content-Digest: " + e.Message); }
    }
}
