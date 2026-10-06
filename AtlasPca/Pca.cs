// Reference verifier for the CORE PCActn checks (capability chain, Merkle plan inclusion,
// Ed25519 leaf signature, counter). Byte-matches @atlasauth/pca and the Go reference verifier.
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace AtlasPca;

/// <summary>A JSON number kept as its exact source text.</summary>
public sealed record Num(string Raw);

public sealed class Verdict
{
    public bool Allow;
    public Dictionary<string, bool> Checks = new() { ["chain"] = false, ["plan_inclusion"] = false, ["leaf_signature"] = false, ["counter"] = false };
    public string Reason = "";
}

public static class Pca
{
    const string SigDomain = "atlas-pca/actn/v1\0";
    const string CapDomain = "atlas-pca/cap/v1\0";
    const string DefaultRev = "reversible";

    // ---- parsing: JSON -> object tree (null, bool, string, Num, List<object?>, Dictionary<string,object?>)
    public static object? ParseJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return Conv(doc.RootElement);
    }

    static object? Conv(JsonElement e)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.Null: return null;
            case JsonValueKind.True: return true;
            case JsonValueKind.False: return false;
            case JsonValueKind.String: return e.GetString();
            case JsonValueKind.Number: return new Num(e.GetRawText());
            case JsonValueKind.Array:
                var l = new List<object?>();
                foreach (var x in e.EnumerateArray()) l.Add(Conv(x));
                return l;
            default:
                var d = new Dictionary<string, object?>();
                foreach (var p in e.EnumerateObject()) d[p.Name] = Conv(p.Value); // last wins
                return d;
        }
    }

    // ---- canonicalization
    public static string Canonicalize(object? v)
    {
        var sb = new StringBuilder();
        Ser(sb, v);
        return sb.ToString();
    }

    static void JsString(StringBuilder sb, string s)
    {
        sb.Append('"');
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { sb.Append(c).Append(s[i + 1]); i++; }
                    else if (char.IsSurrogate(c)) sb.Append("\\u").Append(((int)c).ToString("x4")); // lone surrogate, as JS well-formed stringify
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    static string FmtNumber(string raw)
    {
        if (!double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var f) || double.IsInfinity(f) || double.IsNaN(f))
            throw new InvalidOperationException("canonicalize: non-finite number");
        if (f == 0) return "0";
        if (f == Math.Floor(f) && Math.Abs(f) < 1e15) return ((long)f).ToString(CultureInfo.InvariantCulture);
        return f.ToString("R", CultureInfo.InvariantCulture);
    }

    static void Ser(StringBuilder sb, object? v)
    {
        switch (v)
        {
            case null: sb.Append("null"); break;
            case bool b: sb.Append(b ? "true" : "false"); break;
            case string s: JsString(sb, s); break;
            case Num n: sb.Append(FmtNumber(n.Raw)); break;
            case int i: sb.Append(i.ToString(CultureInfo.InvariantCulture)); break;
            case long l: sb.Append(l.ToString(CultureInfo.InvariantCulture)); break;
            case double d: sb.Append(FmtNumber(d.ToString("R", CultureInfo.InvariantCulture))); break;
            case List<object?> a:
                sb.Append('[');
                for (int k = 0; k < a.Count; k++) { if (k > 0) sb.Append(','); Ser(sb, a[k]); }
                sb.Append(']');
                break;
            case Dictionary<string, object?> m:
                var keys = m.Keys.ToList();
                keys.Sort(string.CompareOrdinal); // UTF-16 code-unit order
                sb.Append('{');
                for (int k = 0; k < keys.Count; k++)
                {
                    if (k > 0) sb.Append(',');
                    JsString(sb, keys[k]); sb.Append(':'); Ser(sb, m[keys[k]]);
                }
                sb.Append('}');
                break;
            default: throw new InvalidOperationException("canonicalize: unsupported type " + v.GetType());
        }
    }

    // ---- hashing
    static byte[] Sha(byte[] b) => SHA256.HashData(b);
    static byte[] Canon(object? v) => Encoding.UTF8.GetBytes(Canonicalize(v));
    static byte[] Cat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

    public static string B64u(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    static byte[]? B64uDecode(string? s)
    {
        if (s == null) return null;
        try
        {
            if (s.Contains('=') || s.Contains('+') || s.Contains('/')) return null;
            var t = s.Replace('-', '+').Replace('_', '/');
            switch (t.Length % 4) { case 2: t += "=="; break; case 3: t += "="; break; case 1: return null; }
            return Convert.FromBase64String(t);
        }
        catch (FormatException) { return null; }
    }

    public static string HashCanonical(object? v) => B64u(Sha(Canon(v)));

    // ---- Merkle
    static byte[] LeafHash(object? leaf) => Sha(Cat(new byte[] { 0x00 }, Canon(leaf)));
    static byte[] NodeHash(byte[] l, byte[] r) => Sha(Cat(new byte[] { 0x01 }, l, r));

    static int Split(int n) { int k = 1; while (k * 2 < n) k *= 2; return k; }

    static byte[] Build(List<byte[]> hs)
    {
        if (hs.Count == 1) return hs[0];
        int k = Split(hs.Count);
        return NodeHash(Build(hs.GetRange(0, k)), Build(hs.GetRange(k, hs.Count - k)));
    }

    public static string MerkleRoot(List<object?> leaves)
    {
        if (leaves.Count == 0) throw new InvalidOperationException("empty leaf set");
        return B64u(Build(leaves.Select(LeafHash).ToList()));
    }

    public static bool VerifyInclusion(string root, Dictionary<string, object?>? proof, object? leaf)
    {
        if (proof == null || !(Get(proof, "path") is List<object?> path)) return false;
        byte[] h;
        try { h = LeafHash(leaf); } catch { return false; }
        foreach (var s in path)
        {
            if (s is not Dictionary<string, object?> step) return false;
            var side = Get(step, "side") as string;
            var sib = B64uDecode(Get(step, "hash") as string);
            if (side != "L" && side != "R") return false;
            if (sib == null) return false;
            h = side == "L" ? NodeHash(sib, h) : NodeHash(h, sib);
        }
        return B64u(h) == root;
    }

    public static string ParamsDigest(object? p) => HashCanonical(p ?? new Dictionary<string, object?>());

    static string ConditionsDigest(object? pre, object? post) =>
        HashCanonical(new Dictionary<string, object?> { ["pre"] = pre, ["post"] = post });

    static Dictionary<string, object?>? PlanLeaf(object? nodeId, Dictionary<string, object?>? action, string cond)
    {
        if (nodeId == null) return null;
        var pd = Get(action, "params_digest") ?? ParamsDigest(null);
        var rc = Get(action, "reversibility_class") ?? DefaultRev;
        return new Dictionary<string, object?>
        {
            ["node_id"] = nodeId, ["verb"] = Get(action, "verb"), ["resource"] = Get(action, "resource"),
            ["params_digest"] = pd, ["reversibility_class"] = rc, ["conditions"] = cond,
        };
    }

    // ---- keys
    static bool VerifyB64u(string? pub, byte[] msg, string? sig)
    {
        var pk = B64uDecode(pub); var sg = B64uDecode(sig);
        if (pk == null || pk.Length != 32 || sg == null || sg.Length != 64) return false;
        try
        {
            var v = new Ed25519Signer();
            v.Init(false, new Ed25519PublicKeyParameters(pk, 0));
            v.BlockUpdate(msg, 0, msg.Length);
            return v.VerifySignature(sg);
        }
        catch { return false; }
    }

    // ---- capability chain
    static object? Get(Dictionary<string, object?>? m, string k) => m != null && m.TryGetValue(k, out var v) ? v : null;
    static bool Has(Dictionary<string, object?>? m, string k) => m != null && m.ContainsKey(k);

    public static string CapHash(object? c) => HashCanonical(c);

    static string CheckSig(Dictionary<string, object?> c, string? signer, string label)
    {
        var body = new Dictionary<string, object?>
        {
            ["issuer"] = Get(c, "issuer"), ["holder"] = Get(c, "holder"), ["caveats"] = Get(c, "caveats"), ["parent"] = Get(c, "parent"),
        };
        string digest;
        try { digest = HashCanonical(body); } catch { return label + ": malformed body"; }
        var bd = Get(c, "body_digest") as string; var id = Get(c, "id") as string;
        if (digest != bd || id != bd) return label + ": body digest mismatch";
        var d = B64uDecode(bd);
        if (d == null || !VerifyB64u(signer, Cat(Encoding.UTF8.GetBytes(CapDomain), d), Get(c, "sig") as string))
            return label + ": bad signature (not signed by expected key)";
        return "";
    }

    static bool StrEq(object? a, object? b) => a is string x && b is string y && x == y;

    public static (string Why, bool Ok) VerifyChain(List<object?> chain, string? expectedRootIssuer, bool haveIssuer)
    {
        if (chain.Count == 0) return ("empty chain", false);
        if (chain[0] is not Dictionary<string, object?> root) return ("hop 0: malformed", false);
        if (Has(root, "parent")) return ("hop 0: root must not have a parent", false);
        if (haveIssuer && !StrEq(Get(root, "issuer"), expectedRootIssuer)) return ("hop 0: root issuer is not the expected principal", false);
        var e = CheckSig(root, Get(root, "issuer") as string, "hop 0");
        if (e != "") return (e, false);
        for (int i = 1; i < chain.Count; i++)
        {
            var label = $"hop {i}";
            if (chain[i - 1] is not Dictionary<string, object?> parent || chain[i] is not Dictionary<string, object?> c)
                return (label + ": malformed", false);
            if (!StrEq(Get(c, "parent"), CapHash(parent))) return (label + ": broken parent link", false);
            if (!StrEq(Get(c, "issuer"), Get(parent, "holder"))) return (label + ": issuer is not the parent's bound holder", false);
            e = CheckSig(c, Get(parent, "holder") as string, label);
            if (e != "") return (e, false);
            var pc = Get(parent, "caveats") as List<object?> ?? new();
            var cc = Get(c, "caveats") as List<object?> ?? new();
            if (cc.Count < pc.Count) return (label + ": drops parent caveat(s)", false);
            for (int j = 0; j < pc.Count; j++)
                if (HashCanonical(cc[j]) != HashCanonical(pc[j])) return ($"{label}: caveat {j} altered or reordered", false);
        }
        return ("", true);
    }

    // ---- PCActn
    public static byte[] ThresholdMessage(Dictionary<string, object?> p)
    {
        var body = p.Where(kv => kv.Key != "sig" && kv.Key != "threshold").ToDictionary(kv => kv.Key, kv => kv.Value);
        return Cat(Encoding.UTF8.GetBytes(SigDomain), Sha(Canon(body)));
    }

    public static Verdict VerifyPcactnCore(Dictionary<string, object?> pcactn, Dictionary<string, object?> grant)
    {
        var v = new Verdict();
        bool failed = false;
        void Fail(string name, string why)
        {
            failed = true; v.Checks[name] = false;
            if (v.Reason == "") v.Reason = name + ": " + why;
        }
        try
        {
            if (!(Get(pcactn, "ver") is Num n && n.Raw == "1")) Fail("version", "unsupported ver");

            var chain = Get(pcactn, "cap_chain") as List<object?> ?? new();
            if (chain.Count == 0) Fail("chain", "empty chain");
            else if (CapHash(chain[0]) != CapHash(grant)) Fail("chain", "chain root is not the grant");
            else
            {
                var gi = Get(grant, "issuer") as string;
                var (why, ok) = VerifyChain(chain, gi, gi != null);
                if (ok) v.Checks["chain"] = true; else Fail("chain", why);
            }

            var plan = Get(pcactn, "plan") as Dictionary<string, object?>;
            var action = Get(pcactn, "action") as Dictionary<string, object?>;
            var cond = Get(plan, "conditions_digest") as string ?? ConditionsDigest(null, null);
            var root = Get(plan, "root") as string ?? "";
            var proof = Get(plan, "inclusion_proof") as Dictionary<string, object?>;
            var leaf = PlanLeaf(Get(plan, "node_id"), action, cond);
            if (leaf != null && VerifyInclusion(root, proof, leaf)) v.Checks["plan_inclusion"] = true;
            else Fail("plan_inclusion", "action is not a node of the committed plan");

            if (chain.Count > 0)
            {
                var leafCap = chain[^1] as Dictionary<string, object?>;
                var holder = Get(leafCap, "holder") as string;
                var sig = Get(pcactn, "sig") as string;
                if (sig != null && VerifyB64u(holder, ThresholdMessage(pcactn), sig)) v.Checks["leaf_signature"] = true;
                else Fail("leaf_signature", "signature does not verify under the leaf holder key");
            }
            else Fail("leaf_signature", "signature does not verify under the leaf holder key");

            if (Get(pcactn, "counter") is Num cn && long.TryParse(cn.Raw, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var ci) && ci >= 0)
                v.Checks["counter"] = true;
            else Fail("counter", "missing or not a non-negative integer");

            v.Allow = !failed;
        }
        catch (Exception ex)
        {
            v.Allow = false;
            v.Reason = "malformed PCActn: " + ex.Message;
        }
        return v;
    }
}
