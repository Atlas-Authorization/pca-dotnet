// Shared conventions of the Intent Layer v2 W-B artifacts (rules 16-18; packages/pca/src/intent-artifacts.ts), mirroring
// IntentArtifacts.java: closed member sets, Ed25519 signatures under a VERIFIER-pinned key over utf8(domain) ||
// strictCanonical(artifact without sig), content-addressed references and own-member parameter paths.
using System.Text.RegularExpressions;

namespace AtlasPca;

internal static class IntentArtifacts
{
    internal static readonly Regex IntentNameRe = new(@"^[a-z][a-z0-9_]{0,63}\z", RegexOptions.CultureInvariant);
    internal static readonly Regex DataClassRe = new(@"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*\z", RegexOptions.CultureInvariant);
    static readonly Regex ParamSegmentRe = new(@"^[A-Za-z0-9_-]{1,64}\z", RegexOptions.CultureInvariant);
    static readonly HashSet<string> ForbiddenSegments = new() { "__proto__", "constructor", "prototype" };

    internal static bool IsPathSegment(string s) => ParamSegmentRe.IsMatch(s) && !ForbiddenSegments.Contains(s);
    internal static bool IsName(object? v) => v is string s && IntentNameRe.IsMatch(s);
    internal static bool IsBoundedString(object? v, int max) => v is string s && s.Length > 0 && IntentJs.U8Len(s) <= max;
    internal static bool IsDigest(object? v) => IntentJs.B32(v);
    /// <summary>A wire scalar: string, boolean or safe integer (not -0).</summary>
    internal static bool IsScalar(object? v) => v is string || v is bool || IntentJs.IsInt(v);
    /// <summary>Same JSON type and value (<c>2 != "2"</c>, <c>true != 1</c>).</summary>
    internal static bool ScalarEq(object? a, object? b)
    {
        if (a is string || b is string) return a is string x && b is string y && x == y;
        if (a is bool || b is bool) return a is bool p && b is bool q && p == q;
        var na = IntentJs.NumOf(a); var nb = IntentJs.NumOf(b);
        if (na != null && nb != null) return na.Value == nb.Value;
        return a == null && b == null;
    }

    internal static string? ClosedMembers(Dictionary<string, object?> o, string[] required, string[] optional, string where)
    {
        foreach (var k in o.Keys) if (!required.Contains(k) && !optional.Contains(k)) return $"unknown member '{where}.{k}'";
        foreach (var k in required) if (!o.ContainsKey(k)) return $"missing member '{where}.{k}'";
        return null;
    }

    /// <summary>The optional suite members every W-B artifact may carry (<c>alg</c> and <c>pq_pk</c> are signed, <c>pq_sig</c> is not).</summary>
    internal static readonly string[] SuiteMembers = { "alg", "pq_pk", "pq_sig" };

    /// <summary>A pin entry's optional <c>pq_pk</c>: absent, or a non-empty string.</summary>
    internal static bool PinPqOk(object? pin) => !IntentJs.Own(pin, "pq_pk") || IntentJs.Get(pin, "pq_pk") is string { Length: > 0 };

    /// <summary>The artifact's suite capability: a non-string <c>alg</c> is malformed, an unimplemented one is
    /// <c>unsupported_suite</c>, <c>pq_pk</c> / <c>pq_sig</c> must be strings, an ed25519 artifact carries neither.</summary>
    internal static string? ArtifactSuiteError(Dictionary<string, object?> a)
    {
        var e = IntentJs.SuiteError(IntentJs.Get(a, "alg"), a.ContainsKey("alg"));
        if (e != null) return e;
        foreach (var k in new[] { "pq_pk", "pq_sig" }) if (a.ContainsKey(k) && a[k] is not string) return k + " must be a string";
        if (IntentJs.SuiteOf(a) == "ed25519" && (a.ContainsKey("pq_pk") || a.ContainsKey("pq_sig"))) return "an ed25519 artifact must not carry pq_pk / pq_sig";
        return null;
    }

    /// <summary><c>utf8(domain) || strictCanonical(artifact without sig and pq_sig)</c>.</summary>
    internal static byte[] ArtifactMessage(string domain, Dictionary<string, object?> artifact)
    {
        var body = new Dictionary<string, object?>(artifact);
        body.Remove("sig");
        body.Remove("pq_sig");
        return IntentJs.Message(domain, body);
    }

    /// <summary>The artifact's signature under the PINNED signer (<paramref name="pinnedPk"/>, and for a PQ / hybrid suite
    /// <paramref name="pinnedPqPk"/>: the artifact's own <c>pq_pk</c> alone never authorises it). Never throws.</summary>
    internal static bool VerifyArtifactSig(string domain, Dictionary<string, object?> artifact, object? pinnedPk, object? pinnedPqPk)
    {
        try
        {
            if (IntentJs.Get(artifact, "sig") is not string || pinnedPk is not string pk) return false;
            return IntentJs.VerifyPinnedSuite(IntentJs.Get(artifact, "alg"), artifact.ContainsKey("alg"), pk, IntentJs.Get(artifact, "pq_pk"),
                ArtifactMessage(domain, artifact), artifact["sig"], IntentJs.Get(artifact, "pq_sig"), IntentJs.Pin(pk, pinnedPqPk));
        }
        catch (Exception) { return false; }
    }

    internal static string ArtifactRef(string refDomain, string slot, object? artifact) => IntentJs.Ref(refDomain, slot, artifact);

    /// <summary>Resolve <c>action.params.a.b</c> through OWN members of plain objects.</summary>
    internal static Predicates.Resolved ResolveParamPath(object? parameters, object? path)
    {
        if (path is not string ps || !ps.StartsWith("action.params.", StringComparison.Ordinal)) return default;
        var segs = ps.Substring("action.params.".Length).Split('.');
        var cur = parameters;
        foreach (var s in segs)
        {
            if (!IsPathSegment(s) || cur is not Dictionary<string, object?> m || !m.TryGetValue(s, out var next)) return default;
            cur = next;
        }
        return new Predicates.Resolved(true, cur);
    }

    internal static bool IsParamPath(object? path)
    {
        if (path is not string ps || !ps.StartsWith("action.params.", StringComparison.Ordinal)) return false;
        var segs = ps.Substring("action.params.".Length).Split('.');
        return segs.Length >= 1 && segs.Length <= 8 && segs.All(IsPathSegment);
    }

    /// <summary>Set <c>root.&lt;path&gt;</c> creating plain objects; false when the path collides with an existing member.</summary>
    internal static bool SetNested(Dictionary<string, object?> root, string path, object? value)
    {
        var segs = path.Split('.');
        var cur = root;
        for (int i = 0; i < segs.Length - 1; i++)
        {
            if (!cur.ContainsKey(segs[i])) cur[segs[i]] = new Dictionary<string, object?>();
            if (cur[segs[i]] is not Dictionary<string, object?> next) return false;
            cur = next;
        }
        var last = segs[^1];
        if (cur.ContainsKey(last)) return false;
        cur[last] = value;
        return true;
    }

    /// <summary>A list member (read with <see cref="IntentJs.Opt"/>); anything else, null included, is malformed and fails closed.</summary>
    internal static List<object?> Iterable(object? o) => o as List<object?> ?? throw new ArgumentException("not a list");

    /// <summary><c>action.params</c> (absent = {}); a present non-object is malformed and fails closed.</summary>
    internal static Dictionary<string, object?> ActionParams(object? action) =>
        IntentJs.Opt(action, "params", new Dictionary<string, object?>()) as Dictionary<string, object?> ?? throw new ArgumentException("action.params is not an object");
}
