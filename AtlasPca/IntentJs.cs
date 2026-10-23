// Shared helpers of the Intent Layer v2 rules (13-18): JavaScript value semantics over the parsed JSON tree
// (Dictionary<string, object?>, List<object?>, Num, string, bool, null), so every rule judges numbers by their IEEE-754
// binary64 value exactly like the TypeScript reference (packages/pca/src). Mirrors IntentJs.java / IntentJs.kt.
using System.Globalization;
using System.Numerics;
using System.Text;

namespace AtlasPca;

/// <summary>
/// Verifier-held state (the <c>context.intent_v2</c> object, the W-B primitive inputs, plaintext params) is NORMALIZED once on
/// entry with <see cref="Normalize"/>: every <see cref="Num"/> becomes the number <c>JSON.parse</c> would yield, spelled as
/// JavaScript prints it (integral values as plain digits, others as the shortest round-trip decimal; <c>-0</c> stays
/// <c>"-0"</c>). After that the strict canonicalizer and every numeric test agree with the reference on any lexical form.
/// </summary>
public static class IntentJs
{
    internal const double MaxSafe = 9007199254740991.0;

    // ---- values ----
    internal static bool IsObj(object? o) => o is Dictionary<string, object?>;
    internal static bool IsArr(object? o) => o is List<object?>;
    internal static Dictionary<string, object?> Obj(object? o) => (Dictionary<string, object?>)o!;
    internal static List<object?> Arr(object? o) => (List<object?>)o!;
    /// <summary>Own member (JSON null counts as present, like a defined property).</summary>
    internal static bool Own(object? o, string k) => o is Dictionary<string, object?> d && d.ContainsKey(k);
    internal static object? Get(object? o, string k) => o is Dictionary<string, object?> d && d.TryGetValue(k, out var v) ? v : null;
    /// <summary>An optional member: ABSENT means <paramref name="dflt"/>; a present member (JSON null included) is returned as
    /// is, so a present null reaches the type check and fails closed (it is malformed, never a default).</summary>
    internal static object? Opt(object? o, string k, object? dflt) => Own(o, k) ? Get(o, k) : dflt;

    /// <summary>Equality of the lenient canonical JSON texts (the predicate DSL's <c>deepEq</c>) computed structurally:
    /// numbers by binary64 value (<c>-0</c> prints as <c>0</c>), strings by UTF-16 code units, objects by key set and member
    /// values, arrays element-wise. A non-JSON value (or a non-finite number) never equals anything.</summary>
    internal static bool JsonEquals(object? a, object? b)
    {
        if (a == null || b == null) return a == null && b == null;
        if (a is string || b is string) return a is string x && b is string y && x == y;
        if (a is bool || b is bool) return a is bool p && b is bool q && p == q;
        var na = NumOf(a); var nb = NumOf(b);
        if (na != null || nb != null) return na is double u && nb is double w && double.IsFinite(u) && double.IsFinite(w) && u == w;
        if (a is List<object?> la && b is List<object?> lb)
        {
            if (la.Count != lb.Count) return false;
            for (int i = 0; i < la.Count; i++) if (!JsonEquals(la[i], lb[i])) return false;
            return true;
        }
        if (a is Dictionary<string, object?> ma && b is Dictionary<string, object?> mb)
        {
            if (ma.Count != mb.Count) return false;
            foreach (var (k, v) in ma) if (!mb.TryGetValue(k, out var w) || !JsonEquals(v, w)) return false;
            return true;
        }
        return false;
    }

    /// <summary>The binary64 value of a JSON number (Num, int, long, double), else null.</summary>
    internal static double? NumOf(object? o) => o switch
    {
        Num n => double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null,
        int i => i,
        long l => l,
        double d => d,
        _ => null,
    };
    internal static bool IsNumber(object? o) => NumOf(o) != null;
    internal static bool IsNegZero(double d) => d == 0.0 && BitConverter.DoubleToInt64Bits(d) != 0L;
    /// <summary><c>Number.isSafeInteger</c> (accepts -0).</summary>
    internal static bool IsSafeInteger(object? o)
    {
        var d = NumOf(o);
        return d is double x && double.IsFinite(x) && x == Math.Round(x) && Math.Abs(x) <= MaxSafe;
    }
    /// <summary>The reference <c>isInt</c>: a safe integer that is not -0.</summary>
    internal static bool IsInt(object? o) => IsSafeInteger(o) && !IsNegZero(NumOf(o)!.Value);
    /// <summary>The reference <c>isNonNeg</c>.</summary>
    internal static bool IsNonNeg(object? o) => IsInt(o) && NumOf(o)!.Value >= 0;
    /// <summary>Value of a safe integer (call after <see cref="IsSafeInteger"/>).</summary>
    internal static long Lng(object? o) => (long)NumOf(o)!.Value;
    internal static bool IsFinite(object? o) => NumOf(o) is double d && double.IsFinite(d);
    internal static Num OfLong(long v) => new(v.ToString(CultureInfo.InvariantCulture));

    // ---- strings ----
    internal static int U8Len(string s) => Encoding.UTF8.GetByteCount(s);
    internal static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
    internal static bool HasLoneSurrogate(string s) => Pca.HasLoneSurrogate(s);
    public static int CompareUtf8(string a, string b) => ((ReadOnlySpan<byte>)Encoding.UTF8.GetBytes(a)).SequenceCompareTo(Encoding.UTF8.GetBytes(b));
    internal static List<string> SortedUtf8(IEnumerable<string> keys)
    {
        var l = keys.ToList();
        l.Sort(CompareUtf8);
        return l;
    }
    /// <summary>Canonical base64url of exactly 32 bytes (a "digest").</summary>
    internal static bool B32(object? o) => Pca.B64uDecode(o, 32) != null;
    /// <summary>Canonical base64url of any length.</summary>
    internal static bool B64Any(object? o) => Pca.B64uDecode(o) != null;

    // ---- hashing ----
    internal static string Canon(object? v) => Pca.Canonicalize(v);
    internal static byte[] CanonBytes(object? v) => Utf8(Pca.Canonicalize(v));
    internal static string HashCanonical(object? v) => Pca.HashCanonical(v);
    /// <summary><c>utf8(domain) || strictCanonical(body)</c>.</summary>
    internal static byte[] Message(string domain, object? body) => Utf8(domain).Concat(CanonBytes(body)).ToArray();
    /// <summary><c>{d: domain, &lt;slot&gt;: value}</c> hashed (an artifact reference).</summary>
    internal static string Ref(string domain, string slot, object? value) =>
        HashCanonical(new Dictionary<string, object?> { ["d"] = domain, [slot] = value });

    // ---- signatures ----
    /// <summary>Strict Ed25519 (rule 7); a malformed key or signature is a failed signature.</summary>
    internal static bool VerifyEd(object? pub, byte[] msg, object? sig) => pub is string && sig is string && Pca.VerifyEdInternal(pub, msg, sig);

    /// <summary>The reason token of a signature refused because this SDK's suite dispatch does not implement the artifact's suite.</summary>
    public const string UnsupportedSuite = "unsupported_suite";

    /// <summary>The suite capability rule: an absent <c>alg</c> is ed25519; a non-string <c>alg</c> is malformed; an <c>alg</c>
    /// this SDK's suite dispatch does not implement fails with <see cref="UnsupportedSuite"/>. Null = ok.</summary>
    internal static string? SuiteError(object? alg, bool algPresent)
    {
        if (!algPresent) return null;
        if (alg is not string s) return "alg must be a string";
        return Pq.Suites.ContainsKey(s) ? null : $"{UnsupportedSuite}: '{s}'";
    }

    /// <summary>The implemented suite an artifact names (absent = ed25519), or null.</summary>
    internal static string? SuiteOf(object? alg, bool algPresent) =>
        !algPresent ? "ed25519" : alg is string s && Pq.Suites.ContainsKey(s) ? s : null;
    internal static string? SuiteOf(Dictionary<string, object?> artifact) => SuiteOf(Get(artifact, "alg"), artifact.ContainsKey("alg"));

    /// <summary><c>bindSuiteFields(base, alg, pqPk)</c>: a non-ed25519 suite signs its name and PQ key into the body.</summary>
    internal static Dictionary<string, object?> BindSuiteFields(Dictionary<string, object?> body, object? alg, bool algPresent, object? pqPk, bool pqPresent)
    {
        var s = SuiteOf(alg, algPresent);
        if (s == null || s == "ed25519") return body;
        var o = new Dictionary<string, object?>(body) { ["alg"] = s };
        if (pqPresent) o["pq_pk"] = pqPk;
        return o;
    }

    /// <summary><c>verifyPinnedSuite</c>: ed25519 verifies under <paramref name="identity"/>; a PQ / hybrid suite only under
    /// the PQ key the VERIFIER pins for it (<paramref name="pqPins"/>), never the artifact's own key alone. Never throws.</summary>
    internal static bool VerifyPinnedSuite(object? alg, bool algPresent, string identity, object? artifactPqPk, byte[] msg,
        object? sig, object? pqSig, IReadOnlyDictionary<string, string>? pqPins)
    {
        try
        {
            var s = SuiteOf(alg, algPresent);
            if (s == null) return false;
            if (s == "ed25519") return VerifyEd(identity, msg, sig);
            return Pca.VerifyPinnedSuiteInternal(alg, algPresent, identity, artifactPqPk, msg, sig, pqSig, pqPins);
        }
        catch { return false; }
    }

    internal static IReadOnlyDictionary<string, string>? Pin(string identity, object? pqPk) =>
        pqPk is string s ? new Dictionary<string, string> { [identity] = s } : null;

    // ---- JSON.parse semantics for verifier state ----
    /// <summary>A deep copy with every number spelled as JavaScript prints the value <c>JSON.parse</c> yields.</summary>
    public static object? Normalize(object? v) => v switch
    {
        Num n => NormNum(n.Raw),
        double d => NormDouble(d, d.ToString("R", CultureInfo.InvariantCulture)),
        Dictionary<string, object?> m => m.ToDictionary(e => e.Key, e => Normalize(e.Value)),
        List<object?> l => l.Select(Normalize).ToList(),
        _ => v,
    };

    internal static Num NormNum(string raw) =>
        double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? NormDouble(d, raw) : new Num(raw);

    static Num NormDouble(double d, string raw)
    {
        if (!double.IsFinite(d)) return new Num(raw); // refused by every strict consumer
        if (IsNegZero(d)) return new Num("-0");
        if (d == Math.Round(d) && Math.Abs(d) < 1e21) return new Num(new BigInteger(d).ToString(CultureInfo.InvariantCulture));
        return new Num(Shortest(d));
    }

    /// <summary>The shortest round-trip decimal of <paramref name="d"/> (JavaScript's digits), printed without an exponent.</summary>
    internal static string Shortest(double d)
    {
        var r = d.ToString("R", CultureInfo.InvariantCulture); // .NET Core 3.0+: shortest round-trip
        if (!r.Contains('E')) return r;
        // expand the exponent form into plain decimal digits
        var neg = r.StartsWith('-');
        if (neg) r = r[1..];
        var parts = r.Split('E');
        var mant = parts[0];
        var exp = int.Parse(parts[1], CultureInfo.InvariantCulture);
        var dot = mant.IndexOf('.');
        var digits = dot < 0 ? mant : mant.Remove(dot, 1);
        var intLen = (dot < 0 ? mant.Length : dot) + exp;
        string plain;
        if (intLen <= 0) plain = "0." + new string('0', -intLen) + digits;
        else if (intLen >= digits.Length) plain = digits + new string('0', intLen - digits.Length);
        else plain = digits[..intLen] + "." + digits[intLen..];
        return neg ? "-" + plain : plain;
    }
}

public static partial class Pca
{
    internal static bool VerifyEdInternal(object? pub, byte[] msg, object? sig) => VerifyB64u(pub, msg, sig);

    /// <summary>A PQ / hybrid artifact signature through the SDK's suite dispatch (<see cref="VerifySuite"/>), under the PQ key
    /// the verifier pins for <paramref name="identity"/> (never the artifact's own key alone).</summary>
    internal static bool VerifyPinnedSuiteInternal(object? alg, bool algPresent, string identity, object? artifactPqPk, byte[] msg, object? sig,
        object? pqSig, IReadOnlyDictionary<string, string>? pqPins)
    {
        var pq = PinnedPq.Resolve(identity, artifactPqPk, pqPins: pqPins);
        if (pq == null) return false;
        var view = new Dictionary<string, object?> { ["sig"] = sig, ["pq_sig"] = pqSig };
        if (algPresent) view["alg"] = alg;
        return VerifySuite(view, identity, msg, pq);
    }

    internal static byte[] Sha256Of(params byte[][] parts) => Sha(Cat(parts));
    internal static byte[] Concat(params byte[][] parts) => Cat(parts);
    internal static string ConditionsDigestOf(object? pre, object? post) => ConditionsDigest(pre, post);
    internal static Dictionary<string, object?>? PlanLeafOf(object? nodeId, Dictionary<string, object?>? action, string cond) => PlanLeaf(nodeId, action, cond);
}
