using System.Globalization;
using System.Numerics;
using AtlasPca;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Abe;

/// <summary>
/// Access structures over attributes: a monotone boolean formula as a threshold tree.
/// <c>{"attr": a}</c> leaf; <c>{"allOf": [...]}</c> AND (n-of-n); <c>{"anyOf": [...]}</c> OR (1-of-n); <c>{"threshold": k, "of": [...]}</c> k-of-n.
/// The normalised form is a JSON tree: <c>{"kind":"leaf","attr":a}</c> or <c>{"kind":"gate","t":k,"of":[...]}</c> with t a long.
/// Negation is not supported (ABE access structures are monotone).
/// </summary>
public static class AbePolicy
{
    /// <summary>Upper bound on total nodes in a policy tree (bounds work on untrusted input).</summary>
    public const int MaxPolicyNodes = 1024;

    /// <summary>Upper bound on gate nesting along any root-to-leaf path: the ciphertext header is authenticated as canonical JSON
    /// (nesting capped at 32), each gate costs three JSON levels and the root sits at level 2, so 10 gates is the most that can be
    /// authenticated. Enforcing it here makes "encryptable" imply "decryptable".</summary>
    public const int MaxPolicyDepth = 10;

    /// <summary>Result of <see cref="Normalize"/>: <c>Tree</c> on success, else <c>Reason</c>.</summary>
    public sealed class Result
    {
        public D? Tree { get; }
        public string? Reason { get; }
        internal Result(D? tree, string? reason) { Tree = tree; Reason = reason; }
        public bool Ok => Tree != null;

        /// <summary>The reference's JSON shape: <c>{ok:true, tree}</c> or <c>{ok:false, reason}</c>.</summary>
        public D ToJson()
        {
            var m = new D { ["ok"] = Ok };
            if (Ok) m["tree"] = Tree; else m["reason"] = Reason;
            return m;
        }
    }

    sealed class Fail : Exception
    {
        public Fail(string reason) : base(reason) { }
    }

    internal static object? Get(D m, string k) => m.TryGetValue(k, out var v) ? v : null;

    public static D Leaf(string attr) => new D { ["kind"] = "leaf", ["attr"] = attr };

    public static D Gate(long t, L of) => new D { ["kind"] = "gate", ["t"] = t, ["of"] = of };

    /// <summary>The value of a JSON number as JavaScript reads it (a double), or null when not a number.</summary>
    internal static double? NumVal(object? o) => o switch
    {
        AtlasPca.Num n => double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null,
        int i => i,
        long l => l,
        double d => d,
        float f => f,
        _ => null,
    };

    /// <summary>JavaScript <c>typeof x === 'number' &amp;&amp; Number.isInteger(x) &amp;&amp; x &gt; 0</c>.</summary>
    internal static bool IsPosInt(object? o) => NumVal(o) is double d && double.IsFinite(d) && d == Math.Floor(d) && d > 0;

    /// <summary>JavaScript's String(n) for a positive integral double.</summary>
    static string JsInt(double d) => JsCanon.NumberString(d);

    /// <summary>Validate and normalise an access structure; fails closed with a reason on any malformed node or oversized tree.</summary>
    public static Result Normalize(object? policy)
    {
        try { return new Result(Walk(policy, "policy", 0, new int[1]), null); }
        catch (Fail f) { return new Result(null, f.Message); }
    }

    static D Walk(object? p, string path, int gates, int[] nodes)
    {
        if (++nodes[0] > MaxPolicyNodes) throw new Fail("policy too large (> " + MaxPolicyNodes + " nodes)");
        if (p is not D m) throw new Fail(path + ": not an object");
        if (m.ContainsKey("attr"))
        {
            var a = m["attr"];
            if (a is not string s || s.Length == 0) throw new Fail(path + ": 'attr' must be a non-empty string");
            if (Pca.HasLoneSurrogate(s)) throw new Fail(path + ": 'attr' is not well-formed UTF-16");
            if (m.ContainsKey("allOf") || m.ContainsKey("anyOf") || m.ContainsKey("threshold") || m.ContainsKey("of"))
                throw new Fail(path + ": a leaf must not mix 'attr' with a gate");
            return Leaf(s);
        }
        var gateKeys = new List<string>();
        foreach (var k in new[] { "allOf", "anyOf", "threshold", "of" })
            if (m.ContainsKey(k) && !(k == "of" && m.ContainsKey("threshold"))) gateKeys.Add(k);
        if (gateKeys.Count > 1)
            throw new Fail(path + ": ambiguous node (" + string.Join(", ", gateKeys) + "); a gate must use exactly one of allOf/anyOf/threshold");
        if (gateKeys.Count == 1 && gates + 1 > MaxPolicyDepth) throw new Fail(path + ": policy nested deeper than " + MaxPolicyDepth + " gates");
        if (m.ContainsKey("allOf"))
        {
            var kids = Children(m["allOf"], "allOf", path, gates, nodes);
            return Gate(kids.Count, kids);
        }
        if (m.ContainsKey("anyOf")) return Gate(1, Children(m["anyOf"], "anyOf", path, gates, nodes));
        if (m.ContainsKey("threshold"))
        {
            var t = m["threshold"];
            if (!IsPosInt(t)) throw new Fail(path + ": 'threshold' must be a positive integer");
            var kids = Children(Get(m, "of"), "of", path, gates, nodes);
            double d = NumVal(t)!.Value;
            if (d > kids.Count) throw new Fail(path + ": threshold " + JsInt(d) + " exceeds the number of branches (" + kids.Count + ")");
            return Gate((long)d, kids);
        }
        throw new Fail(path + ": unknown policy node (expected attr/allOf/anyOf/threshold)");
    }

    static L Children(object? raw, string key, string path, int gates, int[] nodes)
    {
        if (raw is not L l || l.Count == 0) throw new Fail(path + ": '" + key + "' must be a non-empty array");
        var o = new L(l.Count);
        for (int i = 0; i < l.Count; i++) o.Add(Walk(l[i], path + "." + key + "[" + i.ToString(CultureInfo.InvariantCulture) + "]", gates + 1, nodes));
        return o;
    }

    internal static bool IsLeaf(D n) => Get(n, "kind") is string s && s == "leaf";

    internal static List<D> Of(D n) => ((L)n["of"]!).Select(x => (D)x!).ToList();

    /// <summary>The gate threshold as an int (saturating, as Java's Double.intValue).</summary>
    internal static int T(D n)
    {
        double d = NumVal(n["t"])!.Value;
        if (double.IsNaN(d)) return 0;
        return d >= int.MaxValue ? int.MaxValue : d <= int.MinValue ? int.MinValue : (int)d;
    }

    /// <summary>Non-cryptographic prediction: does the attribute set satisfy the tree? (Enforcement is the cryptography.)</summary>
    public static bool Satisfies(D tree, ISet<string> attrs)
    {
        if (IsLeaf(tree)) return attrs.Contains((string)tree["attr"]!);
        int met = 0;
        foreach (var c in Of(tree)) if (Satisfies(c, attrs)) met++;
        return met >= T(tree);
    }

    /// <summary>Every attribute the tree names, sorted (UTF-16 code unit order, as the reference sorts).</summary>
    public static List<string> PolicyAttributes(D tree)
    {
        var o = new SortedSet<string>(StringComparer.Ordinal);
        Collect(tree, o);
        return o.ToList();
    }

    static void Collect(D tree, ICollection<string> into)
    {
        if (IsLeaf(tree)) into.Add((string)tree["attr"]!);
        else foreach (var c in Of(tree)) Collect(c, into);
    }

    /// <summary>Leaf attributes in depth-first order (one span-program row each).</summary>
    internal static List<string> Leaves(D tree)
    {
        var o = new List<string>();
        Collect(tree, o);
        return o;
    }
}
