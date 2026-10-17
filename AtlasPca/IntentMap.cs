// Rule 19 (Intent Layer v2 V15): the committed Intent Map and the Z0 disclosure (packages/pca/src/intent-map-commit.ts
// commitMap / decideMapDisclosure), mirroring IntentMap.java. Every leaf is hashed with its own 32-byte salt and a per-kind tag
// (SHA-256(TAG_kind || r || strictCanonical(leaf))), nodes with TAG_NODE, the tree has the RFC 9162 shape and
// map_commit = base64url(SHA-256(TAG_COMMIT || u64be(n) || root)). The `map` check opens the action's header, cell and metrics
// leaves against the commitment and recomputes the cell of the action. Never throws.
using System.Text.RegularExpressions;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class IntentMap
{
    public const string MapTagHeader = "atlas-pca/intent-map/header/v1\0";
    public const string MapTagCell = "atlas-pca/intent-map/cell/v1\0";
    public const string MapTagMetrics = "atlas-pca/intent-map/metrics/v1\0";
    public const string MapTagLearner = "atlas-pca/intent-map/learner/v1\0";
    public const string MapTagNode = "atlas-pca/intent-map/node/v1\0";
    public const string MapTagCommit = "atlas-pca/intent-map/commit/v1\0";
    /// <summary>The <c>intent_session.map_form</c> value that selects the committed form.</summary>
    public const string MapFormCommit = "commit";
    /// <summary>The OTHER value of a categorical dimension (U+22A5).</summary>
    public const string MapOther = "⊥";
    public const long MaxMapLeaves = 1L << 24;
    public const long MaxVerbCells = 1L << 20;
    public const int MaxMapDims = 16;
    public const int MaxMapCuts = 256;
    public const int MaxMapValues = 256;
    public const int MaxMapStringBytes = 256;
    internal static readonly string[] MetricFields =
        { "residual_risk_ppm", "burden_ppm", "uncertainty_ppm", "disagreement_ppm", "mean_harm_ppm", "fidelity_est_ppm", "entropy_mbits", "questions", "conflicts" };
    static readonly Regex PathRe = new(@"^action\.params\.[A-Za-z0-9_]{1,64}\z", RegexOptions.CultureInvariant);

    /// <summary>The Z0 verdict: when <c>Ok</c>, the action's cell indices, its <c>p_ppm</c> and the committed residual risk.</summary>
    public sealed class Decision
    {
        public bool Ok { get; }
        public string? Reason { get; }
        public IReadOnlyList<long>? Cell { get; }
        public long PPpm { get; }
        public long ResidualRiskPpm { get; }
        internal Decision(bool ok, string? reason, IReadOnlyList<long>? cell, long pPpm, long risk) { Ok = ok; Reason = reason; Cell = cell; PPpm = pPpm; ResidualRiskPpm = risk; }
        internal static Decision Bad(string reason) => new(false, reason, null, 0, 0);
    }

    // ---- hashing ----
    static string TagOf(string kind) => kind switch
    {
        "header" => MapTagHeader,
        "cell" => MapTagCell,
        "metrics" => MapTagMetrics,
        "learner" => MapTagLearner,
        _ => throw new ArgumentException("unknown leaf kind"),
    };

    internal static byte[] U64be(long n)
    {
        var o = new byte[8];
        ulong x = (ulong)n;
        for (int i = 7; i >= 0; i--) { o[i] = (byte)(x & 0xff); x >>= 8; }
        return o;
    }

    /// <summary>SHA-256(TAG_kind || salt || strictCanonical(leaf)); throws on a leaf without a strict canonical form.</summary>
    public static byte[] LeafHash(string kind, byte[]? salt, object? leaf)
    {
        if (salt == null || salt.Length != 32) throw new ArgumentException("mapLeafHash: the salt is 32 bytes");
        return Pca.Sha256Of(IntentJs.Utf8(TagOf(kind)), salt, IntentJs.CanonBytes(leaf));
    }

    static byte[] NodeHash(byte[] l, byte[] r) => Pca.Sha256Of(IntentJs.Utf8(MapTagNode), l, r);
    static string CommitOf(long size, byte[] root) => Pca.B64u(Pca.Sha256Of(IntentJs.Utf8(MapTagCommit), U64be(size), root));

    static long Split(long n) { long k = 1; while (k * 2 < n) k *= 2; return k; }
    static byte[] TreeRoot(List<byte[]> hs)
    {
        if (hs.Count == 1) return hs[0];
        int k = (int)Split(hs.Count);
        return NodeHash(TreeRoot(hs.GetRange(0, k)), TreeRoot(hs.GetRange(k, hs.Count - k)));
    }

    /// <summary>The <c>primitives.intent_map_commit</c> entry point: the commitment of a full leaf list <c>[{kind, salt, leaf}]</c>.</summary>
    public static string CommitLeaves(object? leaves)
    {
        var ls = (L)IntentJs.Normalize(leaves)!;
        if (ls.Count == 0) throw new ArgumentException("mapTree: empty");
        var hs = ls.Select(l => LeafHash((string)IntentJs.Get(l, "kind")!, Pca.B64uDecode(IntentJs.Get(l, "salt"), 32), IntentJs.Get(l, "leaf"))).ToList();
        return CommitOf(hs.Count, TreeRoot(hs));
    }

    /// <summary>RFC 9162 §2.1.3.2 inclusion with this file's node hash: the root, or null when the path does not fit (index, size).</summary>
    internal static byte[]? RootFromPath(long index, long size, byte[] leafHash, List<byte[]> path)
    {
        if (!(index >= 0 && index < size)) return null;
        long fn = index, sn = size - 1;
        var r = leafHash;
        foreach (var p in path)
        {
            if (sn == 0) return null;
            if (fn % 2 == 1 || fn == sn)
            {
                r = NodeHash(p, r);
                if (fn % 2 == 0) while (fn % 2 == 0 && fn != 0) { fn /= 2; sn /= 2; }
            }
            else r = NodeHash(r, p);
            fn /= 2;
            sn /= 2;
        }
        return sn == 0 ? r : null;
    }

    // ---- leaf shapes (closed and typed) ----
    static bool IsStr(object? v, int max) => v is string s && !IntentJs.HasLoneSurrogate(s) && IntentJs.U8Len(s) <= max;
    static bool Closed(object? o, IReadOnlyCollection<string> allowed, IReadOnlyCollection<string> required)
    {
        var m = (D)o!;
        return m.Keys.All(allowed.Contains) && required.All(m.ContainsKey);
    }
    static bool IsDimPath(object? p) => p as string == "action.resource" || (p is string s && PathRe.IsMatch(s));
    static long Lng(object? o) => IntentJs.Lng(o);
    static double Num(object? o) => IntentJs.NumOf(o)!.Value;

    /// <summary>The cells of a numeric dimension as inclusive [lo, hi] ranges (empty ranges dropped).</summary>
    internal static List<(long Lo, long Hi)> NumCells(D d)
    {
        var o = new List<(long, long)>();
        long cur = Lng(d["lo"]);
        foreach (var co in (L)d["cuts"]!)
        {
            long c = Lng(co);
            if (cur <= c - 1) o.Add((cur, c - 1));
            o.Add((c, c));
            cur = c + 1;
        }
        long hi = Lng(d["hi"]);
        if (cur <= hi) o.Add((cur, hi));
        return o;
    }

    static long DimCells(D d) => d["kind"] as string == "num" ? NumCells(d).Count : ((L)d["values"]!).Count;

    static string? DimError(object? dO, int j)
    {
        if (dO is not D d) return $"dims[{j}] must be an object";
        switch (IntentJs.Get(d, "kind") as string)
        {
            case "num":
            {
                var ks = new[] { "kind", "path", "lo", "hi", "cuts" };
                if (!Closed(d, ks, ks)) return $"dims[{j}] must be exactly {{kind, path, lo, hi, cuts}}";
                if (!IsDimPath(d["path"]) || d["path"] as string == "action.resource") return $"dims[{j}].path must be action.params.<name>";
                if (!IntentJs.IsInt(d["lo"]) || !IntentJs.IsInt(d["hi"]) || Num(d["lo"]) > Num(d["hi"])) return $"dims[{j}] lo / hi must be safe integers with lo <= hi";
                if (d["cuts"] is not L cuts || cuts.Count > MaxMapCuts) return $"dims[{j}].cuts must be an array of at most {MaxMapCuts}";
                double prev = double.NegativeInfinity;
                foreach (var c in cuts)
                {
                    if (!IntentJs.IsInt(c) || Num(c) <= prev || Num(c) < Num(d["lo"]) || Num(c) > Num(d["hi"]))
                        return $"dims[{j}].cuts must be strictly increasing safe integers in [lo, hi]";
                    prev = Num(c);
                }
                return null;
            }
            case "cat":
            {
                var ks = new[] { "kind", "path", "values" };
                if (!Closed(d, ks, ks)) return $"dims[{j}] must be exactly {{kind, path, values}}";
                if (!IsDimPath(d["path"])) return $"dims[{j}].path must be action.resource or action.params.<name>";
                if (d["values"] is not L vs || vs.Count == 0 || vs.Count > MaxMapValues) return $"dims[{j}].values must be an array of 1..{MaxMapValues}";
                var seen = new HashSet<string>(StringComparer.Ordinal);
                var vk = new[] { "kind", "value" };
                for (int i = 0; i < vs.Count; i++)
                {
                    if (vs[i] is not D v || !Closed(v, vk, vk)) return $"dims[{j}].values[{i}] must be exactly {{kind, value}}";
                    var k = v["kind"] as string;
                    var value = v["value"];
                    if (v["kind"] is not string || k is not ("exact" or "prefix" or "other")) return $"dims[{j}].values[{i}].kind must be exact, prefix or other";
                    if (!IsStr(value, MaxMapStringBytes)) return $"dims[{j}].values[{i}].value must be a string of at most {MaxMapStringBytes} UTF-8 bytes";
                    bool bad = k == "other" ? i != vs.Count - 1 || (string)value! != MapOther : k == "prefix" && ((string)value!).Length == 0;
                    if (bad) return $"dims[{j}].values: exactly one other ('{MapOther}'), last; prefixes non-empty";
                    if (!seen.Add(k + ":" + (string)value!)) return $"dims[{j}].values must be distinct";
                }
                if (IntentJs.Get(vs[^1], "kind") as string != "other") return $"dims[{j}].values must end with the other value";
                return null;
            }
            default:
                return $"dims[{j}].kind must be num or cat";
        }
    }

    /// <summary>Shape of a header leaf (closed, typed; <c>cells</c> equals the product of the dimensions' cell counts). Null = well-formed.</summary>
    public static string? HeaderError(object? h)
    {
        var ks = new[] { "verb", "first", "cells", "dims" };
        if (h is not D m || !Closed(m, ks, ks)) return "the header leaf must be exactly {verb, first, cells, dims}";
        if (!IsStr(m["verb"], 128) || ((string)m["verb"]!).Length == 0) return "header.verb must be a non-empty string of at most 128 UTF-8 bytes";
        if (!IntentJs.IsNonNeg(m["first"]) || Num(m["first"]) >= MaxMapLeaves) return "header.first must be a leaf index";
        if (!IntentJs.IsInt(m["cells"]) || Num(m["cells"]) < 1 || Num(m["cells"]) > MaxVerbCells) return $"header.cells must be a safe integer in [1, {MaxVerbCells}]";
        if (m["dims"] is not L dims || dims.Count > MaxMapDims) return $"header.dims must be an array of at most {MaxMapDims}";
        var paths = new HashSet<string>(StringComparer.Ordinal);
        long n = 1;
        for (int j = 0; j < dims.Count; j++)
        {
            var e = DimError(dims[j], j);
            if (e != null) return "header." + e;
            var d = (D)dims[j]!;
            if (!paths.Add((string)d["path"]!)) return "header.dims paths must be distinct";
            n *= DimCells(d);
            if (n > MaxVerbCells) return "header: too many cells";
        }
        if (n != Num(m["cells"])) return "header.cells is not the product of the dimensions' cell counts";
        return null;
    }

    public static string? CellError(object? c)
    {
        var ks = new[] { "verb", "cell", "p_ppm", "in_grant" };
        if (c is not D m || !Closed(m, ks, ks)) return "the cell leaf must be exactly {verb, cell, p_ppm, in_grant}";
        if (!IsStr(m["verb"], 128) || ((string)m["verb"]!).Length == 0) return "cell.verb must be a non-empty string of at most 128 UTF-8 bytes";
        if (m["cell"] is not L cell || cell.Count > MaxMapDims || !cell.All(IntentJs.IsNonNeg)) return "cell.cell must be an array of non-negative safe integers";
        if (!IntentJs.IsNonNeg(m["p_ppm"]) || Num(m["p_ppm"]) > 1_000_000) return "cell.p_ppm must be a safe integer in [0, 1000000]";
        if (m["in_grant"] is not bool) return "cell.in_grant must be a boolean";
        return null;
    }

    public static string? MetricsError(object? mo)
    {
        var allowed = MetricFields.Append("log2_vs_mbits").ToArray();
        if (mo is not D m || !Closed(m, allowed, MetricFields)) return $"the metrics leaf must be exactly {{{string.Join(", ", MetricFields)}, log2_vs_mbits?}}";
        foreach (var k in allowed)
        {
            if (k == "log2_vs_mbits" && !m.ContainsKey(k)) continue;
            if (!IntentJs.IsNonNeg(m[k])) return $"metrics.{k} must be a non-negative safe integer";
        }
        return null;
    }

    public static string? LearnerError(object? l)
    {
        var ks = new[] { "learner_digest" };
        if (l is not D m || !Closed(m, ks, ks)) return "the learner leaf must be exactly {learner_digest}";
        return IntentJs.B32(m["learner_digest"]) ? null : "learner.learner_digest must be canonical base64url (32 bytes)";
    }

    /// <summary>Cell of ω under a well-formed header: (indices, flat), or null when a value lies outside its dimension.</summary>
    internal static (long[] Cell, long Flat)? CellOf(D header, object? resource, object? parameters)
    {
        var dims = (L)header["dims"]!;
        var cell = new long[dims.Count];
        long flat = 0;
        for (int j = 0; j < dims.Count; j++)
        {
            var d = (D)dims[j]!;
            var path = (string)d["path"]!;
            var name = path.StartsWith("action.params.", StringComparison.Ordinal) ? path.Substring("action.params.".Length) : path;
            bool present = path == "action.resource" || (parameters is D pm && pm.ContainsKey(name));
            object? x = path == "action.resource" ? resource : present ? ((D)parameters!)[name] : null;
            long i = -1;
            if (d["kind"] as string == "num")
            {
                if (present && IntentJs.IsInt(x))
                {
                    double v = Num(x);
                    var cs = NumCells(d);
                    for (int k = 0; k < cs.Count; k++) if (v >= cs[k].Lo && v <= cs[k].Hi) { i = k; break; }
                }
            }
            else if (present && x is string s && !IntentJs.HasLoneSurrogate(s))
            {
                var vs = (L)d["values"]!;
                int best = -1, bestLen = -1;
                for (int k = 0; k < vs.Count; k++)
                {
                    var vk = IntentJs.Get(vs[k], "kind") as string;
                    var vv = (string)IntentJs.Get(vs[k], "value")!;
                    if (vk == "exact" && string.Equals(vv, s, StringComparison.Ordinal)) { best = k; bestLen = int.MaxValue; break; }
                    if (vk == "prefix" && s.StartsWith(vv, StringComparison.Ordinal) && vv.Length > bestLen) { best = k; bestLen = vv.Length; }
                }
                i = best >= 0 ? best : vs.Count - 1;
            }
            if (i < 0) return null;
            cell[j] = i;
            flat = flat * DimCells(d) + i;
        }
        return (cell, flat);
    }

    static string? EntryShape(object? e, string what)
    {
        var ks = new[] { "index", "salt", "leaf", "path" };
        if (e is not D m || !Closed(m, ks, ks)) return $"disclosure.{what} must be exactly {{index, salt, leaf, path}}";
        if (!IntentJs.IsNonNeg(m["index"])) return $"disclosure.{what}.index must be a non-negative safe integer";
        if (!IntentJs.B32(m["salt"])) return $"disclosure.{what}.salt must be canonical base64url (32 bytes)";
        if (m["path"] is not L path || path.Count > 64 || !path.All(IntentJs.B32)) return $"disclosure.{what}.path must be an array of 32-byte digests";
        return null;
    }

    /// <summary>Shape of a Z0 disclosure (closed, typed). Null = well-formed.</summary>
    public static string? DisclosureError(object? d)
    {
        var ks = new[] { "size", "header", "cell", "metrics" };
        if (d is not D m || !Closed(m, ks, ks)) return "the disclosure must be exactly {size, header, cell, metrics}";
        if (!IntentJs.IsInt(m["size"]) || Num(m["size"]) < 4 || Num(m["size"]) > MaxMapLeaves) return $"disclosure.size must be a safe integer in [4, {MaxMapLeaves}]";
        foreach (var k in new[] { "header", "cell", "metrics" })
        {
            var e = EntryShape(m[k], k);
            if (e != null) return e;
        }
        return HeaderError(IntentJs.Get(m["header"], "leaf")) ?? CellError(IntentJs.Get(m["cell"], "leaf")) ?? MetricsError(IntentJs.Get(m["metrics"], "leaf"));
    }

    /// <summary>Does the disclosed entry <paramref name="e"/> (leaf kind <paramref name="kind"/>) open <paramref name="commit"/>?</summary>
    static bool Opens(string kind, object? e, long size, string commit)
    {
        try
        {
            var h = LeafHash(kind, Pca.B64uDecode(IntentJs.Get(e, "salt"), 32), IntentJs.Get(e, "leaf"));
            var path = ((L)IntentJs.Get(e, "path")!).Select(x => Pca.B64uDecode(x, 32)!).ToList();
            var root = RootFromPath(Lng(IntentJs.Get(e, "index")), size, h, path);
            return root != null && CommitOf(size, root) == commit;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>Z0, the <c>map</c> check (rule 19) over normalized values. <paramref name="paramsPresent"/> false = params absent
    /// ({}); <paramref name="eps"/> null = no ε. First failure wins; never throws.</summary>
    public static Decision Decide(object? mapCommit, object? action, bool paramsPresent, object? parameters, object? disclosure, double? eps)
    {
        try
        {
            var de = DisclosureError(disclosure);
            if (de != null) return Decision.Bad("map disclosure malformed: " + de);
            if (!IntentJs.B32(mapCommit)) return Decision.Bad("the PCActn carries no map commitment");
            var commit = (string)mapCommit!;
            if (paramsPresent && parameters is not D) return Decision.Bad("params must be an object");
            object ps = paramsPresent ? parameters! : new D();
            if (Pca.ParamsDigest(ps) != IntentJs.Get(action, "params_digest") as string) return Decision.Bad("the params do not hash to action.params_digest");
            var hd = IntentJs.Get(disclosure, "header");
            var cd = IntentJs.Get(disclosure, "cell");
            var md = IntentJs.Get(disclosure, "metrics");
            var h = (D)IntentJs.Get(hd, "leaf")!;
            long size = Lng(IntentJs.Get(disclosure, "size"));
            long first = Lng(h["first"]);
            if (IntentJs.Get(action, "verb") is not string verb || verb != (string)h["verb"]!) return Decision.Bad("the disclosed header is not the action's verb");
            if (!(Lng(IntentJs.Get(hd, "index")) < first) || !(first + Lng(h["cells"]) <= size - 2)) return Decision.Bad("the disclosed header does not fit the committed layout");
            if (!Opens("header", hd, size, commit)) return Decision.Bad("the header leaf does not open the map commitment");
            if (!Opens("cell", cd, size, commit)) return Decision.Bad("the cell leaf does not open the map commitment");
            if (!Opens("metrics", md, size, commit)) return Decision.Bad("the metrics leaf does not open the map commitment");
            var w = CellOf(h, IntentJs.Get(action, "resource"), ps);
            if (w == null) return Decision.Bad("the action's value lies outside the committed map's dimension");
            var c = (D)IntentJs.Get(cd, "leaf")!;
            var cc = (L)c["cell"]!;
            bool same = Lng(IntentJs.Get(cd, "index")) == first + w.Value.Flat && (string)c["verb"]! == (string)h["verb"]! && cc.Count == w.Value.Cell.Length;
            if (same) for (int i = 0; i < cc.Count; i++) if (Lng(cc[i]) != w.Value.Cell[i]) same = false;
            if (!same) return Decision.Bad("the disclosed cell is not the action's cell");
            if (c["in_grant"] is not true) return Decision.Bad("the action's cell is outside the committed grant");
            if (Lng(IntentJs.Get(md, "index")) != size - 2) return Decision.Bad("the disclosed metrics leaf is not at its committed position");
            long risk = Lng(IntentJs.Get(IntentJs.Get(md, "leaf"), "residual_risk_ppm"));
            if (eps is double ep && !(risk <= ep)) return Decision.Bad($"the committed residual risk {risk} ppm exceeds ε = {(long)ep}");
            return new Decision(true, null, w.Value.Cell.ToList(), Lng(c["p_ppm"]), risk);
        }
        catch (Exception e)
        {
            return Decision.Bad("map error (fail closed): " + e.GetType().Name);
        }
    }

    /// <summary>The <c>primitives.intent_map</c> entry point: <c>{map_commit, action, params?, disclosure, max_residual_risk_ppm?}</c>
    /// (params absent = {}; ε absent = none).</summary>
    public static Decision DecidePrimitive(object? input)
    {
        try
        {
            var inp = (D)IntentJs.Normalize(input)!;
            bool epsPresent = inp.ContainsKey("max_residual_risk_ppm");
            double? eps = epsPresent ? IntentJs.NumOf(inp["max_residual_risk_ppm"]) : null;
            if (epsPresent && eps == null) return Decision.Bad("max_residual_risk_ppm must be a number");
            return Decide(IntentJs.Get(inp, "map_commit"), inp.TryGetValue("action", out var a) ? a : new D(),
                inp.ContainsKey("params"), IntentJs.Get(inp, "params"), IntentJs.Get(inp, "disclosure"), eps);
        }
        catch (Exception e)
        {
            return Decision.Bad("map error (fail closed): " + e.GetType().Name);
        }
    }
}
