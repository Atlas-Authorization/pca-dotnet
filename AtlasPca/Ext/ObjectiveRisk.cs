// The objective risk functional. Every input of the heuristic risk r is a pure function of COMMITTED facts and of the CANONICAL ACTION (verb + resource + params, canonicalized like the
// PCActn). Nothing the agent merely asserts (features, labels, scope, confidence) is read. Agent and verifier recompute the same r; the grant commits the registry, graph, embedder and
// goal, and a mismatch fails closed (r = 1, valid: false). The result feeds the existing risk score, so the decision core sees the unchanged risk-input shape.
//
// Reversibility comes from a committed registry of verified inverses, the blast radius from reachability over a committed resource graph, the semantic distance from a committed integer
// embedding (a native n-gram feature hash, or a customer model meeting a determinism contract) against a committed goal vector, and the whole can be conformally calibrated.
//
// The digests here are SERVER-ONLY and carry high-precision floats (calibration scores, graph harm weights, risk inputs), so they use the LENIENT canonical hash, not the strict protocol
// one. Values are JSON trees (Dictionary<string, object?>, List<object?>, string, bool, Num); a non-finite number in a tree is a double. Two orders are used: UTF-16 code-unit order for
// verbs, ids and kinds, UTF-8 byte order for the keys of canonical JSON and of parameter leaves. Only IEEE multiplication, addition, division and square root are used in the distance.
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>A committed registry of verified inverse actions: which verb can be undone by which inverse kind, and who verified it.</summary>
public interface IInverseRegistry
{
    /// <summary>The entry registered for exactly this verb (a copy), or null.</summary>
    D? Lookup(string verb);

    /// <summary>The verifier ids whose verification counts; committed as part of the digest.</summary>
    IReadOnlyList<string> TrustedVerifiers();

    /// <summary>The canonical digest of ALL contents; the grant commits this.</summary>
    string Digest();
}

/// <summary>The in-process registry. An entry is <c>{inverseKind, fidelity: exact | partial, verification?: {verifierId, evidenceDigest}}</c>.</summary>
public sealed class InMemoryInverseRegistry : IInverseRegistry
{
    readonly Dictionary<string, D> _m = new(StringComparer.Ordinal);
    readonly List<string> _trusted;

    /// <summary>The trusted verifier ids: de-duplicated and sorted.</summary>
    public InMemoryInverseRegistry(IEnumerable<string>? trustedVerifiers = null)
    {
        _trusted = (trustedVerifiers ?? Array.Empty<string>()).Distinct(StringComparer.Ordinal).ToList();
        _trusted.Sort(StringComparer.Ordinal);
    }

    /// <summary>Registers the entry for <paramref name="verb"/> (a later entry for the same verb replaces the earlier); the entry is copied.</summary>
    public InMemoryInverseRegistry Register(string verb, D entry)
    {
        var c = new D(entry);
        if (entry.GetValueOrDefault("verification") is D v) c["verification"] = new D(v);
        _m[verb] = c;
        return this;
    }

    public D? Lookup(string verb) => _m.TryGetValue(verb, out var e) ? new D(e) : null;

    public IReadOnlyList<string> TrustedVerifiers() => _trusted;

    public string Digest()
    {
        var entries = new L();
        foreach (var verb in _m.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            var e = _m[verb];
            entries.Add(new D
            {
                ["verb"] = verb, ["inverseKind"] = ObjectiveRisk.Member(e, "inverseKind"), ["fidelity"] = ObjectiveRisk.Member(e, "fidelity"),
                ["verification"] = e.GetValueOrDefault("verification"),
            });
        }
        return ObjectiveRisk.Hash(new D { ["v"] = IntentJs.OfLong(1), ["trusted"] = new L(_trusted.Cast<object?>()), ["entries"] = entries });
    }
}

/// <summary>An adjacency model of resources with a content digest the grant commits. A node is <c>{id, harm?: {unit: number}}</c>, an edge <c>{from, to, kind}</c>. Node ids are strings.</summary>
public sealed class ResourceGraph
{
    readonly Dictionary<string, D> _nodes = new(StringComparer.Ordinal);
    readonly Dictionary<string, List<D>> _out = new(StringComparer.Ordinal);

    static string IdOf(object? n) => ObjectiveRisk.Member(n, "id") as string ?? throw new ArgumentException("resource node id must be a string");

    /// <summary>Adds a node; the same id again replaces the node but keeps its edges.</summary>
    public ResourceGraph AddNode(D n)
    {
        var id = IdOf(n);
        _nodes[id] = n;
        if (!_out.ContainsKey(id)) _out[id] = new List<D>();
        return this;
    }

    /// <summary>Adds an edge; both endpoints must already be nodes (an unknown one is refused).</summary>
    public ResourceGraph AddEdge(D e)
    {
        if (ObjectiveRisk.Member(e, "from") is not string f || ObjectiveRisk.Member(e, "to") is not string t || !_nodes.ContainsKey(f) || !_nodes.ContainsKey(t))
            throw new InvalidOperationException("edge endpoints must exist");
        _out[f].Add(e);
        return this;
    }

    public int Size => _nodes.Count;

    /// <summary>The node with this id (as it was added), or null.</summary>
    public D? Node(string id) => _nodes.GetValueOrDefault(id);

    /// <summary>The ids reachable from <paramref name="start"/> (itself included), breadth first, sorted by UTF-16 code units. <paramref name="scope"/> may restrict the edge kinds
    /// (<c>edgeKinds</c>) and the depth (<c>maxDepth</c>: absent or null is unbounded, 0 is just the start). An unknown start reaches nothing.</summary>
    public List<string> Reachable(string start, object? scope = null)
    {
        if (!_nodes.ContainsKey(start)) return new List<string>();
        var ek = ObjectiveRisk.Member(scope, "edgeKinds");
        HashSet<string>? kinds = Jx.Truthy(ek) ? (ek is L kl ? kl.OfType<string>().ToHashSet(StringComparer.Ordinal) : new HashSet<string>()) : null;
        var md = ObjectiveRisk.Member(scope, "maxDepth");
        var maxDepth = md == null || Jx.IsUndef(md) ? double.PositiveInfinity : Jx.ToNumber(md);
        var seen = new HashSet<string>(StringComparer.Ordinal) { start };
        var frontier = new List<string> { start };
        for (double d = 0; d < maxDepth && frontier.Count > 0; d++)
        {
            var next = new List<string>();
            foreach (var u in frontier)
                foreach (var e in _out[u])
                    if (ObjectiveRisk.Member(e, "to") is string to && (kinds == null || (ObjectiveRisk.Member(e, "kind") is string k && kinds.Contains(k))) && seen.Add(to)) next.Add(to);
            frontier = next;
        }
        var r = seen.ToList();
        r.Sort(StringComparer.Ordinal);
        return r;
    }

    public string Digest()
    {
        var n = new L(_nodes.Values.OrderBy(x => IdOf(x), StringComparer.Ordinal).Select(x =>
            (object?)new D { ["id"] = x["id"], ["harm"] = x.GetValueOrDefault("harm") ?? new D() }));
        var edges = _out.Values.SelectMany(l => l).Select(x => new D { ["from"] = x["from"], ["to"] = x["to"], ["kind"] = ObjectiveRisk.Member(x, "kind") })
            .OrderBy(x => JsX.Str(x["from"]) + "\0" + JsX.Str(x["to"]) + "\0" + JsX.Str(x["kind"]), StringComparer.Ordinal).Select(x => (object?)x);
        return ObjectiveRisk.Hash(new D { ["v"] = IntentJs.OfLong(1), ["n"] = n, ["e"] = new L(edges) });
    }
}

/// <summary>An embedder maps the CANONICAL ACTION to an integer vector; it never sees agent-supplied features. <see cref="ModelId"/> is a committed identity: a hash of the config (native) or of
/// the model descriptor (customer model), so two embedders with different behaviour cannot share an id.</summary>
public interface IEmbedder
{
    string ModelId { get; }

    /// <summary>The committed descriptor behind the model id (the native config or the customer model descriptor).</summary>
    object? Config { get; }

    double Dims { get; }

    /// <summary>The vector for a canonical action: it MUST be <see cref="Dims"/> safe integers, deterministic for equal canonical actions. May throw.</summary>
    object? Embed(D canonicalAction);
}

/// <summary>An embedding or vector the objective risk refuses.</summary>
public sealed class EmbeddingError : Exception
{
    public EmbeddingError(string message) : base(message) { }
}

/// <summary>What the objective risk is computed against: the committed facts the verifier holds and the verifier-supplied signals.</summary>
public sealed class ObjectiveRiskContext
{
    public IInverseRegistry Registry { get; set; } = null!;
    /// <summary>The inverse kinds the capability authorizes.</summary>
    public ISet<string> AuthorizedKinds { get; set; } = new HashSet<string>();
    public ResourceGraph Graph { get; set; } = null!;
    /// <summary>The capability's scope <c>{edgeKinds?, maxDepth?}</c> (from the grant, never from the agent), or null.</summary>
    public D? Scope { get; set; }
    public IEmbedder Embedder { get; set; } = null!;
    /// <summary>The goal commitment (see <see cref="ObjectiveRisk.CommitGoal"/>).</summary>
    public object? Goal { get; set; }
    /// <summary>The digests the grant committed: <c>{registryDigest, graphDigest, calibrationDigest?}</c>.</summary>
    public object? Commitments { get; set; }
    /// <summary>The harm currencies <c>[{id, ceiling, weight}]</c>.</summary>
    public L Denominations { get; set; } = new();
    /// <summary>The risk weights <c>{alpha, beta, gamma, delta, epsilon, zeta}</c>.</summary>
    public object? Weights { get; set; }
    /// <summary>The verifier-computed information-flow taint; a value that is not a finite number is the worst case 1.</summary>
    public object? Taint { get; set; }
    /// <summary>The normalized age since the last human touch; a value that is not a finite number is the worst case 1.</summary>
    public object? Age { get; set; }
    /// <summary>The attested uncertainty in [0, 1] (higher is more uncertain); it can only RAISE the risk. Null means none.</summary>
    public object? AttestedUncertainty { get; set; }
    /// <summary>The committed benign raw scores; the risk then becomes the conformally calibrated value. Null means no calibration.</summary>
    public L? Calibration { get; set; }
}

/// <summary>The native embedder: code-point n-grams and word tokens of the verb, the resource and every flattened param leaf, each feature feature-hashed with SHA-256 into a signed bucket.</summary>
public sealed class NativeHashEmbedder : IEmbedder
{
    readonly int _dims, _nmin, _nmax;
    readonly long _wVerb, _wResource, _wParam;
    readonly byte[] _prefix;
    readonly double _cap;
    readonly bool _digestMode;

    public string ModelId { get; }
    public object? Config { get; }
    public double Dims => _dims;

    internal NativeHashEmbedder(object? config)
    {
        ObjectiveRisk.ValidateNativeConfig(config);
        var c = (D)config!;
        var fw = (D)c["fieldWeights"]!;
        var committed = new D { ["scheme"] = ObjectiveRisk.NativeScheme };
        foreach (var (k, v) in c) committed[k] = k == "fieldWeights" ? new D(fw) : v;
        Config = committed;
        ModelId = "native:" + ObjectiveRisk.Hash(committed);
        _dims = (int)Jx.Fin(c["dims"])!.Value;
        _nmin = (int)Jx.Fin(c["ngramMin"])!.Value;
        _nmax = (int)Jx.Fin(c["ngramMax"])!.Value;
        _prefix = Encoding.UTF8.GetBytes((string)c["seed"]! + "\u001f");
        _wVerb = (long)Jx.Fin(fw["verb"])!.Value;
        _wResource = (long)Jx.Fin(fw["resource"])!.Value;
        _wParam = (long)Jx.Fin(fw["param"])!.Value;
        _cap = c.TryGetValue("maxParamLeaves", out var mp) ? Jx.Fin(mp)!.Value : ObjectiveRisk.DefaultMaxParamLeaves;
        _digestMode = c.TryGetValue("paramMode", out var pm) && pm is "digest";
    }

    // flatten params to `path=value` leaves, keys walked in UTF-8 order (nested key order and array encoding are irrelevant)
    static void ParamLeaves(object? v, string path, List<string> output)
    {
        if (v is L l) { for (int i = 0; i < l.Count; i++) ParamLeaves(l[i], $"{path}[{i}]", output); }
        else if (v is D m) { foreach (var k in IntentJs.SortedUtf8(m.Keys)) ParamLeaves(m[k], path.Length > 0 ? $"{path}.{k}" : k, output); }
        else output.Add($"{path}={ObjectiveRisk.Canon(v)}");
    }

    static IEnumerable<string> TextFeatures(string prefix, string text, int nmin, int nmax)
    {
        var cps = ("\u0002" + text + "\u0003").EnumerateRunes().Select(r => r.ToString()).ToArray(); // code points, with boundary markers
        for (int n = nmin; n <= nmax; n++)
            for (int i = 0; i + n <= cps.Length; i++) yield return $"{prefix}c{n}:{string.Concat(cps.Skip(i).Take(n))}";
        var word = new StringBuilder();
        var words = new List<string>();
        foreach (var r in text.EnumerateRunes())
        {
            if (Rune.IsLetter(r) || Rune.IsNumber(r)) word.Append(r.ToString());
            else if (word.Length > 0) { words.Add(word.ToString()); word.Clear(); }
        }
        if (word.Length > 0) words.Add(word.ToString());
        foreach (var w in words) yield return $"{prefix}w:{ObjectiveRisk.ToLowerJs(w)}";
    }

    public object? Embed(D canonicalAction)
    {
        var v = new long[_dims];
        void Add(string feat, long w)
        {
            if (w == 0) return;
            var f = Encoding.UTF8.GetBytes(feat);
            var buf = new byte[_prefix.Length + f.Length];
            _prefix.CopyTo(buf, 0);
            f.CopyTo(buf, _prefix.Length);
            var h = SHA256.HashData(buf);
            var bucket = (int)((((uint)h[0] << 24) | ((uint)h[1] << 16) | ((uint)h[2] << 8) | h[3]) % (uint)_dims);
            v[bucket] += (h[4] & 1) == 0 ? w : -w;
        }
        var verb = Jx.Prop(canonicalAction, "verb");
        var resource = Jx.Prop(canonicalAction, "resource");
        var prms = Jx.Prop(canonicalAction, "params");
        foreach (var f in TextFeatures("v:", (string)verb!, _nmin, _nmax)) Add(f, _wVerb);
        foreach (var f in TextFeatures("r:", (string)resource!, _nmin, _nmax)) Add(f, _wResource);
        var leaves = new List<string>();
        ParamLeaves(prms, "", leaves);
        // fail CLOSED on a param-stuffed action: more leaves than the cap can never produce a (diluted) favorable embedding
        if (leaves.Count > _cap) throw new EmbeddingError($"param leaf count {leaves.Count} exceeds cap {JsX.JsNumString(_cap)}");
        if (_digestMode)
            // the whole params object is bound to ONE digest token, so stuffing params cannot flood or dilute the vector
            Add("p#:" + ObjectiveRisk.Hash(new D { ["t"] = "pca-objrisk-params-v1", ["params"] = prms }), _wParam);
        else
            foreach (var leaf in leaves)
                foreach (var f in TextFeatures("p:", leaf, _nmin, _nmax)) Add(f, _wParam);
        return new L(v.Select(x => (object?)IntentJs.OfLong(x)));
    }
}

sealed class ByoEmbedderImpl : IEmbedder
{
    readonly Func<string, object?> _infer;
    readonly double _qmax;
    public string ModelId { get; }
    public object? Config { get; }
    public double Dims { get; }

    internal ByoEmbedderImpl(object? descriptor, Func<string, object?> infer, string? claimedModelId)
    {
        _infer = infer;
        var dims = Jx.Prop(descriptor, "dims");
        if (!IntentJs.IsSafeInteger(dims) || IntentJs.NumOf(dims)! < 1) throw new ArgumentException("byo: dims must be a positive integer");
        var q = Jx.Prop(descriptor, "quantization");
        var bits = Jx.Prop(q, "bits");
        if (!IntentJs.IsSafeInteger(bits) || IntentJs.NumOf(bits)! < 2 || IntentJs.NumOf(bits)! > 31 || !(Jx.ToNumber(Jx.Prop(q, "scale")) > 0)) throw new ArgumentException("byo: invalid quantization");
        if (Jx.Prop(descriptor, "inputEncoding") is not "pca-canonical-action-json-v1") throw new ArgumentException("byo: unsupported inputEncoding");
        ModelId = ObjectiveRisk.ByoModelId(descriptor);
        if (claimedModelId != null && claimedModelId != ModelId) throw new InvalidOperationException("byo: modelId does not match the committed descriptor");
        _qmax = Math.Pow(2, IntentJs.NumOf(bits)!.Value - 1) - 1;
        Config = descriptor;
        Dims = IntentJs.NumOf(dims)!.Value;
    }

    public object? Embed(D canonicalAction)
    {
        var v = ObjectiveRisk.ValidateVector(_infer(ObjectiveRisk.CanonicalActionJson(canonicalAction)), Dims);
        foreach (var x in v) if (Math.Abs(IntentJs.NumOf(x)!.Value) > _qmax) throw new EmbeddingError("byo: component exceeds declared quantization range");
        return v;
    }
}

public static class ObjectiveRisk
{
    /// <summary>The metric of a goal commitment: the half-chord distance sqrt((1 - cos) / 2).</summary>
    public const string Metric = "half-chord-v1";
    /// <summary>The default rounding grid of distances: 1/4096.</summary>
    public const double DefaultEpsilon = 1.0 / 4096;
    public const string NativeScheme = "pca-native-hash-ngram-v1";
    /// <summary>The protocol cap on flattened param leaves, enforced even when a config omits <c>maxParamLeaves</c>.</summary>
    public const int DefaultMaxParamLeaves = 256;

    /// <summary>The default native embedder config: 256 dims, n-grams 2..4, seed <c>pca-native-v1</c>, field weights verb 4 / resource 2 / param 1.</summary>
    public static D DefaultNativeConfig() => new()
    {
        ["dims"] = IntentJs.OfLong(256), ["ngramMin"] = IntentJs.OfLong(2), ["ngramMax"] = IntentJs.OfLong(4), ["seed"] = "pca-native-v1",
        ["fieldWeights"] = new D { ["verb"] = IntentJs.OfLong(4), ["resource"] = IntentJs.OfLong(2), ["param"] = IntentJs.OfLong(1) },
    };

    // ---- helpers ----

    internal static object? Member(object? o, string k) => o is D m && m.TryGetValue(k, out var v) ? v : Jx.Undef;

    static double Clamp01(double x) => double.IsFinite(x) ? (x < 0 ? 0 : x > 1 ? 1 : x) : 1;

    static object Nm(double d) => Jx.NumOut(d);

    // why a tree has no canonical form: the first value, in the order of the encoder, that has none
    static string? Failure(object? v)
    {
        switch (v)
        {
            case null: case bool: case string: return null;
            case L l: foreach (var x in l) if (Failure(x) is { } f) return f; return null;
            case D m: foreach (var k in IntentJs.SortedUtf8(m.Keys)) if (Failure(m[k]) is { } f) return f; return null;
        }
        if (Jx.IsUndef(v)) return "canonicalize: unsupported type undefined";
        return IntentJs.NumOf(v) is double d && double.IsFinite(d) ? null : "canonicalize: non-finite number";
    }

    /// <summary>The lenient canonical text of a tree (keys in UTF-8 order, any finite number as ECMAScript prints it); throws when there is none.</summary>
    internal static string Canon(object? v) => JsCanon.Lenient(v) ?? throw new InvalidOperationException(Failure(v) ?? "canonicalize: unsupported value");

    /// <summary>base64url(SHA-256(lenient canonical text)).</summary>
    internal static string Hash(object? v) => Pca.B64u(Pca.Sha(Encoding.UTF8.GetBytes(Canon(v))));

    static string Nfc(string s)
    {
        try { return s.Normalize(NormalizationForm.FormC); }
        catch (ArgumentException) { return s; } // shortcut: a string with a lone surrogate is kept as it is, as String.prototype.normalize keeps it
    }

    // Cased and Case_Ignorable for the final-sigma rule
    static bool Cased(Rune r) => Rune.GetUnicodeCategory(r) is UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter or UnicodeCategory.TitlecaseLetter;

    static bool CaseIgnorable(Rune r) =>
        Rune.GetUnicodeCategory(r) is UnicodeCategory.NonSpacingMark or UnicodeCategory.EnclosingMark or UnicodeCategory.Format or UnicodeCategory.ModifierLetter or UnicodeCategory.ModifierSymbol
        || r.Value is 0x27 or 0x2E or 0x3A or 0xB7 or 0x387 or 0x55F or 0x5F4 or 0x2018 or 0x2019 or 0x2024 or 0x2027 or 0xFE13 or 0xFE52 or 0xFE55 or 0xFF07 or 0xFF0E or 0xFF1A;

    /// <summary>JavaScript's <c>toLowerCase</c>: the locale-independent full Unicode mapping. U+0130 becomes <c>i</c> + U+0307 and a capital sigma becomes the final sigma at the end of a word.</summary>
    internal static string ToLowerJs(string s)
    {
        var runes = s.EnumerateRunes().ToArray();
        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < runes.Length; i++)
        {
            var r = runes[i];
            if (r.Value == 0x130) sb.Append("i\u0307");
            else if (r.Value == 0x3A3)
            {
                int a = i - 1;
                while (a >= 0 && CaseIgnorable(runes[a])) a--;
                int b = i + 1;
                while (b < runes.Length && CaseIgnorable(runes[b])) b++;
                sb.Append(a >= 0 && Cased(runes[a]) && !(b < runes.Length && Cased(runes[b])) ? 'ς' : 'σ');
            }
            else sb.Append(Rune.ToLowerInvariant(r).ToString());
        }
        return sb.ToString();
    }

    /// <summary>The constants of the module.</summary>
    public static D Constants() => new()
    {
        ["METRIC"] = Metric, ["DEFAULT_EPSILON"] = Nm(DefaultEpsilon), ["NATIVE_SCHEME"] = NativeScheme, ["DEFAULT_MAX_PARAM_LEAVES"] = IntentJs.OfLong(DefaultMaxParamLeaves),
        ["DEFAULT_NATIVE_CONFIG"] = DefaultNativeConfig(),
    };

    // ---- canonical action ----

    static object? NormValue(object? v)
    {
        switch (v)
        {
            case string s: return Nfc(s);
            case L l: return new L(l.Select(NormValue));
            case D m:
                var o = new D();
                foreach (var (k, x) in m)
                {
                    var nk = Nfc(k);
                    if (o.ContainsKey(nk)) throw new InvalidOperationException("canonicalAction: duplicate key after NFC normalization");
                    o[nk] = NormValue(x);
                }
                return o;
            default: return v;
        }
    }

    /// <summary>The canonical form <c>{verb, resource, params}</c>: verb NFC, trimmed and lowercased, resource NFC and trimmed, every string and key of the params NFC, the whole checked for a stable encoding.
    /// Re-encodings that do not change the action (key order, NFC / NFD, verb case) collapse to one form. Only these three members are read. Throws on anything without a stable encoding.</summary>
    public static D CanonicalAction(object? a)
    {
        if (Member(a, "verb") is not string v || Member(a, "resource") is not string r) throw new InvalidOperationException("canonicalAction: verb/resource must be strings");
        var verb = ToLowerJs(Nfc(v).Trim(Actions.JsSpace));
        var resource = Nfc(r).Trim(Actions.JsSpace);
        if (verb.Length == 0 || resource.Length == 0) throw new InvalidOperationException("canonicalAction: empty verb/resource");
        var raw = Member(a, "params");
        var prms = NormValue(raw == null || Jx.IsUndef(raw) ? new D() : raw);
        if (prms is not D) throw new InvalidOperationException("canonicalAction: params must be an object");
        var c = new D { ["verb"] = verb, ["resource"] = resource, ["params"] = prms };
        Canon(c); // validate
        return c;
    }

    /// <summary>The canonical text of a canonical action.</summary>
    public static string CanonicalActionJson(object? c) => Canon(c);

    /// <summary>The digest of a canonical action.</summary>
    public static string CanonicalActionDigest(object? c) => Hash(c);

    // ---- 1. reversibility ----

    /// <summary>Reversible iff the registry holds an inverse whose verification came from a TRUSTED verifier AND the inverse kind is itself authorized by the capability; anything else is
    /// irreversible. <c>{class: reversible | compensable | irreversible, value: 1 | 0.5 | 0, inverseKind?}</c>: an exact inverse is reversible, any other fidelity compensable.</summary>
    public static D Reversibility(object? action, IInverseRegistry registry, ISet<string> authorizedKinds)
    {
        var verb = Jx.Prop(action, "verb");
        var e = verb is string vs ? registry.Lookup(vs) : null;
        var vf = e == null ? null : e.GetValueOrDefault("verification");
        var trusted = Jx.Truthy(vf) && Member(vf, "verifierId") is string id && registry.TrustedVerifiers().Contains(id);
        if (e == null || !trusted || Member(e, "inverseKind") is not string kind || !authorizedKinds.Contains(kind))
            return new D { ["class"] = "irreversible", ["value"] = IntentJs.OfLong(0) };
        return Member(e, "fidelity") is "exact"
            ? new D { ["class"] = "reversible", ["value"] = IntentJs.OfLong(1), ["inverseKind"] = kind }
            : new D { ["class"] = "compensable", ["value"] = Nm(0.5), ["inverseKind"] = kind };
    }

    // ---- 2. blast radius ----

    /// <summary><c>{count, reachable, normalized, harm}</c>: the resources reachable from the action's resource, their share of the graph (an unknown resource or an empty graph is 1, fail closed)
    /// and the harm summed per denomination over the reachable nodes (only finite values above 0 count).</summary>
    public static D BlastRadius(object? action, ResourceGraph graph, object? scope = null)
    {
        var res = Jx.Prop(action, "resource");
        var reachable = res is string rs ? graph.Reachable(rs, scope) : new List<string>();
        if (reachable.Count == 0 || graph.Size == 0)
            return new D { ["count"] = IntentJs.OfLong(0), ["reachable"] = new L(reachable.Cast<object?>()), ["normalized"] = IntentJs.OfLong(1), ["harm"] = new D() };
        // tallied per dimension in the order dimensions are first seen; a name like __proto__ or constructor is an ordinary key
        var harm = new List<KeyValuePair<string, double>>();
        foreach (var id in reachable)
            if (graph.Node(id)?.GetValueOrDefault("harm") is D units)
                foreach (var (d, v) in units)
                    if (Jx.Fin(v) is double x && x > 0)
                    {
                        var i = harm.FindIndex(p => p.Key == d);
                        if (i >= 0) harm[i] = new(d, harm[i].Value + x); else harm.Add(new(d, x));
                    }
        var h = new D();
        foreach (var (d, v) in harm) h[d] = Nm(v);
        return new D { ["count"] = IntentJs.OfLong(reachable.Count), ["reachable"] = new L(reachable.Cast<object?>()), ["normalized"] = Nm((double)reachable.Count / graph.Size), ["harm"] = h };
    }

    // ---- 3. committed embeddings ----

    static double MaxComponent(double dims) => Math.Floor(Math.Sqrt(JsX.MaxSafe / (2 * Math.Max(1, dims))));

    /// <summary>The vector as safe integers (a negative zero becomes 0), or throws <see cref="EmbeddingError"/>: it must be a list of exactly <paramref name="dims"/> safe integers, each at most
    /// floor(sqrt((2^53 - 1) / (2 * max(1, dims)))) in magnitude (so dot products of two such vectors stay exact in a double).</summary>
    public static L ValidateVector(object? v, double dims)
    {
        if (v is not L l || l.Count != dims) throw new EmbeddingError($"vector must have exactly {JsX.JsNumString(dims)} components");
        var lim = MaxComponent(dims);
        foreach (var x in l)
        {
            if (!IntentJs.IsSafeInteger(x)) throw new EmbeddingError("vector components must be safe integers");
            if (Math.Abs(IntentJs.NumOf(x)!.Value) > lim) throw new EmbeddingError("vector component out of range");
        }
        return new L(l.Select(x => (object?)IntentJs.OfLong((long)IntentJs.NumOf(x)!.Value)));
    }

    static bool OkInt(object? x, double lo, double hi) => IntentJs.IsSafeInteger(x) && IntentJs.NumOf(x)! >= lo && IntentJs.NumOf(x)! <= hi;

    internal static void ValidateNativeConfig(object? c)
    {
        if (!OkInt(Jx.Prop(c, "dims"), 8, 65536)) throw new ArgumentException("native config: dims must be an integer in [8, 65536]");
        var nmin = Jx.Prop(c, "ngramMin");
        if (!OkInt(nmin, 1, 8) || !OkInt(Jx.Prop(c, "ngramMax"), IntentJs.NumOf(nmin)!.Value, 8)) throw new ArgumentException("native config: need 1 <= ngramMin <= ngramMax <= 8");
        if (Jx.Prop(c, "seed") is not string { Length: > 0 }) throw new ArgumentException("native config: seed required");
        var fw = Jx.Prop(c, "fieldWeights");
        foreach (var k in new[] { "verb", "resource", "param" })
            if (!OkInt(Jx.Prop(fw, k), 0, 1000)) throw new ArgumentException($"native config: fieldWeights.{k} must be an integer in [0, 1000]");
        var mp = Jx.Prop(c, "maxParamLeaves");
        if (!Jx.IsUndef(mp) && !OkInt(mp, 1, 1_000_000)) throw new ArgumentException("native config: maxParamLeaves must be an integer in [1, 1000000]");
        var pm = Jx.Prop(c, "paramMode");
        if (!Jx.IsUndef(pm) && pm is not ("leaves" or "digest")) throw new ArgumentException("native config: paramMode must be 'leaves' or 'digest'");
    }

    /// <summary>The native embedder over <paramref name="config"/> (default: <see cref="DefaultNativeConfig"/>): <c>{dims 8..65536, ngramMin, ngramMax (1 &lt;= min &lt;= max &lt;= 8), seed, fieldWeights
    /// {verb, resource, param} (integers 0..1000), maxParamLeaves? (1..1e6), paramMode? (leaves | digest)}</c>. Each feature f of a field is hashed as SHA-256(seed, 0x1F, f): the bucket is the big-endian
    /// u32 of bytes 0..3 modulo dims, the sign the low bit of byte 4, and the bucket accumulates plus or minus the field weight. Throws on an invalid config.</summary>
    public static IEmbedder NativeEmbedder(object? config = null) => new NativeHashEmbedder(config ?? DefaultNativeConfig());

    /// <summary>The model id of a customer model descriptor: <c>byo:</c> and its hash.</summary>
    public static string ByoModelId(object? descriptor) => "byo:" + Hash(descriptor);

    /// <summary>A customer-supplied model that meets the determinism contract: <paramref name="descriptor"/> is <c>{name, version, weightsDigest, runtime, dims, quantization: {bits 2..31, scale &gt; 0},
    /// inputEncoding: "pca-canonical-action-json-v1"}</c>; <paramref name="infer"/> receives the canonical action text and returns the integer vector. A claimed model id must equal the descriptor hash.
    /// Throws on a bad descriptor or claim; its <c>Embed</c> throws on a bad vector or a component beyond the quantization range.</summary>
    public static IEmbedder ByoEmbedder(object? descriptor, Func<string, object?> infer, string? claimedModelId = null) => new ByoEmbedderImpl(descriptor, infer, claimedModelId);

    /// <summary>Runs conformance cases (<c>{action, vector}</c>) shipped with a model: true iff every one reproduces exactly; any failure is false.</summary>
    public static bool ConformanceCheck(IEmbedder e, L cases)
    {
        try
        {
            foreach (var c in cases)
            {
                var v = e.Embed(CanonicalAction(Jx.Prop(c, "action")));
                if (v is not L vl || Jx.Prop(c, "vector") is not L cv || vl.Count != cv.Count) return false;
                for (int i = 0; i < vl.Count; i++) if (!JsX.StrictEq(vl[i], cv[i])) return false;
            }
            return true;
        }
        catch (Exception) { return false; }
    }

    // ---- goal commitment and distance ----

    static D GoalCommitInput(object? g) => new()
    {
        ["embedderModelId"] = Jx.Prop(g, "embedderModelId"), ["config"] = Jx.Prop(g, "config"), ["goalVector"] = Jx.Prop(g, "goalVector"),
        ["metric"] = Jx.Prop(g, "metric"), ["epsilon"] = Jx.Prop(g, "epsilon"),
    };

    /// <summary>Embeds the goal's CANONICAL action and binds it to this embedder: <c>{embedderModelId, config, goalVector, metric, epsilon, commit}</c>, <c>commit</c> the hash of the other five.
    /// <paramref name="epsilon"/> (default 1/4096) is the grid the distances are rounded UP to; it must be in (0, 1]. Throws on invalid input.</summary>
    public static D CommitGoal(IEmbedder embedder, object? goalAction, object? epsilon = null)
    {
        var eps = epsilon ?? Nm(DefaultEpsilon);
        var e = Jx.ToNumber(eps);
        if (!(e > 0 && e <= 1)) throw new ArgumentException("epsilon must be in (0, 1]");
        var goalVector = ValidateVector(embedder.Embed(CanonicalAction(goalAction)), embedder.Dims);
        var g = new D { ["embedderModelId"] = embedder.ModelId, ["config"] = embedder.Config, ["goalVector"] = goalVector, ["metric"] = Metric, ["epsilon"] = eps };
        g["commit"] = Hash(GoalCommitInput(g));
        return g;
    }

    /// <summary>Verifies the commitment hash AND that it is bound to exactly this embedder (id, config, dims). The first failing reason, in this order: unknown metric, bad epsilon, goal commitment hash
    /// mismatch, embedder modelId mismatch, embedder config mismatch, then the vector's own refusal; a fault while checking is its message. Null when valid.</summary>
    public static string? VerifyGoalCommitment(object? g, IEmbedder embedder)
    {
        try
        {
            if (Jx.Prop(g, "metric") is not Metric) return "unknown metric";
            var eps = Jx.ToNumber(Jx.Prop(g, "epsilon"));
            if (!(eps > 0 && eps <= 1)) return "bad epsilon";
            var expected = Hash(GoalCommitInput(g));
            if (!(Jx.Prop(g, "commit") is string c && c == expected)) return "goal commitment hash mismatch";
            if (!(Jx.Prop(g, "embedderModelId") is string m && m == embedder.ModelId)) return "embedder modelId mismatch";
            if (Hash(Jx.Prop(g, "config")) != Hash(embedder.Config)) return "embedder config mismatch";
            ValidateVector(Jx.Prop(g, "goalVector"), embedder.Dims);
            return null;
        }
        catch (Exception e) { return e.Message; }
    }

    /// <summary>The distance of two integer vectors, sin(theta / 2) = sqrt((1 - cos) / 2), rounded UP to the grid <paramref name="epsilon"/> and clamped to [0, 1]: different lengths and a zero vector are 1,
    /// identical vectors 0, a distance under 1e-9 is 0. Only IEEE multiplication, addition, division and square root, in this order (the squared norms are multiplied before the root).</summary>
    public static double VectorDistance(L a, L b, double epsilon = DefaultEpsilon)
    {
        if (a.Count != b.Count) return 1;
        double dot = 0, na = 0, nb = 0;
        bool same = true;
        for (int i = 0; i < a.Count; i++)
        {
            double x = Jx.ToNumber(a[i]), y = Jx.ToNumber(b[i]);
            dot += x * y;
            na += x * x;
            nb += y * y;
            if (!(x == y)) same = false;
        }
        if (na == 0 || nb == 0) return 1;
        if (same) return 0;
        var cos = Math.Max(-1, Math.Min(1, dot / Math.Sqrt(na * nb)));
        var d = Math.Sqrt((1 - cos) / 2);
        if (d < 1e-9) return 0; // float noise floor, far below epsilon
        return Clamp01(Math.Ceiling(d / epsilon) * epsilon);
    }

    static (bool Ok, double Value, string Reason) DistanceChecked(D action, object? goal, IEmbedder embedder)
    {
        var bad = VerifyGoalCommitment(goal, embedder);
        if (!string.IsNullOrEmpty(bad)) return (false, 0, bad);
        try
        {
            var v = ValidateVector(embedder.Embed(action), embedder.Dims);
            var gv = Jx.Prop(goal, "goalVector") as L ?? throw JsX.TypeError("goal vector is not an array");
            return (true, VectorDistance(v, gv, Jx.ToNumber(Jx.Prop(goal, "epsilon"))), "");
        }
        catch (Exception e) { return (false, 0, e.Message); }
    }

    /// <summary>The distance to the committed goal: <c>{ok: true, value}</c>, or <c>{ok: false, reason}</c> (the distance is then 1) on any commitment or embedding failure.</summary>
    public static D CommittedDistanceChecked(D action, object? goal, IEmbedder embedder)
    {
        var r = DistanceChecked(action, goal, embedder);
        return r.Ok ? new D { ["ok"] = true, ["value"] = Nm(r.Value) } : new D { ["ok"] = false, ["reason"] = r.Reason };
    }

    /// <summary>Accepts an agent submission, canonicalizes it and returns the distance to the goal; 1 on any failure. Never throws.</summary>
    public static double CommittedDistance(object? action, object? goal, IEmbedder embedder)
    {
        try
        {
            var r = DistanceChecked(CanonicalAction(action), goal, embedder);
            return r.Ok ? r.Value : 1;
        }
        catch (Exception) { return 1; }
    }

    // ---- 4. split-conformal calibration ----

    /// <summary>For a fresh benign action exchangeable with the held-out <paramref name="benignScores"/>: r = 1 - (1 + #{s &gt;= raw}) / (n + 1), so flagging r &gt; 1 - a has a false-alarm rate of at most a on benign
    /// traffic. Non-decreasing in raw; an empty set or a raw score that is not a finite number is 1.</summary>
    public static double Calibrate(object? rawScore, L benignScores)
    {
        int n = benignScores.Count;
        if (n == 0 || Jx.Fin(rawScore) is not double raw) return 1;
        int ge = 0;
        foreach (var s in benignScores) if (Jx.ToNumber(s) >= raw) ge++;
        return 1 - (1 + ge) / (double)(n + 1);
    }

    // Array.prototype.sort((a, b) => a - b) as V8 runs it: a run is counted from the start, the rest is inserted by binary search (the whole of an array under 64 elements); a comparator that
    // returns NaN (a NaN score) leaves the order it finds. Larger arrays use a stable merge sort, which agrees on every consistent comparator.
    static List<double> SortNumeric(IEnumerable<double> xs)
    {
        var a = xs.ToList();
        if (a.Count < 2) return a;
        if (a.Count >= 64) return a.OrderBy(x => x).ToList();
        int run = 2;
        bool desc = a[1] - a[0] < 0;
        for (int i = 2; i < a.Count; i++)
        {
            var order = a[i] - a[i - 1];
            if (desc ? order >= 0 : order < 0) break;
            run++;
        }
        if (desc) a.Reverse(0, run);
        for (int start = run; start < a.Count; start++)
        {
            int left = 0, right = start;
            var pivot = a[start];
            while (left < right)
            {
                int mid = left + ((right - left) >> 1);
                if (pivot - a[mid] < 0) right = mid; else left = mid + 1;
            }
            for (int p = start; p > left; p--) a[p] = a[p - 1];
            a[left] = pivot;
        }
        return a;
    }

    /// <summary>The split-conformal quantile: with k = ceil((n + 1) * (1 - alpha)), the k-th smallest score; +Infinity when there are no scores or k &gt; n; null (undefined in the reference) when k is not a position.</summary>
    public static double? ConformalThreshold(L benignScores, object? alpha)
    {
        int n = benignScores.Count;
        var k = Math.Ceiling((n + 1) * (1 - Jx.ToNumber(alpha)));
        if (n == 0 || k > n) return double.PositiveInfinity;
        var sorted = SortNumeric(benignScores.Select(Jx.ToNumber));
        var i = k - 1;
        return i >= 0 && i < sorted.Count && i == Math.Floor(i) ? sorted[(int)i] : null;
    }

    /// <summary>The digest of a calibration set, committed by the grant: the hash of the numerically sorted scores; throws on a score that is not finite.</summary>
    public static string CalibrationDigest(L scores) =>
        Hash(new D { ["v"] = IntentJs.OfLong(1), ["scores"] = new L(SortNumeric(scores.Select(Jx.ToNumber)).Select(x => double.IsFinite(x) ? (object?)new Num(JsX.JsNumString(x)) : x)) });

    // ---- 5. harm currency ----

    /// <summary><c>{units, normalized}</c>: the weighted saturating normalization in [0, 1] of the harm <paramref name="units"/> over the denominations (<c>{id, ceiling, weight}</c>; one whose weight or ceiling is not above 0
    /// is skipped; only OWN members of the units are read, a missing one is 0). No denomination is 1 (fail closed).</summary>
    public static D HarmReport(object? units, L denominations)
    {
        double num = 0, den = 0;
        foreach (var d in denominations)
        {
            var weight = Jx.ToNumber(Jx.Prop(d, "weight"));
            var ceiling = Jx.ToNumber(Jx.Prop(d, "ceiling"));
            if (!(weight > 0) || !(ceiling > 0)) continue;
            var key = JsX.Str(Jx.Prop(d, "id"));
            var u = units is D um && um.TryGetValue(key, out var uv) ? Jx.ToNumber(uv) : 0;
            num += weight * Math.Min(1, Math.Max(0, u) / ceiling);
            den += weight;
        }
        return new D { ["units"] = units, ["normalized"] = Nm(den == 0 ? 1 : Clamp01(num / den)) };
    }

    // ---- composition ----

    static D Worst() => new()
    {
        ["semanticDistance"] = IntentJs.OfLong(1), ["reversibility"] = IntentJs.OfLong(0), ["blastRadius"] = IntentJs.OfLong(1), ["taint"] = IntentJs.OfLong(1),
        ["confidence"] = IntentJs.OfLong(0), ["age"] = IntentJs.OfLong(1),
    };

    static D Reject(params string[] reasons) => new()
    {
        ["r"] = IntentJs.OfLong(1), ["valid"] = false, ["reasons"] = new L(reasons.Cast<object?>()), ["raw"] = IntentJs.OfLong(1), ["inputs"] = Worst(),
        ["reversibility"] = new D { ["class"] = "irreversible", ["value"] = IntentJs.OfLong(0) },
        ["blast"] = new D { ["count"] = IntentJs.OfLong(0), ["reachable"] = new L(), ["normalized"] = IntentJs.OfLong(1), ["harm"] = new D() },
        ["harm"] = new D { ["units"] = new D(), ["normalized"] = IntentJs.OfLong(1) }, ["evidenceDigest"] = "",
    };

    static double Fin1(object? x) => Jx.Fin(x) ?? 1;

    /// <summary>Pure function of the canonical action and the committed context: <c>{r, valid, reasons, raw, inputs, reversibility, blast, harm, evidenceDigest}</c>. Any commitment mismatch (registry, graph,
    /// goal / embedder binding, calibration set) or un-encodable action is the fail-closed <c>r = 1</c> with <c>valid: false</c> and every reason that applies, in the order registry, graph, calibration,
    /// goal / embedder. The blast input is the larger of the count-normalized and the harm-normalized value (the harm counts only with at least one denomination and one harm dimension); a taint or age that is
    /// not finite is the worst value; <c>confidence = 1 - clamp(attestedUncertainty)</c>; <c>raw</c> is the risk score, <c>r</c> its calibration when a set is committed. <c>evidenceDigest</c> commits every fact
    /// the number was computed from. Throws only when a digest cannot be formed (a non-finite harm weight or calibration score).</summary>
    public static D Evaluate(object? submitted, ObjectiveRiskContext ctx)
    {
        D action;
        try { action = CanonicalAction(submitted); }
        catch (Exception e) { return Reject("action: " + e.Message); }
        var reasons = new List<string>();
        var commitments = ctx.Commitments;
        if (!JsX.StrictEq(ctx.Registry.Digest(), Member(commitments, "registryDigest"))) reasons.Add("registry digest does not match the committed digest");
        if (!JsX.StrictEq(ctx.Graph.Digest(), Member(commitments, "graphDigest"))) reasons.Add("graph digest does not match the committed digest");
        if (ctx.Calibration != null)
        {
            if (Jx.IsUndef(Member(commitments, "calibrationDigest"))) reasons.Add("calibration set used without a committed digest");
            else if (!JsX.StrictEq(CalibrationDigest(ctx.Calibration), Member(commitments, "calibrationDigest"))) reasons.Add("calibration digest does not match the committed digest");
        }
        var dist = DistanceChecked(action, ctx.Goal, ctx.Embedder);
        if (!dist.Ok) reasons.Add("goal/embedder: " + dist.Reason);
        if (reasons.Count > 0) return Reject(reasons.ToArray());

        var rev = Reversibility(action, ctx.Registry, ctx.AuthorizedKinds);
        var blast = BlastRadius(action, ctx.Graph, ctx.Scope);
        var harm = HarmReport(blast["harm"], ctx.Denominations);
        var uncertainty = Clamp01(ctx.AttestedUncertainty == null ? 0 : Jx.Fin(ctx.AttestedUncertainty) ?? double.NaN); // a value that is not a number is the worst, 1
        var harmCounts = ctx.Denominations.Count > 0 && ((D)blast["harm"]!).Count > 0;
        var sd = dist.Value;
        var rv = Jx.Fin(rev["value"])!.Value;
        var bl = Math.Max(Jx.Fin(blast["normalized"])!.Value, harmCounts ? Jx.Fin(harm["normalized"])!.Value : 0);
        // a verifier that forgot (or corrupted) taint / age gets the worst value, never a throw or a NaN risk
        var taint = Fin1(ctx.Taint);
        var conf = 1 - uncertainty;
        var age = Fin1(ctx.Age);
        var inputs = new D { ["semanticDistance"] = Nm(sd), ["reversibility"] = Nm(rv), ["blastRadius"] = Nm(bl), ["taint"] = Nm(taint), ["confidence"] = Nm(conf), ["age"] = Nm(age) };
        double W(string k) => Jx.Fin(Jx.Prop(ctx.Weights, k)) ?? double.NaN;
        var raw = Risk.Score(new RiskInputs(sd, rv, bl, taint, conf, age), new RiskPolicy(W("alpha"), W("beta"), W("gamma"), W("delta"), W("epsilon"), W("zeta"), 0, 0, 0, 0, 0, 0));
        var r = ctx.Calibration != null ? Calibrate(Nm(raw), ctx.Calibration) : raw;

        var scopeKinds = Member(ctx.Scope, "edgeKinds");
        var md = Member(ctx.Scope, "maxDepth");
        var evidence = new D
        {
            ["action"] = CanonicalActionDigest(action),
            ["scope"] = new D
            {
                ["edgeKinds"] = Jx.Truthy(scopeKinds) && scopeKinds is L sk ? new L(sk.OrderBy(x => JsX.Str(x), StringComparer.Ordinal)) : null,
                ["maxDepth"] = md == null || Jx.IsUndef(md) ? null : md,
            },
            ["authorized"] = new L(ctx.AuthorizedKinds.OrderBy(x => x, StringComparer.Ordinal).Cast<object?>()),
            ["registry"] = Member(commitments, "registryDigest"),
            ["graph"] = Member(commitments, "graphDigest"),
            ["goal"] = Jx.Prop(ctx.Goal, "commit"),
            ["calibration"] = Member(commitments, "calibrationDigest") is var cd && !Jx.IsUndef(cd) ? cd : null,
            ["inputs"] = inputs,
        };
        return new D
        {
            ["r"] = Nm(r), ["valid"] = true, ["reasons"] = new L(), ["raw"] = Nm(raw), ["inputs"] = inputs, ["reversibility"] = rev, ["blast"] = blast, ["harm"] = harm,
            ["evidenceDigest"] = Hash(evidence),
        };
    }

    // ---- dispute-game oracle ----

    /// <summary>The server-authoritative answer to a disputed input, recomputed from the COMMITTED facts over the open-time snapshot's canonical action (<c>snapshot.action.action</c>), nothing the agent asserted:
    /// <c>{input, class, valid: true}</c> for <c>reversibility_class</c>, <c>{input, value, valid: true}</c> for <c>reversibility</c>, <c>blastRadius</c> and <c>semanticDistance</c>. It fails CLOSED: an action that
    /// cannot be reproduced, an unknown input or any fault is <c>{input, valid: false, reason}</c> (the dispute is indeterminate and slashes no one). Never throws.</summary>
    public static D ResolveOracle(ObjectiveRiskContext ctx, object? input, object? snapshot)
    {
        D Bad(string reason) => new() { ["input"] = input, ["valid"] = false, ["reason"] = reason };
        try
        {
            var a = Member(Member(snapshot, "action"), "action");
            if (!Jx.Truthy(a) || Member(a, "verb") is not string verb || Member(a, "resource") is not string resource) return Bad("snapshot action is missing a canonical verb/resource");
            var prms = Member(a, "params");
            var res = Evaluate(new D { ["verb"] = verb, ["resource"] = resource, ["params"] = prms is D ? prms : new D() }, ctx);
            if (res["valid"] is not true) return Bad(string.Join("; ", ((L)res["reasons"]!).Cast<string>()) is { Length: > 0 } why ? why : "objective risk could not be reproduced");
            var inputs = (D)res["inputs"]!;
            return input switch
            {
                "reversibility_class" => new D { ["input"] = input, ["class"] = ((D)res["reversibility"]!)["class"], ["valid"] = true },
                "reversibility" => new D { ["input"] = input, ["value"] = inputs["reversibility"], ["valid"] = true },
                "blastRadius" => new D { ["input"] = input, ["value"] = inputs["blastRadius"], ["valid"] = true },
                "semanticDistance" => new D { ["input"] = input, ["value"] = inputs["semanticDistance"], ["valid"] = true },
                _ => Bad("unknown disputed input: " + JsX.Str(input)),
            };
        }
        catch (Exception e) { return Bad("objective oracle error (fail closed): " + e.Message); }
    }
}

/// <summary>The binding of the objective risk to the live decision path, without touching the signed PCActn: the facts live in the already-signed grant envelope (<c>objective_risk</c>), the actual
/// registry, resource graph and calibration set are INSTANCE-held config whose digests must equal the committed ones.</summary>
public static partial class ObjectiveBinding
{
    static InMemoryInverseRegistry BuildRegistry(object? cfg)
    {
        var trusted = ObjectiveRisk.Member(cfg, "trusted_verifiers");
        var reg = new InMemoryInverseRegistry(trusted is L tl ? tl.Cast<string>() : null);
        if (ObjectiveRisk.Member(cfg, "entries") is L entries)
            foreach (var eo in entries)
            {
                var e = (D)eo!;
                var entry = new D { ["inverseKind"] = ObjectiveRisk.Member(e, "inverse_kind"), ["fidelity"] = ObjectiveRisk.Member(e, "fidelity") };
                var v = ObjectiveRisk.Member(e, "verification");
                if (Jx.Truthy(v))
                    entry["verification"] = new D { ["verifierId"] = ObjectiveRisk.Member(v, "verifier_id"), ["evidenceDigest"] = ObjectiveRisk.Member(v, "evidence_digest") };
                reg.Register((string)ObjectiveRisk.Member(e, "verb")!, entry);
            }
        return reg;
    }

    static ResourceGraph BuildGraph(object? cfg)
    {
        var g = new ResourceGraph();
        if (ObjectiveRisk.Member(cfg, "nodes") is L nodes) foreach (var n in nodes) g.AddNode((D)n!);
        if (ObjectiveRisk.Member(cfg, "edges") is L edges) foreach (var e in edges) g.AddEdge((D)e!);
        return g;
    }

    /// <summary>Resolves the objective risk inputs for <paramref name="action"/> under <paramref name="grant"/>. Total (never throws). Nothing committed: <c>{mode: "none"}</c> (the heuristic is unchanged).
    /// Committed and reproduced: <c>{mode: "objective", inputs: {reversibility, blastRadius, semanticDistance}, r, evidenceDigest}</c>. Committed but malformed, not reproducible or invalid:
    /// <c>{mode: "mismatch", reasons, onMismatch}</c>, which is <c>deny</c> unless the grant asks for <c>heuristic</c> AND the instance opts in with <c>allow_heuristic_fallback: true</c> (a GRANT cannot
    /// downgrade the verifier's objective risk on its own say-so). <paramref name="instance"/> is <c>{registry: {trusted_verifiers, entries: [{verb, inverse_kind, fidelity, verification?: {verifier_id,
    /// evidence_digest}}]}, graph: {nodes, edges}, calibration, allow_heuristic_fallback}</c>; <paramref name="taint"/> and <paramref name="age"/> are verifier-supplied (default 1) and only feed r.</summary>
    public static D ResolveObjectiveRisk(object? grant, object? action, object? instance, double? taint = null, double? age = null)
    {
        var read = ReadObjectiveCommitment(grant);
        if (read.Malformed != null) return new D { ["mode"] = "mismatch", ["reasons"] = new L { read.Malformed }, ["onMismatch"] = "deny" };
        if (read.Commitment == null) return new D { ["mode"] = "none" };
        var c = read.Commitment;
        var requested = c.GetValueOrDefault("on_mismatch") as string ?? "deny";
        // a GRANT cannot downgrade the verifier's objective risk to the heuristic on its own say-so
        var onMismatch = requested == "heuristic" && ObjectiveRisk.Member(instance, "allow_heuristic_fallback") is true ? "heuristic" : "deny";
        D Miss(params string[] reasons) => new() { ["mode"] = "mismatch", ["reasons"] = new L(reasons.Cast<object?>()), ["onMismatch"] = onMismatch };
        try
        {
            var env = Pca.ReadEnvelope(grant);
            if (env == null) return Miss("grant carries no valid envelope");
            if (instance == null || Jx.IsUndef(instance)) return Miss("the grant commits objective-risk facts but the instance holds no objective-risk config");
            var registry = BuildRegistry(ObjectiveRisk.Member(instance, "registry"));
            var graph = BuildGraph(ObjectiveRisk.Member(instance, "graph"));
            var emb = (D)c["embedder"]!;
            var embedder = ObjectiveRisk.NativeEmbedder(emb["config"]);
            if (embedder.ModelId != (string)emb["model_id"]!) return Miss("embedder model_id does not match the committed one");
            var calibration = ObjectiveRisk.Member(instance, "calibration") as L;
            var hasCalDigest = c.ContainsKey("calibration_digest");
            if (hasCalDigest && (calibration == null || ObjectiveRisk.CalibrationDigest(calibration) != (string?)c["calibration_digest"])) return Miss("calibration set does not match the committed digest");
            var commitments = new D { ["registryDigest"] = c["registry_digest"], ["graphDigest"] = c["graph_digest"] };
            if (hasCalDigest) commitments["calibrationDigest"] = c["calibration_digest"];
            var res = ObjectiveRisk.Evaluate(action, new ObjectiveRiskContext
            {
                Registry = registry, AuthorizedKinds = ((L)c["authorized_kinds"]!).Cast<string>().ToHashSet(StringComparer.Ordinal), Graph = graph, Scope = c.GetValueOrDefault("scope") as D,
                Embedder = embedder, Goal = c["goal"], Commitments = commitments, Denominations = c.GetValueOrDefault("denominations") as L ?? new L(),
                Weights = ((D)env["risk_policy"]!)["weights"], Taint = taint == null ? IntentJs.OfLong(1) : Jx.NumOut(taint.Value), Age = age == null ? IntentJs.OfLong(1) : Jx.NumOut(age.Value),
                Calibration = hasCalDigest ? calibration : null,
            });
            if (res["valid"] is not true) return Miss(((L)res["reasons"]!).Cast<string>().ToArray());
            var inputs = (D)res["inputs"]!;
            return new D
            {
                ["mode"] = "objective",
                ["inputs"] = new D { ["reversibility"] = inputs["reversibility"], ["blastRadius"] = inputs["blastRadius"], ["semanticDistance"] = inputs["semanticDistance"] },
                ["r"] = res["r"], ["evidenceDigest"] = res["evidenceDigest"],
            };
        }
        catch (Exception e) { return Miss("objective risk evaluation error (fail closed): " + e.Message); }
    }
}
