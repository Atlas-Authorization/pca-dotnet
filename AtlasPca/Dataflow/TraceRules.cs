using System.Globalization;
using System.Text.RegularExpressions;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Dataflow;

/// <summary>A trace-rule refusal; <see cref="Code"/> is one of id, syntax, duration, window, selector, resource_on_effect, unknown_tool,
/// empty_selector, too_large, internal, horizon, unsupported, unsatisfiable.</summary>
public sealed class TraceRuleException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

/// <summary>Invariant-style "never B after A within W" rules compiled to derive caveats the verifier already enforces, plus the
/// lethal-trifecta lint. Rules, selectors, verb tables and edges are JSON trees (maps, lists, strings, <see cref="Num"/>); a rule is
/// <c>{id, never:{tools,traits,resources,any}, after:{...}, within_ms, reason?}</c>, a verb table maps a verb to <c>{traits:[..], effects?:[..]}</c>.
/// Anything the target cannot express exactly is a <see cref="TraceRuleException"/>, never skipped.</summary>
public static class TraceRules
{
    public const int MaxTraceCaveats = 64;
    const int BChunk = 8;

    public static readonly IReadOnlyList<string> PrivateReadTraits = new[] { "pca.pii_access", "pca.financial_data_read", "pca.credential_access", "pca.regulated_data" };
    public static readonly IReadOnlyList<string> ExternalSendTraits = new[] { "pca.external_communication", "pca.network_egress", "pca.data_export", "pca.public_exposure" };

    // JavaScript \s, . and \S spelled out (.NET's differ: \u0085, ᠎, and "." / "$" line-terminator handling)
    const string Ws = @"[\t\n\v\f\r    - \u2028\u2029  　﻿]";
    const string NonWs = @"[^\t\n\v\f\r    - \u2028\u2029  　﻿]";
    const string Dot = @"[^\n\r\u2028\u2029]";
    const RegexOptions Ro = RegexOptions.CultureInvariant;
    static readonly Regex RuleIdRe = new(@"\A[a-z][a-z0-9_]{0,39}\z", Ro);
    static readonly Regex VerbRe = new(@"\A[A-Za-z0-9_.:/-]{1,256}\z", Ro);
    static readonly Regex DurationRe = new(@"\A([1-9][0-9]{0,9})(ms|s|m|h|d)\z", Ro);
    static readonly Regex RuleRe = new(@"\A" + Ws + "*never" + Ws + "+(" + Dot + "+?)" + Ws + "+after" + Ws + "+(" + Dot + "+?)" + Ws + "+within" + Ws + "+(" + NonWs + "+)" + Ws + @"*\z", Ro);
    static readonly Regex HeadRe = new(@"\Araise" + Ws + @"+(?:""([^""]*)""|'([^']*)')" + Ws + @"+if:\z", Ro);
    static readonly Regex FlowRe = new(@"\A\(([A-Za-z0-9_]+):" + Ws + @"*(ToolCall|ToolOutput|Message)\)" + Ws + "*->" + Ws + @"*\(([A-Za-z0-9_]+):" + Ws + @"*(ToolCall|ToolOutput|Message)\)\z", Ro);
    static readonly Regex IsToolRe = new(@"\A([A-Za-z0-9_]+)" + Ws + "+is" + Ws + @"+tool:([A-Za-z0-9_.:/-]+)(\(" + Dot + @"*\))?\z", Ro);

    static Exception Fail(string code, string message) => new TraceRuleException(code, message);

    static string JsTrim(string s)
    {
        int a = 0, z = s.Length;
        while (a < z && JsJson.IsJsSpace(s[a])) a++;
        while (z > a && JsJson.IsJsSpace(s[z - 1])) z--;
        return s[a..z];
    }

    static long Duration(string t)
    {
        var m = DurationRe.Match(t);
        if (!m.Success) throw Fail("duration", $"'{t}' is not a duration like 10m, 2h or 7d");
        double unit = m.Groups[2].Value switch { "ms" => 1, "s" => 1000, "m" => 60_000, "h" => 3_600_000, _ => 86_400_000 };
        var ms = double.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture) * unit;
        if (ms > CaveatLang.DeriveMaxWindowMs) throw Fail("window", $"a window of {t} exceeds the 30-day history the verifier keeps");
        return (long)ms;
    }

    static D Selector(string text, bool never)
    {
        var tools = new L(); var traits = new L(); var resources = new L(); var any = false;
        foreach (var raw in text.Split(','))
        {
            var a = JsTrim(raw);
            if (a == "any") any = true;
            else if (a.StartsWith("tool:", StringComparison.Ordinal) && VerbRe.IsMatch(a[5..])) tools.Add(a[5..]);
            else if (a.StartsWith("trait:", StringComparison.Ordinal) && VerbRe.IsMatch(a[6..])) traits.Add(a[6..]);
            else if (a.StartsWith("resource:", StringComparison.Ordinal) && a.Length > 9 && a.Length <= 9 + 256)
            {
                if (never) throw Fail("resource_on_effect", "a resource selector can only name the earlier action (the check reads the current verb)");
                resources.Add(a[9..]);
            }
            else throw Fail("selector", $"'{a}' is not tool:<verb>, trait:<id>, resource:<prefix> or any");
        }
        return new D { ["tools"] = tools, ["traits"] = traits, ["resources"] = resources, ["any"] = any };
    }

    static D ParseRule(string id, string text, bool hasReason, string? reason)
    {
        if (!RuleIdRe.IsMatch(id)) throw Fail("id", $"rule id '{id}' must match ^[a-z][a-z0-9_]{{0,39}}$");
        var m = RuleRe.Match(text);
        if (!m.Success) throw Fail("syntax", $"expected 'never <selector> after <selector> within <duration>', got '{text}'");
        var d = new D
        {
            ["id"] = id,
            ["never"] = Selector(m.Groups[1].Value, true),
            ["after"] = Selector(m.Groups[2].Value, false),
            ["within_ms"] = IntentJs.OfLong(Duration(m.Groups[3].Value)),
        };
        if (hasReason) d["reason"] = reason;
        return d;
    }

    /// <summary>Parse <c>never &lt;B&gt; after &lt;A&gt; within &lt;duration&gt;</c>.</summary>
    public static D ParseTraceRule(string id, string text) => ParseRule(id, text, false, null);
    /// <summary>As above with a reason (an explicit <c>null</c> reason is kept as <c>null</c>).</summary>
    public static D ParseTraceRule(string id, string text, string? reason) => ParseRule(id, text, true, reason);

    /// <summary>Import the Invariant subset <c>raise "msg" if:</c> / <c>(x: ToolCall|ToolOutput) -&gt; (y: ToolCall)</c> / <c>x is tool:name</c> lines.
    /// <paramref name="horizon"/> (a duration) is required; <paramref name="dropUnsupported"/> removes other conditions (a weaker rule refuses more).
    /// Returns <c>{rule, dropped:[..]}</c>.</summary>
    public static D ParseInvariantRule(string id, string text, string? horizon, bool dropUnsupported = false)
    {
        if (!RuleIdRe.IsMatch(id)) throw Fail("id", $"rule id '{id}' must match ^[a-z][a-z0-9_]{{0,39}}$");
        if (horizon == null) throw Fail("horizon", "an Invariant rule has no window: pass the horizon explicitly");
        var withinMs = Duration(horizon);
        var lines = text.Split('\n').Select(JsTrim).Where(l => l.Length > 0 && !l.StartsWith('#')).ToList();
        var head = HeadRe.Match(lines.Count > 0 ? lines[0] : "");
        if (!head.Success) throw Fail("syntax", "the first line must be raise \"<message>\" if:");
        var flow = FlowRe.Match(lines.Count > 1 ? lines[1] : "");
        if (!flow.Success) throw Fail("unsupported", "the second line must be one flow '(x: ToolCall|ToolOutput) -> (y: ToolCall)' (chains of three and other patterns are not supported)");
        string a = flow.Groups[1].Value, ta = flow.Groups[2].Value, b = flow.Groups[3].Value, tb = flow.Groups[4].Value;
        if (ta == "Message" || tb != "ToolCall") throw Fail("unsupported", "only a tool call or tool output followed by a tool call can be compiled");
        if (a == b) throw Fail("syntax", "the two events need distinct names");
        var tools = new Dictionary<string, List<string>>(StringComparer.Ordinal) { [a] = new(), [b] = new() };
        var dropped = new L();
        foreach (var l in lines.Skip(2))
        {
            var m = IsToolRe.Match(l);
            if (m.Success && tools.TryGetValue(m.Groups[1].Value, out var own) && !m.Groups[3].Success)
            {
                own.Add(m.Groups[2].Value);
                continue;
            }
            if (dropUnsupported)
            {
                // `x is tool:name({args})` keeps the tool and drops the argument pattern: a wider match, so more refusals
                if (m.Success && tools.TryGetValue(m.Groups[1].Value, out var own2)) own2.Add(m.Groups[2].Value);
                dropped.Add(l);
                continue;
            }
            throw Fail("unsupported", $"'{l}' is outside the compilable subset (x is tool:<name>); pass dropUnsupported to refuse more instead");
        }
        foreach (var v in new[] { a, b }) if (tools[v].Count > 1) throw Fail("unsatisfiable", $"'{v}' is constrained to two different tools, so the rule can never fire");
        D Sel(string v) => new() { ["tools"] = tools[v].Cast<object?>().ToList(), ["traits"] = new L(), ["resources"] = new L(), ["any"] = tools[v].Count == 0 };
        var rule = new D
        {
            ["id"] = id,
            ["never"] = Sel(b),
            ["after"] = Sel(a),
            ["within_ms"] = IntentJs.OfLong(withinMs),
            ["reason"] = head.Groups[1].Success ? head.Groups[1].Value : head.Groups[2].Success ? head.Groups[2].Value : "",
        };
        return new D { ["rule"] = rule, ["dropped"] = dropped };
    }

    // ---- JavaScript property-read semantics over the tree --------------------------------------------------------------------

    static object? Prop(object? o, string k)
    {
        if (o == null || ReferenceEquals(o, DataFlow.Undefined)) throw new InvalidOperationException($"Cannot read properties of {(o == null ? "null" : "undefined")} (reading '{k}')");
        return o is D d && d.TryGetValue(k, out var v) ? v : DataFlow.Undefined;
    }

    static bool Truthy(object? v) => v switch
    {
        null => false,
        bool b => b,
        string s => s.Length > 0,
        Num n => JsJson.ToJsNumber(n) is var x && x != 0 && !double.IsNaN(x),
        _ => !ReferenceEquals(v, DataFlow.Undefined),
    };

    /// <summary>String(x) for a rule id (a regex test coerces a non-string).</summary>
    static string Coerce(object? v) => ReferenceEquals(v, DataFlow.Undefined) ? "undefined" : JsJson.ToJsString(v);

    static L AsList(object? v) => v as L ?? throw new InvalidOperationException("not an array");

    static List<string> Expand(object? s, object? table, string what)
    {
        if (table is not D t) throw new InvalidOperationException("Cannot convert undefined or null to object");
        var verbs = t.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        var outSet = new HashSet<string>(StringComparer.Ordinal);
        if (Truthy(Prop(s, "any"))) foreach (var v in verbs) outSet.Add(v);
        foreach (var tool in AsList(Prop(s, "tools")))
        {
            var name = (string)tool!;
            if (!t.ContainsKey(name)) throw Fail("unknown_tool", $"{what}: tool '{name}' is not an action in the verb table");
            outSet.Add(name);
        }
        foreach (var tr in AsList(Prop(s, "traits")))
        {
            var trait = (string)tr!;
            var hit = verbs.Where(v => Includes(Prop(Prop(t, v), "traits"), trait)).ToList();
            if (hit.Count == 0) throw Fail("empty_selector", $"{what}: trait '{trait}' matches no action");
            foreach (var v in hit) outSet.Add(v);
        }
        return outSet.OrderBy(v => v, StringComparer.Ordinal).ToList();
    }

    static bool Includes(object? list, string x) => list switch
    {
        L l => l.Any(e => e is string s && s == x),
        string s => s.Contains(x, StringComparison.Ordinal),
        _ => throw new InvalidOperationException("includes is not a function"),
    };

    /// <summary>Lower rules to derive caveats over the verifier's history: returns <c>{caveats, edges, digest}</c>. <paramref name="rules"/> is a list
    /// of rule maps, <paramref name="table"/> the verb table.</summary>
    public static D CompileTraceRules(object? rules, object? table)
    {
        IEnumerable<object?> items = rules switch
        {
            L l => l,
            string s => s.EnumerateRunes().Select(r => (object?)r.ToString()).ToList(),
            _ => throw new InvalidOperationException("rules is not iterable"),
        };
        var caveats = new L();
        var edges = new L();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var r in items)
        {
            var idKey = Coerce(Prop(r, "id"));
            if (!RuleIdRe.IsMatch(idKey) || ids.Contains(idKey)) throw Fail("id", $"rule id '{idKey}' is malformed or repeated");
            ids.Add(idKey);
            var within = Prop(r, "within_ms");
            if (!(IntentJs.IsSafeInteger(within) && IntentJs.NumOf(within)!.Value >= 1 && IntentJs.NumOf(within)!.Value <= CaveatLang.DeriveMaxWindowMs))
                throw Fail("window", $"rule '{idKey}': within_ms must be 1..30 days");
            var withinMs = (long)IntentJs.NumOf(within)!.Value;
            var never = Prop(r, "never");
            var after = Prop(r, "after");
            if (AsList(Prop(never, "resources")).Count > 0) throw Fail("resource_on_effect", $"rule '{idKey}': a resource selector cannot name the later action");
            var bs = Expand(never, table, $"rule '{idKey}' never");
            var asides = new List<D>();
            foreach (var v in Expand(after, table, $"rule '{idKey}' after")) asides.Add(new D { ["verb"] = v });
            foreach (var p in AsList(Prop(after, "resources")).Select(x => (string)x!).Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal)) asides.Add(new D { ["resource_prefix"] = p });
            if (bs.Count == 0 || asides.Count == 0) throw Fail("empty_selector", $"rule '{idKey}': a side matches nothing");
            int n = 0;
            foreach (var a in asides)
            {
                for (int i = 0; i < bs.Count; i += BChunk)
                {
                    var chunk = bs.Skip(i).Take(BChunk);
                    var isB = new D { ["op"] = "or", ["args"] = chunk.Select(v => (object?)new D { ["op"] = "eq", ["a"] = new D { ["ref"] = "verb" }, ["b"] = new D { ["const"] = v } }).ToList() };
                    var count = new D { ["name"] = "seen", ["kind"] = "count", ["window_ms"] = IntentJs.OfLong(withinMs) };
                    foreach (var kv in a) count[kv.Key] = kv.Value;
                    var c = new D
                    {
                        ["type"] = "derive",
                        ["id"] = $"trace.{idKey}.{n++}",
                        ["defs"] = new L
                        {
                            count,
                            new D { ["name"] = "verb", ["kind"] = "action", ["field"] = "verb" },
                            new D { ["name"] = "is_b", ["kind"] = "expr", ["expr"] = isB },
                        },
                        // refused iff an A happened within the window AND this action is a B; unknown (no history, no verb) refuses too
                        ["check"] = new D
                        {
                            ["op"] = "not",
                            ["arg"] = new D
                            {
                                ["op"] = "and",
                                ["args"] = new L { new D { ["op"] = "gt", ["a"] = new D { ["ref"] = "seen" }, ["b"] = new D { ["const"] = new Num("0") } }, new D { ["ref"] = "is_b" } },
                            },
                        },
                    };
                    var e = CaveatLang.DeriveError(c);
                    if (e != null) throw Fail("internal", $"rule '{idKey}' compiled to an invalid caveat: {e}");
                    caveats.Add(c);
                    if (caveats.Count > MaxTraceCaveats) throw Fail("too_large", $"more than {MaxTraceCaveats} caveats: split the rule set or narrow the selectors");
                }
                foreach (var v in bs)
                    edges.Add(new D
                    {
                        ["rule"] = idKey,
                        ["from"] = a.TryGetValue("verb", out var verb) ? new D { ["tool"] = verb } : new D { ["resource"] = a["resource_prefix"] },
                        ["to"] = v,
                        ["within_ms"] = IntentJs.OfLong(withinMs),
                    });
            }
        }
        return new D { ["caveats"] = caveats, ["edges"] = edges, ["digest"] = Pca.HashCanonical(new D { ["d"] = "atlas-pca/trace-rules/v1", ["caveats"] = caveats }) };
    }

    /// <summary>The lethal trifecta lint: private data, untrusted content and a way out in one action set. A send is cut off when every untrusted
    /// read, or every private read, has an edge rule to it. Reports only. Returns <c>{private_reads, untrusted_reads, sends, findings}</c>.</summary>
    public static D LethalTrifecta(object? table, object? edges, IReadOnlyList<string>? untrusted = null, IReadOnlyList<string>? untrustedTraits = null)
    {
        if (table is not D t) throw new InvalidOperationException("Cannot convert undefined or null to object");
        var verbs = t.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        var traitsOf = (string v) => AsList(Prop(t[v], "traits")).Select(x => x as string).ToList();
        bool Has(string v, IEnumerable<string> ts) => traitsOf(v).Any(x => x != null && ts.Contains(x));
        bool ReadOnly(string v)
        {
            var eff = Prop(t[v], "effects");
            if (eff == null || ReferenceEquals(eff, DataFlow.Undefined)) return false;
            var l = AsList(eff);
            return l.Count > 0 && l.All(e => e is string s && s == "read");
        }
        var u = untrusted ?? Array.Empty<string>();
        var ut = untrustedTraits ?? Array.Empty<string>();
        var priv = verbs.Where(v => Has(v, PrivateReadTraits)).ToList();
        var untr = verbs.Where(v => u.Contains(v) || Has(v, ut) || (ReadOnly(v) && traitsOf(v).Contains("pca.network_egress"))).ToList();
        var sends = verbs.Where(v => Has(v, ExternalSendTraits) && !ReadOnly(v)).ToList();
        var findings = new L();
        if (priv.Count > 0 && untr.Count > 0 && sends.Count > 0)
        {
            var el = AsList(edges);
            bool Ruled(string from, string to) => el.Any(e =>
                Prop(e, "from") is D f && f.TryGetValue("tool", out var tool) && tool is string ts && ts == from && Prop(e, "to") is string es && es == to);
            foreach (var s in sends)
            {
                var fu = untr.Where(x => !Ruled(x, s)).ToList();
                var fp = priv.Where(x => !Ruled(x, s)).ToList();
                if (fu.Count > 0 && fp.Count > 0)
                    findings.Add(new D { ["send"] = s, ["from_untrusted"] = fu.Cast<object?>().ToList(), ["from_private"] = fp.Cast<object?>().ToList() });
            }
        }
        return new D
        {
            ["private_reads"] = priv.Cast<object?>().ToList(),
            ["untrusted_reads"] = untr.Cast<object?>().ToList(),
            ["sends"] = sends.Cast<object?>().ToList(),
            ["findings"] = findings,
        };
    }
}
