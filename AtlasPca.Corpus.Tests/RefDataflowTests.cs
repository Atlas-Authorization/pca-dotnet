using AtlasPca.Dataflow;
using AtlasPca.Js;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the data-flow model, trace rules and detector adapters against the TypeScript reference.</summary>
public class RefDataflowTests
{
    const string M = "ref-dataflow";

    // ---- spec plumbing: a tagged value crosses as {"$t": value, "cap": ...}, an untagged one as {"$raw": v} ----
    static object? Val(object? s)
    {
        if (s is D m && m.ContainsKey("$raw")) return m["$raw"];
        if (s is D t && t.ContainsKey("$t")) return DataFlow.Tag(t["$t"], Capability.FromTree(t["cap"]));
        return s;
    }

    static IReadOnlyCollection<string>? StrSet(D m, string key)
    {
        if (!m.TryGetValue(key, out var v)) return null;
        if (v is not L l || l.Any(x => x is not string)) throw new ArgumentException(key + " must be a Set");
        return new HashSet<string>(l.Cast<string>(), StringComparer.Ordinal);
    }

    static Sink? MkSink(object? s)
    {
        if (s is not D m || m.GetValueOrDefault("id") is not string id) return null;
        if (m.GetValueOrDefault("accepts") is not D a) return new Sink(id, null);
        return new Sink(id, new FlowPolicy
        {
            External = a.GetValueOrDefault("external") is true ? true : null,
            RequireTrusted = a.GetValueOrDefault("requireTrusted") is true ? true : null,
            AllowedSources = StrSet(a, "allowedSources"),
            DeniedSources = StrSet(a, "deniedSources"),
        });
    }

    static IEnumerable<string>? Readers(object? opts) =>
        opts is D o && o.TryGetValue("readers", out var r) ? ((L)r!).Cast<string>().ToList() : null;

    static object Tg(object? t) => ((Tagged)t!).ToTree();

    [Fact] public void ClassifyFlow() => Base.Check(M, "classifyFlow", a => DataFlow.ClassifyFlow(Val(a[0]), MkSink(a[1])).ToTree());

    [Fact]
    public void CanFlow() => Base.Check(M, "canFlow", a =>
    {
        var (ok, reason) = DataFlow.CanFlow(Val(a[0]), MkSink(a[1]));
        var d = new D { ["ok"] = ok };
        if (reason != null) d["reason"] = reason;
        return d;
    });

    [Fact] public void Tag() => Base.Check(M, "tag", a => Tg(DataFlow.Tag(a[0], Capability.FromTree(a[1]))));
    [Fact] public void FromTrustedQuery() => Base.Check(M, "fromTrustedQuery", a => Tg(DataFlow.FromTrustedQuery(a[0], Readers(a[1]))));
    [Fact] public void FromToolOutput() => Base.Check(M, "fromToolOutput", a => Tg(DataFlow.FromToolOutput((string)a[0]!, a[1], Readers(a[2]))));
    [Fact] public void FromSource() => Base.Check(M, "fromSource", a => Tg(DataFlow.FromSource((string)a[0]!, a[1], ((D)a[2]!).GetValueOrDefault("isTrusted") is true, Readers(a[2]))));

    [Fact] public void UnionSources() => Base.Check(M, "unionSources", a => DataFlow.UnionSources(((L)a[0]!).Select(Capability.FromTree)).Cast<object?>().ToList());
    [Fact] public void CombineCaps() => Base.Check(M, "combineCaps", a => DataFlow.CombineCaps(((L)a[0]!).Select(Capability.FromTree).ToList()).ToTree());

    [Fact]
    public void Derive() => Base.Check(M, "derive", a =>
    {
        var name = (string)a[1]!;
        Func<IReadOnlyList<object?>, object?> combine = name switch
        {
            "count" => v => IntentJs.OfLong(v.Count),
            "pair" => v => v.ToList(),
            "first" => v => v.Count > 0 ? v[0] : null,
            _ => _ => throw new InvalidOperationException("combiner failed"),
        };
        return Tg(DataFlow.Derive(((L)a[0]!).Select(Val).ToList(), combine));
    });

    [Fact]
    public void CheckAction() => Base.Check(M, "checkAction", a =>
    {
        var act = (D)a[0]!;
        var args = ((L)a[1]!).Select(s => s is D h && h.GetValueOrDefault("$hole") is true ? DataFlow.Hole : s == null ? DataFlow.Undefined : Val(s)).ToList();
        var gov = (D)a[2]!;
        Func<ActionRef, Sink?> sinkFor = _ => gov.GetValueOrDefault("throws") is true ? throw new InvalidOperationException("governor failed") : MkSink(gov.GetValueOrDefault("sink"));
        var opts = (D)a[3]!;
        double? expected = opts.TryGetValue("expectedArgs", out var e) ? JsJson.ToJsNumber(e) : null;
        return DataFlow.CheckAction(new ActionRef((string)act["verb"]!, (string)act["resource"]!), args, sinkFor, expected).ToTree();
    });

    [Fact]
    public void DualContext() => Base.Check(M, "dualContext", a =>
    {
        var spec = (D)a[0]!;
        Func<object?, object?> plan = (string)spec["plan"]! switch
        {
            "identity" => q => q,
            "wrap" => q => new D { ["planned"] = q },
            _ => _ => throw new InvalidOperationException("planner failed"),
        };
        Func<object?, object?> quarantine = (string)spec["quarantine"]! switch
        {
            "tagged_untrusted" => p => DataFlow.FromToolOutput("quarantine", p),
            "trusted" => p => DataFlow.FromTrustedQuery(p),
            "raw" => p => new D { ["value"] = p, ["cap"] = new D { ["sources"] = new L { "trusted-query" }, ["isTrusted"] = true } },
            _ => _ => throw new InvalidOperationException("q failed"),
        };
        var (planned, result) = DataFlow.DualContext(Val(spec["query"]), plan, quarantine);
        return new D { ["plan"] = planned, ["result"] = result.ToTree() };
    });

    [Fact] public void ExternalSendSink() => Base.Check(M, "externalSendSink", a => DataFlow.ExternalSendSink((string)a[0]!).ToTree());
    [Fact] public void SensitiveSink() => Base.Check(M, "sensitiveSink", a => DataFlow.SensitiveSink((string)a[0]!).ToTree());
    [Fact] public void LevelOf() => Base.Check(M, "levelOf", a => DataFlow.LevelOf(Val(a[0])));
    [Fact] public void Consts() => Base.Check(M, "consts", _ => new D { ["TRUSTED_QUERY"] = DataFlow.TrustedQuery, ["tool"] = DataFlow.ToolProvenance("x"), ["tool2"] = DataFlow.ToolProvenance("") });

    // ---- trace rules ----
    [Fact] public void ParseTraceRule() => Base.Check(M, "parseTraceRule", a => a.Count > 2 ? TraceRules.ParseTraceRule((string)a[0]!, (string)a[1]!, (string?)a[2]) : TraceRules.ParseTraceRule((string)a[0]!, (string)a[1]!));

    [Fact]
    public void ParseInvariantRule() => Base.Check(M, "parseInvariantRule", a =>
    {
        var o = a[2] as D;
        return TraceRules.ParseInvariantRule((string)a[0]!, (string)a[1]!, o?.GetValueOrDefault("horizon") as string, o?.GetValueOrDefault("dropUnsupported") is true);
    });

    [Fact]
    public void CompileTexts() => Base.Check(M, "compileTexts", a =>
        TraceRules.CompileTraceRules(new L(((L)a[0]!).Select(p => (object?)TraceRules.ParseTraceRule((string)((L)p!)[0]!, (string)((L)p!)[1]!))), a[1]));

    [Fact] public void CompileTraceRules() => Base.Check(M, "compileTraceRules", a => TraceRules.CompileTraceRules(a[0], a[1]));

    [Fact]
    public void LethalTrifecta() => Base.Check(M, "lethalTrifecta", a =>
    {
        var o = a.Count < 3 ? new D() : a[2] as D ?? throw new InvalidOperationException("Cannot read properties of null"); // an omitted options argument is {}
        IReadOnlyList<string>? Strs(string k) => o.TryGetValue(k, out var v) ? ((L)v!).Cast<string>().ToList() : null;
        return TraceRules.LethalTrifecta(a[0], a[1], Strs("untrusted"), Strs("untrusted_traits"));
    });

    [Fact]
    public void TraceConsts() => Base.Check(M, "traceConsts", _ => new D
    {
        ["MAX_TRACE_CAVEATS"] = TraceRules.MaxTraceCaveats,
        ["PRIVATE_READ_TRAITS"] = TraceRules.PrivateReadTraits.Cast<object?>().ToList(),
        ["EXTERNAL_SEND_TRAITS"] = TraceRules.ExternalSendTraits.Cast<object?>().ToList(),
    });

    // ---- detectors ----
    static AdapterContext Ctx(object? c)
    {
        var m = (D)c!;
        return new AdapterContext
        {
            Detector = (string)m["detector"]!,
            Version = (string)m["version"]!,
            Content = m.GetValueOrDefault("content"),
            SecretKey = Base.Bytes(m["secretKey"]),
            Now = JsJson.ToJsNumber(m["now"]),
            Session = m.TryGetValue("session", out var s) ? s : DataFlow.Undefined,
            CalibrationRef = m.TryGetValue("calibration_ref", out var r) ? r : DataFlow.Undefined,
        };
    }

    [Fact] public void CategoryId() => Base.Check(M, "categoryId", a => Detectors.CategoryId(a[0]));
    [Fact] public void LakeraReceipt() => Base.Check(M, "lakeraReceipt", a => Detectors.LakeraReceipt(a[0], Ctx(a[1])));
    [Fact] public void PromptSecurityReceipt() => Base.Check(M, "promptSecurityReceipt", a => Detectors.PromptSecurityReceipt(a[0], Ctx(a[1])));
    [Fact] public void GenericReceipt() => Base.Check(M, "genericReceipt", a => Detectors.GenericReceipt(a[0], Ctx(a[1])));

    [Fact]
    public void EveryFnHasATest() { Base.Covers(M, new[]
    {
        "classifyFlow", "canFlow", "tag", "fromTrustedQuery", "fromToolOutput", "fromSource", "unionSources", "combineCaps", "derive", "checkAction", "dualContext",
        "externalSendSink", "sensitiveSink", "levelOf", "consts", "parseTraceRule", "parseInvariantRule", "compileTraceRules", "compileTexts", "lethalTrifecta", "traceConsts",
        "categoryId", "lakeraReceipt", "promptSecurityReceipt", "genericReceipt",
    }); Assert.Equal(2322, Base.Total(M)); }
}
