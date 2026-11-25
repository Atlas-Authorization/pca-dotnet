using AtlasPca.Dataflow;
using AtlasPca.Js;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the second data-flow reference corpus (test-data/ref-dataflow-py.json.gz). Its values are build specs
/// (<c>{k: trusted | tool | source | tag | derive | raw | fake, ...}</c>), its sinks write their policy members in snake_case, its governors are
/// <c>{kind: fixed | throw | byVerb}</c>, and a detector key is the seed byte repeated 32 times.</summary>
public class RefDataflowPyTests
{
    const string M = "ref-dataflow-py";

    static IEnumerable<string>? Readers(D s) => s.TryGetValue("readers", out var r) ? ((L)r!).Cast<string>().ToList() : null;

    static object? Build(object? spec)
    {
        var s = (D)spec!;
        var v = s.GetValueOrDefault("value");
        switch ((string)s["k"]!)
        {
            case "trusted": return DataFlow.FromTrustedQuery(v, Readers(s));
            case "tool": return DataFlow.FromToolOutput((string)s["name"]!, v, Readers(s));
            // only an explicit true is trusted
            case "source": return DataFlow.FromSource((string)s["source"]!, v, s.GetValueOrDefault("trusted") is true, Readers(s));
            case "tag": return DataFlow.Tag(v, Capability.FromTree(s["cap"]));
            case "derive":
                Func<IReadOnlyList<object?>, object?> op = (string)s["op"]! switch
                {
                    "concat" => a => string.Join("|", a.Select(x => (string)x!)),
                    "first" => a => a[0],
                    "count" => a => IntentJs.OfLong(a.Count),
                    var o => throw new InvalidOperationException("unknown op " + o),
                };
                return DataFlow.Derive(((L)s["inputs"]!).Select(Build).ToList(), op);
            case "raw": return v;
            case "fake": return new D { ["value"] = v, ["cap"] = new D() };
            default: throw new InvalidOperationException("unknown spec " + s["k"]);
        }
    }

    static L Sorted(IEnumerable<string> xs) => xs.OrderBy(x => x, StringComparer.Ordinal).Cast<object?>().ToList();

    static D CapJson(Capability c)
    {
        var o = new D { ["sources"] = Sorted(c.Sources), ["isTrusted"] = c.IsTrusted };
        if (c.Readers != null) o["readers"] = Sorted(c.Readers);
        return o;
    }

    static D OutT(object? t)
    {
        if (t is not Tagged g) return new D { ["tagged"] = false };
        var o = CapJson(g.Cap);
        o["tagged"] = true;
        o["value"] = g.Value;
        return o;
    }

    static IReadOnlyCollection<string>? StrSet(D m, string key) =>
        m.GetValueOrDefault(key) is L l ? new HashSet<string>(l.Cast<string>(), StringComparer.Ordinal) : null;

    // a sink that is not an object, or whose id is not a string, is no sink; a policy that is not an object is a malformed sink
    static Sink? MkSink(object? s)
    {
        if (s is not D m || m.GetValueOrDefault("id") is not string id) return null;
        if (m.GetValueOrDefault("accepts") is not D a) return new Sink(id, null);
        return new Sink(id, new FlowPolicy
        {
            External = a.GetValueOrDefault("external") is true ? true : null,
            RequireTrusted = a.GetValueOrDefault("require_trusted") is true ? true : null,
            AllowedSources = StrSet(a, "allowed_sources"),
            DeniedSources = StrSet(a, "denied_sources"),
        });
    }

    [Fact] public void BuildSpecs() => Base.Check(M, "build", a => OutT(Build(a[0])), min: 31);
    [Fact] public void ToolProvenance() => Base.Check(M, "toolProvenance", a => DataFlow.ToolProvenance((string)a[0]!), min: 2);
    [Fact] public void ClassifyFlow() => Base.Check(M, "classifyFlow", a => DataFlow.ClassifyFlow(Build(a[0]), MkSink(a[1])).ToTree(), min: 160);

    [Fact]
    public void CanFlow() => Base.Check(M, "canFlow", a =>
    {
        var (ok, reason) = DataFlow.CanFlow(Build(a[0]), MkSink(a[1]));
        var d = new D { ["ok"] = ok };
        if (reason != null) d["reason"] = reason;
        return d;
    }, min: 60);

    [Fact] public void ExternalSendSink() => Base.Check(M, "externalSendSink", a => DataFlow.ExternalSendSink((string)a[0]!).ToTree(), min: 1);
    [Fact] public void SensitiveSink() => Base.Check(M, "sensitiveSink", a => DataFlow.SensitiveSink((string)a[0]!).ToTree(), min: 1);

    [Fact]
    public void CheckAction() => Base.Check(M, "checkAction", a =>
    {
        var act = (D)a[0]!;
        // a null element is an argument nobody tagged
        var args = (a[1] as L)?.Select(s => s == null ? DataFlow.Hole : Build(s)).ToList();
        var g = (D)a[2]!;
        Func<ActionRef, Sink?> sinkFor = r => (string)g["kind"]! switch
        {
            "throw" => throw new InvalidOperationException("no sink"),
            "byVerb" => MkSink(((D)g["map"]!).TryGetValue(r.Verb, out var by) ? by : g["default"]),
            _ => MkSink(g.GetValueOrDefault("sink")),
        };
        double? expected = a.Count > 3 && a[3] != null ? JsJson.ToJsNumber(a[3]) : null;
        return DataFlow.CheckAction(new ActionRef((string)act["verb"]!, (string)act["resource"]!), args, sinkFor, expected).ToTree();
    }, min: 124);

    [Fact]
    public void DualContext() => Base.Check(M, "dualContext", a =>
    {
        Func<object?, object?> quarantine = (string)a[1]! switch
        {
            "tool" => p => DataFlow.FromToolOutput("q", "r:" + (string)p!),
            "trusted" => p => DataFlow.FromTrustedQuery(p),
            "raw" => p => p,
            _ => p => new D { ["value"] = p, ["cap"] = new D() },
        };
        var (plan, result) = DataFlow.DualContext(Build(a[0]), x => "plan:" + (string)x!, quarantine);
        return new D { ["plan"] = plan, ["result"] = OutT(result) };
    }, min: 24);

    // the name says what the case builds; its argument is only an index into the generator's table
    static string Label(D c) => ((string)c["name"]!).Split('/', 2)[1].Split('#')[0];

    static D T(object? v, params string[]? readers)
    {
        var s = new D { ["k"] = "trusted", ["value"] = v };
        if (readers != null && readers.Length > 0) s["readers"] = readers.Cast<object?>().ToList();
        return s;
    }

    static List<Capability> Caps(params D[] specs) => specs.Select(s => ((Tagged)Build(s)!).Cap).ToList();
    static List<Capability> Mixed() => Caps(T("a"), new D { ["k"] = "tool", ["name"] = "w", ["value"] = "b" });

    [Fact]
    public void LevelOf()
    {
        int n = 0;
        foreach (var c in Base.Of(M, "levelOf"))
        {
            n++;
            var have = Label(c) switch
            {
                "null" => DataFlow.LevelOf(null),
                "string" => DataFlow.LevelOf("trusted"),
                "mixed tool+user" => DataFlow.LevelOf(DataFlow.Derive(new L { DataFlow.FromToolOutput("a", IntentJs.OfLong(1)), DataFlow.FromSource("user", IntentJs.OfLong(2)) }, v => IntentJs.OfLong(3))),
                "empty derive" => DataFlow.LevelOf(DataFlow.Derive(new L(), _ => IntentJs.OfLong(1))),
                _ => DataFlow.LevelOf(Build(Base.Args(c)[0])),
            };
            Assert.True((string)c["out"]! == have, (string)c["name"]! + ": " + have);
        }
        Assert.Equal(10, n);
    }

    [Fact]
    public void CombineCapsAndUnionSources()
    {
        int n = 0;
        foreach (var c in Base.Of(M, "combineCaps"))
        {
            n++;
            var caps = Label(c) switch
            {
                "empty" => new List<Capability>(),
                "three" => Caps(T("a"), T("b", "x", "y"), T("c", "y")),
                "untrusted" => Mixed(),
                var l => throw new InvalidOperationException("unknown combineCaps case " + l),
            };
            Assert.True(Base.Eq(c["out"], CapJson(DataFlow.CombineCaps(caps))), (string)c["name"]!);
        }
        Assert.Equal(3, n);
        var u = Base.Of(M, "unionSources").ToList();
        Assert.Single(u);
        Assert.Equal("two", Label(u[0]));
        Assert.True(Base.Eq(u[0]["out"], Sorted(DataFlow.UnionSources(Mixed()))));
    }

    // ---- detectors ----
    static byte[] Key(object? seed) => Enumerable.Repeat((byte)Base.Long(seed), 32).ToArray();

    static AdapterContext Ctx(object? c)
    {
        var m = (D)c!;
        return new AdapterContext
        {
            Detector = (string)m["detector"]!,
            Version = (string)m["version"]!,
            Content = m.GetValueOrDefault("content"),
            SecretKey = Key(m["seed"]),
            Now = JsJson.ToJsNumber(m["now"]),
            Session = m.TryGetValue("session", out var s) ? s : DataFlow.Undefined,
            CalibrationRef = m.TryGetValue("calibration_ref", out var r) ? r : DataFlow.Undefined,
        };
    }

    [Fact] public void LakeraReceipt() => Base.Check(M, "lakeraReceipt", a => Detectors.LakeraReceipt(a[0], Ctx(a[1])), min: 102);
    [Fact] public void PromptSecurityReceipt() => Base.Check(M, "promptSecurityReceipt", a => Detectors.PromptSecurityReceipt(a[0], Ctx(a[1])), min: 110);
    [Fact] public void GenericReceipt() => Base.Check(M, "genericReceipt", a => Detectors.GenericReceipt(a[0], Ctx(a[1])), min: 94);
    [Fact] public void DetectorInputDigest() => Base.Check(M, "detectorInputDigest", a => Detectors.DetectorInputDigest(a[0]), min: 9);

    // the reference copies the body's own members: an object's members, a string's indexed characters, a list's indexed elements, nothing of null
    static D Spread(object? body) => body switch
    {
        D d => d,
        string s => s.Select((ch, i) => (i, v: (object?)ch.ToString())).ToDictionary(x => x.i.ToString(System.Globalization.CultureInfo.InvariantCulture), x => x.v),
        L l => l.Select((v, i) => (i, v)).ToDictionary(x => x.i.ToString(System.Globalization.CultureInfo.InvariantCulture), x => x.v),
        _ => new D(),
    };

    [Fact] public void SignDetectorReceipt() => Base.Check(M, "signDetectorReceipt", a => Detectors.SignDetectorReceipt(Spread(a[0]), Key(a[1])), min: 31);
    [Fact] public void DetectorReceiptShapeError() => Base.Check(M, "detectorReceiptShapeError", a => DetectorReceipts.ShapeError(a[0]), min: 10);
    [Fact] public void DetectorReceiptRef() => Base.Check(M, "detectorReceiptRef", a => DetectorReceipts.Ref(a[0]), min: 10);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[]
        {
            "build", "levelOf", "toolProvenance", "combineCaps", "unionSources", "classifyFlow", "canFlow", "externalSendSink", "sensitiveSink", "checkAction", "dualContext",
            "lakeraReceipt", "promptSecurityReceipt", "genericReceipt", "detectorInputDigest", "signDetectorReceipt", "detectorReceiptShapeError", "detectorReceiptRef",
        });
        Assert.Equal(783, Base.Cases(M).Count);
    }
}
