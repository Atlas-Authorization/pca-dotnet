using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 differential oracle of provenance by default (test-data/k05-argprov.json.gz, TS reference packages/pca/src/arg-provenance.ts +
/// server/require-pca.ts defaultProvenanceBundle).</summary>
public class K05ArgProvDiffTests
{
    const string M = "argprov";

    [Fact] public void ReceiptWireError() => K05.Check(M, "provReceiptWireError", a => ArgProvenance.ReceiptWireError(a[0]));
    [Fact] public void IsMediatorPin() => K05.Check(M, "isProvMediatorPin", a => ArgProvenance.IsMediatorPin(a[0]));
    [Fact] public void ActionInfoError() => K05.Check(M, "provActionInfoError", a => ArgProvenance.ActionInfoError(a[0]));
    [Fact] public void IsReadOnlyAction() => K05.Check(M, "isReadOnlyAction", a => ArgProvenance.IsReadOnlyAction(a[0]));
    [Fact] public void EnvelopeError() => K05.Check(M, "provEnvelopeError", a => ArgProvenance.EnvelopeError(a[0]));
    [Fact] public void OccursAsToken() => K05.Check(M, "occursAsToken", a => ArgProvenance.OccursAsToken((string)a[0]!, (string)a[1]!));
    [Fact] public void Leaves() => K05.Check(M, "provLeaves", a => ArgProvenance.Leaves(a[0]));

    [Fact]
    public void Decide() => K05.Check(M, "decideArgProvenance", a =>
    {
        if (a[0] is not D i) return ArgProvenance.Decide(null).ToJson();
        return ArgProvenance.Decide(new ArgProvenanceInput
        {
            Bundle = i.GetValueOrDefault("bundle"), Operation = i.GetValueOrDefault("operation"), Mediators = i.GetValueOrDefault("mediators"),
            Action = i.GetValueOrDefault("action"), PrincipalPlan = i.GetValueOrDefault("principalPlan") is true,
            PrincipalControl = i.GetValueOrDefault("principalControl") is true, Observed = i.GetValueOrDefault("observed"),
        }).ToJson();
    }, eq: (c, h) => K05.Show(EvalPrefix(c["out"])) == K05.Show(EvalPrefix(K05.Json(h))), min: 7000);

    // The reference's catch-all reason "evaluation error (fail closed): <message>" compares the prefix only (.NET names the exception
    // type; the reference its message); the outcome, code and every other member must still match.
    const string EvalErr = "evaluation error (fail closed): ";
    static object? EvalPrefix(object? v) => v is D m && m.GetValueOrDefault("reason") is string r && r.StartsWith(EvalErr, StringComparison.Ordinal)
        ? new D(m) { ["reason"] = EvalErr } : v;

    // spec {mediator, kid, sk (b64u seed), session, clock: [ms per append], steps}; out {pin, outs: [receipt | bundle | {$throws}]}.
    // A step's throw compares as a refusal (the message text is each runtime's own).
    static object? NoText(object? v) => v switch
    {
        D m when m.ContainsKey("$throws") => new D { ["$throws"] = "" },
        D m => m.ToDictionary(e => e.Key, e => NoText(e.Value)),
        L l => l.Select(NoText).ToList(),
        _ => v,
    };

    [Fact]
    public void Recorder() => K05.Check(M, "recorder", a =>
    {
        var sp = (D)a[0]!;
        var clock = new Queue<double>(((L)sp["clock"]!).Select(x => IntentJs.NumOf(x)!.Value));
        double last = 0;
        // the TS clock may return a fraction: the recorder truncates it (a typed long clock here)
        var rec = new ProvenanceRecorder((string)sp["mediator"]!, (string)sp["kid"]!, SuiteKey.Ed25519(EdKey.FromSeed(Pca.B64uDecode(sp["sk"])!)),
            (string)sp["session"]!, () => (long)Math.Truncate(clock.Count > 0 ? last = clock.Dequeue() : last));
        var outs = new L();
        foreach (L s in (L)sp["steps"]!)
        {
            try
            {
                var k = (string)s[0]!;
                D Op() => (D)s[1]!;
                outs.Add(k switch
                {
                    "principal" => rec.Principal((string)s[1]!),
                    "tool" => rec.Tool((string)s[1]!, s[2]),
                    "retrieval" => rec.Retrieval((string)s[1]!, s[2]),
                    "web" => rec.Web((string)s[1]!, s[2]),
                    "action" => rec.ForAction((string)Op()["verb"]!, (string)Op()["resource"]!, Op()["params"]),
                    "direct" => ArgProvenance.PrincipalDirect(rec, (string)Op()["verb"]!, (string)Op()["resource"]!, Op()["params"]),
                    _ => throw new InvalidDataException("unknown step " + k),
                });
            }
            catch (InvalidDataException) { throw; }
            catch (Exception e) { outs.Add(new D { ["$throws"] = e.Message }); }
        }
        return new D { ["pin"] = rec.Pin.ToJson(), ["outs"] = outs };
    }, eq: (c, h) => K05.Show(NoText(c["out"])) == K05.Show(NoText(K05.Json(h))));

    [Fact]
    public void ActionDigest() => K05.Check(M, "provActionDigest", a =>
    {
        var op = (D)a[0]!;
        return ArgProvenance.ActionDigest((string)op["verb"]!, (string)op["resource"]!, op["params"]);
    });

    [Fact] public void ReceiptRef() => K05.Check(M, "provReceiptRef", a => ArgProvenance.ReceiptRef((D)a[0]!));

    // {header?, body?}: an unreadable header is a refusal (the gate denies), as the reference throws
    [Fact]
    public void ReadBundle() => K05.Check(M, "defaultProvenanceBundle", a =>
    {
        var r = (D)a[0]!;
        var (bundle, unreadable) = ArgProvenance.ReadBundle(r.GetValueOrDefault("header") as string, r.GetValueOrDefault("body") as string);
        return unreadable ? K05.Refused : bundle;
    });

    [Fact]
    public void EveryFn() => K05.Covers(M, new[]
    {
        "provReceiptWireError", "isProvMediatorPin", "provActionInfoError", "isReadOnlyAction", "provEnvelopeError", "occursAsToken", "provLeaves",
        "decideArgProvenance", "recorder", "provActionDigest", "provReceiptRef", "defaultProvenanceBundle",
    });
}
