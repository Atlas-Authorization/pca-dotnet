using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the leftovers of five intent modules (test-data/ref-intent-misc2.json.gz, 770 cases): the signed "ask the principal" question and its problem, the strict-artifact helpers, classifier verdicts, policy,
/// quorum decision and attestation gate, the signing and digest half of accumulator receipts and sequencer key sets, and admission and settlement through a session store (one fresh in-memory store per case). A reference
/// throw requires a refusal. Every fn has a handler and the totals are asserted.</summary>
public class RefIntentMisc2Tests
{
    const string M = "ref-intent-misc2";

    static object? Nums(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m => m.ToDictionary(e => e.Key, e => Nums(e.Value)),
        L l => l.Select(Nums).ToList(),
        _ => v,
    };

    static (string? Alg, SuiteSecretKeys? Keys) Suite(L a, int i)
    {
        if (a.Count <= i || a[i] is not D d) return (null, null);
        return (d.GetValueOrDefault("alg") as string, d.GetValueOrDefault("pqSeed") is { } seed ? new SuiteSecretKeys { MlDsa = PqSuites.MlDsa65Keygen(Base.Bytes(seed)) } : null);
    }

    static string[] Strs(object? o) => o is L l ? l.Select(x => (string)x!).ToArray() : [];

    static D Resolved(object? p, object? path)
    {
        var r = IntentArtifacts.ResolveParamPath(p, path);
        return r.Found ? new D { ["found"] = true, ["value"] = r.Value } : new D { ["found"] = false };
    }

    static D ClassOut(IntentClassifier.ClassResult r) => r.Ok ? new D { ["ok"] = true, ["classes"] = r.Classes, ["votes"] = r.Votes } : new D { ["ok"] = false, ["reason"] = r.Reason };

    static IReadOnlyDictionary<string, string>? Pins(object? pin) => pin is D d && d.GetValueOrDefault("pqPins") is D pp ? pp.Where(e => e.Value is string).ToDictionary(e => e.Key, e => (string)e.Value!) : null;

    static object? Admit(L a)
    {
        IIntentSessionStore store = new MemoryIntentSessionStore(true);
        var res = new L();
        foreach (var opo in (L)a[0]!)
        {
            var op = (L)opo!;
            switch ((string)op[0]!)
            {
                case "store":
                {
                    var spec = ((D)op[1]!).GetValueOrDefault("durable");
                    store = new MemoryIntentSessionStore(spec is "absent" ? null : spec);
                    res.Add(null);
                    break;
                }
                case "admit":
                {
                    var args = (D)op[1]!;
                    try
                    {
                        var verdict = IntentMisc2.AdmitIntentAction(store, args, acc =>
                        {
                            if (args["verifyAs"] is "throws") throw new InvalidOperationException("verify down"); // nothing is recorded for a verifier that threw
                            res.Add(new D { ["acc"] = acc });
                            return new D { ["allow"] = ((D)args["verifyAs"]!)["allow"] };
                        }, args.GetValueOrDefault("requireDurable") is not false);
                        res.Add(verdict);
                    }
                    catch (Exception) { res.Add(new D { ["$err"] = true }); }
                    break;
                }
                case "settle": res.Add(IntentMisc2.SettleIntentEvent(store, (string)op[1]!, (string)op[2]!, (string)op[3]!)); break;
                case "events": res.Add(store.WithSession((string)op[1]!, tx => tx.Events())); break;
                default: res.Add(new D { ["$err"] = true }); break;
            }
        }
        return res;
    }

    static Dictionary<string, Func<L, object?>> Fns => new()
    {
        ["constants"] = _ => IntentMisc2.Constants(),
        // intent-artifacts
        ["isPathSegment"] = a => IntentArtifacts.IsPathSegment(a[0] as string ?? AtlasPca.Js.JsJson.ToJsString(a[0])),
        ["isPlainObject"] = a => a[0] is D,
        ["isSafeInt"] = a => IntentJs.IsInt(a[0]),
        ["utf8Len"] = a => IntentJs.U8Len((string)a[0]!),
        ["isBoundedString"] = a => a[0] is string s && s.Length > 0 && IntentJs.U8Len(s) <= IntentJs.NumOf(a[1])!.Value,
        ["isDigest"] = a => IntentArtifacts.IsDigest(a[0]),
        ["isScalar"] = a => IntentArtifacts.IsScalar(a[0]),
        ["scalarEq"] = a => IntentArtifacts.ScalarEq(a[0], a[1]),
        ["closedMembers"] = a => IntentArtifacts.ClosedMembers((D)a[0]!, Strs(a[1]), Strs(a.Count > 2 ? a[2] : null), a.Count > 3 && a[3] is string w ? w : "object"),
        ["pinPqOk"] = a => a.Count == 0 || (a[0] is string s && s.Length > 0),
        ["artifactSuiteError"] = a => a[0] is D d ? IntentArtifacts.ArtifactSuiteError(d) : "artifact must be an object",
        ["artifactMessage"] = a => IntentArtifacts.ArtifactMessage((string)a[0]!, (D)a[1]!),
        ["signArtifact"] = a => { var (alg, keys) = Suite(a, 3); return IntentMisc2.SignArtifact((string)a[0]!, (D)a[1]!, Base.Bytes(a[2]), alg, keys); },
        ["verifyArtifactSig"] = a => IntentMisc2.VerifyArtifactSig((string)a[0]!, (D)a[1]!, a[2]),
        ["artifactRef"] = a => IntentArtifacts.ArtifactRef((string)a[0]!, (string)a[1]!, a[2]),
        ["publicKeyB64u"] = a => IntentMisc2.PublicKeyB64u(Base.Bytes(a[0])),
        ["resolveParamPath"] = a => Resolved(a[0], a[1]),
        ["isParamPath"] = a => IntentArtifacts.IsParamPath(a[0]),
        ["setNested"] = a => { var x = (D)a[0]!; var root = (D)x["root"]!; var ok = IntentArtifacts.SetNested(root, (string)x["path"]!, x.GetValueOrDefault("value")); return new D { ["ok"] = ok, ["root"] = root }; },
        ["isClock"] = a => IntentJs.IsInt(a[0]),
        ["ownGet"] = a => a[0] is D d ? d.GetValueOrDefault((string)a[1]!) : null,
        ["nullRecord"] = _ => new D(),
        // intent-required
        ["intentActionDigest"] = a => IntentRequired.IntentActionDigest((D)a[0]!),
        ["cellCoordsError"] = a => IntentRequired.CellCoordsError(a[0]),
        ["intentRequiredShapeError"] = a => IntentRequired.IntentRequiredShapeError(a[0], !(a.Count > 1 && a[1] is D o && o.GetValueOrDefault("signed") is false)),
        ["signIntentRequired"] = a => { var (alg, keys) = Suite(a, 3); return IntentRequired.SignIntentRequired((D)a[0]!, (string)a[1]!, Base.Bytes(a[2]), alg, keys); },
        ["verifyIntentRequired"] = a => IntentRequired.VerifyIntentRequired(a[0], a[1], a[2]),
        ["verifyIntentRequiredAt"] = a => IntentRequired.VerifyIntentRequiredAt(a[0], a[1], a[2]),
        ["intentProblem"] = a => IntentRequired.IntentProblem((string)a[0]!, a.Count > 1 ? a[1] as D : null),
        // intent-classifier
        ["validateClassifierVerdictWire"] = a => IntentClassifier.ValidateVerdictWire(a[0]),
        ["classifierContentDigest"] = a => IntentJs.HashCanonical(a[0]),
        ["signClassifierVerdict"] = a => { var (alg, keys) = Suite(a, 2); return IntentMisc2.SignClassifierVerdict((D)a[0]!, Base.Bytes(a[1]), alg, keys); },
        ["classifierVerdictRef"] = a => IntentClassifier.VerdictRef((D)a[0]!),
        ["validateClassifierPolicy"] = a => IntentClassifier.ValidatePolicy(a[0]),
        ["classifierCheckActive"] = a => a[0] is D d && IntentClassifier.ClassifierCheckActive(d.GetValueOrDefault("committed"), d.GetValueOrDefault("policy")),
        ["decideClassifierDimensions"] = a => a[0] is D ? ClassOut(IntentClassifier.Decide(a[0])) : new D { ["ok"] = false, ["reason"] = "classes: input must be an object" },
        ["verifyClassifierAttestation"] = a => IntentMisc2.VerifyClassifierAttestation(a[0], a.Count > 1 ? a[1] : null, a.Count > 2 ? a[2] : null),
        // intent-acc
        ["monitorStates"] = a => IntentAcc.MonitorStates((D)a[0]!)?.Cast<object?>().ToList(),
        ["monitorInitialState"] = a => IntentHistory.MonitorInitialState((D)a[0]!),
        ["distinctKey"] = a => IntentAcc.DistinctKey(a[0]),
        ["sortedDistinct"] = a => IntentMisc2.SortedDistinct(Strs(a[0])),
        ["signAccReceipt"] = a => { var (alg, keys) = Suite(a, 2); return IntentMisc2.SignAccReceipt((D)a[0]!, Base.Bytes(a[1]), alg, keys); },
        ["accReceiptDigest"] = a => IntentAcc.ReceiptDigest(a[0]),
        ["accReceiptCoreDigest"] = a => IntentMisc2.AccReceiptCoreDigest((D)a[0]!),
        ["verifyReceiptSignature"] = a => a[0] is D r && IntentAcc.VerifyReceiptSignature(r, (string)a[1]!, Pins(a.Count > 2 ? a[2] : null)),
        ["signSequencerKeySet"] = a => { var (alg, keys) = Suite(a, 2); return IntentMisc2.SignSequencerKeySet((D)a[0]!, Base.Bytes(a[1]), alg, keys); },
        ["sequencerKeySetDigest"] = a => IntentAcc.SequencerKeySetDigest(a[0]),
        ["verifyKeySet"] = a => IntentAcc.VerifySequencerKeySet(a[0], (string)a[1]!, a.Count > 2 ? a[2] : null),
        // intent-history
        ["accContextFor"] = a =>
        {
            var cand = (D)a[2]!;
            return IntentHistory.AccContextFor((D)a[0]!, (L)a[1]!, (D)cand["params"]!, cand.GetValueOrDefault("t"), a.Count > 3 ? a[3] : null);
        },
        ["admit"] = Admit,
    };

    // Asserted divergence: the reference accepts an unpinned PQ key under its legacy allowUnboundPq opt-out; the native never offers that opt-out and refuses it.
    static Func<D, object?, bool>? Compare(string fn) => fn != "verifyReceiptSignature" ? null : (c, have) =>
        c["args"] is L ar && ar.Count > 2 && ar[2] is D o && o.GetValueOrDefault("allowUnboundPq") is true
            ? Base.Show(c["out"]) == "true" && Base.Show(Base.Json(have)) == "false"
            : Base.Eq(c["out"], have);

    static void Fn(string fn, int min) => Base.Check(M, fn, a => Base.Json(Fns[fn]((L)Nums(a)!)), Compare(fn), null, min);

    [Fact] public void Constants() => Fn("constants", 1);
    [Fact] public void ArtifactPredicates() { foreach (var (f, n) in new[] { ("isPathSegment", 16), ("isPlainObject", 8), ("isSafeInt", 12), ("utf8Len", 7), ("isBoundedString", 12), ("isDigest", 12), ("isScalar", 16), ("scalarEq", 11), ("closedMembers", 8), ("pinPqOk", 6), ("isClock", 12), ("ownGet", 11), ("nullRecord", 1) }) Fn(f, n); }
    [Fact] public void ArtifactSigning() { foreach (var (f, n) in new[] { ("artifactSuiteError", 12), ("artifactMessage", 10), ("signArtifact", 8), ("verifyArtifactSig", 18), ("artifactRef", 8), ("publicKeyB64u", 2) }) Fn(f, n); }
    [Fact] public void ParamPaths() { foreach (var (f, n) in new[] { ("resolveParamPath", 25), ("isParamPath", 25), ("setNested", 14) }) Fn(f, n); }
    [Fact] public void RequiredQuestion() { foreach (var (f, n) in new[] { ("intentActionDigest", 6), ("cellCoordsError", 26), ("intentRequiredShapeError", 90), ("signIntentRequired", 8), ("verifyIntentRequired", 26), ("verifyIntentRequiredAt", 26), ("intentProblem", 42) }) Fn(f, n); }
    [Fact] public void Classifier() { foreach (var (f, n) in new[] { ("validateClassifierVerdictWire", 26), ("classifierContentDigest", 12), ("signClassifierVerdict", 7), ("classifierVerdictRef", 5), ("validateClassifierPolicy", 42), ("classifierCheckActive", 11), ("decideClassifierDimensions", 44), ("verifyClassifierAttestation", 11) }) Fn(f, n); }
    [Fact] public void AccumulatorSigning() { foreach (var (f, n) in new[] { ("monitorStates", 13), ("monitorInitialState", 13), ("distinctKey", 18), ("sortedDistinct", 7), ("signAccReceipt", 16), ("accReceiptDigest", 4), ("accReceiptCoreDigest", 4), ("verifyReceiptSignature", 8), ("signSequencerKeySet", 15), ("sequencerKeySetDigest", 3), ("verifyKeySet", 8) }) Fn(f, n); }
    [Fact] public void HistoryAdmission() { foreach (var (f, n) in new[] { ("accContextFor", 13), ("admit", 11) }) Fn(f, n); }

    [Fact]
    public void Covers()
    {
        Base.Covers(M, Fns.Keys);
        Assert.Equal(770, Base.Total(M));
        Assert.Equal(Fns.Count, Base.Cases(M).Select(c => (string)c["fn"]!).Distinct().Count());
    }
}
