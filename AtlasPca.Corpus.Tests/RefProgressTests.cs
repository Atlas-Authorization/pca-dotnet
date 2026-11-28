using AtlasPca;
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of proof of progress over test-data/ref-progress.json.gz: the potentials and their registry, the goal commitment, step and state digests, the trajectory anchor, state attestations and the
/// attested source, the tracker, the verification of steps and trajectories, and signed steps. Host objects come from specs: a potential kind (the built-ins, "const:N", "v" = state.v untouched, "throws", "negative", "frac",
/// "nan", "big"), a registry {mode: registry | record, potentials: [[id, kind, embedder?]]}, a guard ("allow", "deny", "throws", "truthy", "action:d", "seq:n", "after-v:n"), an attestation hook ("allow", "deny", "throws",
/// "truthy" or {attested: opts}) and a source {kind: memory | attested | liar-digest | liar-source | throws | null, id, initial, signerSecret?}. An element {"$err": text} is a refused operation (the text is the
/// engine's, so any refusal matches, except for the registry operations whose texts are the module's own). The reference's legacy option that accepts a PQ state attestation without a pinned key is NOT
/// ported: the corpus cases that only it accepts are asserted refused, with their count.</summary>
public class RefProgressTests
{
    const string M = "ref-progress";

    static object? Nums(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m => m.ToDictionary(e => e.Key, e => Nums(e.Value)),
        L l => l.Select(Nums).ToList(),
        _ => v,
    };

    static Func<object?, object?, object?> Kind(string k)
    {
        return k switch
        {
            "l1-feature-v1" => (Func<object?, object?, object?>)Progress.L1FeaturePotential,
            "dag-remaining-v1" => (Func<object?, object?, object?>)Progress.DagRemainingPotential,
            "dag-weighted-v1" => (Func<object?, object?, object?>)Progress.DagWeightedPotential,
            "v" => (Func<object?, object?, object?>)((_, s) => s is D m && m.TryGetValue("v", out var v) ? v : Jx.Undef),
            "throws" => (Func<object?, object?, object?>)((_, _) => throw new InvalidOperationException("potential boom")),
            "negative" => (Func<object?, object?, object?>)((_, _) => -1.0),
            "frac" => (Func<object?, object?, object?>)((_, _) => 0.5),
            "nan" => (Func<object?, object?, object?>)((_, _) => double.NaN),
            "big" => (Func<object?, object?, object?>)((_, _) => 9007199254740992.0),
            _ when k.StartsWith("const:", StringComparison.Ordinal) => (Func<object?, object?, object?>)((_, _) => double.Parse(k[6..], System.Globalization.CultureInfo.InvariantCulture)),
            _ => throw new InvalidOperationException("bad potential kind " + k),
        };
    }

    static Func<object?, object?, object?> Fn(object? k) => Kind((string)k!);

    static string EmbedderOf(object? e) => e == null ? "" : e as string ?? throw new ArgumentException("embedder must be a string");

    static PotentialRegistry? Registry(object? spec)
    {
        if (spec is not D s) return null;
        var pots = (L)s["potentials"]!;
        if (s["mode"] is "record")
        {
            // a plain record: a later entry for an id replaces the earlier one in place
            var rec = new List<KeyValuePair<string, PotentialSpec>>();
            foreach (var po in pots)
            {
                var p = (L)po!;
                var id = (string)p[0]!;
                var ps = new PotentialSpec(Fn(p[1]), p.Count > 2 ? EmbedderOf(p[2]) : "");
                var at = rec.FindIndex(x => x.Key == id);
                if (at >= 0) rec[at] = new(id, ps); else rec.Add(new(id, ps));
            }
            return PotentialRegistry.From(rec);
        }
        var r = new PotentialRegistry();
        foreach (var po in pots)
        {
            var p = (L)po!;
            r.Register((p[0] as string)!, Fn(p[1]), p.Count > 2 ? EmbedderOf(p[2]) : "");
        }
        return r;
    }

    static Func<D, object?>? Guard(object? g)
    {
        if (g is not string s) return null;
        double N(string x) => double.Parse(x, System.Globalization.CultureInfo.InvariantCulture);
        if (s == "allow") return _ => true;
        if (s == "deny") return _ => false;
        if (s == "throws") return _ => throw new InvalidOperationException("guard boom");
        if (s == "truthy") return _ => "yes";
        if (s.StartsWith("action:", StringComparison.Ordinal)) { var d = s[7..]; return t => !(t["action_digest"] is string a && a == d); }
        if (s.StartsWith("seq:", StringComparison.Ordinal)) { var n = N(s[4..]); return t => !(IntentJs.NumOf(t["seq"]) == n); }
        if (s.StartsWith("after-v:", StringComparison.Ordinal))
        {
            var n = N(s[8..]);
            return t => !(t["after"] is D a && a.TryGetValue("v", out var v) && Jx.IsNum(v) && IntentJs.NumOf(v) == n);
        }
        throw new InvalidOperationException("bad guard " + s);
    }

    static Func<D, object?>? Attestation(object? a)
    {
        if (a == null) return null;
        if (a is D m) return Progress.AttestedStateVerifier((D)m["attested"]!);
        return (string)a switch
        {
            "allow" => _ => true,
            "deny" => _ => false,
            "throws" => _ => throw new InvalidOperationException("att boom"),
            "truthy" => _ => "yes",
            _ => throw new InvalidOperationException("bad attestation " + a),
        };
    }

    // the reference options with registry / guard / attestation as host objects (a null one is absent)
    static D? Opts(object? o)
    {
        if (o is not D m) return null;
        var d = (D)Nums(m)!;
        foreach (var k in new[] { "registry", "guard", "attestation" })
            if (d.ContainsKey(k))
            {
                var v = d[k];
                d.Remove(k);
                object? host;
                if (k == "registry") host = Registry(v);
                else if (k == "guard") host = Guard(v);
                else host = Attestation(v);
                if (host != null) d[k] = host;
            }
        return d;
    }

    sealed class Src : IStateSource
    {
        public string Id { get; init; } = "";
        public Func<D, D?> Obs = null!;
        public Action<object?> Set = null!;
        public Func<List<D>?> Atts = () => null;
        public D? Observe(D request) => Obs(request);
    }

    static byte[] B64u(string s) => Pca.B64uDecode(s) ?? throw new InvalidDataException("bad base64url");

    static Src Source(object? spec)
    {
        var s = (D)spec!;
        var id = (string)s["id"]!;
        var initial = s.GetValueOrDefault("initial");
        var kind = (string)s["kind"]!;
        if (kind == "attested")
        {
            object? world = Base.Deep(initial);
            var a = new AttestedStateSource(id, B64u((string)s["signerSecret"]!), _ => world, s.GetValueOrDefault("alg") as string);
            return new Src { Id = id, Obs = a.Observe, Set = n => world = Base.Deep(n), Atts = () => a.Attestations };
        }
        var mem = new InMemoryStateSource(initial, id);
        if (kind == "memory") return new Src { Id = id, Obs = mem.Observe, Set = mem.Apply };
        return new Src
        {
            Id = id, Set = mem.Apply,
            Obs = r =>
            {
                if (kind == "throws") throw new InvalidOperationException("source boom");
                if (kind == "null") return null;
                var ob = mem.Observe(r)!;
                var o = new D(ob);
                if (kind == "liar-digest") o["state_digest"] = new string('x', 43);
                if (kind == "liar-source") o["source"] = "someone-else";
                return o;
            },
        };
    }

    static D Err(Exception e) => new() { ["$err"] = e.Message };

    // an element that is {"$err": text} on both sides matches whatever the text; every other element compares by value
    static bool SameWithLooseErrors(D c, object? have)
    {
        var want = c["out"];
        if (want is L wl && have is L hl)
        {
            if (wl.Count != hl.Count) return false;
            for (int i = 0; i < wl.Count; i++)
            {
                if (IsErr(wl[i]) && IsErr(hl[i])) continue;
                if (!Base.Eq(wl[i], hl[i])) return false;
            }
            return true;
        }
        if (want is D wd && have is D hd && wd.ContainsKey("observations"))
        {
            foreach (var k in wd.Keys) if (!hd.ContainsKey(k) || !SameWithLooseErrors(new D { ["out"] = wd[k] }, hd[k])) return false;
            return wd.Count == hd.Count;
        }
        return Base.Eq(want, have);
    }

    static bool IsErr(object? x) => x is D d && d.Count == 1 && d.ContainsKey("$err");

    [Fact] public void Constants() => Base.Check(M, "constants", _ => Progress.Constants());
    [Fact] public void L1FeaturePotential() => Base.Check(M, "l1FeaturePotential", a => Progress.L1FeaturePotential(Nums(a[0]), Nums(a[1])), min: 20);
    [Fact] public void DagRemainingPotential() => Base.Check(M, "dagRemainingPotential", a => Progress.DagRemainingPotential(Nums(a[0]), Nums(a[1])), min: 21);
    [Fact] public void DagWeightedPotential() => Base.Check(M, "dagWeightedPotential", a => Progress.DagWeightedPotential(Nums(a[0]), Nums(a[1])), min: 24);

    [Fact]
    public void RegistryOps() => Base.Check(M, "registryOps", a =>
    {
        PotentialRegistry? r = null;
        var res = new L();
        foreach (var oo in (L)a[0]!)
        {
            var op = (L)oo!;
            try
            {
                switch ((string)op[0]!)
                {
                    case "new": r = new PotentialRegistry(); res.Add(null); break;
                    case "defaults": r = PotentialRegistry.Defaults(); res.Add(null); break;
                    case "default-frozen": r = Progress.DefaultPotentials; res.Add(null); break;
                    case "from":
                        r = PotentialRegistry.From(((D)op[1]!).Select(e => e.Value is string k
                            ? new KeyValuePair<string, PotentialSpec>(e.Key, new PotentialSpec(Fn(k), ""))
                            : new KeyValuePair<string, PotentialSpec>(e.Key, new PotentialSpec(Fn(((D)e.Value!)["fn"]), EmbedderOf(((D)e.Value!).GetValueOrDefault("embedder"))))));
                        res.Add(null);
                        break;
                    case "register": r!.Register((op[1] as string)!, Fn(op[2]), op.Count > 3 ? EmbedderOf(op[3]) : ""); res.Add(null); break;
                    case "get": res.Add(r!.Get((string)op[1]!) is { } sp ? new D { ["embedder"] = sp.Embedder } : null); break;
                    case "has": res.Add(r!.Has((string)op[1]!)); break;
                    case "ids": res.Add(new L(r!.Ids().Cast<object?>())); break;
                    case "freeze": r!.Freeze(); res.Add(null); break;
                    default: throw new InvalidOperationException("bad op");
                }
            }
            catch (Exception e) { res.Add(Err(e)); }
        }
        return res;
    }, min: 7);

    [Fact] public void GoalDigest() => Base.Check(M, "goalDigest", a => Progress.GoalDigest(Nums(a[0])), min: 31);
    [Fact] public void CommitGoal() => Base.Check(M, "commitGoal", a => Progress.CommitGoal(Nums(a[0])), min: 31);
    [Fact] public void VerifyGoalCommitment() => Base.Check(M, "verifyGoalCommitment", a => Progress.VerifyGoalCommitment(Nums(a[0]), a[1]), min: 53);
    [Fact] public void StateDigest() => Base.Check(M, "stateDigest", a => Progress.StateDigest(Nums(a[0])), min: 14);
    [Fact] public void TrajectoryHead() => Base.Check(M, "trajectoryHead", a => JsX.JsonOf(Progress.TrajectoryHead((L)a[0]!)), min: 6);
    [Fact] public void ProgressStepDigest() => Base.Check(M, "progressStepDigest", a => JsX.JsonOf(Progress.ProgressStepDigest(a[0])), min: 37);
    [Fact] public void TrajectoryAnchorCommit() => Base.Check(M, "trajectoryAnchorCommit", a => Progress.TrajectoryAnchorCommit(a[0], a[1]), min: 8);
    [Fact] public void VerifyTrajectoryAnchor() => Base.Check(M, "verifyTrajectoryAnchor", a => Progress.VerifyTrajectoryAnchor(a[0], a[1], a[2]), min: 17);

    [Fact]
    public void AnchorTrajectoryHead() => Base.Check(M, "anchorTrajectoryHead", a =>
    {
        var ledger = new TransparencyLedger("p");
        foreach (var c in (L)a[2]!) ledger.AppendCommitment((string)c!);
        return Progress.AnchorTrajectoryHead(ledger, (L)a[0]!, (string)a[1]!);
    }, min: 10);

    // the verifier pins of a state attestation; the reference's option that accepts an unpinned PQ key is not ported
    static IReadOnlyDictionary<string, string>? Pins(object? pin) =>
        pin is D p && p.GetValueOrDefault("pqPins") is D m ? m.Where(e => e.Value is string).ToDictionary(e => e.Key, e => (string)e.Value!) : null;

    static int refusedUnpinned;

    [Fact]
    public void VerifyStateAttestation()
    {
        refusedUnpinned = 0;
        Base.Check(M, "verifyStateAttestation", a => Progress.VerifyStateAttestation(a[0], a[1], Pins(a[2])), eq: (c, have) =>
        {
            var viaOption = Base.Args(c)[2] is D p && p.GetValueOrDefault("allowUnboundPq") is true;
            if (viaOption && c["out"] is true && have is false) { refusedUnpinned++; return true; }
            return Base.Eq(c["out"], have);
        }, min: 55);
        // the cases only the legacy unpinned-PQ option accepts are refused here
        Assert.Equal(2, refusedUnpinned);
    }

    [Fact] public void AttestedStateVerifier() => Base.Check(M, "attestedStateVerifier", a => Progress.AttestedStateVerifier((D)Nums(a[0])!)((D)a[1]!) is true, min: 15);

    [Fact]
    public void AttestedSource() => Base.Check(M, "attestedSource", a =>
    {
        var s = Source(a[0]);
        var observations = new L();
        foreach (var r in (L)a[1]!)
        {
            try { observations.Add(s.Observe((D)r!)); }
            catch (Exception e) { observations.Add(Err(e)); }
        }
        return new D { ["observations"] = observations, ["attestations"] = s.Atts() is { } l ? new L(l.Cast<object?>()) : null };
    }, eq: SameWithLooseErrors, min: 8);

    [Fact]
    public void Tracker() => Base.Check(M, "tracker", a =>
    {
        var goal = Nums(a[0]);
        var srcs = ((L)a[5]!).Select(Source).ToList();
        var t = new ProgressTracker(goal, (a[1] as string) ?? Progress.GoalDigest(goal), Nums(a[2]), Registry(a[3]), Guard(a[4]));
        var res = new L();
        foreach (var oo in (L)a[6]!)
        {
            var op = (L)oo!;
            try
            {
                switch ((string)op[0]!)
                {
                    case "step": res.Add(t.Step(Nums(op[1]), op[2])); break;
                    case "stepObserved": res.Add(t.StepObserved(srcs[(int)IntentJs.NumOf(op[1])!.Value], op[2])); break;
                    case "apply": srcs[(int)IntentJs.NumOf(op[1])!.Value].Set(Nums(op[2])); res.Add(null); break;
                    case "steps": res.Add(new L(t.Steps.Cast<object?>())); break;
                    case "state": res.Add(t.State); break;
                    case "currentStateDigest": res.Add(t.CurrentStateDigest); break;
                    case "spent": res.Add(t.Spent); break;
                    case "remaining": res.Add(t.Remaining); break;
                    case "reached": res.Add(t.Reached); break;
                    default: throw new InvalidOperationException("bad op");
                }
            }
            catch (Exception e) { res.Add(Err(e)); }
        }
        return res;
    }, eq: SameWithLooseErrors, min: 40);

    [Fact] public void VerifyProgressStep() => Base.Check(M, "verifyProgressStep", a => Progress.VerifyProgressStep(Nums(a[0]), a[1], Nums(a[2]), Opts(a[3])), min: 147);
    [Fact] public void VerifyTrajectory() => Base.Check(M, "verifyTrajectory", a => Progress.VerifyTrajectory(Nums(a[0]), a[1], Nums(a[2]), Opts(a[3])), min: 130);
    [Fact] public void VerifySignedProgressStep() => Base.Check(M, "verifySignedProgressStep", a => Progress.VerifySignedProgressStep(Nums(a[0]), a[1], Nums(a[2]), Opts(a[3]) ?? new D()), min: 26);
    [Fact] public void VerifySignedTrajectory() => Base.Check(M, "verifySignedTrajectory", a => Progress.VerifySignedTrajectory(Nums(a[0]), a[1], Nums(a[2]), Opts(a[3]) ?? new D()), min: 15);
    [Fact] public void SignProgressStep() => Base.Check(M, "signProgressStep", a => Progress.SignProgressStep(a[0], Base.Bytes(a[1]), (string)a[2]!), min: 7);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[]
        {
            "constants", "l1FeaturePotential", "dagRemainingPotential", "dagWeightedPotential", "registryOps", "goalDigest", "commitGoal", "verifyGoalCommitment", "stateDigest", "trajectoryHead",
            "progressStepDigest", "trajectoryAnchorCommit", "verifyTrajectoryAnchor", "anchorTrajectoryHead", "verifyStateAttestation", "attestedStateVerifier", "attestedSource", "tracker",
            "verifyProgressStep", "verifyTrajectory", "verifySignedProgressStep", "verifySignedTrajectory", "signProgressStep",
        });
        Assert.Equal(723, Base.Total(M));
    }
}
