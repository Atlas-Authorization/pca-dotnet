// The server-side judgments of the optimistic fast path (the reference optimistic module): verifyClaim, fileFraudProof, verifyFraudProof (re-runs the Policy VM on the
// frozen open-time snapshot under the grant the verifier trusts), adjudicateDispute (substitutes an objective oracle's value for the one disputed input and re-adjudicates),
// adjudicateDisputeGame (refereed bisection down to the one contested step) and freezeOpenSnapshot. The settlement layer never takes a slash on a challenger's word: it
// recomputes these itself. Claims, proofs, grants and snapshots are JSON trees; verdicts are JSON trees too. Nothing here throws on hostile input.
using System.Globalization;
using AtlasPca.Authzen;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>Resolves the truthful value of a disputed input from server-authoritative facts (never from the agent's claim or the challenger's assertion). Returns
/// <c>{input, value?, class?, valid, reason?}</c>; total: report <c>valid: false</c> rather than throw (a throw is an indeterminate dispute all the same).</summary>
public delegate D? ObjectiveOracle(string input, D snapshot);

public static partial class Optimistic
{
    /// <summary>A reversibility class that is NEVER eligible for the optimistic fast path.</summary>
    public const string IrreversibleClass = "irreversible";

    /// <summary>The realistic floor of a derived challenge window (30 s).</summary>
    public const double DefaultMinChallengeWindowMs = 30_000;

    static readonly string[] DisputableInputs = { "reversibility_class", "reversibility", "blastRadius", "semanticDistance" };

    static bool IsDisputable(object? i) => i is string s && DisputableInputs.Contains(s);

    static D? AsObj(object? v) => v switch { D d => d, L => new D(), _ => null }; // typeof [] === 'object'

    static D Shallow(object? v) => AsObj(v) is { } m ? new D(m) : new D();

    static double Dnum(object? o) => IntentJs.NumOf(o) ?? double.NaN;

    static Num N(double d) => (Num)IntentJs.Normalize(d)!;

    static string Js(double d) => JsCanon.NumberString(d);

    static string Fixed3(double x) => Research.Immune.ToFixed(x, 3);

    static D Summary(bool release, object? r, bool optimisticAllowed) => new() { ["releaseGuardianShare"] = release, ["r"] = r, ["optimisticAllowed"] = optimisticAllowed };

    static D SummarizeDecision(D d) =>
        Summary(d.GetValueOrDefault("releaseGuardianShare") is true, IntentJs.NumOf(d.GetValueOrDefault("r")) is double r ? N(r) : null,
            (d.GetValueOrDefault("requiredThreshold") as D)?.GetValueOrDefault("optimisticAllowed") is true);

    static D WithGrant(D snapshot, object? grant)
    {
        var d = new D(snapshot);
        d["grant"] = grant;
        return d;
    }

    static string Reasons(D decision) =>
        string.Join("; ", (decision.GetValueOrDefault("reasons") as L ?? new L()).Select(x => IntentRevocation.JsText(x, true)));

    static bool SameMember(D a, D b, string k) => MemberEq(a, b, k);

    // ---- claim verification ----

    /// <summary>The reference <c>verifyClaim</c>: <c>{ok: true}</c> or <c>{ok: false, reason}</c>. The claim covers THIS PCActn, is not irreversible, and its signature and window verify against
    /// <paramref name="serverNow"/> (a non-finite or absent clock reads the wall clock). Never throws.</summary>
    public static D VerifyClaim(object? claim, object? pcactn, string signerPublic, double? serverNow = null, ChallengeWindowPolicy? policy = null)
    {
        policy ??= ChallengeWindowPolicy.Default;
        var now = serverNow is double s && double.IsFinite(s) ? s : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        string reason;
        try
        {
            switch (ClaimCheck(claim, Pca.HashCanonical(pcactn), signerPublic, now, policy))
            {
                case "ok": return new D { ["ok"] = true };
                case "irreversible": reason = "irreversible action is ineligible for the optimistic path"; break;
                case "digest": reason = "claim does not cover this PCActn"; break;
                case "claimed_r": reason = "claimed_r is not finite"; break;
                case "window":
                    {
                        var c = AsObj(claim) ?? new D();
                        reason = ValidateWindow(Dnum(c.GetValueOrDefault("issued_at")), Dnum(c.GetValueOrDefault("challenge_window_ms")), now, policy) ?? "malformed challenge window";
                        break;
                    }
                case "signature": reason = "claim signature does not verify"; break;
                default: reason = "malformed claim"; break;
            }
        }
        catch (Exception e) { reason = "claim verification error: " + e.Message; }
        return new D { ["ok"] = false, ["reason"] = reason };
    }

    // ---- fraud proofs ----

    static D Verdict(bool fraudulent, string? bondRef, string reason)
    {
        var m = new D { ["fraudulent"] = fraudulent };
        if (bondRef != null) m["slashBondRef"] = bondRef;
        m["reason"] = reason;
        return m;
    }

    static string? InnerClass(D snap) => ((snap.GetValueOrDefault("action") as D)?.GetValueOrDefault("action") as D)?.GetValueOrDefault("reversibility_class") as string;

    /// <summary>The reference <c>fileFraudProof</c>: a fraud proof against <paramref name="claim"/> for <paramref name="pcactn"/>, or null when the claim was compliant (or cannot be framed:
    /// a different action, no snapshot). The decision is NEVER taken from the caller: it is re-derived by replaying the Policy VM on <paramref name="openSnapshot"/> (the frozen open-time
    /// input) under <paramref name="grant"/>. A claim is fraudulent when the action is irreversible, the VM denies, the optimistic path is not allowed at the real risk, or the real r
    /// materially exceeds the claimed r.</summary>
    public static D? FileFraudProof(D claim, D pcactn, object? grant, D? openSnapshot, double? rMargin = null)
    {
        if (openSnapshot == null) return null;
        var actual = PolicyVmDecide.Decide(WithGrant(openSnapshot, grant));
        if (!(claim.GetValueOrDefault("pcactn_digest") is string cd && cd == Pca.HashCanonical(pcactn))) return null; // cannot frame a different action
        double margin = rMargin is double m && double.IsFinite(m) ? Math.Max(0, m) : DefaultRMargin;
        var thr = actual.GetValueOrDefault("requiredThreshold") as D ?? new D();
        bool release = actual.GetValueOrDefault("releaseGuardianShare") is true, optimistic = thr.GetValueOrDefault("optimisticAllowed") is true;
        double r = Dnum(actual.GetValueOrDefault("r")), claimed = Dnum(claim.GetValueOrDefault("claimed_r"));
        var evidence = new D(openSnapshot);
        evidence.Remove("grant");
        string kind, reason;
        if (claim.GetValueOrDefault("reversibility_class") as string == IrreversibleClass || (AsObj(pcactn.GetValueOrDefault("action")) is { } pa && pa.GetValueOrDefault("reversibility_class") as string == IrreversibleClass))
        {
            kind = "irreversible"; reason = "irreversible action took the optimistic path";
        }
        else if (!release)
        {
            var rs = Reasons(actual);
            kind = "policy-denied"; reason = "Policy VM denied the action: " + (rs.Length == 0 ? "not compliant" : rs);
        }
        else if (!optimistic)
        {
            kind = "optimistic-not-allowed"; reason = $"optimistic path not allowed at real r={Fixed3(r)} (t={IntentRevocation.JsText(thr.GetValueOrDefault("t"), thr.ContainsKey("t"))})";
        }
        else if (r > claimed + margin)
        {
            kind = "risk-understated"; reason = $"claimed r={Js(claimed)} but real r={Fixed3(r)}";
        }
        else return null;
        return new D
        {
            ["pcactn_digest"] = claim.GetValueOrDefault("pcactn_digest"), ["bond_ref"] = claim.GetValueOrDefault("bond_ref"), ["claimed_r"] = claim.GetValueOrDefault("claimed_r"),
            ["decision"] = Summary(release, N(r), optimistic), ["evidence"] = evidence, ["r_margin"] = N(margin), ["kind"] = kind, ["reason"] = reason,
        };
    }

    /// <summary>Independently verify a fraud proof (the reference <c>verifyFraudProof</c>): re-run the Policy VM on the frozen open-time snapshot under the grant the verifier trusts (never the
    /// proof's evidence), confirm the proof's decision matches, and confirm the recomputed decision refutes the claim. Returns <c>{fraudulent, slashBondRef?, reason}</c>. Never throws.</summary>
    public static D VerifyFraudProof(D claim, object? proofO, object? grant, object? snapO)
    {
        try
        {
            if (AsObj(proofO) is not { } proof) return Verdict(false, null, "malformed fraud proof");
            if (!SameMember(proof, claim, "pcactn_digest")) return Verdict(false, null, "fraud proof targets a different PCActn than the claim");
            if (!SameMember(proof, claim, "bond_ref")) return Verdict(false, null, "fraud proof names a different bond than the claim");
            if (AsObj(snapO) is not { } snap) return Verdict(false, null, "no frozen open-time snapshot supplied; cannot judge the claim");
            var recomputed = PolicyVmDecide.Decide(WithGrant(Shallow(snap), grant));
            var s = SummarizeDecision(recomputed);
            double r = Dnum(s["r"]);
            if (AsObj(proof.GetValueOrDefault("decision")) is not { } pd)
                return Verdict(false, null, "fraud-proof verification error: Cannot read properties of " + (proof.ContainsKey("decision") && proof["decision"] == null ? "null" : "undefined") + " (reading 'releaseGuardianShare')");
            if (!Equals(s["releaseGuardianShare"], pd.GetValueOrDefault("releaseGuardianShare")) || !Equals(s["optimisticAllowed"], pd.GetValueOrDefault("optimisticAllowed"))
                || Math.Abs(r - Dnum(pd.GetValueOrDefault("r"))) > 1e-9)
                return Verdict(false, null, "proof decision does not match an independent recomputation");
            double margin = Finite(proof.GetValueOrDefault("r_margin")) is double pm ? Math.Max(0, pm) : DefaultRMargin;
            bool irreversible = claim.GetValueOrDefault("reversibility_class") as string == IrreversibleClass || InnerClass(snap) == IrreversibleClass;
            var bond = claim.GetValueOrDefault("bond_ref") as string;
            if (irreversible) return Verdict(true, bond, "irreversible action is ineligible for the optimistic path");
            if (s["releaseGuardianShare"] is not true)
            {
                var rs = Reasons(recomputed);
                return Verdict(true, bond, "Policy VM denies the action: " + (rs.Length == 0 ? "not compliant" : rs));
            }
            if (s["optimisticAllowed"] is not true) return Verdict(true, bond, "optimistic path not allowed at real r=" + Fixed3(r));
            double claimed = Dnum(claim.GetValueOrDefault("claimed_r"));
            if (r > claimed + margin) return Verdict(true, bond, $"risk understated: claimed {Js(claimed)}, real {Fixed3(r)}");
            return Verdict(false, null, "claim is compliant under independent recomputation; bond stands");
        }
        catch (Exception e) { return Verdict(false, null, "fraud-proof verification error: " + e.Message); }
    }

    // ---- dispute adjudication ----

    static D Indeterminate(string input, string reason, D? baseline = null, object? agentValue = null)
    {
        var worst = Summary(false, N(1), false);
        var m = new D { ["outcome"] = "indeterminate", ["fraudulent"] = false, ["slashCounterBond"] = false, ["input"] = input };
        if (agentValue != null) m["agentValue"] = agentValue;
        m["baseline"] = baseline ?? worst;
        m["adjudicated"] = worst;
        m["reason"] = reason;
        return m;
    }

    static object? SnapshotValueOf(D snap, string input)
    {
        if (input == "reversibility_class")
        {
            var v = (AsObj(snap.GetValueOrDefault("caveatContext")))?.GetValueOrDefault("reversibilityClass");
            return v ?? (AsObj(snap.GetValueOrDefault("action")) is { } a ? AsObj(a.GetValueOrDefault("action"))?.GetValueOrDefault("reversibility_class") : null);
        }
        return AsObj(snap.GetValueOrDefault("risk"))?.GetValueOrDefault(input);
    }

    /// <summary>A COPY of <paramref name="snap"/> with the authoritative value (or class) <paramref name="res"/> carries substituted for its input. Throws when the resolution lacks what it needs.</summary>
    static D Substitute(D snap, D res)
    {
        var input = (string)res["input"]!;
        var next = new D(snap);
        var cc = AsObj(snap.GetValueOrDefault("caveatContext"));
        if (input == "reversibility_class")
        {
            if (res.GetValueOrDefault("class") is not string { Length: > 0 } cls) throw new InvalidOperationException("oracle reversibility_class resolution carries no class");
            var a = Shallow(snap.GetValueOrDefault("action"));
            var inner = Shallow(a.GetValueOrDefault("action"));
            inner["reversibility_class"] = cls;
            a["action"] = inner;
            next["action"] = a;
            // decide lets caveatContext.reversibilityClass OVERRIDE the action's: keep them consistent
            if (cc != null && cc.ContainsKey("reversibilityClass")) next["caveatContext"] = new D(cc) { ["reversibilityClass"] = cls };
            return next;
        }
        if (Finite(res.GetValueOrDefault("value")) == null) throw new InvalidOperationException($"oracle {input} resolution carries no finite value");
        var risk = Shallow(snap.GetValueOrDefault("risk"));
        risk[input] = res["value"];
        next["risk"] = risk;
        if (input == "blastRadius" && cc != null && cc.ContainsKey("blastRadius")) next["caveatContext"] = new D(cc) { ["blastRadius"] = res["value"] };
        return next;
    }

    static bool FastPathAdmits(D s, double claimedR, double margin) => s["releaseGuardianShare"] is true && s["optimisticAllowed"] is true && Dnum(s["r"]) <= claimedR + margin;

    static string Stringify(object? v) => v == null ? "undefined" : JsCanon.Lenient(v) ?? "undefined";

    /// <summary>Adjudicate a contestable dispute (the reference <c>adjudicateDispute</c>). Re-runs the Policy VM on the frozen snapshot with the ORACLE's value substituted for the single disputed
    /// input, under the grant the verifier trusts. Fails closed to <c>indeterminate</c> (slashing no one) on a mismatched target, a missing snapshot, an oracle that cannot resolve, or any error. The
    /// challenger's asserted value is never read for the verdict. Never throws.</summary>
    public static D AdjudicateDispute(D claim, object? disputeO, object? grant, object? snapO, ObjectiveOracle? oracle, double? rMargin = null)
    {
        double margin = rMargin is double m && double.IsFinite(m) ? Math.Max(0, m) : DefaultRMargin;
        var dispute = AsObj(disputeO);
        string fallback = dispute?.GetValueOrDefault("input") as string ?? "reversibility_class";
        try
        {
            if (dispute == null) return Indeterminate("reversibility_class", "malformed dispute");
            var inO = dispute.GetValueOrDefault("input");
            if (!IsDisputable(inO)) return Indeterminate("reversibility_class", "unknown disputed input: " + (inO is string s0 ? s0 : inO == null ? (dispute.ContainsKey("input") ? "null" : "undefined") : Stringify(inO)));
            var input = (string)inO!;
            if (!SameMember(dispute, claim, "pcactn_digest")) return Indeterminate(input, "dispute targets a different PCActn than the claim");
            if (!SameMember(dispute, claim, "bond_ref")) return Indeterminate(input, "dispute names a different bond than the claim");
            if (AsObj(snapO) is not { } open) return Indeterminate(input, "no frozen open-time snapshot supplied; cannot adjudicate");
            if (oracle == null) return Indeterminate(input, "no objective oracle supplied");

            var snap = WithGrant(Shallow(open), grant);
            var baseline = SummarizeDecision(PolicyVmDecide.Decide(snap));
            var agentValue = SnapshotValueOf(snap, input);

            var res = oracle(input, snap);
            if (res == null || res.GetValueOrDefault("input") as string != input || !IntentRevocation.Truthy(res.GetValueOrDefault("valid")))
            {
                var why = res?.GetValueOrDefault("reason");
                return Indeterminate(input, $"objective oracle could not authoritatively resolve {input}" + (IntentRevocation.Truthy(why) ? ": " + IntentRevocation.JsText(why, true) : ""), baseline, agentValue);
            }
            var oracleValue = res.GetValueOrDefault("class") ?? res.GetValueOrDefault("value");
            var adjudicated = SummarizeDecision(PolicyVmDecide.Decide(Substitute(snap, res)));
            double claimedR = Dnum(claim.GetValueOrDefault("claimed_r"));

            var o = new D { ["input"] = input };
            if (agentValue != null) o["agentValue"] = agentValue;
            if (oracleValue != null) o["oracleValue"] = oracleValue;
            o["baseline"] = baseline;
            o["adjudicated"] = adjudicated;
            if (!FastPathAdmits(adjudicated, claimedR, margin))
            {
                var why = adjudicated["releaseGuardianShare"] is not true ? "the Policy VM denies the action"
                    : adjudicated["optimisticAllowed"] is not true ? "the optimistic path is not allowed (higher threshold) at r=" + Fixed3(Dnum(adjudicated["r"]))
                    : $"the real r={Fixed3(Dnum(adjudicated["r"]))} exceeds the claimed r={Js(claimedR)}";
                o["outcome"] = "agent-fraud";
                o["fraudulent"] = true;
                o["slashBondRef"] = claim.GetValueOrDefault("bond_ref");
                o["slashCounterBond"] = false;
                o["reason"] = $"understated {input}: agent relied on {Stringify(agentValue)}, oracle says {Stringify(oracleValue)} — {why}";
                return o;
            }
            o["outcome"] = "claim-upheld";
            o["fraudulent"] = false;
            o["slashCounterBond"] = true;
            o["reason"] = $"the objective oracle upholds the agent's {input} ({Stringify(oracleValue)}); fast-path admission survives — the dispute is frivolous";
            return o;
        }
        catch (Exception e) { return Indeterminate(fallback, "dispute adjudication error (fail closed): " + e.Message); }
    }

    // ---- interactive dispute game (refereed bisection) ----

    /// <summary>Object.is on two JSON members: both absent, or both numbers that are the same value (NaN equals NaN, 0 differs from -0).</summary>
    static bool ObjectIs(object? a, bool ha, object? b, bool hb)
    {
        if (!ha || !hb) return !ha && !hb;
        if (IntentJs.NumOf(a) is not double x || IntentJs.NumOf(b) is not double y) return false;
        return (double.IsNaN(x) && double.IsNaN(y)) || (x == y && IntentJs.IsNegZero(x) == IntentJs.IsNegZero(y));
    }

    /// <summary>Exact equality of two step assertions: the same numeric value (or none) and the same class (or none).</summary>
    static bool AssertionEquals(D a, D b)
    {
        bool ha = a.TryGetValue("class", out var ca), hb = b.TryGetValue("class", out var cb);
        bool classEq = ha == hb && (!ha || (ca is string x && cb is string y ? x == y : Equals(ca, cb)));
        bool valueEq = ObjectIs(a.GetValueOrDefault("value"), a.ContainsKey("value"), b.GetValueOrDefault("value"), b.ContainsKey("value"));
        return valueEq && classEq;
    }

    static D ApplyAssertion(D snap, string input, D a)
    {
        var res = new D { ["input"] = input, ["valid"] = true };
        if (a.ContainsKey("value")) res["value"] = a["value"];
        if (a.ContainsKey("class")) res["class"] = a["class"];
        return Substitute(snap, res);
    }

    static D StateAfter(D snap, L steps, L assertions, int j)
    {
        var s = snap;
        for (int i = 0; i < j; i++)
        {
            if (steps[i] is not string input || assertions[i] is not D a) throw new InvalidOperationException("dispute game trace is shorter than its step list");
            s = ApplyAssertion(s, input, a);
        }
        return SummarizeDecision(PolicyVmDecide.Decide(s));
    }

    /// <summary>Adjudicate an INTERACTIVE multi-round dispute game by refereed bisection (the reference <c>adjudicateDisputeGame</c>). The two parties' committed traces (<c>game.defender</c> and
    /// <c>game.challenger</c>, parallel to <c>game.steps</c>) are narrowed to the ONE step on which they first diverge; only that step is then resolved with the objective oracle, by delegating to
    /// <see cref="AdjudicateDispute"/> against the mutually agreed pre-state. Returns <c>{verdict, converged, contestedStep, contestedInput?, transcript, rounds}</c>. Fails closed to
    /// <c>indeterminate</c> (slashing no one) on any malformed input, binding mismatch, missing snapshot or oracle, absence of a genuine admission dispute, or error. Never throws.</summary>
    public static D AdjudicateDisputeGame(D claim, object? gameO, object? grant, object? snapO, ObjectiveOracle? oracle, double? rMargin = null)
    {
        double margin = rMargin is double mm && double.IsFinite(mm) ? Math.Max(0, mm) : DefaultRMargin;
        var game = gameO as D;
        D Fail(string reason, string? input = null) => new()
        {
            ["verdict"] = Indeterminate(input ?? (game?.GetValueOrDefault("steps") is L { Count: > 0 } st0 && IsDisputable(st0[0]) ? (string)st0[0]! : "reversibility_class"), reason),
            ["converged"] = false, ["contestedStep"] = IntentJs.OfLong(-1), ["transcript"] = new L(), ["rounds"] = IntentJs.OfLong(0),
        };
        try
        {
            if (game == null) return Fail("malformed dispute game");
            if (!SameMember(game, claim, "pcactn_digest")) return Fail("dispute game targets a different PCActn than the claim");
            if (!SameMember(game, claim, "bond_ref")) return Fail("dispute game names a different bond than the claim");
            if (game.GetValueOrDefault("steps") is not L { Count: >= 1 } steps) return Fail("dispute game has no steps");
            foreach (var s in steps) if (!IsDisputable(s)) return Fail("unknown disputed input: " + (s is string ss ? ss : s == null ? "null" : IntentRevocation.JsText(s, true)));
            if (game.GetValueOrDefault("defender") is not L defender || game.GetValueOrDefault("challenger") is not L challenger || defender.Count != steps.Count || challenger.Count != steps.Count)
                return Fail("party assertions do not cover every step");
            if (AsObj(snapO) is not { } open) return Fail("no frozen open-time snapshot supplied; cannot adjudicate");
            if (oracle == null) return Fail("no objective oracle supplied");

            int n = steps.Count;
            var snap = WithGrant(Shallow(open), grant);
            double claimedR = Dnum(claim.GetValueOrDefault("claimed_r"));

            // genuine-dispute gate: the defender's full trace must still admit the fast path and the challenger's must not
            var defenderFinal = StateAfter(snap, steps, defender, n);
            var challengerFinal = StateAfter(snap, steps, challenger, n);
            if (!FastPathAdmits(defenderFinal, claimedR, margin)) return Fail("defender does not defend the fast-path admission; nothing to adjudicate");
            if (FastPathAdmits(challengerFinal, claimedR, margin)) return Fail("the parties do not disagree on admission; no genuine dispute to bisect");

            bool PrefixAgrees(int m)
            {
                for (int i = 0; i < m; i++)
                    if (defender[i] is not D di || challenger[i] is not D ci || !AssertionEquals(di, ci)) return false;
                return true;
            }
            if (PrefixAgrees(n)) return Fail("the parties committed identical traces; no contested step to bisect");

            int lo = 0, hi = n;
            var transcript = new L();
            while (hi - lo > 1)
            {
                int mid = (lo + hi) / 2;
                bool agreed = PrefixAgrees(mid);
                transcript.Add(new D { ["lo"] = IntentJs.OfLong(lo), ["hi"] = IntentJs.OfLong(hi), ["mid"] = IntentJs.OfLong(mid), ["agreedAtMid"] = agreed });
                if (agreed) lo = mid; else hi = mid;
            }
            int contested = lo;
            var contestedInput = (string)steps[contested]!;

            // the agreed pre-state: every earlier, mutually agreed correction folded in (re-verified, so a search-invariant violation cannot smuggle a challenger-only correction in)
            var pre = snap;
            for (int i = 0; i < contested; i++)
            {
                if (defender[i] is not D di || challenger[i] is not D ci || !AssertionEquals(di, ci)) return Fail("agreed prefix is not actually agreed; cannot reconstruct the pre-state", contestedInput);
                pre = ApplyAssertion(pre, (string)steps[i]!, di);
            }
            if (challenger[contested] is not D move) return Fail("challenger has no assertion for the contested step", contestedInput);
            var dispute = new D { ["pcactn_digest"] = claim.GetValueOrDefault("pcactn_digest"), ["bond_ref"] = claim.GetValueOrDefault("bond_ref"), ["input"] = contestedInput };
            if (move.ContainsKey("value")) dispute["asserted_value"] = move["value"];
            if (move.ContainsKey("class")) dispute["asserted_class"] = move["class"];
            var verdict = AdjudicateDispute(claim, dispute, grant, pre, oracle, margin);
            return new D
            {
                ["verdict"] = verdict, ["converged"] = true, ["contestedStep"] = IntentJs.OfLong(contested), ["contestedInput"] = contestedInput,
                ["transcript"] = transcript, ["rounds"] = IntentJs.OfLong(transcript.Count),
            };
        }
        catch (Exception e) { return Fail("dispute game adjudication error (fail closed): " + e.Message); }
    }

    // ---- frozen open-time snapshot ----

    /// <summary>The reference <c>freezeOpenSnapshot</c>: a deep, JSON-normalized copy of a Policy VM input captured when a claim opened (store it with the claim). A .NET tree has no freeze, so the copy shares
    /// nothing with the argument: mutating the original cannot change what a later verdict replays.</summary>
    public static D FreezeOpenSnapshot(D input) => (D)IntentJs.Normalize(StoreJs.DeepCopy(input))!;
}
