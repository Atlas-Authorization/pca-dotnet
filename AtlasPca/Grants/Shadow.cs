// Shadow policy rollout: run candidates beside the enforced policy without letting any of them change the answer, keep verifier-signed
// diffs, and gate promotion on observed behaviour and principal-signed explanations (packages/pca-grants shadow.ts).
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Grants;

/// <summary>What one candidate would have decided. <c>Decision</c> is deny, escalate, allow or error.</summary>
public sealed record ShadowOutcome(string Digest, string Decision, bool Diverged, bool Widening)
{
    public JD ToJson() => new() { ["digest"] = Digest, ["decision"] = Decision, ["diverged"] = Diverged, ["widening"] = Widening };
}

public sealed record ShadowCandidate(string Digest, Func<object?, string?> Decide);

public static class Shadow
{
    public const string DiffDomain = "atlas-pca/shadow-diff/v1\0";
    public const string WideningExplanationDomain = "atlas-pca/shadow-widening-explanation/v1\0";
    public const string PromotionApprovalDomain = "atlas-pca/shadow-promotion-approval/v1\0";
    static readonly Dictionary<string, int> Rank = new() { ["deny"] = 0, ["escalate"] = 1, ["allow"] = 2 };
    static bool IsKind(object? x) => x is string s && Rank.ContainsKey(s);
    static bool Wider(string a, string b) => Rank[a] > Rank[b];

    /// <summary>The enforced decision first, then what each candidate would have said. The returned decision is the enforced one, always;
    /// a candidate that throws or answers anything but a decision is recorded as <c>error</c>.</summary>
    public static (string Decision, List<ShadowOutcome> Outcomes) RunShadow(object? input, Func<object?, string?> enforced, IEnumerable<ShadowCandidate> candidates)
    {
        var decision = enforced(input);
        var outs = new List<ShadowOutcome>();
        foreach (var c in candidates)
        {
            try
            {
                var d = c.Decide(G.Clone(input));
                if (!IsKind(d)) outs.Add(new ShadowOutcome(c.Digest, "error", false, false));
                else outs.Add(new ShadowOutcome(c.Digest, d!, d != decision, IsKind(decision) && Wider(d!, decision!)));
            }
            catch (Exception) { outs.Add(new ShadowOutcome(c.Digest, "error", false, false)); }
        }
        return (decision ?? "", outs);
    }

    /// <summary>The <c>shadow</c> member of a decision record, from the outcomes: <c>{digest, decision, diverged}</c> for each.</summary>
    public static JL RecordField(IEnumerable<ShadowOutcome> outcomes) =>
        new(outcomes.Select(o => (object?)new JD { ["digest"] = o.Digest, ["decision"] = o.Decision, ["diverged"] = o.Diverged }));

    static readonly string[] DiffKeys = { "v", "shadow_digest", "enforced_digest", "action_digest", "enforced", "shadow", "widening", "at", "signer" };

    /// <summary>A recorded diff is well formed, internally consistent and signed by its signer (and by <paramref name="signer"/> when given).</summary>
    public static bool VerifyShadowDiff(object? d, string? signer = null)
    {
        if (d is not JD x || !(G.Get(x, "v") is Num one && one.Raw == "1") || !G.Str(G.Get(x, "shadow_digest"), 128) || !G.Str(G.Get(x, "enforced_digest"), 128)
            || !G.Str(G.Get(x, "action_digest"), 128) || !IsKind(G.Get(x, "enforced")) || !IsKind(G.Get(x, "shadow")) || G.Get(x, "widening") is not bool w
            || !G.Nat(G.Get(x, "at")) || !G.Str(G.Get(x, "signer"), 128)) return false;
        var enforced = (string)x["enforced"]!; var shadow = (string)x["shadow"]!;
        if (enforced == shadow || w != Wider(shadow, enforced)) return false;
        if (signer != null && (string)x["signer"]! != signer) return false;
        return Sig.VerifyBody(DiffDomain, G.Pick(x, DiffKeys), x["signer"], G.Get(x, "sig"));
    }

    /// <summary>Collects the signed diffs and counters per candidate (in memory).</summary>
    public sealed class ShadowLog
    {
        readonly EdKey key;
        readonly Dictionary<string, long[]> stat = new(StringComparer.Ordinal); // total, diverged, widened, tightened, errors
        readonly Dictionary<string, List<JD>> list = new(StringComparer.Ordinal);
        public ShadowLog(EdKey key) { this.key = key; }
        public string Signer => key.Id;

        /// <summary>Count one observation; sign and keep a diff when the candidate diverged.</summary>
        public JD? Observe(string enforcedDigest, string actionDigest, string enforced, ShadowOutcome outcome, long at)
        {
            if (!stat.TryGetValue(outcome.Digest, out var s)) stat[outcome.Digest] = s = new long[5];
            s[0]++;
            if (outcome.Decision == "error") { s[4]++; return null; }
            if (!outcome.Diverged) return null;
            s[1]++;
            if (outcome.Widening) s[2]++; else s[3]++;
            var b = new JD
            {
                ["v"] = new Num("1"), ["shadow_digest"] = outcome.Digest, ["enforced_digest"] = enforcedDigest, ["action_digest"] = actionDigest,
                ["enforced"] = enforced, ["shadow"] = outcome.Decision, ["widening"] = outcome.Widening, ["at"] = G.N(at), ["signer"] = Signer,
            };
            var diff = new JD(b);
            diff["sig"] = Sig.SignBody(DiffDomain, b, key);
            if (!list.TryGetValue(outcome.Digest, out var l)) list[outcome.Digest] = l = new List<JD>();
            l.Add(diff);
            return diff;
        }

        public JD Stats(string digest)
        {
            var s = stat.TryGetValue(digest, out var x) ? x : new long[5];
            return new JD { ["total"] = G.N(s[0]), ["diverged"] = G.N(s[1]), ["widened"] = G.N(s[2]), ["tightened"] = G.N(s[3]), ["errors"] = G.N(s[4]) };
        }

        public List<JD> Diffs(string digest) => list.TryGetValue(digest, out var l) ? l.Select(G.CloneD).ToList() : new List<JD>();
    }

    /// <summary>A principal states that this widening is intended (<c>reason_digest</c> binds the display-only reason text).</summary>
    public static JD SignWideningExplanation(EdKey key, string shadowDigest, string actionDigest, string reasonDigest)
    {
        var b = new JD { ["v"] = new Num("1"), ["shadow_digest"] = shadowDigest, ["action_digest"] = actionDigest, ["reason_digest"] = reasonDigest, ["principal"] = key.Id };
        var o = new JD(b);
        o["sig"] = Sig.SignBody(WideningExplanationDomain, b, key);
        return o;
    }

    static readonly string[] ExpKeys = { "v", "shadow_digest", "action_digest", "reason_digest", "principal" };
    static bool VerifyExplanation(object? e) =>
        e is JD x && G.Get(x, "v") is Num one && one.Raw == "1" && G.Str(G.Get(x, "shadow_digest"), 128) && G.Str(G.Get(x, "action_digest"), 128) && G.Str(G.Get(x, "reason_digest"), 128)
        && G.Str(G.Get(x, "principal"), 128) && Sig.VerifyBody(WideningExplanationDomain, G.Pick(x, ExpKeys), x["principal"], G.Get(x, "sig"));

    public static JD SignPromotionApproval(EdKey key, string shadowDigest, string enforcedDigest, long at)
    {
        var b = new JD { ["v"] = new Num("1"), ["shadow_digest"] = shadowDigest, ["enforced_digest"] = enforcedDigest, ["at"] = G.N(at), ["principal"] = key.Id };
        var o = new JD(b);
        o["sig"] = Sig.SignBody(PromotionApprovalDomain, b, key);
        return o;
    }

    static readonly string[] ApKeys = { "v", "shadow_digest", "enforced_digest", "at", "principal" };
    static bool VerifyApproval(object? a) =>
        a is JD x && G.Get(x, "v") is Num one && one.Raw == "1" && G.Str(G.Get(x, "shadow_digest"), 128) && G.Str(G.Get(x, "enforced_digest"), 128) && G.Nat(G.Get(x, "at"))
        && G.Str(G.Get(x, "principal"), 128) && Sig.VerifyBody(PromotionApprovalDomain, G.Pick(x, ApKeys), x["principal"], G.Get(x, "sig"));

    static JD No(string code, string reason, List<string>? unexplained = null)
    {
        var o = new JD { ["ok"] = false, ["code"] = code, ["reason"] = reason };
        if (unexplained != null) o["unexplained"] = unexplained.Cast<object?>().ToList();
        return o;
    }

    /// <summary>May the candidate be promoted? <paramref name="o"/> is <c>{shadow_digest, enforced_digest, minSamples, principals, explanations?, surface, approval?}</c>;
    /// the result is <c>{ok: true, samples, widenings, surface}</c> or <c>{ok: false, code, reason, unexplained?}</c>. Fails closed.</summary>
    public static JD PromotionGate(ShadowLog log, JD o)
    {
        try
        {
            var surface = G.Get(o, "surface") as string;
            if (!G.Str(G.Get(o, "shadow_digest"), 128) || !G.Str(G.Get(o, "enforced_digest"), 128) || !G.Nat(G.Get(o, "minSamples")) || G.L(G.Get(o, "minSamples")) < 1
                || G.Get(o, "principals") is not JL principals || surface is not ("narrower" or "equal" or "wider" or "unknown")) return No("bad_input", "bad gate options");
            var shadowDigest = (string)o["shadow_digest"]!; var enforcedDigest = (string)o["enforced_digest"]!;
            var minSamples = G.L(o["minSamples"]);
            var s = log.Stats(shadowDigest);
            var total = G.L(s["total"]); var errors = G.L(s["errors"]); var diverged = G.L(s["diverged"]);
            if (total < minSamples) return No("too_few_samples", $"{total} observation(s), need {minSamples}");
            if (errors > 0) return No("shadow_errors", $"{errors} observation(s) where the candidate failed");
            var diffs = log.Diffs(shadowDigest);
            if (!diffs.All(d => VerifyShadowDiff(d, log.Signer) && (string)d["shadow_digest"]! == shadowDigest && (string)d["enforced_digest"]! == enforcedDigest) || diffs.Count != diverged)
                return No("bad_diff", "a recorded diff does not verify, belongs to another pair, or is missing");
            var explained = new HashSet<string>(StringComparer.Ordinal);
            var ex = G.Get(o, "explanations");
            if (ex is JL el)
            {
                foreach (var e in el)
                    if (VerifyExplanation(e) && principals.Contains(G.Get(e, "principal")) && (string)G.Get(e, "shadow_digest")! == shadowDigest) explained.Add((string)G.Get(e, "action_digest")!);
            }
            else if (ex != null && ex is not string) throw new InvalidOperationException("explanations is not iterable");
            var unexplained = diffs.Where(d => (bool)d["widening"]! && !explained.Contains((string)d["action_digest"]!)).Select(d => (string)d["action_digest"]!).Distinct(StringComparer.Ordinal).ToList();
            unexplained.Sort(StringComparer.Ordinal);
            if (unexplained.Count > 0) return No("unexplained_widening", $"{unexplained.Count} widening(s) without a principal's explanation", unexplained);
            if (surface is "wider" or "unknown")
            {
                var a = G.Get(o, "approval");
                if (!VerifyApproval(a) || !principals.Contains(G.Get(a, "principal")) || (string)G.Get(a, "shadow_digest")! != shadowDigest || (string)G.Get(a, "enforced_digest")! != enforcedDigest)
                    return No("advisory_wider", $"the analyzer reports the candidate {(surface == "wider" ? "wider" : "not provably narrower")} on the declared surfaces: a principal-signed approval is required");
            }
            return new JD { ["ok"] = true, ["samples"] = G.N(total), ["widenings"] = G.N(diffs.Count(d => (bool)d["widening"]!)), ["surface"] = surface };
        }
        catch (Exception) { return No("bad_input", "evaluation error (fail closed)"); }
    }

    /// <summary>The body of the bundle revision that makes the candidate the enforced policy (revision + 1, chained to the enforced revision,
    /// shadow list cleared). Needs a passing gate for exactly this candidate and the candidate listed in the enforced revision's shadow.</summary>
    public static JD PromoteShadow(JD enforced, JD candidate, JD gate, object? now)
    {
        var digest = K3.BundleDigest(candidate) ?? throw new ArgumentException("promoteShadow: the candidate is not canonical");
        if (G.Get(gate, "ok") is not true) throw new ArgumentException($"promoteShadow: the gate did not pass ({G.Get(gate, "code")})");
        if (!(G.Get(enforced, "shadow") is JL sh && sh.Contains(digest))) throw new ArgumentException("promoteShadow: the candidate is not listed in the enforced revision's shadow");
        if (!Pca.SafeNat(now, out _)) throw new ArgumentException("promoteShadow: bad time");
        var o = G.Without(candidate, "sigs", "shadow", "prev");
        o["revision"] = G.N(G.L(G.Get(enforced, "revision")) + 1);
        o["prev"] = K3.BundleDigest(enforced) ?? throw new ArgumentException("promoteShadow: the enforced revision is not canonical");
        o["issued_at"] = now;
        return o;
    }
}
