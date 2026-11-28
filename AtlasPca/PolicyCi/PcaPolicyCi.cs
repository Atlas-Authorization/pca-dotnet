// A CI gate that statically catches unsafe PCA policies before they ship. It drives the static analyzer (reachability, totality, delegation-safety
// subsumption, numeric satisfiability) over an envelope, a minted grant, a compiled policy or a delegation chain and reports findings
// {rule, severity, message, where?}. Rules (each toggleable): over-broad-grant, privilege-escalation, redundant-caveat, dangerous-reachability,
// missing-safety-floor, and schema-mismatch when a schema is given. Sound by construction: a hard error comes only from a proven analyzer verdict;
// anything undecidable fails safe to a warning or note. A rule that throws is a finding (internal-error), never a crash and never silence.
// Options are JSON-shaped maps: rules, maxCombinations, schema, schemaOptions, and for the summary maxSeverity.
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using static AtlasPca.PolicyCi.CiJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.PolicyCi;

public static class PcaPolicyCi
{
    /// <summary>Verb substrings treated as dangerous (case-insensitive includes match).</summary>
    public static readonly IReadOnlyList<string> DefaultDangerousVerbs = new[]
    {
        "delete", "destroy", "drop", "remove", "purge", "transfer", "payout", "wire", "withdraw", "admin", "grant", "revoke", "deploy", "shutdown", "rotate",
    };

    static L DefaultDangerous() => new(DefaultDangerousVerbs.Cast<object?>());

    /// <summary>Severity ordering used for thresholds; higher is more severe. Keys in the reference's order.</summary>
    public static readonly IReadOnlyList<(string Key, int Rank)> SeverityRank = new[] { ("info", 1), ("warn", 2), ("error", 3) };

    static bool HasRank(string k) => SeverityRank.Any(r => r.Key == k);
    static int RankOf(string k) => SeverityRank.First(r => r.Key == k).Rank;

    /// <summary>A rule that throws is a finding, not a crash and not silence: a gate must not pass a policy it could not finish checking.</summary>
    static L Guarded(string rule, Func<L> run)
    {
        try { return run(); }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            var msg = e is InsufficientExecutionStackException ? "Maximum call stack size exceeded" : e.Message;
            return new L { Obj(("rule", "internal-error"), ("severity", "error"), ("message", $"rule {rule} could not run: {msg}")) };
        }
    }

    // ---- resolved config ----

    sealed class Resolved
    {
        public bool OverBroad, PrivilegeEscalation, RedundantCaveat, DangerousReach, SafetyFloor, RequireExpiry, RequireScopeGate;
        public object? OverBroadVerbs = null, ReachVerbs = null, Targets = null;
    }

    static object? VerbList(object? cfg)
    {
        if (!TypeofObject(cfg)) return DefaultDangerous();
        var dv = Jx.Prop(cfg, "dangerousVerbs");
        return Truthy(dv) ? dv : DefaultDangerous();
    }

    static Resolved ResolveRules(object? rules)
    {
        var r = rules == null || Jx.IsUndef(rules) ? new D() : rules;
        var ob = Jx.Prop(r, "overBroadGrant");
        var dr = Jx.Prop(r, "dangerousReachability");
        var sf = Jx.Prop(r, "missingSafetyFloor");
        var c = new Resolved
        {
            OverBroad = !(ob is false),
            OverBroadVerbs = VerbList(ob),
            PrivilegeEscalation = !(Jx.Prop(r, "privilegeEscalation") is false),
            RedundantCaveat = !(Jx.Prop(r, "redundantCaveat") is false),
            DangerousReach = !(dr is false),
            ReachVerbs = VerbList(dr),
        };
        var tg = TypeofObject(dr) ? Jx.Prop(dr, "targets") : Jx.Undef;
        c.Targets = Truthy(tg) ? tg : new L();
        c.SafetyFloor = !(sf is false);
        c.RequireExpiry = !TypeofObject(sf) || !(Jx.Prop(sf, "requireExpiry") is false);
        c.RequireScopeGate = !TypeofObject(sf) || !(Jx.Prop(sf, "requireScopeGate") is false);
        return c;
    }

    static D AnalyzerOpts(object? opts)
    {
        var ao = new D();
        var m = Jx.Opt(opts, "maxCombinations");
        if (!Jx.IsUndef(m)) ao["maxCombinations"] = m;
        return ao;
    }

    static object? OptGet(object? opts, string k) => opts == null ? throw JsX.TypeError($"Cannot read properties of null (reading '{k}')") : Jx.Prop(opts, k);

    // ---- lintPolicy / lintChain / lint ----

    static L Malformed(object? reason) => new() { Obj(("rule", "malformed-policy"), ("severity", "error"), ("message", reason)) };

    /// <summary>Lints a single PCA policy (an envelope, a minted grant, a compiled policy or a bare <c>{predicates, caveats?}</c>); an empty list is clean.</summary>
    public static L LintPolicy(object? input, object? opts = null)
    {
        opts ??= new D();
        var norm = CiNormalize.NormalizePolicyInput(input);
        if (norm["ok"] is not true) return Malformed(norm["reason"]);
        var cfg = ResolveRules(OptGet(opts, "rules"));
        var ao = AnalyzerOpts(opts);
        var policy = (D)norm["policy"]!;
        var o = new L();
        if (cfg.OverBroad) o.AddRange(Guarded("over-broad-grant", () => CiRules.RuleOverBroadGrant(policy, cfg.OverBroadVerbs, ao)));
        if (cfg.RedundantCaveat) o.AddRange(Guarded("redundant-caveat", () => CiRules.RuleRedundantCaveat(policy)));
        if (cfg.DangerousReach) o.AddRange(Guarded("dangerous-reachability", () => CiRules.RuleDangerousReachability(policy, cfg.ReachVerbs, cfg.Targets, ao)));
        if (cfg.SafetyFloor) o.AddRange(Guarded("missing-safety-floor", () => CiRules.RuleMissingSafetyFloor(policy, cfg.RequireExpiry, cfg.RequireScopeGate, cfg.OverBroadVerbs)));
        var schema = Jx.Prop(opts, "schema");
        if (!Jx.IsUndef(schema)) o.AddRange(Guarded("schema-mismatch", () => CiRules.RuleSchemaMismatch(policy, schema, Jx.Prop(opts, "schemaOptions"))));
        return o;
    }

    /// <summary>Lints a delegation chain (root to leaf): grants or already-effective <c>{predicates, caveats}</c> hops. Runs the privilege-escalation
    /// check across every consecutive pair, then the single-policy rules on the acting leaf's effective authority.</summary>
    public static L LintChain(IReadOnlyList<object?> chain, object? opts = null)
    {
        opts ??= new D();
        var norm = CiNormalize.NormalizeChain(chain);
        if (norm["ok"] is not true) return Malformed(norm["reason"]);
        var cfg = ResolveRules(OptGet(opts, "rules"));
        var ao = AnalyzerOpts(opts);
        var hops = (L)norm["hops"]!;
        var o = new L();
        if (cfg.PrivilegeEscalation) o.AddRange(Guarded("privilege-escalation", () => CiRules.RulePrivilegeEscalation(hops, ao)));
        if (hops.Count > 0)
        {
            var leaf = (D)hops[^1]!;
            if (cfg.OverBroad) o.AddRange(Guarded("over-broad-grant", () => CiRules.RuleOverBroadGrant(leaf, cfg.OverBroadVerbs, ao)));
            if (cfg.RedundantCaveat) o.AddRange(Guarded("redundant-caveat", () => CiRules.RuleRedundantCaveat(leaf)));
            if (cfg.DangerousReach) o.AddRange(Guarded("dangerous-reachability", () => CiRules.RuleDangerousReachability(leaf, cfg.ReachVerbs, cfg.Targets, ao)));
            if (cfg.SafetyFloor) o.AddRange(Guarded("missing-safety-floor", () => CiRules.RuleMissingSafetyFloor(leaf, cfg.RequireExpiry, cfg.RequireScopeGate, cfg.OverBroadVerbs)));
        }
        return o;
    }

    /// <summary>Dispatch: a list input is a delegation chain, anything else a single policy.</summary>
    public static L Lint(object? input, object? opts = null) => input is L chain ? LintChain(chain, opts) : LintPolicy(input, opts);

    // ---- lintPolicies + summary ----

    /// <summary>Lints a list of labeled policies (<c>{label?, policy}</c>) or chains and rolls the findings into a summary.</summary>
    public static D LintPolicies(IReadOnlyList<object?> items, object? opts = null)
    {
        opts ??= new D();
        var results = new L();
        for (int i = 0; i < items.Count; i++)
        {
            var item = items[i];
            var label = Jx.Prop(item, "label");
            results.Add(Obj(("label", label == null || Jx.IsUndef(label) ? $"policy[{i}]" : label), ("findings", Lint(Jx.Prop(item, "policy"), opts))));
        }
        return Summarize(results, opts);
    }

    /// <summary>Rolls labeled findings into counts and an exit-code mapping (<c>error</c> gives non-zero); nothing linted never reports success.</summary>
    public static D Summarize(object? results, object? opts = null)
    {
        opts ??= new D();
        var ms = Jx.Prop(opts, "maxSeverity");
        var maxSeverity = ms == null || Jx.IsUndef(ms) ? "error" : ms;
        var key = Str(maxSeverity);
        if (!HasRank(key)) throw new ArgumentException("summarize: maxSeverity must be one of " + string.Join(", ", SeverityRank.Select(r => r.Key)));
        if (results is not L list || list.Count == 0)
            return Obj(("results", new L()), ("counts", Obj(("error", N(0)), ("warn", N(0)), ("info", N(0)))), ("maxSeverity", maxSeverity), ("ok", false), ("exitCode", N(2)), ("reason", "no policies were linted"));
        long error = 0, warn = 0, info = 0, failing = 0;
        var threshold = RankOf(key);
        foreach (var r in list)
        {
            var fs = Jx.Prop(r, "findings");
            if (fs is not L findings) throw TypeErr("r.findings is not iterable");
            foreach (var f in findings)
            {
                var sv = Jx.Prop(f, "severity");
                var sk = Jx.IsUndef(sv) ? "undefined" : Str(sv);
                // a finding whose severity is not one of the three is counted as an error: it must never slip under the threshold
                var sev = HasRank(sk) ? sk : "error";
                if (sev == "error") error++; else if (sev == "warn") warn++; else info++;
                if (RankOf(sev) >= threshold) failing++;
            }
        }
        var ok = failing == 0;
        return Obj(("results", results), ("counts", Obj(("error", N(error)), ("warn", N(warn)), ("info", N(info)))), ("maxSeverity", maxSeverity), ("ok", ok), ("exitCode", N(ok ? 0 : 1)));
    }

    // ---- pinned lint rule list ----

    static bool IsDigest(string s) => s.Length == 43 && s.All(c => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-');

    /// <summary>Enforces the pinned digest of the action-kit lint rule list: <paramref name="pinText"/> is the pin file's content (one digest,
    /// surrounding whitespace ignored). Returns <c>{ok, message}</c>; an empty or malformed pin fails.</summary>
    public static D CheckLintRulesPin(string pinText, string? actual = null)
    {
        actual ??= ActionLintRules.LintRulesDigest();
        var pinned = JsX.JsTrim(pinText);
        if (!IsDigest(pinned)) return Obj(("ok", false), ("message", "the lint rules pin is not a digest (expected 43 base64url characters)"));
        return pinned == actual
            ? Obj(("ok", true), ("message", $"lint rules digest {actual} matches the pin"))
            : Obj(("ok", false), ("message", $"lint rules digest {actual} differs from the pin {pinned}: the rule list changed; review it and update the pin"));
    }
}
