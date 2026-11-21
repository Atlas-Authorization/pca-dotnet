// The hosted action registry of one instance: the publish gate and the verifier's view of the active versions. Pure: storage, keys and time are
// the caller's. Fail closed everywhere: an action the view does not know, that no pinned reviewer key confirmed, or that is deprecated gets the
// top of the trait registry, no provenance facts, is irreversible and never undoable.
using System.Text.RegularExpressions;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionHosted
{
    public const string RulesDocKind = "pca-action-rules";
    public const string HostedVersionDomain = "atlas-pca/hosted-action-version/v1";
    static readonly Regex PlainSemver = new(@"^[0-9]+\.[0-9]+\.[0-9]+\z", RegexOptions.CultureInvariant);
    static readonly string[] EffectiveDims = { "confirmation", "effective.traits", "effective.profile" };
    static readonly string[] CaveatKindList = { "amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap" };
    // one shared core registry: reference identity decides whether two versions share a trait registry
    internal static readonly Dictionary<string, D> Core = Actions.CoreRegistry;

    static string ServerClass(string rev) => rev switch { "reversible" => "reversible", "rate_limited" => "costly", _ => "irreversible" };

    /// <summary>The trait registry of a version: core plus its custom traits. Throws for custom traits that do not extend their implies.</summary>
    public static Dictionary<string, D> RegistryOfTraits(IReadOnlyList<object?> traits) => traits.Count == 0 ? Core : Actions.ExtendRegistry(Core, traits);

    /// <summary>The confirmation verifier of an instance: a signature by a pinned reviewer key (no pins: nothing is confirmed).</summary>
    public static Func<D, bool>? ReviewOptsOf(object? pins, Dictionary<string, D> reg) => pins == null ? null : ActionUndoEngine.AttestationVerifier(pins, reg);

    /// <summary>Null iff x is a rules document for ns whose every verb is in defs and whose rules lint without errors.</summary>
    public static string? RulesDocError(object? x, string ns, IEnumerable<D> defs)
    {
        if (x is not D xd) return "rules must be a pca-action-rules document";
        foreach (var k in xd.Keys)
            if (k is not ("v" or "kind" or "ns" or "rules" or "reviews")) return $"rules: unknown member '{k}'";
        var v = Ak.G(xd, "v");
        if (v is not Num || Ak.Dbl(v) != 1 || Ak.S(xd, "kind") != RulesDocKind) return $"rules: not a {RulesDocKind} v1 document";
        if (Ak.S(xd, "ns") != ns) return $"rules: ns '{IntentRevocation.JsText(Ak.G(xd, "ns"), xd.ContainsKey("ns"))}' is not the pack's '{ns}'";
        if (Ak.G(xd, "rules") is not D rules) return "rules.rules must map verbs to rules blocks";
        if (xd.ContainsKey("reviews") && Ak.G(xd, "reviews") is not D) return "rules.reviews must map verbs to rules reviews";
        var byVerb = new Dictionary<string, D>();
        foreach (var d in defs) byVerb[(string)d["verb"]!] = d;
        foreach (var (verb, block) in rules)
        {
            if (!byVerb.TryGetValue(verb, out var def)) return $"rules: '{verb}' is not an action of the pack";
            var errs = ActionBusinessRules.LintBusinessRules(def, block).Where(f => Ak.S(f, "severity") == "error").Select(f => Ak.S(f, "message")).ToList();
            if (errs.Count > 0) return $"rules for '{verb}': " + string.Join("; ", errs);
        }
        if (Ak.G(xd, "reviews") is D reviews)
            foreach (var verb in reviews.Keys)
                if (!byVerb.ContainsKey(verb)) return $"rules.reviews: '{verb}' is not an action of the pack";
        return null;
    }

    public static string HostedVersionDigest(D v) => Pca.HashCanonical(new D
    {
        ["d"] = HostedVersionDomain, ["pack"] = v["pack"], ["rules"] = v["rules"], ["traits"] = v["traits"],
        ["deprecated"] = Ak.ToL(Ak.Strs(v["deprecated"]).OrderBy(x => x, StringComparer.Ordinal)),
    });

    static D Fail(string code, string reason, List<string>? verbs = null)
    {
        var o = new D { ["ok"] = false, ["code"] = code, ["reason"] = reason };
        if (verbs != null && verbs.Count > 0) o["verbs"] = Ak.ToL(verbs);
        return o;
    }

    static bool SafeConfirmed(D d, Func<D, bool>? review)
    {
        try { return ActionEffective.IsConfirmed(d, review); } catch (Exception) { return false; }
    }

    /// <summary>DiffDefs, but each side under its own registry and review (a trait registry change shows up in the effective dimensions).</summary>
    static D DiffDefsAcross(D o, D n, Dictionary<string, D> oReg, Dictionary<string, D> nReg, Func<D, bool>? oRev, Func<D, bool>? nRev)
    {
        var bs = ActionDiff.DiffDefs(o, n, nReg, nRev);
        if (ReferenceEquals(oReg, nReg)) return bs;
        var eo = (D)ActionEffective.EffectiveWith(o, oReg, oRev)["eff"]!;
        var en = (D)ActionEffective.EffectiveWith(n, nReg, nRev)["eff"]!;
        string? rel = Actions.Leq(eo, en) ? (Actions.Leq(en, eo) ? null : "narrow") : (Actions.Leq(en, eo) ? "widen" : "incomparable");
        if (rel == null) return bs;
        var rs = Ak.Strs(bs["reasons"]).Where(r => !r.StartsWith("effective.profile", StringComparison.Ordinal)).ToList();
        rs.Add("effective.profile: " + rel);
        rs.Sort(StringComparer.Ordinal);
        var bc = Ak.S(bs, "class");
        var cls = rel == "incomparable" || bc == "incomparable" || (rel == "widen" && bc == "narrow") || (rel == "narrow" && bc == "widen") ? "incomparable"
            : rel == "widen" || bc == "widen" ? "widen" : "narrow";
        return new D { ["class"] = cls, ["reasons"] = Ak.ToL(rs) };
    }

    /// <summary>Decide whether a version may become the active one of its namespace and compute what it changes. i: {current?, pack, rules?, traits?,
    /// publisherKeys, pins?, pin?}. Refused: bad_pack, bad_traits, bad_rules, ns_mismatch, bad_version / not_newer, widen_unreviewed.</summary>
    public static D PublishGate(D i)
    {
        object traitsO = new L();
        if (i.ContainsKey("traits"))
        {
            if (i["traits"] is not L tl) return Fail("bad_traits", "traits must be a list of trait definitions");
            traitsO = tl;
        }
        var traits = (L)traitsO;
        Dictionary<string, D> reg;
        try { reg = RegistryOfTraits(traits); }
        catch (Exception e) { return Fail("bad_traits", e.Message); }
        var pv = ActionBuild.VerifyPack(Ak.G(i, "pack"), (L)i["publisherKeys"]!, reg);
        if (pv["ok"] is not true) return Fail("bad_pack", (string)pv["reason"]!);
        var pack = (D)i["pack"]!;
        var packVersion = (string)pack["version"]!;
        var packNs = (string)pack["ns"]!;
        var packDefs = ((L)pack["defs"]!).Select(x => (D)x!).ToList();
        if (!PlainSemver.IsMatch(packVersion)) return Fail("bad_version", $"version '{packVersion}' must be MAJOR.MINOR.PATCH");
        var cur = Ak.G(i, "current") as D;
        if (cur != null && (string)cur["ns"]! != packNs) return Fail("ns_mismatch", $"the active namespace is '{cur["ns"]}', the pack is '{packNs}'");
        if (cur != null && !Ak.JsTruthy(Ak.G(i, "pin")) && Actions.CompareVersions(packVersion, (string)cur["version"]!) <= 0)
            return Fail("not_newer", $"version {packVersion} is not above the active {cur["version"]}");
        object? rules = !i.ContainsKey("rules") ? new D { ["v"] = new Num("1"), ["kind"] = RulesDocKind, ["ns"] = packNs, ["rules"] = new D() } : i["rules"];
        var rerr = RulesDocError(rules, packNs, packDefs);
        if (rerr != null) return Fail("bad_rules", rerr);
        var rulesD = (D)rules!;
        var ruleBlocks = (D)rulesD["rules"]!;

        var pins = Ak.G(i, "pins");
        var review = ReviewOptsOf(pins, reg);
        var prevReg = reg;
        if (cur != null)
        {
            try { prevReg = RegistryOfTraits((L)cur["traits"]!); }
            catch (Exception) { prevReg = reg; }
        }
        var prevReview = ReviewOptsOf(pins, prevReg);
        var changes = new List<D>();
        var blocked = new List<string>();
        var reasons = new List<string>();
        var oldDefs = new Dictionary<string, D>();
        if (cur != null) foreach (var x in (L)((D)cur["pack"]!)["defs"]!) oldDefs[(string)((D)x!)["verb"]!] = (D)x!;
        var oldDep = cur != null ? new HashSet<string>(Ak.Strs(cur["deprecated"])) : new HashSet<string>();
        var newVerbs = new HashSet<string>(packDefs.Select(d => (string)d["verb"]!));
        foreach (var n in packDefs)
        {
            var verb = (string)n["verb"]!;
            oldDefs.TryGetValue(verb, out var o);
            var newRules = Ak.G(ruleBlocks, verb);
            var confirmed = SafeConfirmed(n, review);
            D change;
            if (o == null || oldDep.Contains(verb))
            {
                change = new D { ["verb"] = verb, ["class"] = "added", ["reasons"] = new L() };
                if (confirmed) change["reviewed"] = true;
            }
            else
            {
                var df = DiffDefsAcross(o, n, prevReg, reg, prevReview, review);
                var drs = Ak.Strs(df["reasons"]);
                change = new D { ["verb"] = verb, ["class"] = df["class"], ["reasons"] = Ak.ToL(drs) };
                if (drs.Any(r => EffectiveDims.Any(dim => r.StartsWith(dim + ": widen", StringComparison.Ordinal) || r.StartsWith(dim + ": incomparable", StringComparison.Ordinal))))
                {
                    if (confirmed) change["reviewed"] = true;
                    else
                    {
                        blocked.Add(verb);
                        reasons.Add($"{verb}: its effective authority widens without a valid confirmation of the new definition");
                    }
                }
            }
            object? oldRules = null;
            if (o != null && !oldDep.Contains(verb)) oldRules = Ak.G(((D)((D)cur!["rules"]!)["rules"]!), verb);
            if (oldRules != null || newRules != null)
            {
                D rd;
                try { rd = ActionBusinessRules.DiffBusinessRules(n, oldRules, newRules); }
                catch (Exception e) { rd = new D { ["class"] = "incomparable", ["reasons"] = new L { "rules: " + e.Message } }; }
                if (Ak.S(rd, "class") != "equal") change["rules"] = rd;
                if (Ak.S(rd, "class") is "widen" or "incomparable")
                {
                    var rev = Ak.G(rulesD, "reviews") is D rvs ? Ak.G(rvs, verb) : null;
                    var err = ActionBusinessRules.RulesReviewError(rev, n, newRules ?? new D(), pins);
                    if (err == null) change["reviewed"] = true;
                    else
                    {
                        blocked.Add(verb);
                        reasons.Add($"{verb}: its business rules widen ({string.Join(", ", Ak.Strs(rd["reasons"]))}) without a valid rules review: {err}");
                    }
                }
            }
            if (Ak.S(change, "class") != "equal" || Ak.G(change, "rules") != null) changes.Add(change);
        }
        var deprecated = new HashSet<string>(oldDep.Where(v => !newVerbs.Contains(v)));
        foreach (var v in oldDefs.Keys)
        {
            if (newVerbs.Contains(v) || oldDep.Contains(v)) continue;
            deprecated.Add(v);
            changes.Add(new D { ["verb"] = v, ["class"] = "deprecated", ["reasons"] = new L { "removed from the namespace: treated as unknown" } });
        }
        var sortedChanges = changes.OrderBy(c => (string)c["verb"]!, StringComparer.Ordinal).ToList();
        if (blocked.Count > 0)
        {
            var ob = Fail("widen_unreviewed", string.Join("\n", reasons), Ak.SortUniq(blocked));
            ob["changes"] = new L(sortedChanges);
            return ob;
        }
        var dep = deprecated.ToList();
        dep.Sort(StringComparer.Ordinal);
        var body = new D { ["pack"] = pack, ["rules"] = rulesD, ["traits"] = traits, ["deprecated"] = Ak.ToL(dep) };
        var ver = new D { ["ns"] = packNs, ["version"] = packVersion, ["digest"] = HostedVersionDigest(body), ["prev"] = cur != null ? cur["digest"] : null };
        foreach (var kv in body) ver[kv.Key] = kv.Value;
        ver["changes"] = new L(sortedChanges);
        return new D { ["ok"] = true, ["version"] = ver };
    }

    // ---- the verifier's view ---------------------------------------------------------------------------------------------------

    /// <summary>Grant facts for rule 22 from a stored grant: envelope caveat types plus the pin block's caveats and escalation tiers.</summary>
    public static D GrantFactsOf(object? grant)
    {
        var env = Pca.ReadEnvelope(grant);
        var a = (env != null ? Ak.G(env, "actions") as D : null) ?? new D();
        long Tier(object? v, long dflt) => v is Num && Ak.Dbl(v) is var t && t == Math.Floor(t) && t >= 0 && t <= 3 ? (long)t : dflt;
        var caveats = new List<object?>();
        if (env != null && Ak.G(env, "caveats") is L ec) foreach (var c in ec) caveats.Add(c is D cd ? Ak.G(cd, "type") : null);
        if (Ak.G(a, "caveats") is L ac) caveats.AddRange(ac);
        return new D { ["caveats"] = new L(caveats.OfType<string>()), ["max_esc"] = Tier(Ak.G(a, "max_esc"), 3), ["preauth_esc"] = Tier(Ak.G(a, "preauth_esc"), 0) };
    }

    static D BrokenRules(string verb) => new()
    {
        ["v"] = new Num("1"), ["verb"] = verb, ["rules_digest"] = "", ["def_digest"] = "",
        ["tighten"] = new L { new D { ["id"] = "rules_broken", ["when"] = new D { ["field"] = "action.verb", ["op"] = "eq", ["value"] = verb }, ["signal"] = "deny", ["reason"] = "the business rules of this action no longer compile" } },
        ["accumulators"] = new L(),
    };

    sealed class Entry
    {
        public D Def = null!;
        public Dictionary<string, D> Reg = null!;
        public Func<D, bool>? Review;
        public D? Rules;
    }

    /// <summary>The verifier's view: Lookup(verb), Provenance(op), UndoPlan(op), Floor(verb, grant, callContext).</summary>
    public sealed class HostedView
    {
        readonly Dictionary<string, Entry> byVerb = new();
        readonly HashSet<string> deprecated = new();
        readonly HashSet<string> broken = new();
        readonly D top;
        readonly List<string> topTraitIds;
        readonly Dictionary<string, D> cache = new();
        readonly Dictionary<string, D> prov = new();
        readonly Dictionary<Dictionary<string, D>, Func<D, D?>> undo = new(ReferenceEqualityComparer.Instance);
        public List<string> Versions { get; } = new();

        public HostedView(IEnumerable<D> versions, object? pins)
        {
            var regs = new List<Dictionary<string, D>>();
            foreach (var v in versions)
            {
                Versions.Add($"{v["ns"]}@{v["version"]}");
                Dictionary<string, D> reg;
                try { reg = RegistryOfTraits((L)v["traits"]!); }
                catch (Exception)
                {
                    foreach (var dx in Ak.Lst(Ak.G(v, "pack"), "defs"))
                        if (dx is D dd && dd.GetValueOrDefault("verb") is string bv) broken.Add(bv);
                    continue;
                }
                regs.Add(reg);
                var review = ReviewOptsOf(pins, reg);
                var vrules = (D)((D)v["rules"]!)["rules"]!;
                foreach (var dx in (L)((D)v["pack"]!)["defs"]!)
                {
                    var d = (D)dx!;
                    var verb = (string)d["verb"]!;
                    if (byVerb.ContainsKey(verb)) continue;
                    var e = new Entry { Def = d, Reg = reg, Review = review };
                    if (Ak.G(vrules, verb) is D rb && rb.Count > 0) e.Rules = rb;
                    byVerb[verb] = e;
                }
                foreach (var s in Ak.Strs(v["deprecated"])) deprecated.Add(s);
            }
            foreach (var x in deprecated.Concat(broken).ToList()) byVerb.Remove(x);
            var tops = (regs.Count == 0 ? new List<Dictionary<string, D>> { Core } : regs).Select(r => Actions.FloorOf(r, Actions.TopTraits(r).Cast<object?>())).ToList();
            top = tops[0];
            foreach (var b in tops.Skip(1)) top = Actions.Leq(top, b) ? b : Actions.Leq(b, top) ? top : Actions.Join(top, b);
            topTraitIds = Ak.SortUniq((regs.Count == 0 ? new List<Dictionary<string, D>> { Core } : regs).SelectMany(r => Actions.TopTraits(r)));
            foreach (var (verb, e) in byVerb)
            {
                try { if (SafeConfirmed(e.Def, e.Review)) prov[verb] = ActionProvenance.ProvenanceInfoOf(e.Def, e.Reg, e.Review); }
                catch (Exception) { /* unknown: sensitive */ }
            }
            var groups = new Dictionary<Dictionary<string, D>, List<D>>(ReferenceEqualityComparer.Instance);
            foreach (var e in byVerb.Values)
            {
                if (!groups.TryGetValue(e.Reg, out var gl)) groups[e.Reg] = gl = new List<D>();
                gl.Add(e.Def);
            }
            foreach (var (greg, gdefs) in groups) undo[greg] = ActionUndoEngine.UndoEngine(gdefs, pins, greg);
        }

        public D Lookup(string verb)
        {
            if (cache.TryGetValue(verb, out var hit)) return hit;
            byVerb.TryGetValue(verb, out var e);
            var o = new D { ["verb"] = verb, ["confirmed"] = false, ["known"] = e != null, ["deprecated"] = deprecated.Contains(verb), ["profile"] = top,
                ["traits"] = Ak.ToL(topTraitIds), ["serverClass"] = "irreversible" };
            if (e == null && broken.Contains(verb) && !deprecated.Contains(verb)) { o["known"] = true; o["rules"] = BrokenRules(verb); }
            if (e != null)
            {
                try
                {
                    var eff = ActionEffective.EffectiveWith(e.Def, e.Reg, e.Review);
                    var confirmed = eff["confirmed"] is true;
                    object? idem = null;
                    if (Ak.G(e.Def, "idempotency") is D idm && Ak.S(idm, "mode") == "key_param") idem = idm["param"];
                    var nxt = new D(o) { ["def_digest"] = Actions.DefDigest(e.Def), ["confirmed"] = confirmed };
                    if (idem != null) nxt["idempotency_param"] = idem;
                    if (confirmed)
                    {
                        var ef = (D)eff["eff"]!;
                        nxt["profile"] = ef; nxt["traits"] = eff["traits"]; nxt["serverClass"] = ServerClass((string)ef["rev"]!);
                    }
                    if (e.Rules != null) nxt["rules"] = ActionBusinessRules.CompileBusinessRules(e.Def, e.Rules);
                    o = nxt;
                }
                catch (Exception)
                {
                    o = new D(o) { ["confirmed"] = false, ["profile"] = top, ["traits"] = Ak.ToL(topTraitIds), ["serverClass"] = "irreversible", ["rules"] = BrokenRules(verb) };
                }
            }
            cache[verb] = o;
            return o;
        }

        public D? Provenance(D op) => prov.GetValueOrDefault((string)op["verb"]!);

        public D? UndoPlan(D op) => byVerb.TryGetValue((string)op["verb"]!, out var e) ? undo[e.Reg](op) : null;

        public string Floor(string verb, D grant, IEnumerable<string> callContext)
        {
            try
            {
                var kinds = Ak.Strs(grant["caveats"]).Where(c => CaveatKindList.Contains(c));
                return Actions.FloorDecision(new D { ["caveats"] = Ak.ToL(kinds), ["max_esc"] = grant["max_esc"], ["preauth_esc"] = grant["preauth_esc"] },
                    new D { ["context"] = Ak.ToL(callContext) }, (D)Lookup(verb)["profile"]!);
            }
            catch (Exception) { return "deny"; }
        }
    }

    public static HostedView HostedViewOf(IEnumerable<D> versions, object? pins) => new(versions, pins);

    /// <summary>The context keys the hosted server itself establishes for a call: fresh revocation always; an idempotency key when one is present.</summary>
    public static List<string> HostedCallContext(D? lookup, D? parameters)
    {
        var out_ = new List<string> { "fresh_revocation" };
        if (Ak.G(lookup, "idempotency_param") is string k)
        {
            // a verb that names an idempotency parameter is always called with a parameter object; an absent one is a caller bug, refused as the reference does
            if (parameters == null) throw new ArgumentNullException(nameof(parameters), "hostedCallContext: the call has no parameters");
            if (Ak.G(parameters, k) is string s && s.Length > 0) out_.Add("idempotency");
        }
        return out_;
    }

    /// <summary>The event keys of a rules block's rate limits: verb, window and scope id (never a rule index or the rules digest).</summary>
    public static L RateKeysOf(D c, D who)
    {
        var res = new L();
        foreach (var ao in Ak.Lst(c, "accumulators"))
        {
            var a = (D)ao!;
            var scope = Ak.S(a, "scope") == "org" ? "org" : "principal";
            var id = Ak.G(who, scope == "org" ? "org" : "principal");
            var win = (D)a["win"]!;
            var ms = Ak.S(win, "kind") == "task" ? 0 : Ak.I(win["ms"]);
            var e = new D { ["id"] = a["id"], ["ms"] = ms };
            if (id is string s && s.Length > 0 && ms > 0) e["key"] = $"{Ak.S(c, "verb")}|{ms}|{scope}:{s}";
            res.Add(e);
        }
        return res;
    }
}
