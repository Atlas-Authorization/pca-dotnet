// Rule 17: per-parameter provenance, label receipts and flow rules (packages/pca/src/param-provenance.ts
// decideParamProvenance, label-receipts.ts, the taint lattice of taint.ts: trusted 0 < first_party 1 < tool 2 < web 3 < agent 4;
// the join is the highest rank; tainted = rank >= 2), mirroring ParamProvenance.java. Never throws.
using System.Text.RegularExpressions;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class ParamProvenance
{
    public const string LabelsDomain = "atlas-pca/labels/v1\0";
    public const string LabelsRefDomain = "atlas-pca/labels-ref/v1";
    public const string LabelRefPrefix = "pca-labels:";
    public const string PublicClass = "public";
    public const int MaxLabelFields = 64;
    public const int MaxProvPaths = 32;
    public const int MaxProvRefs = 8;
    public const int MaxCommittedLabels = 16;
    static readonly Regex ProvPathRe = new(@"^action\.params\.[A-Za-z0-9_]{1,64}\z", RegexOptions.CultureInvariant);
    static readonly HashSet<string> ProtoNames = new() { "__proto__", "constructor", "prototype" };
    internal static readonly string[] TaintLevels = { "trusted", "first_party", "tool", "web", "agent" };
    static readonly string[] Modes = { "allow", "question", "question_typed", "deny" };
    const int TaintedRank = 2;

    /// <summary>The rule-17 verdict. <c>Labels</c>: classified path to level; <c>Classes</c>: path to sorted class list; <c>Env</c>: nested labels.</summary>
    public sealed record ProvResult(string Outcome, string? Reason, string? Friction, D Labels, D Classes, D Env);

    internal static bool IsTaintLevel(object? k) => k is string s && TaintLevels.Contains(s);
    internal static int Rank(object? level) => IsTaintLevel(level) ? Array.IndexOf(TaintLevels, (string)level!) : 4;
    static bool IsProvPath(string k) => ProvPathRe.IsMatch(k) && !ProtoNames.Contains(k.Substring("action.params.".Length));

    internal static string? ValidateLabelsWire(object? lo)
    {
        if (lo is not D l) return "label receipt must be an object";
        var m = IntentArtifacts.ClosedMembers(l, new[] { "v", "kind", "site", "session", "response_digest", "fields", "issued_at", "kid", "sig" }, IntentArtifacts.SuiteMembers, "labels");
        if (m != null) return m;
        if (!OracleFacts.IsOne(l["v"]) || l["kind"] as string != "pca-labels") return "label receipt must be {v: 1, kind: \"pca-labels\"}";
        if (!IntentArtifacts.IsBoundedString(l["site"], 256)) return "'labels.site' must be a non-empty string (<= 256 bytes)";
        if (!IntentArtifacts.IsDigest(l["session"])) return "'labels.session' must be canonical base64url (32 bytes)";
        if (!IntentArtifacts.IsDigest(l["response_digest"])) return "'labels.response_digest' must be canonical base64url (32 bytes)";
        if (l["fields"] is not D fields) return "'labels.fields' must be an object";
        if (fields.Count == 0 || fields.Count > MaxLabelFields) return $"'labels.fields' must hold 1..{MaxLabelFields} fields";
        foreach (var (k, f) in fields)
        {
            if (!IntentArtifacts.IsBoundedString(k, 256)) return "label field paths must be non-empty strings (<= 256 bytes)";
            if (f is not D fd || IntentArtifacts.ClosedMembers(fd, new[] { "class", "value_digest" }, Array.Empty<string>(), "object") != null)
                return $"label field '{k}' must be exactly {{class, value_digest}}";
            if (fd["class"] is not string cls || cls.Length > 128 || !IntentArtifacts.DataClassRe.IsMatch(cls)) return $"label field '{k}': invalid data class";
            if (!IntentArtifacts.IsDigest(fd["value_digest"])) return $"label field '{k}': value_digest must be canonical base64url (32 bytes)";
        }
        if (!IntentJs.IsNonNeg(l["issued_at"])) return "'labels.issued_at' must be a non-negative safe integer";
        if (!IntentArtifacts.IsBoundedString(l["kid"], 64)) return "'labels.kid' must be a non-empty string (<= 64 bytes)";
        if (l["sig"] is not string) return "'labels.sig' must be a string";
        return null;
    }

    public static string LabelsRef(D l) => IntentArtifacts.ArtifactRef(LabelsRefDomain, "l", l);

    internal static string? VerifyLabels(object? l, L keys)
    {
        var w = ValidateLabelsWire(l);
        if (w != null) return w;
        var r = (D)l!;
        var se = IntentArtifacts.ArtifactSuiteError(r);
        if (se != null) return "signature suite: " + se;
        var key = keys.Select(k => k as D).FirstOrDefault(k => k != null && Equals(r["site"], IntentJs.Get(k, "site")) && Equals(r["kid"], IntentJs.Get(k, "kid")));
        if (key == null) return $"no pinned label key for site '{r["site"]}' kid '{r["kid"]}'";
        return IntentArtifacts.VerifyArtifactSig(LabelsDomain, r, key["pk"], IntentJs.Get(key, "pq_pk")) ? null : "bad label receipt signature";
    }

    /// <summary>The most specific flow pattern for <paramref name="cls"/>: itself, else the longest <c>p.*</c> prefix, else <c>*</c>.</summary>
    internal static string? FlowRuleFor(D rules, string cls)
    {
        if (rules.ContainsKey(cls)) return cls;
        string? best = null;
        foreach (var p in rules.Keys)
        {
            if (!p.EndsWith(".*", StringComparison.Ordinal)) continue;
            var prefix = p[..^1];
            if (cls.StartsWith(prefix, StringComparison.Ordinal) && (best == null || p.Length > best.Length)) best = p;
        }
        if (best != null) return best;
        return rules.ContainsKey("*") ? "*" : null;
    }

    internal static bool FlowAllowed(D rules, string cls, string origin, string? aud)
    {
        if (aud == origin || cls == PublicClass) return true;
        var p = FlowRuleFor(rules, cls);
        if (p == null) return false;
        return rules[p] is L sinks && sinks.Any(x => x is string xs && xs == aud);
    }

    internal static string? ValidateFlowRules(object? rules)
    {
        if (rules is not D r) return "flows must be an object";
        foreach (var (p, sinks) in r)
        {
            var b = p == "*" ? "x" : p.EndsWith(".*", StringComparison.Ordinal) ? p[..^2] : p;
            if (!IntentArtifacts.DataClassRe.IsMatch(b)) return $"flow pattern '{p}' is not a class, a 'prefix.*' or '*'";
            if (sinks is not L sl || sl.Any(s => !IntentArtifacts.IsBoundedString(s, 256))) return $"flow pattern '{p}' needs a list of audiences";
        }
        return null;
    }

    internal static string? ValidateProvenancePolicy(object? po)
    {
        if (po is not D p || IntentJs.Get(p, "params") is not D parameters) return "provenance policy needs a params map";
        var cm = IntentArtifacts.ClosedMembers(p, new[] { "params" }, new[] { "registry", "label_keys", "critical_max", "material_tainted", "critical_tainted", "flows" }, "policy");
        if (cm != null) return cm;
        foreach (var (k, v) in parameters)
        {
            if (!IntentArtifacts.IsParamPath(k)) return $"policy param '{k}' is not an action.params path";
            if (v as string != "material" && v as string != "critical") return $"policy param '{k}': sensitivity must be material or critical";
        }
        if (p.ContainsKey("registry"))
        {
            if (p["registry"] is not D reg) return "registry must be an object";
            foreach (var (k, v) in reg) if (!IntentArtifacts.IsBoundedString(k, 256) || !IsTaintLevel(v)) return $"registry entry '{k}' must map to a taint level";
        }
        if (p.ContainsKey("label_keys"))
        {
            if (p["label_keys"] is not L lk) return "label_keys must be a list";
            foreach (var k in lk)
                if (k is not D kd || IntentArtifacts.ClosedMembers(kd, new[] { "site", "kid", "pk" }, new[] { "pq_pk" }, "label_key") != null
                    || !IntentArtifacts.IsBoundedString(IntentJs.Get(kd, "site"), 256) || !IntentArtifacts.IsBoundedString(IntentJs.Get(kd, "kid"), 64)
                    || !IntentArtifacts.IsDigest(IntentJs.Get(kd, "pk")) || !IntentArtifacts.PinPqOk(kd)) return "every label key needs site, kid, a 32-byte pk and an optional string pq_pk";
        }
        if (p.ContainsKey("critical_max") && !IsTaintLevel(p["critical_max"])) return "critical_max must be a taint level";
        if (p.ContainsKey("material_tainted") && !(p["material_tainted"] is string mt && Modes.Contains(mt))) return "material_tainted must be allow | question | question_typed | deny";
        if (p.ContainsKey("critical_tainted") && !(p["critical_tainted"] is string ct && ct != "allow" && Modes.Contains(ct))) return "critical_tainted must be question | question_typed | deny";
        if (p.ContainsKey("flows"))
        {
            var e = ValidateFlowRules(p["flows"]);
            if (e != null) return e;
        }
        return null;
    }

    internal static string? ValidateProvWire(object? prov)
    {
        if (prov is not D m) return "'prov' must be an object";
        if (m.Count > MaxProvPaths) return $"'prov' holds more than {MaxProvPaths} paths";
        foreach (var (k, refs) in m)
        {
            if (!IsProvPath(k)) return $"'prov' key '{k}' is not action.params.<name> ([A-Za-z0-9_]{{1,64}}, not a prototype name)";
            if (refs is not L rl || rl.Count == 0 || rl.Count > MaxProvRefs) return $"'prov.{k}' must hold 1..{MaxProvRefs} refs";
            foreach (var r in rl) if (!IntentArtifacts.IsBoundedString(r, 256)) return $"'prov.{k}' refs must be non-empty strings (<= 256 bytes)";
        }
        return null;
    }

    /// <summary><c>pca-labels:&lt;digest&gt;#&lt;field&gt;</c> split at the FIRST <c>#</c>, or null.</summary>
    internal static (string Receipt, string Field)? ParseLabelRef(string reference)
    {
        if (!reference.StartsWith(LabelRefPrefix, StringComparison.Ordinal)) return null;
        var rest = reference.Substring(LabelRefPrefix.Length);
        int i = rest.IndexOf('#');
        if (i < 0) return null;
        var receipt = rest[..i];
        var field = rest[(i + 1)..];
        return IntentArtifacts.IsDigest(receipt) && field.Length > 0 ? (receipt, field) : null;
    }

    static List<string> Sorted(IEnumerable<string> keys)
    {
        var l = keys.ToList();
        l.Sort(IntentJs.CompareUtf8);
        return l;
    }

    /// <summary>The <c>primitives.intent_provenance</c> entry point: normalizes <paramref name="input"/>, then decides.</summary>
    public static ProvResult Decide(object? input)
    {
        try { return Decide((D)IntentJs.Normalize(input)!); }
        catch (Exception e) { return new ProvResult("deny", "provenance: evaluation error (fail closed): " + e.GetType().Name, null, new D(), new D(), new D()); }
    }

    /// <summary>Rule 17 over an already normalized input <c>{aud, session, action, prov?, committed_labels?, labels?, policy}</c>.</summary>
    internal static ProvResult Decide(D input)
    {
        var labels = new D();
        var classes = new D();
        ProvResult Deny(string reason) => new("deny", "provenance: " + reason, null, labels, classes, new D());
        try
        {
            var policyO = IntentJs.Get(input, "policy");
            var pe = ValidateProvenancePolicy(policyO);
            if (pe != null) return Deny("policy misconfigured (fail closed): " + pe);
            var policy = (D)policyO!;
            var prov = IntentJs.Opt(input, "prov", new D());
            var we = ValidateProvWire(prov);
            if (we != null) return Deny(we);
            if (IntentJs.Opt(input, "committed_labels", new L()) is not L committed || committed.Count > MaxCommittedLabels)
                return Deny($"committed labels must be a list of at most {MaxCommittedLabels} digests");
            var committedSet = new HashSet<string>();
            foreach (var d in committed) if (!IntentArtifacts.IsDigest(d) || !committedSet.Add((string)d!)) return Deny("committed labels must be distinct canonical 32-byte digests");
            if (IntentJs.Get(input, "action") is not D act) return Deny("action must be an object");
            if (IntentJs.Opt(act, "params", new D()) is not D parameters) return Deny("action.params must be an object");
            if (IntentJs.Opt(input, "labels", new L()) is not L suppliedLabels) return Deny("labels must be an array");
            var provMap = (D)prov!;
            var paths = Sorted(provMap.Keys);
            foreach (var p in paths) if (!IntentArtifacts.ResolveParamPath(parameters, p).Found) return Deny($"prov names '{p}', a parameter the action does not carry");
            foreach (var a in paths) foreach (var b in paths) if (a != b && b.StartsWith(a + ".", StringComparison.Ordinal)) return Deny($"prov paths '{a}' and '{b}' overlap");

            var receipts = new Dictionary<string, D>();
            foreach (var r in suppliedLabels)
            {
                try { if (ValidateLabelsWire(r) == null) receipts[LabelsRef((D)r!)] = (D)r!; } catch (Exception) { /* no reference */ }
            }
            var reg = (D)IntentJs.Opt(policy, "registry", new D())!;
            var keys = (L)IntentJs.Opt(policy, "label_keys", new L())!;
            var aud = IntentJs.Get(input, "aud") as string;
            var audText = IntentRevocation.JsText(IntentJs.Get(input, "aud"), input.ContainsKey("aud"));
            var origins = new Dictionary<string, List<(string Cls, string Origin)>>();

            foreach (var p in paths)
            {
                var value = IntentArtifacts.ResolveParamPath(parameters, p).Value;
                int join = -1;
                foreach (var refO in (L)provMap[p]!)
                {
                    var reference = (string)refO!;
                    if (!reference.StartsWith(LabelRefPrefix, StringComparison.Ordinal))
                    {
                        join = Math.Max(join, reg.TryGetValue(reference, out var lv) && IsTaintLevel(lv) ? Rank(lv) : 4);
                        continue;
                    }
                    var lr = ParseLabelRef(reference);
                    if (lr == null) return Deny($"malformed label ref on '{p}'");
                    if (!committedSet.Contains(lr.Value.Receipt)) return Deny($"label ref on '{p}' names a receipt the PCActn does not commit");
                    if (!receipts.TryGetValue(lr.Value.Receipt, out var rc)) return Deny($"label receipt for '{p}' was not supplied");
                    var ve = VerifyLabels(rc, keys);
                    if (ve != null) return Deny($"label receipt for '{p}': {ve}");
                    if (!Equals(rc["session"], IntentJs.Get(input, "session"))) return Deny($"label receipt for '{p}' is bound to another session");
                    var fields = (D)rc["fields"]!;
                    if (!fields.TryGetValue(lr.Value.Field, out var fieldO)) return Deny($"label receipt for '{p}' has no field '{lr.Value.Field}'");
                    var field = (D)fieldO!;
                    bool match;
                    try { match = IntentJs.HashCanonical(value) == field["value_digest"] as string; } catch (Exception) { match = false; }
                    join = Math.Max(join, match ? ((string)rc["site"]! == aud ? 1 : 2) : 4);
                    if (!origins.TryGetValue(p, out var ol)) origins[p] = ol = new();
                    ol.Add(((string)field["class"]!, (string)rc["site"]!));
                }
                labels[p] = TaintLevels[join < 0 ? 4 : join];
            }
            var sens = (D)policy["params"]!;
            foreach (var p in Sorted(sens.Keys))
            {
                if (labels.ContainsKey(p)) continue;
                if (IntentArtifacts.ResolveParamPath(parameters, p).Found) labels[p] = "agent";
            }
            var flows = (D)IntentJs.Opt(policy, "flows", new D())!;
            foreach (var p in Sorted(origins.Keys))
            {
                var cs = origins[p].Select(o => o.Cls).Distinct().ToList();
                cs.Sort(IntentJs.CompareUtf8);
                classes[p] = cs.Cast<object?>().ToList();
                foreach (var o in origins[p])
                    if (!FlowAllowed(flows, o.Cls, o.Origin, aud)) return Deny($"flow: class '{o.Cls}' from '{o.Origin}' may not reach '{audText}' (parameter '{p}')");
            }
            int capRank = Rank(IntentJs.Opt(policy, "critical_max", "agent"));
            var labelled = Sorted(labels.Keys);
            foreach (var p in labelled)
                if (sens.TryGetValue(p, out var sv) && sv as string == "critical" && Rank(labels[p]) > capRank)
                    return Deny($"critical parameter '{p}' has provenance '{labels[p]}', above the policy maximum '{IntentJs.Get(policy, "critical_max")}'");
            bool question = false, typed = false;
            foreach (var p in labelled)
            {
                if (!sens.TryGetValue(p, out var s) || s == null || Rank(labels[p]) < TaintedRank) continue;
                var mode = s as string == "critical" ? IntentJs.Opt(policy, "critical_tainted", "question_typed") as string : IntentJs.Opt(policy, "material_tainted", "question") as string;
                if (mode == "deny") return Deny($"tainted {s} parameter '{p}' (provenance '{labels[p]}') is denied by policy");
                if (mode == "question" || mode == "question_typed") question = true;
                if (mode == "question_typed") typed = true;
            }
            var env = new D();
            foreach (var p in labelled) if (!IntentArtifacts.SetNested(env, p, labels[p])) return Deny($"provenance paths overlap at '{p}'");
            return question
                ? new ProvResult("question", "provenance: a tainted value needs the principal (lazy question)", typed ? "typed" : "tap", labels, classes, env)
                : new ProvResult("pass", null, null, labels, classes, env);
        }
        catch (Exception e) { return Deny("evaluation error (fail closed): " + e.GetType().Name); }
    }

    /// <summary>The read-cell verdict (V14): <c>Outcome</c> allow / question / deny, the optional fields to minimise, the uncovered ones.</summary>
    public sealed record ReadPurposeResult(string Outcome, IReadOnlyList<string> Minimise, IReadOnlyList<string> Uncovered);

    static bool ClassCovered(L patterns, string cls) =>
        cls == PublicClass || patterns.Any(p => p is string s && (s == "*" || s == cls || (s.EndsWith(".*", StringComparison.Ordinal) && cls.StartsWith(s[..^1], StringComparison.Ordinal))));

    /// <summary>Read cell decision (V14; <c>primitives.intent_read_purpose</c>, label-receipts.ts <c>decideReadPurpose</c>) over
    /// <c>{fields: [{path, class, optional?}], purpose, coverage: {purpose: [pattern]}, on_uncovered?}</c>: a field is covered when
    /// its class is <c>public</c> or matches a pattern of the OWN member <c>coverage[purpose]</c> (a class, <c>p.*</c>, <c>*</c>); an
    /// uncovered optional field is minimised, any other uncovered field makes the read <c>on_uncovered</c> (default
    /// <c>question</c>). Both lists de-duplicated and sorted in UTF-8 byte order. Malformed input (JSON null anywhere included) is
    /// deny with empty lists. Never throws.</summary>
    public static ReadPurposeResult DecideReadPurpose(object? input)
    {
        var malformed = new ReadPurposeResult("deny", new List<string>(), new List<string>());
        try
        {
            if (IntentJs.Normalize(input) is not D inp) return malformed;
            var onUncovered = inp.TryGetValue("on_uncovered", out var ou) ? ou : "question";
            if (IntentJs.Get(inp, "fields") is not L fields || IntentJs.Get(inp, "purpose") is not string purpose || IntentJs.Get(inp, "coverage") is not D coverage
                || onUncovered as string is not ("question" or "deny")) return malformed;
            foreach (var pats in coverage.Values) if (pats is not L pl || pl.Any(x => x is not string)) return malformed;
            foreach (var f in fields)
                if (f is not D fd || IntentJs.Get(fd, "path") is not string || IntentJs.Get(fd, "class") is not string || (fd.ContainsKey("optional") && fd["optional"] is not bool)) return malformed;
            var patterns = coverage.TryGetValue(purpose, out var pv) ? (L)pv! : new L();
            var minimise = new HashSet<string>(StringComparer.Ordinal);
            var uncovered = new HashSet<string>(StringComparer.Ordinal);
            foreach (D f in fields.Cast<D>())
            {
                if (ClassCovered(patterns, (string)f["class"]!)) continue;
                (f.TryGetValue("optional", out var o) && o is true ? minimise : uncovered).Add((string)f["path"]!);
            }
            return new ReadPurposeResult(uncovered.Count == 0 ? "allow" : (string)onUncovered!, IntentJs.SortedUtf8(minimise), IntentJs.SortedUtf8(uncovered));
        }
        catch (Exception) { return malformed; }
    }
}
