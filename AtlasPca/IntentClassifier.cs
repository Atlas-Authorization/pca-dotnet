// Rule 18: classifier verdicts (packages/pca/src/intent-classifier.ts decideClassifierDimensions), mirroring
// IntentClassifier.java. A verdict is signed by its `judge` key, which must be on the classifier's allowlist; per classifier
// exactly one label must reach the k-of-n quorum of distinct judges. First failure wins; never throws.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class IntentClassifier
{
    public const string IntentClassifierDomain = "atlas-pca/intent-classifier/v1\0";
    public const string IntentClassifierRefDomain = "atlas-pca/intent-classifier-ref/v1";
    public const int MaxCommittedClasses = 8;
    public const int MaxClassifierLabels = 32;

    /// <summary>The rule-18 verdict: <c>Classes</c> maps each classifier id to its quorum label.</summary>
    public sealed record ClassResult(bool Ok, string? Reason, D? Classes)
    {
        internal static ClassResult Fail(string reason) => new(false, "classes: " + reason, null);
    }

    internal static string? ValidateVerdictWire(object? vo)
    {
        if (vo is not D v) return "verdict must be an object";
        var m = IntentArtifacts.ClosedMembers(v, new[] { "v", "kind", "classifier", "session", "content_digest", "label", "measurement", "judge", "sig" }, IntentArtifacts.SuiteMembers, "verdict");
        if (m != null) return m;
        if (!OracleFacts.IsOne(v["v"]) || v["kind"] as string != "pca-intent-classification") return "verdict must be {v: 1, kind: \"pca-intent-classification\"}";
        if (!IntentArtifacts.IsName(v["classifier"])) return "'verdict.classifier' must match ^[a-z][a-z0-9_]{0,63}$";
        if (!IntentArtifacts.IsDigest(v["session"])) return "'verdict.session' must be canonical base64url (32 bytes)";
        if (!IntentArtifacts.IsDigest(v["content_digest"])) return "'verdict.content_digest' must be canonical base64url (32 bytes)";
        if (!IntentArtifacts.IsBoundedString(v["label"], 64)) return "'verdict.label' must be a non-empty string (<= 64 bytes)";
        if (!IntentArtifacts.IsBoundedString(v["measurement"], 256)) return "'verdict.measurement' must be a non-empty string (<= 256 bytes)";
        if (!IntentArtifacts.IsDigest(v["judge"])) return "'verdict.judge' must be canonical base64url (32 bytes)";
        if (v["sig"] is not string) return "'verdict.sig' must be a string";
        return null;
    }

    public static string VerdictRef(D v) => IntentArtifacts.ArtifactRef(IntentClassifierRefDomain, "c", v);

    internal static string? ValidatePolicy(object? po)
    {
        if (po is not D p || IntentJs.Get(p, "classifiers") is not L list) return "classifier policy needs a classifiers list";
        var cm = IntentArtifacts.ClosedMembers(p, new[] { "classifiers" }, Array.Empty<string>(), "policy");
        if (cm != null) return cm;
        var ids = new HashSet<string>();
        foreach (var co in list)
        {
            if (co is not D c || IntentArtifacts.ClosedMembers(c, new[] { "id", "param", "labels", "keys", "k" }, new[] { "measurements", "pq_keys" }, "classifier") != null)
                return "every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}";
            if (!IntentArtifacts.IsName(IntentJs.Get(c, "id")) || !ids.Add((string)c["id"]!))
                return "every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$";
            var id = (string)c["id"]!;
            if (!IntentArtifacts.IsParamPath(IntentJs.Get(c, "param"))) return $"classifier '{id}': param must be an action.params path";
            if (IntentJs.Get(c, "labels") is not L labels || labels.Count == 0 || labels.Count > MaxClassifierLabels) return $"classifier '{id}': labels must hold 1..{MaxClassifierLabels} strings";
            if (labels.Any(l => !IntentArtifacts.IsBoundedString(l, 64)) || labels.Cast<string>().Distinct().Count() != labels.Count) return $"classifier '{id}': labels must be distinct non-empty strings";
            if (IntentJs.Get(c, "keys") is not L keys || keys.Count == 0 || keys.Any(k => !IntentArtifacts.IsDigest(k)) || keys.Cast<string>().Distinct().Count() != keys.Count)
                return $"classifier '{id}': keys must be distinct 32-byte keys";
            if (!IntentJs.IsInt(IntentJs.Get(c, "k")) || IntentJs.NumOf(c["k"])!.Value < 1 || IntentJs.NumOf(c["k"])!.Value > keys.Count) return $"classifier '{id}': k must be an integer in [1, {keys.Count}]";
            if (c.ContainsKey("measurements") && (c["measurements"] is not L ms || ms.Any(x => x is not string))) return $"classifier '{id}': measurements must be a list of strings";
            if (c.ContainsKey("pq_keys") && (c["pq_keys"] is not D pk || pk.Any(e => !keys.Any(x => x as string == e.Key) || e.Value is not string { Length: > 0 })))
                return $"classifier '{id}': pq_keys must map allowlisted keys to PQ keys";
        }
        return null;
    }

    /// <summary>True iff rule 18 is active: the committed verdicts or the classifier policy is a non-empty array.</summary>
    public static bool ClassifierCheckActive(object? committed, object? policy) =>
        OracleFacts.NonEmpty(committed) || OracleFacts.NonEmpty(IntentJs.Get(policy, "classifiers"));

    /// <summary>The <c>primitives.intent_classifier</c> entry point: normalizes <paramref name="input"/>, then decides.</summary>
    public static ClassResult Decide(object? input)
    {
        try { return Decide((D)IntentJs.Normalize(input)!); }
        catch (Exception e) { return ClassResult.Fail("evaluation error (fail closed): " + e.GetType().Name); }
    }

    /// <summary>Rule 18 over an already normalized input <c>{session, action, committed?, verdicts?, policy}</c>.</summary>
    internal static ClassResult Decide(D input)
    {
        try
        {
            var pe = ValidatePolicy(IntentJs.Get(input, "policy"));
            if (pe != null) return ClassResult.Fail("policy misconfigured (fail closed): " + pe);
            if (IntentJs.Opt(input, "committed", new L()) is not L committed || committed.Count > MaxCommittedClasses)
                return ClassResult.Fail($"committed verdicts must be a list of at most {MaxCommittedClasses} digests");
            var seen = new HashSet<string>();
            foreach (var d in committed) if (!IntentArtifacts.IsDigest(d) || !seen.Add((string)d!)) return ClassResult.Fail("committed verdicts must be distinct canonical 32-byte digests");
            if (IntentJs.Opt(input, "verdicts", new L()) is not L supplied) return ClassResult.Fail("verdicts must be an array");
            if (IntentJs.Get(input, "action") is not D act) return ClassResult.Fail("action must be an object");
            if (IntentJs.Opt(act, "params", new D()) is not D parameters) return ClassResult.Fail("action.params must be an object");
            var byRef = new Dictionary<string, D>();
            foreach (var v in supplied)
            {
                if (ValidateVerdictWire(v) != null) continue;
                try { byRef[VerdictRef((D)v!)] = (D)v!; } catch (Exception) { /* no reference */ }
            }
            var classifiers = (L)IntentJs.Get(IntentJs.Get(input, "policy"), "classifiers")!;
            var votes = new Dictionary<string, Dictionary<string, int>>();
            var pairs = new HashSet<string>();
            foreach (var d in committed)
            {
                if (!byRef.TryGetValue((string)d!, out var v)) return ClassResult.Fail("a committed verdict was not supplied (or is malformed)");
                var se = IntentArtifacts.ArtifactSuiteError(v);
                if (se != null) return ClassResult.Fail("verdict signature suite: " + se);
                var c = classifiers.Select(x => x as D).FirstOrDefault(x => x != null && Equals(v["classifier"], IntentJs.Get(x, "id")));
                if (c == null) return ClassResult.Fail($"verdict for undeclared classifier '{v["classifier"]}'");
                var id = (string)c["id"]!;
                if (!((L)c["keys"]!).Any(k => Equals(k, v["judge"]))) return ClassResult.Fail($"classifier '{id}': judge key is not on the allowlist");
                var pq = c.ContainsKey("pq_keys") ? IntentJs.Get(c["pq_keys"], (string)v["judge"]!) : null;
                if (!IntentArtifacts.VerifyArtifactSig(IntentClassifierDomain, v, v["judge"], pq)) return ClassResult.Fail($"classifier '{id}': bad verdict signature");
                if (!Equals(v["session"], IntentJs.Get(input, "session"))) return ClassResult.Fail($"classifier '{id}': verdict bound to another session");
                var content = IntentArtifacts.ResolveParamPath(parameters, c["param"]);
                if (!content.Found) return ClassResult.Fail($"classifier '{id}': the action carries no '{c["param"]}'");
                if (IntentJs.HashCanonical(content.Value) != v["content_digest"] as string) return ClassResult.Fail($"classifier '{id}': verdict is about other content");
                if (!((L)c["labels"]!).Any(l => Equals(l, v["label"]))) return ClassResult.Fail($"classifier '{id}': label '{v["label"]}' is not in its label set");
                if (c.ContainsKey("measurements") && !((L)c["measurements"]!).Any(x => Equals(x, v["measurement"]))) return ClassResult.Fail($"classifier '{id}': measurement is not pinned");
                if (!pairs.Add(id + "\u0000" + v["judge"])) return ClassResult.Fail($"classifier '{id}': two verdicts from one judge");
                if (!votes.TryGetValue(id, out var t)) votes[id] = t = new();
                var label = (string)v["label"]!;
                t[label] = (t.TryGetValue(label, out var n) ? n : 0) + 1;
            }
            var classes = new D();
            foreach (var co in classifiers)
            {
                var c = (D)co!;
                var id = (string)c["id"]!;
                var t = votes.TryGetValue(id, out var tv) ? tv : new Dictionary<string, int>();
                double k = IntentJs.NumOf(c["k"])!.Value;
                var winners = ((L)c["labels"]!).Cast<string>().Where(l => (t.TryGetValue(l, out var n) ? n : 0) >= k).ToList();
                if (winners.Count == 0) return ClassResult.Fail($"classifier '{id}': no label reaches the quorum {IntentJs.Lng(c["k"])}");
                if (winners.Count > 1) return ClassResult.Fail($"classifier '{id}': ambiguous, {winners.Count} labels reach the quorum");
                classes[id] = winners[0];
            }
            return new ClassResult(true, null, classes);
        }
        catch (Exception e) { return ClassResult.Fail("evaluation error (fail closed): " + e.GetType().Name); }
    }
}
