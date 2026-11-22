using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The cross-signer options of a clause policy: <c>Precedence</c> lists signers from most to least authoritative (it names the winner among several matching forbids),
/// <c>PermitSigners</c>, when given, drops permits from any other signer (fail closed).</summary>
public sealed record ClauseOptions(IReadOnlyList<string>? Precedence = null, IReadOnlyList<string>? PermitSigners = null);

/// <summary>The value the evaluators gave one clause: <c>true</c>, <c>false</c> or <c>unknown</c> (for a forbid or an escalate, true and unknown both count as matched).</summary>
public sealed record ClauseRow(string Id, string Kind, string Value);

/// <summary>A forbid-wins decision with its witness: the winning clause (<c>WinnerKind</c> is <c>permit</c>, <c>forbid</c>, <c>escalate</c>, <c>none</c> for a default deny or
/// <c>malformed</c>) and every other matching clause (<c>Shadowed</c>).</summary>
public sealed record ClauseDecision(string Decision, string WinnerKind, string? WinnerId, IReadOnlyList<string> Shadowed, IReadOnlyList<ClauseRow> Values);

/// <summary>FORBID-WINS DECISION WITNESS AND CERTIFICATE (security contract C-240, C-241). A policy is a flat list of CLAUSES (<c>{id, kind, signer?, when}</c>): <c>permit</c>
/// clauses grant (an undecidable one is "not matched"); <c>forbid</c> clauses veto and <c>escalate</c> clauses cap the decision at escalate, both in veto polarity (an undecidable
/// one is "matched"). The decision is order-independent: any forbid matched is a deny (a forbid beats every permit, whoever signed either); else no permit matched is a deny (default
/// deny); else any escalate matched is an escalate; else allow. <see cref="Certify"/> turns the decision into a canonical certificate and <see cref="Check"/> re-derives it from the
/// clauses and the action with the real evaluators, so a verifier never trusts a certificate it did not recompute. Pure and total: a malformed clause or action is a deny naming <c>malformed</c>.</summary>
public static class Forbid
{
    public const long CertVersion = 1;
    public const string CertKind = "forbid-wins";
    /// <summary>The most clauses one policy may carry (a bound on the certificate size).</summary>
    public const int MaxClauses = 512;

    static string[] Kinds => new[] { "permit", "forbid", "escalate" };
    static string[] Values => new[] { "true", "false", "unknown" };

    /// <summary>Null when the clause list is well formed (distinct ids, known kinds, a predicate for each), else why not.</summary>
    public static string? Error(object? clauses)
    {
        if (clauses is not JL list) return "clauses must be an array";
        if (list.Count > MaxClauses) return $"more than {MaxClauses} clauses";
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < list.Count; i++)
        {
            if (list[i] is not JD c) return $"clauses[{i}] must be an object";
            if (c.GetValueOrDefault("id") is not string { Length: > 0 and <= 128 } id) return $"clauses[{i}].id must be a string of 1..128 characters";
            if (!seen.Add(id)) return $"clauses[{i}].id '{id}' is a duplicate";
            if (c.GetValueOrDefault("kind") is not string kind || !Kinds.Contains(kind)) return $"clauses[{i}].kind must be permit, forbid or escalate";
            if (c.ContainsKey("signer") && c["signer"] is not string { Length: <= 256 }) return $"clauses[{i}].signer must be a string of at most 256 characters";
            if (c.GetValueOrDefault("when") is not JD) return $"clauses[{i}].when must be a predicate object";
        }
        return null;
    }

    static ClauseDecision Malformed() => new("deny", "malformed", null, Array.Empty<string>(), Array.Empty<ClauseRow>());

    static string ValueOf(JD c, Dictionary<string, object?> ctx)
    {
        var when = c["when"];
        if ((string)c["kind"]! == "permit") return Predicates.PredicateMatches(when, ctx) ? "true" : "false";
        // veto polarity: a clean match is true; cannot-decide-but-the-veto-applies is unknown; a clean miss is false
        if (!Prohibitions.WhenMatches(when, ctx)) return "false";
        return Predicates.PredicateMatches(when, ctx) ? "true" : "unknown";
    }

    static int Rank(string? signer, IReadOnlyList<string> precedence)
    {
        var i = signer == null ? -1 : precedence.ToList().IndexOf(signer);
        return i < 0 ? precedence.Count : i; // an unlisted signer ranks last
    }

    /// <summary>Decides a clause list against an action (<c>{action: {verb, resource, params?}, subject?, env?}</c>). The decision is order-independent; the named winner is deterministic.</summary>
    public static ClauseDecision Decide(object? clauses, Dictionary<string, object?>? ctx, ClauseOptions? opts = null)
    {
        try
        {
            if (Error(clauses) != null) return Malformed();
            var a = ctx != null && ctx.TryGetValue("action", out var av) ? av as JD : null;
            if (a == null || a.GetValueOrDefault("verb") is not string || a.GetValueOrDefault("resource") is not string) return Malformed();
            var cl = ((JL)clauses!).Cast<JD>().ToList();
            var precedence = opts?.Precedence ?? Array.Empty<string>();
            var permitSigners = opts?.PermitSigners;
            bool Active(JD c) => (string)c["kind"]! != "permit" || permitSigners == null || (c.GetValueOrDefault("signer") is string s && permitSigners.Contains(s));
            var rows = cl.Select(c => new ClauseRow((string)c["id"]!, (string)c["kind"]!, Active(c) ? ValueOf(c, ctx!) : "false")).ToList();
            List<JD> Hit(string k) => cl.Where((c, i) => (string)c["kind"]! == k && rows[i].Value != "false").ToList();
            var forbids = Hit("forbid").OrderBy(c => Rank(c.GetValueOrDefault("signer") as string, precedence)).ThenBy(c => (string)c["id"]!, StringComparer.Ordinal).ToList();
            var permits = Hit("permit");
            var escalates = Hit("escalate");
            IReadOnlyList<string> Others(JD? win) => forbids.Concat(permits).Concat(escalates).Where(c => !ReferenceEquals(c, win)).Select(c => (string)c["id"]!).ToList();
            if (forbids.Count > 0) return new("deny", "forbid", (string)forbids[0]["id"]!, Others(forbids[0]), rows);
            if (permits.Count == 0) return new("deny", "none", null, Others(null), rows);
            if (escalates.Count > 0) return new("escalate", "escalate", (string)escalates[0]["id"]!, Others(escalates[0]), rows);
            return new("allow", "permit", (string)permits[0]["id"]!, Others(permits[0]), rows);
        }
        catch (Exception) { return Malformed(); }
    }

    /// <summary>The canonical certificate of the decision: <c>{v, kind, policy, action, decision, winner, shadowed, clauses}</c>.</summary>
    public static JD Certify(object? clauses, Dictionary<string, object?>? ctx, ClauseOptions? opts = null)
    {
        var d = Decide(clauses, ctx, opts);
        var byId = new Dictionary<string, JD>(StringComparer.Ordinal);
        if (clauses is JL cl) foreach (var c in cl) if (c is JD cd && cd.GetValueOrDefault("id") is string id) byId[id] = cd;
        return new JD
        {
            ["v"] = CertVersion, ["kind"] = CertKind, ["policy"] = Pca.HashCanonical(clauses), ["action"] = Pca.HashCanonical(ctx), ["decision"] = d.Decision,
            ["winner"] = new JD { ["kind"] = d.WinnerKind, ["id"] = d.WinnerId }, ["shadowed"] = d.Shadowed.Select(s => (object?)s).ToList(),
            ["clauses"] = d.Values.Select(v =>
            {
                var row = new JD { ["id"] = v.Id, ["kind"] = v.Kind };
                if (byId.TryGetValue(v.Id, out var src) && src.GetValueOrDefault("signer") is { } signer) row["signer"] = signer;
                row["value"] = v.Value;
                return (object?)row;
            }).ToList(),
        };
    }

    /// <summary>The rule over the certificate's own table (no evaluator needed): the decision, winner and shadowed list that the per-clause values force.</summary>
    public static bool Consistent(object? cert, ClauseOptions? opts = null)
    {
        try
        {
            if (cert is not JD c || !(IntentJs.NumOf(c.GetValueOrDefault("v")) == CertVersion) || !Equals(c.GetValueOrDefault("kind"), CertKind) || c.GetValueOrDefault("clauses") is not JL rows) return false;
            var winner = c.GetValueOrDefault("winner") as JD;
            var rs = rows.Cast<JD>().ToList();
            if (Equals(winner?.GetValueOrDefault("kind"), "malformed"))
                return rs.Count == 0 && Equals(c.GetValueOrDefault("decision"), "deny") && winner!.GetValueOrDefault("id") == null && c.GetValueOrDefault("shadowed") is JL sh0 && sh0.Count == 0;
            var precedence = opts?.Precedence ?? Array.Empty<string>();
            foreach (var r in rs)
                if (r.GetValueOrDefault("kind") is not string rk || !Kinds.Contains(rk) || r.GetValueOrDefault("value") is not string rv || !Values.Contains(rv)) return false;
            List<JD> Hit(string k) => rs.Where(r => (string)r["kind"]! == k && (string)r["value"]! != "false").ToList();
            var forbids = Hit("forbid").OrderBy(r => Rank(r.GetValueOrDefault("signer") as string, precedence)).ThenBy(r => r.GetValueOrDefault("id") as string ?? "", StringComparer.Ordinal).ToList();
            var permits = Hit("permit");
            var escalates = Hit("escalate");
            JD? win = forbids.Count > 0 ? forbids[0] : permits.Count == 0 ? null : escalates.Count > 0 ? escalates[0] : permits[0];
            var decision = forbids.Count > 0 ? "deny" : permits.Count == 0 ? "deny" : escalates.Count > 0 ? "escalate" : "allow";
            var kind = forbids.Count > 0 ? "forbid" : permits.Count == 0 ? "none" : escalates.Count > 0 ? "escalate" : "permit";
            var shadowed = forbids.Concat(permits).Concat(escalates).Where(r => !ReferenceEquals(r, win)).Select(r => r.GetValueOrDefault("id")).ToList();
            return Equals(c.GetValueOrDefault("decision"), decision) && Equals(winner?.GetValueOrDefault("kind"), kind) && Equals(winner?.GetValueOrDefault("id"), win?.GetValueOrDefault("id"))
                && Pca.Canonicalize(c.GetValueOrDefault("shadowed")) == Pca.Canonicalize(shadowed);
        }
        catch (Exception) { return false; }
    }

    /// <summary>Recomputes the certificate from the clauses and the action; it must match byte for byte (canonical form).</summary>
    public static (bool Ok, string? Reason) Check(object? cert, object? clauses, Dictionary<string, object?>? ctx, ClauseOptions? opts = null)
    {
        try
        {
            if (Error(clauses) != null) return (false, "malformed clauses");
            if (!Consistent(cert, opts)) return (false, "certificate table does not entail its decision");
            var again = Certify(clauses, ctx, opts);
            if (Pca.HashCanonical(again) != Pca.HashCanonical(cert)) return (false, "certificate does not match the recomputed decision");
            return (true, null);
        }
        catch (Exception) { return (false, "certificate check error (fail closed)"); }
    }
}
