// POLICY CLASSES (access is granted only if every consulted policy class allows it): the decision is the meet of the class answers,
// and the record names who said no. Port of packages/pca/src/policy-classes.ts; replays packages/pca/conformance/policy-classes-vectors.json.
// Total; never throws.
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public sealed record ClassVerdict(string Class, long Revision, string Digest, string Decision);

public sealed record ClassDecision(string Decision, List<ClassVerdict> Classes, List<string> DeniedBy, List<string> EscalatedBy, string? Reason = null);

public static class PolicyClasses
{
    public static readonly string[] Classes = { "constitution", "regulatory", "org", "blueprint", "user" };
    static readonly string[] Decisions = { "allow", "escalate", "deny" };

    /// <summary>Null = a well-formed list: closed members, known classes, each at most once.</summary>
    public static string? ClassVerdictsError(object? list)
    {
        if (list is not JL l) return "policy classes must be an array";
        if (l.Count > Classes.Length) return $"more than {Classes.Length} policy classes";
        var seen = new HashSet<string>();
        for (int i = 0; i < l.Count; i++)
        {
            if (l[i] is not JD v) return $"policy_classes[{i}] must be an object";
            foreach (var k in v.Keys) if (k is not ("class" or "revision" or "digest" or "decision")) return $"policy_classes[{i}] has unknown member '{k}'";
            if (v.GetValueOrDefault("class") is not string c || !Classes.Contains(c)) return $"policy_classes[{i}].class is not a known class";
            if (!seen.Add(c)) return $"policy class '{c}' appears twice";
            if (!Pca.SafeNat(v.GetValueOrDefault("revision"), out _)) return $"policy_classes[{i}].revision must be a non-negative safe integer";
            if (v.GetValueOrDefault("digest") is not string d || d.Length == 0 || d.Length > 128) return $"policy_classes[{i}].digest invalid";
            if (v.GetValueOrDefault("decision") is not string dc || !Decisions.Contains(dc)) return $"policy_classes[{i}].decision must be allow, escalate or deny";
        }
        return null;
    }

    public static ClassDecision DecideClasses(object? list)
    {
        ClassDecision Deny(string reason) => new("deny", new(), new(), new(), reason);
        try
        {
            if (list is JL { Count: 0 }) return Deny("no_policy_class");
            var e = ClassVerdictsError(list);
            if (e != null) return Deny($"malformed policy classes: {e}");
            var classes = ((JL)list!).Select(x =>
            {
                var v = (JD)x!;
                Pca.SafeNat(v["revision"], out var rev);
                return new ClassVerdict((string)v["class"]!, rev, (string)v["digest"]!, (string)v["decision"]!);
            }).OrderBy(c => Array.IndexOf(Classes, c.Class)).ToList();
            var d = "allow";
            foreach (var c in classes) d = PcaDecision.Meet(d, c.Decision);
            return new(d, classes, classes.Where(c => c.Decision == "deny").Select(c => c.Class).ToList(), classes.Where(c => c.Decision == "escalate").Select(c => c.Class).ToList());
        }
        catch (Exception) { return Deny("evaluation error (fail closed)"); }
    }
}
