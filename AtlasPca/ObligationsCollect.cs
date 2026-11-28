// Policy-side obligation collection (the reference collectObligations).
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

public static partial class Obligations
{
    /// <summary>The obligations of every rule whose <c>when</c> is true OR cannot be decided (a missing value adds the obligations: more duties is the
    /// tightening direction), merged by <see cref="Merge"/>. <paramref name="rules"/> is <c>[{id, when, obligations}]</c> (null: none); a malformed rule
    /// list or obligation list is a refusal. <paramref name="ctx"/> carries <c>action</c>, <c>subject</c>, <c>env</c>.</summary>
    public static ObligationMerge CollectObligations(object? rules, JD? ctx)
    {
        try
        {
            if (rules == null) return new(true, Array.Empty<object?>());
            if (rules is not List<object?> list) return new(false, Array.Empty<object?>(), "obligation rules must be an array");
            var lists = new List<object?>();
            var ids = new HashSet<string>(StringComparer.Ordinal);
            for (var i = 0; i < list.Count; i++)
            {
                if (list[i] is not JD r || r.GetValueOrDefault("id") is not string id || id.Length == 0 || id.Length > 64 || r.GetValueOrDefault("when") is not JD when
                    || r.Keys.Any(k => k != "id" && k != "when" && k != "obligations"))
                    return new(false, Array.Empty<object?>(), $"obligation rule {i} is malformed");
                if (!ids.Add(id)) return new(false, Array.Empty<object?>(), $"obligation rule id '{id}' is a duplicate");
                var obligations = r.ContainsKey("obligations") ? r["obligations"] : Absent;
                var e = ObligationsError(obligations);
                if (e != null || obligations is not List<object?> ol || ol.Count == 0)
                    return new(false, Array.Empty<object?>(), $"obligation rule '{id}': {e ?? "obligations must not be empty"}");
                if (Predicates.EvaluateConditionTri(when, ctx) != Predicates.Tri.False) lists.Add(ol);
            }
            return Merge(lists);
        }
        catch (Exception) { return new(false, Array.Empty<object?>(), "evaluation error (fail closed)"); }
    }
}
