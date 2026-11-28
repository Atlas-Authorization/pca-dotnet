// Policy plumbing: an outcome as the analyzer's concrete action (params / env / subject trees) and the real predicate evaluator
// plus the static caveat gate as an admission oracle. Nothing here re-implements predicate semantics.
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentPolicyKit
{
    /// <summary>Default resource string when the space has no resource dimension for a verb.</summary>
    public const string AnyResource = "resource:any";

    /// <summary>{predicates, caveats} of a policy: a member that is not an array counts as empty. A truthy primitive is not a policy and throws, like the reference's <c>in</c> test.</summary>
    public static D NormalizePolicy(object? p)
    {
        if (p is string { Length: > 0 } || p is bool b && b || IntentJs.NumOf(p) is double n && n != 0 && !double.IsNaN(n))
            throw new InvalidOperationException("Cannot use 'in' operator to search for 'caveats' in " + JsX.Str(p));
        var preds = IntentJs.Get(p, "predicates");
        var cavs = IntentJs.Get(p, "caveats");
        return new D { ["predicates"] = preds is L ? preds : new L(), ["caveats"] = cavs is L ? cavs : new L() };
    }

    static void SetPath(D root, string[] segs, int from, object? value)
    {
        var cur = root;
        for (int i = from; i < segs.Length - 1; i++)
        {
            if (!(cur.TryGetValue(segs[i], out var next) && next is D)) cur[segs[i]] = new D();
            cur = (D)cur[segs[i]]!;
        }
        cur[segs[^1]] = value;
    }

    static object? Plain(object? v) => v is double d ? N(d) : v;

    /// <summary>The outcome as the analyzer's concrete action (params / env / subject trees, reversibility from the space).</summary>
    public static D OutcomeToAction(VerbSpace vs, Outcome o)
    {
        var prms = new D(); var env = new D(); var subject = new D();
        var resource = AnyResource;
        foreach (var (path, value) in o.Values)
        {
            var segs = path.Split('.');
            if (path == "action.resource") resource = JsX.Str(Plain(value));
            else if (segs[0] == "action" && segs.Length > 2 && segs[1] == "params") SetPath(prms, segs, 2, Plain(value));
            else if (segs[0] == "env" && segs.Length > 1) SetPath(env, segs, 1, Plain(value));
            else if (segs[0] == "subject" && segs.Length > 1) SetPath(subject, segs, 1, Plain(value));
        }
        var a = new D { ["verb"] = o.Verb, ["resource"] = resource, ["params"] = prms, ["reversibilityClass"] = vs.Reversibility };
        if (env.Count > 0) a["env"] = env;
        if (subject.Count > 0) a["subject"] = subject;
        return a;
    }

    /// <summary>A policy compiled for admission queries (compile once, query many times): the analyzer's policy model asked about the outcome as a concrete action.</summary>
    public sealed class Admitter
    {
        readonly PolicyModel _model;
        internal Admitter(object? p) { _model = Enumerate.ToModel(p); }

        /// <summary>Does the policy admit the outcome (allow or escalate: permitted, possibly with a human)?</summary>
        public bool Admits(VerbSpace vs, Outcome o) => Enumerate.AdmitsAction(_model, OutcomeToAction(vs, o));
    }

    /// <summary>Compile a policy once, query many times.</summary>
    public static Admitter MakeAdmitter(object? policy) => new(policy);

    public static VerbSpace? VsOf(Omega omega, Outcome o) => omega.Verbs.Find(v => v.Verb == o.Verb);
}
