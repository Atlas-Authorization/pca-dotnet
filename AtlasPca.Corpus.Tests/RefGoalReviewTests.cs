using System.Globalization;
using AtlasPca.GoalPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the review flow (card, diff, signed approval, loader) over a stub compiler kernel.</summary>
public class RefGoalReviewTests
{
    const string M = "ref-goal-review";
    static D O(object? o) => (D)o!;

    sealed class StubKernel : GoalReview.ReviewKernel
    {
        readonly string mode;
        public StubKernel(string mode) { this.mode = mode; }

        public D Compile(D goal, D ont)
        {
            if (mode == "throwcompile") throw new Exception("boom");
            var grants = (L)goal["grants"]!;
            var r = new D();
            if (grants.Count == 0) { r["ok"] = false; r["reasons"] = new L { "empty" }; return r; }
            var gids = new L();
            foreach (var g in grants) gids.Add(O(g)["gid"]);
            var pol = new D { ["gids"] = gids, ["n"] = new Num(grants.Count.ToString(CultureInfo.InvariantCulture)) };
            r["ok"] = true; r["policy"] = pol;
            return r;
        }

        public string PolicyDigest(D policy)
        {
            if (mode == "throwdigest") throw new Exception("boom");
            return Pca.HashCanonical(new D { ["d"] = "stub-policy", ["p"] = policy });
        }

        public List<string> Analyze(D policy) => (int)double.Parse(((Num)policy["n"]!).Raw, CultureInfo.InvariantCulture) >= 5 ? new List<string> { "too many" } : new List<string>();

        public bool CanDecide() => mode != "nodecide";

        public string Decide(D goal, D ont, D act, D hist)
        {
            foreach (var g in (L)goal["grants"]!) if (Equals(O(g)["verb"], act.GetValueOrDefault("verb"))) return "allow";
            return "deny";
        }

        public bool CanListNewlyAllowed() => mode != "nonewly";

        public D NewlyAllowed(D prev, D next, D ont, long limit)
        {
            var w = new L();
            foreach (var x in (L)next["grants"]!)
            {
                bool known = false;
                foreach (var y in (L)prev["grants"]!) if (Equals(O(y)["gid"], O(x)["gid"])) known = true;
                if (known) continue;
                w.Add(new D { ["verb"] = O(x)["verb"], ["res"] = "r", ["params"] = new D(), ["t"] = new Num("0"), ["sess"] = "s", ["prin"] = "p", ["org"] = "o", ["agent"] = "a", ["depth"] = new Num("0") });
            }
            return new D { ["witnesses"] = w, ["complete"] = true };
        }
    }

    static long? Lng(object? o)
    {
        if (o == null) return null;
        try
        {
            var d = decimal.Parse(((Num)o).Raw, NumberStyles.Float, CultureInfo.InvariantCulture);
            if (d == decimal.Truncate(d) && d >= long.MinValue && d <= long.MaxValue) return (long)d;
        }
        catch (Exception) { }
        return long.MaxValue;
    }

    [Fact] public void EffectiveLimits() => Base.Check(M, "effectiveLimits", a => GoalReview.EffectiveLimits(a[0] as D));

    [Fact]
    public void RenderPolicyCard() => Base.Check(M, "renderPolicyCard", a =>
    {
        var opts = O(a[2]);
        return GoalReview.RenderPolicyCard(a[0] as D, a[1] as L, opts.GetValueOrDefault("limits") as D, opts.GetValueOrDefault("allowHoles") is true);
    });

    [Fact] public void CardDigest() => Base.Check(M, "cardDigest", a => GoalReview.CardDigest(O(a[0])));
    [Fact] public void CardToText() => Base.Check(M, "cardToText", a => GoalReview.CardToText(O(a[0])));

    [Fact]
    public void DiffGoals() => Base.Check(M, "diffGoals", a =>
    {
        var op = O(a[2]);
        var km = (string)op["kmode"]!;
        return GoalReview.DiffGoals(O(a[0]), O(a[1]), km == "none" ? null : new StubKernel(km), op.GetValueOrDefault("limits") as D, op.GetValueOrDefault("ontology") as D);
    });

    [Fact] public void DiffToText() => Base.Check(M, "diffToText", a => GoalReview.DiffToText(O(a[0])));

    [Fact]
    public void ApproveGoalSeed() => Base.Check(M, "approveGoalSeed", a =>
    {
        var op = O(a[2]);
        var o = new GoalReview.ApproveOptions
        {
            Kernel = new StubKernel((string)op["kmode"]!),
            Now = Lng(op.GetValueOrDefault("now")),
            TtlMs = Lng(op.GetValueOrDefault("ttlMs")),
            Limits = op.GetValueOrDefault("limits") as D,
            Base = op.GetValueOrDefault("base") as D,
        };
        return GoalReview.ApproveGoal(a[0] as D, Pca.B64uDecode(a[1]) ?? throw new InvalidDataException("seed"), o);
    });

    [Fact]
    public void LoadApprovedGoal() => Base.Check(M, "loadApprovedGoal", a =>
    {
        var op = O(a[2]);
        var o = new GoalReview.LoadOptions
        {
            Kernel = new StubKernel((string)op["kmode"]!),
            Reviewers = op.GetValueOrDefault("reviewers") as L,
            OntologyDigest = op.GetValueOrDefault("ontology_digest") as string,
            Now = Lng(op.GetValueOrDefault("now")),
            Limits = op.GetValueOrDefault("limits") as D,
        };
        return GoalReview.LoadApprovedGoal(a[0] as D, a[1] as D, o);
    });

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "effectiveLimits", "renderPolicyCard", "cardDigest", "cardToText", "diffGoals", "diffToText", "approveGoalSeed", "loadApprovedGoal" }); Assert.Equal(450, Base.Total(M)); }
}
