using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 differential oracle of leases and break-glass grants (test-data/k05-grants.json.gz, TS reference
/// packages/pca-grants/src/lease.ts + breakglass.ts). Registry walks replay every step on a fresh registry and compare each step's
/// whole result.</summary>
public class K05GrantsDiffTests
{
    const string M = "grants";

    static List<string> Strs(object? o) => ((L)o!).Select(x => (string)x!).ToList();

    static LeasePolicy Policy(object? po)
    {
        var p = (D)po!;
        var min = p.GetValueOrDefault("minApprovals") is { } m ? K05.Long(m) : 1;
        var elig = p.GetValueOrDefault("eligibleApprovers") is { } e ? Strs(e) : null;
        var fresh = p.GetValueOrDefault("freshJustification") is bool f ? f : true;
        return new LeasePolicy(p.GetValueOrDefault("authorities") is { } a ? Strs(a) : new List<string>(), min, elig, fresh);
    }

    static D Accept(LeaseAccept a)
    {
        if (a.Ok) return new D { ["ok"] = true, ["replaced"] = a.Replaced, ["seq"] = a.Seq };
        if (a.Replaced || a.Seq != 0) throw new InvalidOperationException("a refusal carries replaced=false, seq=0");
        return new D { ["ok"] = false, ["code"] = a.Code };
    }

    static D Revoke(LeaseRevoke r)
    {
        if (r.Ok) return new D { ["ok"] = true, ["revoked"] = (long)r.Revoked };
        if (r.Revoked != 0) throw new InvalidOperationException("a refusal carries revoked=0");
        return new D { ["ok"] = false, ["code"] = r.Code };
    }

    static D Decision(LeaseDecision d)
    {
        var o = new D { ["decision"] = d.Decision };
        if (d.Code != null) o["code"] = d.Code;
        if (d.LeaseId != null) o["lease_id"] = d.LeaseId;
        if (d.ExpiresAt != null) o["expires_at"] = d.ExpiresAt.Value;
        return o;
    }

    static D BgResult(BreakGlassResult r) =>
        r.Ok ? new D { ["ok"] = true, ["replaced"] = r.Replaced } : new D { ["ok"] = false, ["code"] = r.Code };

    static D BgDecision(BreakGlassDecision d)
    {
        var o = new D { ["decision"] = d.Decision };
        if (d.Decision == "allow")
        {
            o["id"] = d.Id; o["use"] = d.Use; o["remaining"] = d.Remaining; o["review_due"] = d.ReviewDue;
            return o;
        }
        if (d.Code != null) o["code"] = d.Code;
        if (d.Id != null) o["id"] = d.Id;
        return o;
    }

    [Fact] public void VerifyLease() => K05.Check(M, "verifyLease", a => Lease.VerifyLease(a[0]), min: 890);
    [Fact] public void VerifyLeaseRevocation() => K05.Check(M, "verifyLeaseRevocation", a => Lease.VerifyRevocation(a[0]), min: 980);
    [Fact] public void VerifyBreakGlass() => K05.Check(M, "verifyBreakGlass", a => BreakGlass.VerifyBreakGlass(a[0]), min: 680);
    [Fact] public void VerifyBreakGlassReview() => K05.Check(M, "verifyBreakGlassReview", a => BreakGlass.VerifyReview(a[0]), min: 395);

    [Fact]
    public void SodError() => K05.Check(M, "sodError", a =>
    {
        var r = (D)a[0]!; var p = Policy(a[1]);
        return Lease.SodError((string)r["requester"]!, (string)r["holder"]!, Strs(r["approvers"]), p.MinApprovals, p.EligibleApprovers, Strs(a[2]));
    }, min: 395);

    [Fact]
    public void LeaseWalk() => K05.Check(M, "leaseWalk", a =>
    {
        var reg = new LeaseRegistry(Policy(a[0]), new MemoryAtomicKv());
        var out_ = new L();
        foreach (var sx in (L)a[1]!)
        {
            var s = (D)sx!;
            switch ((string)s["op"]!)
            {
                case "accept": out_.Add(Accept(reg.Accept(s.GetValueOrDefault("rec"), s.GetValueOrDefault("chain") is { } c ? Strs(c) : new List<string>()))); break;
                case "revoke": out_.Add(Revoke(reg.Revoke(s.GetValueOrDefault("rec")))); break;
                default: out_.Add(Decision(Lease.Check(s.GetValueOrDefault("rec"), reg, s.GetValueOrDefault("now")))); break;
            }
        }
        return out_;
    }, min: 675);

    [Fact]
    public void BgWalk() => K05.Check(M, "bgWalk", a =>
    {
        var p = (D)a[0]!;
        var reg = new BreakGlassRegistry(new BreakGlassPolicy(Strs(p["authorities"]), Strs(p["reviewers"])), new MemoryAtomicKv());
        var out_ = new L();
        foreach (var sx in (L)a[1]!)
        {
            var s = (D)sx!;
            object? G(string k) => s.GetValueOrDefault(k);
            switch ((string)s["op"]!)
            {
                case "accept": out_.Add(BgResult(reg.Accept(G("rec"), G("now")))); break;
                case "use": out_.Add(BgDecision(reg.Use(G("id"), G("holder"), G("action_digest"), G("now"), G("notified")))); break;
                case "review": out_.Add(BgResult(reg.Review(G("rec"), G("holder"), G("now")))); break;
                default: out_.Add(reg.IsFrozen(G("holder"), G("now"))); break;
            }
        }
        return out_;
    }, min: 620);

    [Fact]
    public void EveryFn() => K05.Covers(M, new[] { "verifyLease", "verifyLeaseRevocation", "verifyBreakGlass", "verifyBreakGlassReview", "sodError", "leaseWalk", "bgWalk" });
}
