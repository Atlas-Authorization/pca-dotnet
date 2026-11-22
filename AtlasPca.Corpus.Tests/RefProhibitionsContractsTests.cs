using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The prohibition and contract names the shared vectors and the base prohibition corpus do not reach (test-data/ref-prohibitions.json.gz, 1637 cases;
/// test-data/ref-contracts.json.gz, 1269 cases): every function, every case. Where the reference tells an option that is present (even null, or of another
/// type) from one that is absent, the typed call gets a value that can never match (no valid sequence number, no valid digest, a time that is not a number).</summary>
public class RefProhibitionsContractsTests
{
    const string P = "ref-prohibitions";
    const string C = "ref-contracts";

    static D Row(InvariantEval e)
    {
        var d = new D { ["id"] = e.Id, ["kind"] = e.Kind, ["result"] = e.Result };
        if (e.ReasonValue != null) d["reason"] = e.ReasonValue;
        else if (e.Reason != null) d["reason"] = e.Reason;
        return d;
    }

    static L Rows(IEnumerable<InvariantEval> ev) => ev.Select(e => (object?)Row(e)).ToList();
    static D Res(ProhibitionResult r) => new() { ["ok"] = r.Ok, ["violated"] = r.Violated, ["reasons"] = r.Reasons, ["evaluated"] = Rows(r.Evaluated) };

    // the loader has replaced {"$seed": label} by the base64url seed; anything else is not a signing key
    static EdKey Key(object? s) => EdKey.FromSeed(Pca.B64uDecode(s, 32) ?? throw new ArgumentException("not a signing key"));

    // a time that is not a number never satisfies the finite check
    static double NumArg(object? a) => IntentJs.NumOf(a) ?? double.NaN;

    // the reference copies a value's own members: an object's, a string's indexed characters, a list's indexed elements; null has none to read
    static D Spread(object? v) => v switch
    {
        null => throw new ArgumentNullException(nameof(v)),
        D d => d,
        string s => s.Select((ch, i) => (i, v: (object?)ch.ToString())).ToDictionary(x => x.i.ToString(System.Globalization.CultureInfo.InvariantCulture), x => x.v),
        L l => l.Select((x, i) => (i, x)).ToDictionary(t => t.i.ToString(System.Globalization.CultureInfo.InvariantCulture), t => t.x),
        _ => new D(),
    };

    // ---- prohibitions ----
    [Fact]
    public void ProhibitionConstants() => Base.Check(P, "constants", _ => new D
    {
        ["CONSTITUTION_VERSION"] = Prohibitions.ConstitutionVersion, ["CONSTITUTION_SIG_DOMAIN"] = SafetyEvidence.ConstitutionSigDomain,
        ["EVIDENCE_VERSION"] = SafetyEvidence.Version, ["SAFETY_EVIDENCE_SIG_DOMAIN"] = SafetyEvidence.SigDomain,
        ["STATE_DIGEST_DOMAIN"] = Prohibitions.StateDigestDomain, ["STATE_CHAIN_DOMAIN"] = Prohibitions.StateChainDomain,
        ["MAX_LEDGER"] = Prohibitions.MaxLedger, ["MAX_INVARIANTS"] = Prohibitions.MaxInvariants, ["MAX_DEADLINE"] = Prohibitions.MaxDeadline,
    }, min: 1);

    // a label that is not text is printed as the reference prints it
    [Fact] public void ValidateWhen() => Base.Check(P, "validateWhen", a => Prohibitions.ValidateWhen(a[0], a[1] as string ?? Prohibitions.JsString(a[1])), min: 277);
    [Fact] public void WhenMatches() => Base.Check(P, "whenMatches", a => Prohibitions.WhenMatches(a[0], a[1] as D), min: 671);
    [Fact] public void SignConstitution() => Base.Check(P, "signConstitution", a => SafetyEvidence.SignConstitution(a[0] as D ?? throw new ArgumentException("not an object"), Key(a[1])), min: 31);

    [Fact]
    public void AdvanceState() => Base.Check(P, "advanceState", a =>
    {
        var state = a[2] as D;
        var next = Prohibitions.AdvanceState(a[0] as D, a[1], state, a.Count > 3 ? NumArg(a[3]) : null);
        return next ?? a[2]; // a refusal returns the input state, whatever it is
    }, min: 249);

    [Fact] public void EvidenceDigest() => Base.Check(P, "evidenceDigest", a => SafetyEvidence.EvidenceDigest(a[0]), min: 110);

    [Fact]
    public void ComposeAuthority() => Base.Check(P, "composeAuthority", a =>
    {
        // only the boolean true is a grant
        var r = Prohibitions.ComposeAuthority(a[0] is true, a[1] as D, a[2], a[3]);
        return new D { ["allow"] = r.Allow, ["decidedBy"] = r.DecidedBy, ["permitted"] = r.Permitted, ["prohibition"] = Res(r.Prohibition) };
    }, min: 298);

    [Fact]
    public void ProhibitionsCovers()
    {
        Base.Covers(P, new[] { "constants", "validateWhen", "whenMatches", "signConstitution", "composeAuthority", "advanceState", "evidenceDigest" });
        Assert.Equal(1637, Base.Cases(P).Count);
    }

    // ---- contracts ----
    [Fact]
    public void ContractConstants() => Base.Check(C, "constants", _ => new D
    {
        ["CONTRACT_VERSION"] = Contracts.Version, ["CONTRACT_SIG_DOMAIN"] = Contracts.SigDomain, ["MAX_CLAUSES"] = Contracts.MaxClauses, ["MAX_CLAUSE_DEPTH"] = Contracts.MaxClauseDepth,
    }, min: 1);

    [Fact]
    public void ValidateClause() => Base.Check(C, "validateClause", a =>
        Contracts.ValidateClause(a[0], new HashSet<string>(((L)a[1]!).Cast<string>(), StringComparer.Ordinal), (int)Math.Ceiling(NumArg(a[2]))), min: 65);

    [Fact] public void ContractId() => Base.Check(C, "contractId", a => Contracts.ContractId(Spread(a[0])), min: 16);
    [Fact] public void SignContract() => Base.Check(C, "signContract", a => Contracts.Sign(a[0] as D ?? throw new ArgumentException("not an object"), Key(a[1])), min: 31);
    [Fact] public void EmbeddedConstitution() => Base.Check(C, "embeddedConstitution", a => Contracts.EmbeddedConstitution(Spread(a[0])), min: 9);
    [Fact] public void ContractFromConstitution() => Base.Check(C, "contractFromConstitution", a => Contracts.FromConstitution(Spread(a[0])), min: 8);

    static D Res(ContractResult r) => new() { ["ok"] = r.Ok, ["violated"] = r.Violated, ["reasons"] = r.Reasons, ["evaluated"] = Rows(r.Evaluated) };

    static D Res(AdvanceContractResult r) => new()
    {
        ["ok"] = r.Ok, ["violated"] = r.Violated, ["reasons"] = r.Reasons, ["evaluated"] = Rows(r.Evaluated), ["next"] = r.Next, ["decidedBy"] = r.DecidedBy,
    };

    [Fact] public void CheckContract() => Base.Check(C, "checkContract", a => Res(Contracts.Check(a[0] as D, a[1], a[2])), min: 453);

    // the options as the reference reads them: a member that is present, even null or of another type, is a check
    static (long? Seq, string? Digest, double? Now) Opts(L a, int i)
    {
        if (a.Count <= i || a[i] is not D o) return (null, null, null);
        long? seq = o.TryGetValue("expectedSeq", out var es) ? (Base.IsJsonInt(es) ? IntentJs.Lng(es) : long.MinValue) : null;
        string? dg = o.TryGetValue("expectedStateDigest", out var ed) ? ed as string ?? "<not a digest>" : null;
        double? now = o.GetValueOrDefault("now") is { } n ? NumArg(n) : null;
        return (seq, dg, now);
    }

    // The untyped entry. The typed call has no options bag, so a bag that IS null cannot be handed to it: the reference fails reading the bag's members
    // inside its guarded block and answers fail closed over the plain check, with the state unchanged. That answer is built here from the public check.
    static AdvanceContractResult AdvanceUntyped(D state, D? action, object? contract, L a, int i)
    {
        if (a.Count > i && a[i] == null)
        {
            var b = Contracts.Check(action, contract, state);
            return new(false, b.Violated.Where(v => v != "<state>").Append("<state>").ToList(), b.Reasons.Append("<state>: advance error (fail closed)").ToList(), b.Evaluated, state, "state");
        }
        var (seq, dg, now) = Opts(a, i);
        return Contracts.Advance(state, action, contract, seq, dg, now);
    }

    [Fact]
    public void AdvanceContract()
    {
        Assert.Equal(1, Base.Of(C, "advanceContract").Count(c => Base.Args(c).Count > 3 && Base.Args(c)[3] == null));
        Assert.Equal(555, Base.Check(C, "advanceContract", a => Res(AdvanceUntyped((a[0] as D)!, a[1] as D, a[2], a, 3)), min: 555));
    }

    [Fact]
    public void CheckAndAdvanceContract() => Assert.Equal(131, Base.Check(C, "checkAndAdvanceContract", a =>
    {
        if (a.Count > 4 && a[4] == null) throw new InvalidOperationException("a null options bag: map it as AdvanceUntyped does");
        var (seq, dg, now) = Opts(a, 4);
        bool permitted = a[0] is true;
        var (r, allow) = Contracts.CheckAndAdvance(permitted, (a[1] as D)!, a[2] as D, a[3], seq, dg, now);
        var o = Res(r);
        o["allow"] = allow;
        o["permitted"] = permitted;
        return o;
    }, min: 131));

    [Fact]
    public void ContractsCovers()
    {
        Base.Covers(C, new[]
        {
            "constants", "validateClause", "contractId", "signContract", "embeddedConstitution", "contractFromConstitution", "checkContract", "advanceContract", "checkAndAdvanceContract",
        });
        Assert.Equal(1269, Base.Cases(C).Count);
    }
}
