using AtlasPca.Authzen;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the AuthZEN guards, default action mapping, approval reading, PDP refusal and merge paths, handler and
/// search APIs against the TypeScript reference. The permit paths (proof-carrying and static) run through the native Policy-VM decision.</summary>
public class RefAuthzenTests
{
    const string M = "ref-authzen";
    const long Now = 1_000_000;

    static Num N(long v) => new(v.ToString());
    static D Ok => new() { ["allow"] = true };

    static AuthzenPdp Pdp(string name)
    {
        D? Granted(D _) => new() { ["grant"] = new D(), ["policy"] = new D() };
        var cfg = name switch
        {
            "none" => new AuthzenPdpConfig { Resolve = _ => null, Now = () => Now },
            "throws" => new AuthzenPdpConfig { Resolve = _ => throw new Exception("boom"), Now = () => Now },
            "noauth" => new AuthzenPdpConfig { Resolve = Granted, Now = () => Now },
            "auth" => new AuthzenPdpConfig { Resolve = Granted, Authorizer = _ => Task.FromResult(Ok), Now = () => Now },
            "max2" => new AuthzenPdpConfig { Resolve = _ => null, MaxEvaluations = 2, Now = () => Now },
            "toolmap" => new AuthzenPdpConfig { Resolve = _ => null, ToolCapability = n => "cap." + n, Now = () => Now },
            "toolthrow" => new AuthzenPdpConfig { Resolve = _ => null, ToolCapability = _ => throw new Exception("bad tool"), Now = () => Now },
            _ => throw new ArgumentException(name),
        };
        return new AuthzenPdp(cfg);
    }

    static D U(string id) => new() { ["type"] = "user", ["id"] = id };
    static D Res(params object?[] results) => new() { ["results"] = new L(results) };
    static D Ent(string type, string id) => new() { ["type"] = type, ["id"] = id };

    static Func<D, Task<D>> Fn(D r) => _ => Task.FromResult(r);
    static Func<D, Task<D>> Boom => _ => throw new Exception("x");
    static Func<D, Task<D>> Echo => r => Task.FromResult(new D { ["results"] = new L(), ["context"] = new D { ["saw"] = r } });

    static AuthzenSearchProvider Prov(string name) => name switch
    {
        "none" => new AuthzenSearchProvider(),
        "full" => new AuthzenSearchProvider
        {
            SearchSubject = Fn(new D
            {
                ["results"] = new L { U("a"), U("b"), Ent("group", "g"), U("a"), new D { ["id"] = "a", ["type"] = "user" } },
                ["page"] = new D { ["next_token"] = "", ["total"] = N(3), ["properties"] = new D { ["k"] = N(1) } }, ["context"] = new D { ["c"] = N(1) },
            }),
            SearchResource = Fn(new D { ["results"] = new L { Ent("doc", "1"), Ent("doc", "2"), Ent("user", "x") }, ["page"] = new D { ["next_token"] = "n1" } }),
            SearchAction = Fn(Res(new D { ["name"] = "read" }, new D { ["name"] = "write" }, new D { ["name"] = "read" }, new D { ["name"] = "read", ["properties"] = new D { ["p"] = N(1) } })),
        },
        "nopage" => new AuthzenSearchProvider { SearchSubject = Fn(Res(U("a"), U("b"))), SearchResource = Fn(Res()), SearchAction = Fn(Res()) },
        "emptyprops" => new AuthzenSearchProvider { SearchSubject = Fn(new D { ["results"] = new L { U("a") }, ["page"] = new D { ["next_token"] = "z", ["properties"] = new D() }, ["context"] = new D() }) },
        "bad" => new AuthzenSearchProvider { SearchSubject = Fn(Res((object?)null)), SearchResource = Fn(Res(N(5))), SearchAction = Fn(Res(null, N(5))) },
        "notarray" => new AuthzenSearchProvider { SearchSubject = Fn(new D { ["results"] = "x" }), SearchResource = Fn(new D()), SearchAction = Fn(new D { ["results"] = null }) },
        "throws" => new AuthzenSearchProvider { SearchSubject = Boom, SearchResource = Boom, SearchAction = Boom },
        "echo" => new AuthzenSearchProvider { SearchSubject = Echo, SearchResource = Echo, SearchAction = Echo },
        "partial" => new AuthzenSearchProvider { SearchResource = Fn(Res()) },
        _ => throw new ArgumentException(name),
    };

    const string ME = "ref-authzen-java-extra";
    const long T0 = 1_800_000_000_000;

    /// <summary>The PDP of one case description: {grant, policy?, audience? (absent = not given, null = accept any), insecureSkipPlanRootCheck?, authorizedPlanRoots?,
    /// authorizer? (an authorizer that allows), requireAuthorizer?, requireProof?, budget?, risk?, plan?}.</summary>
    static AuthzenPdp ExtraPdp(D d)
    {
        D? Resolve(D _)
        {
            var r = new D { ["grant"] = d["grant"], ["policy"] = d.GetValueOrDefault("policy") ?? new D { ["predicates"] = new L(), ["caveats"] = new L() } };
            foreach (var k in new[] { "budget", "risk", "plan" }) if (d.GetValueOrDefault(k) != null) r[k] = d[k];
            return r;
        }
        return new AuthzenPdp(new AuthzenPdpConfig
        {
            Resolve = Resolve,
            Now = () => T0,
            AudienceSet = d.ContainsKey("audience"),
            Audience = d.GetValueOrDefault("audience") as string,
            InsecureSkipPlanRootCheck = d.GetValueOrDefault("insecureSkipPlanRootCheck") as bool?,
            AuthorizedPlanRoots = (d.GetValueOrDefault("authorizedPlanRoots") as L)?.Select(x => (string)x!).ToList(),
            Authorizer = d.GetValueOrDefault("authorizer") is true ? (Func<D, Task<D>>)(_ => Task.FromResult(Ok)) : null,
            RequireAuthorizer = d.GetValueOrDefault("requireAuthorizer") as bool?,
            RequireProof = d.GetValueOrDefault("requireProof") as bool?,
        });
    }

    static T Run<T>(Task<T> t) => t.GetAwaiter().GetResult();

    [Fact] public void IsAccessEvaluationRequest() => Base.Check(M, "isAccessEvaluationRequest", a => AuthzenGuards.IsAccessEvaluationRequest(a[0]));
    [Fact] public void IsAccessEvaluationsRequest() => Base.Check(M, "isAccessEvaluationsRequest", a => AuthzenGuards.IsAccessEvaluationsRequest(a[0]));
    [Fact] public void IsCoazToolAuthorizationRequest() => Base.Check(M, "isCoazToolAuthorizationRequest", a => AuthzenGuards.IsCoazToolAuthorizationRequest(a[0]));
    [Fact] public void IsAuthzenSubject() => Base.Check(M, "isAuthzenSubject", a => AuthzenGuards.IsAuthzenSubject(a[0]));
    [Fact] public void IsAuthzenAction() => Base.Check(M, "isAuthzenAction", a => AuthzenGuards.IsAuthzenAction(a[0]));
    [Fact] public void IsAuthzenResource() => Base.Check(M, "isAuthzenResource", a => AuthzenGuards.IsAuthzenResource(a[0]));
    [Fact] public void IsSubjectSearch() => Base.Check(M, "isSubjectSearch", a => AuthzenSearch.IsSubjectSearch(a[0]));
    [Fact] public void IsResourceSearch() => Base.Check(M, "isResourceSearch", a => AuthzenSearch.IsResourceSearch(a[0]));
    [Fact] public void IsActionSearch() => Base.Check(M, "isActionSearch", a => AuthzenSearch.IsActionSearch(a[0]));
    [Fact] public void DefaultToAction() => Base.Check(M, "defaultToAction", a => AuthzenGuards.DefaultToAction((D)a[0]!));
    [Fact] public void ApprovalOf() => Base.Check(M, "approvalOf", a => AuthzenGuards.ApprovalOf(a[0]));
    [Fact] public void IsApprovalRequired() => Base.Check(M, "isApprovalRequired", a => AuthzenGuards.IsApprovalRequired(a[0]));
    [Fact] public void PdpEvaluate() => Base.Check(M, "pdp.evaluate", a => Run(Pdp((string)a[0]!).Evaluate((D)a[1]!)));
    [Fact] public void PdpEvaluations() => Base.Check(M, "pdp.evaluations", a => Run(Pdp((string)a[0]!).Evaluations((D)a[1]!)));
    [Fact] public void PdpEvaluateTool() => Base.Check(M, "pdp.evaluateTool", a => Run(Pdp((string)a[0]!).EvaluateTool((D)a[1]!)));
    [Fact] public void Handler() => Base.Check(M, "authzenHandler", a => Run(AuthzenHandler.Handle(Pdp((string)a[0]!), (D)a[1]!)));
    [Fact] public void SearchHandler() => Base.Check(M, "authzenSearchHandler", a => Run(AuthzenSearch.Handle(Prov((string)a[0]!), (D)a[1]!)));
    [Fact] public void SearchMetadata() => Base.Check(M, "searchMetadata", a => AuthzenSearch.SearchMetadata((string)a[0]!, Prov((string)a[1]!)));

    [Fact] public void ExtraEvaluate() => Base.Check(ME, "evaluate", a => Run(ExtraPdp((D)a[0]!).Evaluate((D)a[1]!)));
    [Fact] public void ExtraCovers() { Base.Covers(ME, new[] { "evaluate" }); Assert.Equal(42, Base.Total(ME)); }

    [Fact]
    public void Covers() { Base.Covers(M, new[]
    {
        "isAccessEvaluationRequest", "isAccessEvaluationsRequest", "isCoazToolAuthorizationRequest", "isAuthzenSubject", "isAuthzenAction", "isAuthzenResource",
        "isSubjectSearch", "isResourceSearch", "isActionSearch", "defaultToAction", "approvalOf", "isApprovalRequired", "pdp.evaluate", "pdp.evaluations", "pdp.evaluateTool",
        "authzenHandler", "authzenSearchHandler", "searchMetadata",
    }); Assert.Equal(3095, Base.Total(M)); }
}
