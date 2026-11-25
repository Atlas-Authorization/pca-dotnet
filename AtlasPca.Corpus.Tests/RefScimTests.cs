using AtlasPca.Js;
using AtlasPca.Scim;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential oracle of the SCIM 2.0 /Agents server, the passport mapping and the push adapters (test-data/ref-scim.json.gz, TypeScript reference pca-scim).</summary>
public class RefScimTests
{
    const string M = "ref-scim";
    static readonly double T0 = Base.ClockMs(M); // the clock the corpus generator ran under

    // the named option table of the reference's session cases
    static ScimHandlerOptions Table(string name)
    {
        long tick = 0;
        Func<D, object?> yes = _ => true;
        return name switch
        {
            "open" => new() { BaseUrl = "https://scim.acme.com/scim/v2", Now = () => T0, Authenticate = yes },
            "slash" => new() { BaseUrl = "https://scim.acme.com/scim/v2///", Now = () => T0, Authenticate = yes },
            "nobase" => new() { Now = () => T0, AllowUnauthenticated = true },
            "tick" => new() { BaseUrl = "https://x.example", Now = () => T0 + 1000 * tick++, Authenticate = yes },
            "deny" => new() { Now = () => T0, Authenticate = _ => false },
            "throwauth" => new() { Now = () => T0, Authenticate = _ => throw new InvalidOperationException("x") },
            "truthy" => new() { Now = () => T0, Authenticate = _ => "yes" },
            "noauth" => new() { Now = () => T0 },
            "notfn" => new() { Now = () => T0 }, // a non-function authenticate is as good as none
            _ => throw new ArgumentException(name),
        };
    }

    [Fact]
    public void Session() => Base.Check(M, "scimSession", a =>
    {
        var h = ScimAgents.ScimHandler(new MemoryAgentStore(), Table((string)a[0]!));
        foreach (var r in (L)a[1]!) h((D)r!);
        return ((L)a[2]!).Select(r => (object?)h((D)r!).ToTree()).ToList();
    });

    [Fact] public void Fingerprint() => Base.Check(M, "passportFingerprint", a => ScimAgents.PassportFingerprint((D)a[0]!));
    [Fact] public void Issue() => Base.Check(M, "issuePassport", a => ScimAgents.IssuePassport((D)a[0]!));

    [Fact]
    public void PassportToScim() => Base.Check(M, "passportToScim", a =>
    {
        var m = new MetaInput();
        if (a[2] is Num t) m.Now = () => IntentJs.NumOf(t)!.Value;
        else
        {
            var d = (D)a[2]!;
            m.BaseUrl = d.GetValueOrDefault("baseUrl") as string;
            m.Created = d.GetValueOrDefault("created") as string;
            m.LastModified = d.GetValueOrDefault("lastModified") as string;
        }
        return ScimAgents.PassportToScim((D)a[0]!, (D)a[1]!, m);
    });

    [Fact] public void ToProvisioningRequest() => Base.Check(M, "scimToProvisioningRequest", a => ScimAgents.ScimToProvisioningRequest(a[0]));
    [Fact] public void ParseFilter() => Base.Check(M, "parseFilter", a => ScimAgents.ParseFilter(a[0]));
    [Fact] public void ScimError() => Base.Check(M, "scimError", a => a.Count > 2 ? ScimAgents.ScimErrorWith((int)Base.Long(a[0]), (string)a[1]!, a[2]) : ScimAgents.ScimError((int)Base.Long(a[0]), (string)a[1]!));
    [Fact] public void ListResponse() => Base.Check(M, "scimListResponse", a => ScimAgents.ScimListResponse((L)a[0]!, a[1], a[2]));

    [Fact]
    public void Registry() => Base.Check(M, "registry", a =>
    {
        var r = ScimAgents.BuildRegistry(((L)a[0]!).Select(p => (D)p!));
        var id = (string)a[1]!;
        return new D { ["all"] = r.All().Select(p => (object?)p).ToList(), ["has"] = r.Has(id), ["get"] = r.Get(id) };
    });

    [Fact] public void ToEntra() => Base.Check(M, "toEntraAgentPayload", a => ScimAgents.ToEntraAgentPayload((D)a[0]!));
    [Fact] public void ToOkta() => Base.Check(M, "toOktaScimPayload", a => ScimAgents.ToOktaScimPayload((D)a[0]!));

    static ScimAgents.FetchLike Fake(string mode, L calls) => (url, init) =>
    {
        calls.Add(new D
        {
            ["url"] = url,
            ["init"] = new D { ["method"] = init.Method, ["headers"] = init.Headers.ToDictionary(e => e.Key, e => (object?)e.Value), ["body"] = init.Body },
        });
        return Task.FromResult(mode switch
        {
            "ok201" => new ScimAgents.PushReply(true, 201, () => Task.FromResult<object?>(new D { ["id"] = "obj-1" })),
            "err500" => new ScimAgents.PushReply(false, 500, () => Task.FromResult<object?>(new D { ["detail"] = "x" })),
            "badjson" => new ScimAgents.PushReply(true, 204, () => throw new InvalidOperationException("no body")),
            "nullbody" => new ScimAgents.PushReply(true, 200, () => Task.FromResult<object?>(null)),
            _ => throw new ArgumentException(mode),
        });
    };

    static D Push(Func<D, ScimAgents.PushTarget, Task<ScimAgents.PushResult>> f, D agent, string mode, string endpoint = "https://dir.example/scim/Agents", string token = "TOK")
    {
        var calls = new L();
        var res = f(agent, new ScimAgents.PushTarget { Endpoint = endpoint, Token = token, Fetch = Fake(mode, calls) }).GetAwaiter().GetResult();
        return new D { ["result"] = new D { ["ok"] = res.Ok, ["status"] = res.Status, ["body"] = res.Body }, ["calls"] = calls };
    }

    [Fact] public void PushToEntra() => Base.Check(M, "pushToEntra", a => Push(ScimAgents.PushToEntra, (D)a[1]!, (string)a[2]!));
    [Fact] public void PushToOkta() => Base.Check(M, "pushToOkta", a => Push(ScimAgents.PushToOkta, (D)a[1]!, (string)a[2]!));

    [Fact]
    public void PushProvision() => Base.Check(M, "pushProvision", a =>
        Push((agent, target) => ScimAgents.PushProvision(ScimAgents.ToEntraAgentPayload(agent), target), (D)a[0]!, (string)a[1]!, "e", "t"));

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "scimSession", "passportFingerprint", "issuePassport", "passportToScim", "scimToProvisioningRequest", "parseFilter", "scimError",
        "scimListResponse", "registry", "toEntraAgentPayload", "toOktaScimPayload", "pushToEntra", "pushToOkta", "pushProvision",
    }); Assert.Equal(1124, Base.Total(M)); }
}
