using AtlasPca;
using AtlasPca.Connect;
using AtlasPca.Connectors;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the connector catalog (manifest validation and digests, the provider registry, authorize URL / PKCE /
/// URL variables, access-token placement, code exchange and refresh into the vault, manifest-to-vault-provider mapping) against the
/// TypeScript reference (test-data/ref-connectors.json.gz). Errors are compared as data (class name and message); a failure that is not a
/// connector error is the generic "Error". A reference throw requires the native to throw.</summary>
public class RefConnectorsTests
{
    const string M = "ref-connectors";

    static D ErrOut(Exception e)
    {
        if (e is not ConnectorError ce) return new D { ["ok"] = false, ["name"] = "Error" };
        var o = new D { ["ok"] = false, ["name"] = e.GetType().Name, ["message"] = ce.Message };
        if (e is ManifestValidationError mv && mv.Issues.Count > 0) o["issues"] = mv.Issues.Cast<object?>().ToList();
        return o;
    }

    static object? Guard(Func<object?> f)
    {
        try { return new D { ["ok"] = true, ["value"] = f() }; }
        catch (Exception e) { return ErrOut(e); }
    }

    static ProviderRegistry WithReg(object? customs)
    {
        var r = PcaConnectors.CreateDefaultRegistry();
        if (customs is L l) foreach (var m in l) r.Register(m);
        return r;
    }

    static D ConfigJson(ProviderConfig c)
    {
        var o = new D { ["tokenEndpoint"] = c.TokenEndpoint, ["clientId"] = c.ClientId };
        if (c.ClientSecret != null) o["clientSecret"] = c.ClientSecret;
        if (c.SupportsScopeNarrowing != null) o["supportsScopeNarrowing"] = c.SupportsScopeNarrowing.Value;
        if (c.ExtraParams != null) o["extraParams"] = c.ExtraParams.ToDictionary(e => e.Key, e => (object?)e.Value);
        return o;
    }

    sealed class ScriptedResponse(D r) : IVaultHttpResponse
    {
        public bool Ok => r.GetValueOrDefault("ok") is true;
        public int Status => (int)IntentJs.NumOf(r["status"])!.Value;
        public object? Json() => r.GetValueOrDefault("jsonThrows") is true ? throw new InvalidDataException("bad json") : r.GetValueOrDefault("json");
        public string Text() => r.GetValueOrDefault("textThrows") is true ? throw new InvalidDataException("bad text") : r.GetValueOrDefault("text") as string ?? "";
    }

    static VaultFetch? Transport(object? script, L log)
    {
        if (script is not L s) return null;
        int i = 0;
        return (url, init) =>
        {
            log.Add(new D { ["url"] = url, ["method"] = init.Method, ["headers"] = init.Headers.ToDictionary(e => e.Key, e => (object?)e.Value), ["body"] = init.Body });
            var r = (D)s[Math.Min(i++, s.Count - 1)]!;
            if (r.GetValueOrDefault("throws") is string t) throw new InvalidOperationException(t);
            return new ScriptedResponse(r);
        };
    }

    static object? TokenRun(object? c0, bool exchange)
    {
        var c = (D)c0!;
        var log = new L();
        var store = new InMemoryConnectionStore();
        var now = (long)IntentJs.NumOf(c["now"])!.Value;
        var vault = new TokenVault(new TokenVaultOptions { Strict = false, InsecureSkipPlanRootCheck = true, Store = store, Now = () => now });
        var bind = (D)c["bind"]!;
        var args = new D();
        foreach (var (k, v) in c) if (k is not ("bind" or "script" or "customs")) args[k] = v;
        var binding = new ConnectBinding
        {
            Vault = vault, AgentId = (string)bind["agentId"]!, ConnectionId = bind.GetValueOrDefault("connectionId") as string, Principal = (string)bind["principal"]!,
            Scopes = bind.GetValueOrDefault("scopes") is L sc ? sc.Select(x => (string)x!).ToList() : null, Audience = bind.GetValueOrDefault("audience") as string,
        };
        var fetch = Transport(c.GetValueOrDefault("script"), log);
        object? result;
        try
        {
            var reg = WithReg(c.GetValueOrDefault("customs"));
            var stored = exchange ? PcaConnectors.ExchangeCode(args, binding, fetch, reg) : PcaConnectors.Refresh(args, binding, fetch, reg);
            result = new D { ["ok"] = true, ["value"] = stored.ToJson() };
        }
        catch (Exception e) { result = ErrOut(e); }
        var g = store.Get(new ConnectionKey((string)bind["agentId"]!, (string)c["providerId"]!, bind.GetValueOrDefault("connectionId") as string ?? "default"));
        return new D { ["result"] = result, ["fetchCalls"] = log, ["stored"] = g?.ToJson() };
    }

    [Fact] public void ValidateManifest() => Base.Check(M, "validateManifest", a => PcaConnectors.ValidateManifest(a[0]));

    [Fact] public void AssertManifest() => Base.Check(M, "assertManifest", a => Guard(() => PcaConnectors.AssertManifest(a[0])));

    [Fact] public void ManifestDigest() => Base.Check(M, "manifestDigest", a => PcaConnectors.ManifestDigest(a[0]));

    [Fact]
    public void Catalog() => Base.Check(M, "catalog", _ => new D
    {
        ["ids"] = PcaConnectors.ListProviders().Select(m => m["id"]).ToList(),
        ["manifests"] = PcaConnectors.ListProviders(),
        ["digest"] = PcaConnectors.CatalogDigest(),
        ["google"] = PcaConnectors.GetProvider("google"),
        ["nope"] = PcaConnectors.GetProvider("nope"),
    });

    [Fact]
    public void Registry() => Base.Check(M, "registry", a =>
    {
        var s = (D)a[0]!;
        var r = s.GetValueOrDefault("empty") is true ? new ProviderRegistry() : PcaConnectors.CreateDefaultRegistry();
        var o = new L();
        foreach (var op0 in (L)s["ops"]!)
        {
            var op = (D)op0!;
            try
            {
                object? v = (string)op["op"]! switch
                {
                    "register" => r.Register(op["manifest"], op.GetValueOrDefault("opts") as D),
                    "get" => r.Get((string)op["id"]!),
                    "require" => r.Require((string)op["id"]!),
                    "has" => r.Has((string)op["id"]!),
                    "list" => r.List(),
                    "ids" => r.Ids(),
                    _ => PcaConnectors.CatalogDigest(r),
                };
                o.Add(new D { ["ok"] = true, ["value"] = v });
            }
            catch (Exception e) { o.Add(ErrOut(e)); }
        }
        return o;
    });

    [Fact] public void SubstituteVars() => Base.Check(M, "substituteVars", a => Guard(() => PcaConnectors.SubstituteVars((string)a[0]!, a.Count > 1 ? a[1] : InteropJsUndef)));

    [Fact] public void PkceChallenge() => Base.Check(M, "pkceChallenge", a => Guard(() => a.Count > 1 ? PcaConnectors.PkceChallenge((string)a[0]!, (string)a[1]!) : PcaConnectors.PkceChallenge((string)a[0]!)));

    [Fact]
    public void BuildAuthorizeUrl() => Base.Check(M, "buildAuthorizeUrl", a => Guard(() => PcaConnectors.BuildAuthorizeUrl((string)a[0]!, (D)a[1]!, WithReg(a.Count > 2 ? a[2] : null))));

    [Fact] public void ApplyAccessToken() => Base.Check(M, "applyAccessToken", a => Guard(() => PcaConnectors.ApplyAccessToken((D)a[0]!, a[1])));

    [Fact]
    public void ManifestToProviderConfig() => Base.Check(M, "manifestToProviderConfig", a => Guard(() => ConfigJson(PcaConnectors.ManifestToProviderConfig(PcaConnectors.GetProvider((string)a[0]!)!, (D)a[1]!))));

    [Fact]
    public void BuildVaultProviders() => Base.Check(M, "buildVaultProviders", a => Guard(() =>
        PcaConnectors.BuildVaultProviders((D)a[0]!).ToDictionary(e => e.Key, e => (object?)ConfigJson(e.Value))));

    [Fact] public void Exchange() => Base.Check(M, "exchange", a => TokenRun(a[0], true));

    [Fact] public void Refresh() => Base.Check(M, "refresh", a => TokenRun(a[0], false));

    [Fact]
    public void AllFnsHandled() { Base.Covers(M, new[] { "validateManifest", "assertManifest", "manifestDigest", "catalog", "registry", "substituteVars", "pkceChallenge", "buildAuthorizeUrl", "applyAccessToken", "manifestToProviderConfig", "buildVaultProviders", "exchange", "refresh" }); Assert.Equal(1708, Base.Total(M)); }

    static readonly object InteropJsUndef = AtlasPca.InteropJs.JsX.Undef;
}
