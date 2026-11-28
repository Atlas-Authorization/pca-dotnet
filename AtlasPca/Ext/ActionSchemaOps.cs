// The rest of the site action schema surface of the reference (action-schema.ts) over the JSON tree: the exported vocabularies, limits, regex sources and wallet floors, the value-dependent reversibility, the wallet
// floor, the verb lookup, the site-signed schema (sign, discovery key entry, digest, verify) under the Ed25519, ML-DSA and hybrid suites, the MCP annotation hints and the drafting importers (MCP tool lists and OpenAPI documents).
// Shape, conformance and the content address are ActionSchema; this adds what a site and a tool author call.
using AtlasPca.Js;
using AtlasPca.Mcp;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class ActionSchemaOps
{
    public const string WellKnownPcaActionsPath = "/.well-known/pca-actions.json";
    public static readonly IReadOnlyList<string> WalletFloorPrefixes = ["money.", "party.", "contact.", "person.", "credential."];
    public static readonly IReadOnlyList<string> WalletFloorExact = ["text.message"];

    static L Strs(params string[] xs) => xs.Cast<object?>().ToList();
    static D Re(string source) => new() { ["$regex"] = source };

    /// <summary>Every exported constant: the domains, the closed vocabularies, the limits, the regexes (as <c>{"$regex": source}</c>) and the wallet floors.</summary>
    public static D Constants() => new()
    {
        ["ACTION_SCHEMA_DOMAIN"] = ActionSchema.ActionSchemaDomain, ["ACTION_SCHEMA_KIND"] = ActionSchema.ActionSchemaKind, ["ACTION_SCHEMA_REF_DOMAIN"] = ActionSchema.ActionSchemaRefDomain,
        ["DEFAULT_MAX_ITEMS"] = IntentJs.OfLong(ActionSchema.DefaultMaxItems), ["DEFAULT_MAX_LEN"] = IntentJs.OfLong(ActionSchema.DefaultMaxLen), ["MAX_SCHEMA_PARAMS"] = IntentJs.OfLong(ActionSchema.MaxSchemaParams),
        ["MAX_SCHEMA_VALUES"] = IntentJs.OfLong(ActionSchema.MaxSchemaValues), ["MAX_SCHEMA_VERBS"] = IntentJs.OfLong(ActionSchema.MaxSchemaVerbs),
        ["PARAM_PATH_RE"] = Re(@"^action\.params\.[A-Za-z0-9_]{1,64}$"), ["PARAM_PATH_RE_V2"] = Re(@"^action\.params\.[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}$"), ["UNIT_ID_RE"] = Re(@"^[a-z0-9_]+(?:\.[a-z0-9_]+)*$"),
        ["PARAM_TYPES"] = Strs("string", "integer", "boolean", "date", "set", "array"),
        ["PARAM_TYPES_V2"] = Strs("string", "integer", "boolean", "date", "set", "array", "datetime", "duration", "object_ref"),
        ["SCHEMA_REVERSIBILITY"] = Strs("reversible", "rate_limited", "irreversible"),
        ["SCHEMA_V2_CAVEATS"] = Strs("amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap"),
        ["SCHEMA_V2_CONTEXT"] = Strs("approval_ref", "dry_run_first", "fresh_revocation", "idempotency", "revocable", "sandbox_attested"),
        ["SCHEMA_V2_EFFECTS"] = Strs("read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign"),
        ["SCHEMA_V2_PROVENANCE"] = Strs("first_party", "tool", "agent"),
        ["SCHEMA_V2_PRULES"] = Strs("array_bounded", "export_bounded", "id_not_wildcard", "money_amount_bounded", "money_has_currency", "pay_has_idempotency", "recipient_param_declared", "secret_not_logged"),
        ["SCHEMA_V2_TAGS"] = Strs("pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql"),
        ["SENSITIVITIES"] = Strs("free", "material", "critical"), ["WALLET_FLOOR_EXACT"] = WalletFloorExact.Cast<object?>().ToList(), ["WALLET_FLOOR_PREFIXES"] = WalletFloorPrefixes.Cast<object?>().ToList(),
        ["WELL_KNOWN_PCA_ACTIONS_PATH"] = WellKnownPcaActionsPath,
    };

    static string? KeyOfValue(object? x) => x switch
    {
        string s => s,
        bool b => b ? "true" : "false",
        _ when IntentJs.IsSafeInteger(x) => JsCanon.NumberString(IntentJs.NumOf(x)!.Value),
        _ => null,
    };

    /// <summary>The value-dependent reversibility class of one action: the class its <c>reversibility_by</c> map gives the parameter's value (an unmapped or absent value takes the default, else <c>irreversible</c>: fail closed),
    /// else the verb's own class (a read is reversible, any other verb irreversible by default). Own-property lookups only.</summary>
    public static object? ReversibilityOf(D verb, D parameters)
    {
        if (verb.GetValueOrDefault("reversibility_by") is { } rbo && AttestationSoft.Truthy(rbo))
        {
            var rb = rbo as D ?? new D();
            var param = rb.GetValueOrDefault("param") as string ?? throw new InvalidOperationException("Cannot read properties of undefined (reading 'slice')");
            var name = param.Length >= 14 ? param[14..] : "";
            var k = parameters.TryGetValue(name, out var pv) ? KeyOfValue(pv) : null;
            if (k != null && rb.GetValueOrDefault("map") is D map && map.TryGetValue(k, out var mapped)) return mapped;
            return rb.GetValueOrDefault("default") ?? "irreversible";
        }
        return verb.GetValueOrDefault("reversibility") ?? (verb.GetValueOrDefault("kind") is "read" ? "reversible" : "irreversible");
    }

    /// <summary>Whether a semantic type is raised to at least material by the wallet, whatever the site says: an exact match, or a prefix match. <paramref name="floor"/> <c>{prefixes?, exact?}</c> (null: the defaults).</summary>
    public static bool FloorApplies(string semantic, D? floor = null)
    {
        var pre = floor?.GetValueOrDefault("prefixes") as L ?? WalletFloorPrefixes.Cast<object?>().ToList();
        var ex = floor?.GetValueOrDefault("exact") as L ?? WalletFloorExact.Cast<object?>().ToList();
        return ex.Any(e => e is string s && s == semantic) || pre.Any(p => p is string ps && semantic.StartsWith(ps, StringComparison.Ordinal));
    }

    /// <summary>The first verb declaration named <paramref name="verb"/>, or null. Throws on a null entry of the verbs list.</summary>
    public static D? SchemaVerb(object? doc, string verb)
    {
        if (IntentJs.Get(doc, "verbs") is not L verbs) return null;
        foreach (var v in verbs)
        {
            if (v == null) throw new InvalidOperationException("Cannot read properties of null (reading 'verb')");
            if (v is D d && d.GetValueOrDefault("verb") is string s && s == verb) return d;
        }
        return null;
    }

    /// <summary>Sign a schema as the site: <c>{...doc, sig: {alg, kid, value, pq_value?}}</c>. <paramref name="alg"/> null is ed25519; another suite needs its PQ key in <paramref name="keys"/>. Throws on a shape-invalid document.</summary>
    public static D SignActionSchema(D doc, string kid, byte[] siteSecret, string? alg = null, SuiteSecretKeys? keys = null)
    {
        var bad = ActionSchema.ShapeError(doc, signed: false);
        if (bad != null) throw new InvalidOperationException("signActionSchema: " + bad);
        if (!ActionSchema.IsStr(kid, 128)) throw new InvalidOperationException("signActionSchema: sig.kid must be a non-empty string");
        if (IntentJs.SuiteOf(alg ?? "ed25519", true) is not { } resolved) throw new InvalidOperationException($"signActionSchema: unknown signature alg '{alg}'");
        var parts = PqSuites.SignSuiteArtifact(alg, PqSuites.SuiteKeysOf(siteSecret, keys), IntentJs.Message(ActionSchema.ActionSchemaDomain, doc));
        var sig = new D { ["alg"] = resolved, ["kid"] = kid, ["value"] = parts.Sig };
        if (parts.PqSig != null) sig["pq_value"] = parts.PqSig;
        return new D(doc) { ["sig"] = sig };
    }

    /// <summary>The discovery key entry <c>{kid, alg, pk, pq_pk?}</c> of a site signer.</summary>
    public static D ActionSchemaKeyOf(string kid, byte[] siteSecret, string? alg = null, SuiteSecretKeys? keys = null)
    {
        if (!ActionSchema.IsStr(kid, 128)) throw new InvalidOperationException("actionSchemaKeyOf: kid must be a non-empty string");
        if (IntentJs.SuiteOf(alg ?? "ed25519", true) is not { } resolved) throw new InvalidOperationException($"actionSchemaKeyOf: unknown signature alg '{alg}'");
        using var k = EdKey.FromSeed(siteSecret);
        var o = new D { ["kid"] = kid, ["alg"] = resolved, ["pk"] = k.Id };
        if (PqSuites.SuitePqPublicKey(resolved, keys) is { } pq) o["pq_pk"] = pq;
        return o;
    }

    /// <summary>The content address of a (signed) schema.</summary>
    public static string ActionSchemaDigest(object? doc) => ActionSchema.Digest(doc);

    /// <summary>Verify a site-signed schema against the discovery key list: <c>{ok: true}</c> or <c>{ok: false, reason}</c>. Never throws.</summary>
    public static D VerifyActionSchema(object? doc, object? keys) => ActionSchema.Verify(doc, keys) is { } reason ? new D { ["ok"] = false, ["reason"] = reason } : new D { ["ok"] = true };

    /// <summary>An MCP tool's annotations as a LOWER bound on reversibility (hints never lower a classification): a read-only hint is <c>{kind: "read", atLeast: "reversible"}</c>, a destructive one
    /// <c>{kind: "write", atLeast: "rate_limited"}</c>, else <c>{kind: "write", atLeast: "reversible"}</c>.</summary>
    public static D ReversibilityFromMcpHints(object? annotations)
    {
        if (IntentJs.Get(annotations, "readOnlyHint") is true) return new D { ["kind"] = "read", ["atLeast"] = "reversible" };
        if (IntentJs.Get(annotations, "destructiveHint") is true) return new D { ["kind"] = "write", ["atLeast"] = "rate_limited" };
        return new D { ["kind"] = "write", ["atLeast"] = "reversible" };
    }

    /// <summary>The draft action schema of an MCP <c>tools/list</c>: <c>{schema, todo}</c> (the decisions the developer must make before signing).</summary>
    public static D DraftSchemaFromMcpTools(object? tools, object? site)
    {
        if (tools is not L tl) throw new InvalidOperationException("tools is not iterable");
        return McpDraft.Draft(tl, site as D ?? throw new InvalidOperationException("Cannot read properties of undefined (reading 'verbPrefix')"));
    }

    /// <summary>The draft action schema of an OpenAPI document (see McpDraft): <c>{schema, todo}</c>; <paramref name="site"/> is <c>{site, aud, version}</c>.</summary>
    public static D DraftSchemaFromOpenApi(object? doc, object? site) => McpDraft.DraftOpenApi(doc, site);
}
