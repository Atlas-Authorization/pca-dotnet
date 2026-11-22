// SCIM 2.0 provisioning for PCA agents: the passport <-> SCIM Agent mapping, the `attr eq "value"` filter, RFC 7644 PATCH, the
// framework-agnostic /Agents handler and the Entra / Okta push adapters. Requests, resources and bodies are JSON trees (Dictionary);
// the store, the clock, the authenticate callback and the HTTP fetch are injected.
using System.Globalization;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Scim;

/// <summary>A malformed SCIM value; <see cref="ScimType"/> is the RFC 7644 scimType of the error body.</summary>
public sealed class ScimValueException(string scimType, string detail) : Exception(detail)
{
    public string ScimType { get; } = scimType;
}

/// <summary>Inputs for the `meta` block. <c>Now</c> is the clock (milliseconds since the epoch) for any defaulted timestamp.</summary>
public sealed class MetaInput
{
    public string? BaseUrl { get; set; }
    public string? Created { get; set; }
    public string? LastModified { get; set; }
    public Func<double>? Now { get; set; }
}

/// <summary>A stored agent: its materialized SCIM resource plus the backing passport.</summary>
public sealed record StoredAgent(D Resource, D Passport);

/// <summary>The persistence seam the SCIM handler writes through (store and fetch only; SCIM semantics live in the handler).</summary>
public interface IAgentStore
{
    IReadOnlyList<StoredAgent> All();
    StoredAgent? Get(string id);
    void Put(StoredAgent stored);
    bool Delete(string id);
    PassportRegistry Registry();
}

/// <summary>A read-only passport registry view (the reference's buildRegistry).</summary>
public sealed class PassportRegistry
{
    readonly List<string> _order = new();
    readonly Dictionary<string, D> _byId = new();
    public PassportRegistry(IEnumerable<D> passports)
    {
        foreach (var p in passports)
        {
            if (p.GetValueOrDefault("id") is not string id) continue;
            if (!_byId.ContainsKey(id)) _order.Add(id);
            _byId[id] = p;
        }
    }
    public D? Get(string id) => _byId.GetValueOrDefault(id);
    public bool Has(string id) => _byId.ContainsKey(id);
    public IReadOnlyList<D> All() => _order.Select(i => _byId[i]).ToList();
}

/// <summary>The default in-memory store; insertion order is preserved (a replaced agent keeps its place).</summary>
public sealed class MemoryAgentStore : IAgentStore
{
    readonly List<string> _order = new();
    readonly Dictionary<string, StoredAgent> _byId = new();
    public MemoryAgentStore(IEnumerable<StoredAgent>? seed = null) { foreach (var s in seed ?? Array.Empty<StoredAgent>()) Put(s); }
    public IReadOnlyList<StoredAgent> All() => _order.Select(i => _byId[i]).ToList();
    public StoredAgent? Get(string id) => _byId.GetValueOrDefault(id);
    public void Put(StoredAgent stored)
    {
        var id = (string)stored.Resource["id"]!;
        if (!_byId.ContainsKey(id)) _order.Add(id);
        _byId[id] = stored;
    }
    public bool Delete(string id) { if (!_byId.Remove(id)) return false; _order.Remove(id); return true; }
    public PassportRegistry Registry() => new(_order.Select(i => _byId[i].Passport));
}

public sealed record ScimResponse(int Status, object? Body, bool HasBody, IReadOnlyDictionary<string, string> Headers)
{
    /// <summary>{status, body?, headers} as a JSON tree (the body is absent for a 204).</summary>
    public D ToTree()
    {
        var d = new D { ["status"] = new Num(Status.ToString(CultureInfo.InvariantCulture)) };
        if (HasBody) d["body"] = Body;
        d["headers"] = Headers.ToDictionary(e => e.Key, e => (object?)e.Value);
        return d;
    }
}

public sealed class ScimHandlerOptions
{
    public string? BaseUrl { get; set; }
    public Func<double>? Now { get; set; }
    /// <summary>Must return exactly <c>true</c> to admit a request; false, a throw or any other value yields 401.</summary>
    public Func<D, object?>? Authenticate { get; set; }
    public bool AllowUnauthenticated { get; set; }
}

public static class ScimAgents
{
    public const string AgentSchemaUrn = "urn:ietf:params:scim:schemas:atlas:2.0:Agent";
    public const string ListResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
    public const string PatchOpSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
    public const string ErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error";
    public const string AgentResourceType = "Agent";
    public const string EntraAgentExtensionUrn = "urn:ietf:params:scim:schemas:extension:microsoft:agent:2.0:Agent";
    public const string OktaAgentExtensionUrn = "urn:okta:scim:schemas:custom:1.0:Agent";
    const string ScimContentType = "application/scim+json";

    // ---- passport re-exports ----

    public static string PassportFingerprint(D identity) => Issue.PassportFingerprint(identity);
    public static D IssuePassport(D identity) => Issue.IssuePassport(identity);
    public static PassportRegistry BuildRegistry(IEnumerable<D> passports) => new(passports);

    // ---- untrusted-body readers ----

    static D? AsRecord(object? v) => v as D;
    static string? AsString(object? v) => v as string;
    static bool? AsBoolean(object? v) => v switch { bool b => b, "true" => true, "false" => false, _ => null };
    static L? AsStringArray(object? v) => v is L l && l.All(x => x is string) ? l : null;
    static object? Get(D? d, string k) => d != null && d.TryGetValue(k, out var v) ? v : null;

    static string IsoAt(Func<double> now)
    {
        var ms = Math.Truncate(now());
        if (double.IsNaN(ms) || Math.Abs(ms) > 8.64e15) throw new ArgumentOutOfRangeException("now", "Invalid time value");
        try { return DateTimeOffset.FromUnixTimeMilliseconds((long)ms).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture); }
        catch (ArgumentOutOfRangeException) { throw new ArgumentOutOfRangeException("now", "year outside 0000-9999 is not supported"); }
    }

    static D BuildMeta(string id, D resourceSansMeta, MetaInput input)
    {
        var now = input.Now ?? (() => AtlasPca.ReplayClock.NowMs());
        var b = input.BaseUrl != null ? input.BaseUrl.TrimEnd('/') : "";
        var location = $"{b}/Agents/{JsJson.EncodeUriComponent(id)}";
        return new D
        {
            ["resourceType"] = AgentResourceType,
            ["created"] = input.Created ?? IsoAt(now),
            ["lastModified"] = input.LastModified ?? IsoAt(now),
            ["location"] = location,
            ["version"] = $"W/\"{Pca.HashCanonical(resourceSansMeta)}\"",
        };
    }

    /// <summary>Project a passport and its governance attributes into a SCIM Agent resource. The reference throws when the projection has no `owner` (the digest cannot cover undefined).</summary>
    public static D PassportToScim(D passport, D proj, MetaInput? meta = null)
    {
        meta ??= new MetaInput();
        var id = passport.GetValueOrDefault("id");
        if (!proj.ContainsKey("owner")) throw new InvalidOperationException("canonicalize: unsupported type undefined");
        var dn = proj.GetValueOrDefault("displayName");
        var active = proj.GetValueOrDefault("active");
        var b = new D
        {
            ["schemas"] = new L { AgentSchemaUrn },
            ["id"] = id,
            ["displayName"] = dn ?? $"{ToS(passport.GetValueOrDefault("model_id"))} ({ToS(passport.GetValueOrDefault("operator"))})",
            ["active"] = active ?? true,
            ["owner"] = proj["owner"],
            ["capabilities"] = proj.GetValueOrDefault("capabilities") is L caps ? new L(caps) : new L(),
            ["passportRef"] = id,
            ["passport"] = passport,
        };
        if (proj.TryGetValue("externalId", out var ext)) b["externalId"] = ext;
        if (proj.TryGetValue("holder", out var holder)) b["holder"] = holder;
        var r = new D(b);
        r["meta"] = BuildMeta((string)id!, b, meta);
        return r;
    }

    static string ToS(object? v) => v == null ? "undefined" : JsJson.ToJsString(v);

    static D ReadIdentity(D body)
    {
        var nested = AsRecord(Get(body, "passport"));
        if (nested != null)
        {
            var modelId = AsString(Get(nested, "model_id"));
            var op = AsString(Get(nested, "operator"));
            if (modelId == null || op == null) throw new ScimValueException("invalidValue", "passport.model_id and passport.operator are required");
            var identity = new D
            {
                ["model_id"] = modelId,
                ["operator"] = op,
                ["hardware_rooted"] = AsBoolean(Get(nested, "hardware_rooted")) ?? false,
                ["issued_at"] = Get(nested, "issued_at") is Num n ? n : new Num("0"),
            };
            if (AsString(Get(nested, "weights_digest")) is { } w) identity["weights_digest"] = w;
            if (AsString(Get(nested, "system_prompt_digest")) is { } sp) identity["system_prompt_digest"] = sp;
            if (AsString(Get(nested, "tool_manifest_digest")) is { } tm) identity["tool_manifest_digest"] = tm;
            if (AsString(Get(nested, "runtime_measurement")) is { } rm) identity["runtime_measurement"] = rm;
            if (AsBoolean(Get(nested, "weights_measured")) is { } wm) identity["weights_measured"] = wm;
            return identity;
        }
        var model = AsString(Get(body, "model")) ?? AsString(Get(body, "model_id"));
        var oper = AsString(Get(body, "operator"));
        if (model == null || oper == null) throw new ScimValueException("invalidValue", "an Agent requires either a `passport` object or `model` + `operator`");
        return new D { ["model_id"] = model, ["operator"] = oper, ["hardware_rooted"] = AsBoolean(Get(body, "hardwareRooted")) ?? false, ["issued_at"] = new Num("0") };
    }

    static D ReadProjection(D body)
    {
        var owner = AsString(Get(body, "owner")) ?? AsString(Get(body, "operator")) ?? AsString(Get(AsRecord(Get(body, "passport")), "operator")) ?? "";
        var proj = new D { ["owner"] = owner };
        if (AsString(Get(body, "displayName")) is { } dn) proj["displayName"] = dn;
        if (AsString(Get(body, "externalId")) is { } ext) proj["externalId"] = ext;
        if (AsBoolean(Get(body, "active")) is { } act) proj["active"] = act;
        if (AsStringArray(Get(body, "capabilities")) is { } caps) proj["capabilities"] = caps;
        if (AsString(Get(body, "holder")) is { } h) proj["holder"] = h;
        return proj;
    }

    /// <summary>Distil a SCIM Agent write body into {identity, projection}. Throws <see cref="ScimValueException"/> on a malformed body.</summary>
    public static D ScimToProvisioningRequest(object? value)
    {
        var body = AsRecord(value) ?? throw new ScimValueException("invalidSyntax", "request body must be a JSON object");
        if (body.TryGetValue("schemas", out var schemas) && !(schemas is L sl && sl.Any(s => s as string == AgentSchemaUrn)))
            throw new ScimValueException("invalidValue", $"schemas must include {AgentSchemaUrn}");
        return new D { ["identity"] = ReadIdentity(body), ["projection"] = ReadProjection(body) };
    }

    // ---- envelopes ----

    public static D ScimError(int status, string detail, string? scimType = null)
    {
        var b = new D { ["schemas"] = new L { ErrorSchema }, ["status"] = status.ToString(CultureInfo.InvariantCulture), ["detail"] = detail };
        if (scimType != null) b["scimType"] = scimType;
        return b;
    }

    /// <summary>The same error with a scimType member as given, a null one included (only an absent argument leaves it out).</summary>
    public static D ScimErrorWith(int status, string detail, object? scimType)
    {
        var b = ScimError(status, detail);
        b["scimType"] = scimType;
        return b;
    }

    /// <summary>A ListResponse over an already-paginated page; the counts are JSON numbers.</summary>
    public static D ScimListResponse(L resources, object? totalResults, object? startIndex) => new()
    {
        ["schemas"] = new L { ListResponseSchema },
        ["totalResults"] = totalResults,
        ["startIndex"] = startIndex,
        ["itemsPerPage"] = new Num(resources.Count.ToString(CultureInfo.InvariantCulture)),
        ["Resources"] = resources,
    };

    // ---- filter ----

    static readonly HashSet<string> Filterable = new() { "userName", "displayName", "externalId", "id", "active", "owner" };

    static bool IsWord(char c) => c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '_';

    /// <summary>Parse the `attr eq "value"` / `attr eq true|false` subset (the reference's regex, by hand: ASCII \w, JavaScript \s). {attr, value}.</summary>
    public static D ParseFilter(object? filter)
    {
        if (filter is not string f) throw new ScimValueException("invalidFilter", "filter must be a string");
        var fail = new ScimValueException("invalidFilter", $"unsupported filter (only `attr eq \"value\"` is supported): {f}");
        int i = 0, n = f.Length;
        void Sp() { while (i < n && JsJson.IsJsSpace(f[i])) i++; }
        Sp();
        int a0 = i;
        while (i < n && IsWord(f[i])) i++;
        if (i == a0) throw fail;
        var attr = f[a0..i];
        int s1 = i; Sp(); if (i == s1) throw fail;
        if (i + 2 > n || !f.AsSpan(i, 2).Equals("eq", StringComparison.OrdinalIgnoreCase)) throw fail;
        i += 2;
        s1 = i; Sp(); if (i == s1) throw fail;
        object value;
        if (i < n && f[i] == '"')
        {
            int j = i + 1;
            var sb = new System.Text.StringBuilder();
            for (; ; )
            {
                if (j >= n) throw fail;
                var c = f[j];
                if (c == '"') break;
                if (c == '\\')
                {
                    if (j + 1 >= n || f[j + 1] is '\n' or '\r' or '\u2028' or '\u2029') throw fail;
                    sb.Append(f[j + 1]);
                    j += 2;
                }
                else { sb.Append(c); j++; }
            }
            i = j + 1;
            Sp();
            if (i != n) throw fail;
            if (!Filterable.Contains(attr)) throw new ScimValueException("invalidFilter", $"filter attribute not supported: {attr}");
            value = sb.ToString();
        }
        else
        {
            bool? lit = i + 4 <= n && f.AsSpan(i, 4).Equals("true", StringComparison.OrdinalIgnoreCase) ? (bool?)true
                : i + 5 <= n && f.AsSpan(i, 5).Equals("false", StringComparison.OrdinalIgnoreCase) ? (bool?)false : null;
            if (lit == null) throw fail;
            i += lit.Value ? 4 : 5;
            Sp();
            if (i != n) throw fail;
            if (!Filterable.Contains(attr)) throw new ScimValueException("invalidFilter", $"filter attribute not supported: {attr}");
            value = lit.Value;
        }
        return new D { ["attr"] = attr, ["value"] = value };
    }

    static bool MatchesFilter(D agent, D f)
    {
        var v = f["value"];
        return (string)f["attr"]! switch
        {
            "userName" or "displayName" => v is string s && agent.GetValueOrDefault("displayName") as string == s,
            "externalId" => v is string s2 && agent.GetValueOrDefault("externalId") as string == s2,
            "id" => v is string s3 && agent.GetValueOrDefault("id") as string == s3,
            "owner" => v is string s4 && agent.GetValueOrDefault("owner") as string == s4,
            "active" => v is bool b && agent.GetValueOrDefault("active") is bool ab && ab == b,
            _ => false,
        };
    }

    // ---- PATCH ----

    static readonly HashSet<string> MutablePaths = new() { "active", "displayName", "externalId", "owner", "capabilities", "holder" };

    sealed record PatchOp(string Op, string? Path, bool HasValue, object? Value);

    static List<PatchOp> ReadPatchOps(object? value)
    {
        var body = AsRecord(value) ?? throw new ScimValueException("invalidSyntax", "PATCH body must be a JSON object");
        if (Get(body, "Operations") is not L ops || ops.Count == 0) throw new ScimValueException("invalidValue", "PATCH requires a non-empty Operations array");
        var res = new List<PatchOp>();
        foreach (var raw in ops)
        {
            var o = AsRecord(raw);
            var op = AsString(Get(o, "op"))?.ToLowerInvariant();
            if (op is not ("add" or "replace" or "remove"))
                throw new ScimValueException("invalidValue", $"unsupported PATCH op: {(o != null && o.ContainsKey("op") ? JsJson.ToJsString(o["op"]) : "undefined")}");
            res.Add(new PatchOp(op, AsString(Get(o, "path")), o != null && o.ContainsKey("value"), Get(o, "value")));
        }
        return res;
    }

    static D ProjectionOf(D resource)
    {
        var proj = new D { ["owner"] = resource["owner"], ["active"] = resource["active"], ["capabilities"] = new L((L)resource["capabilities"]!) };
        if (resource.TryGetValue("displayName", out var dn)) proj["displayName"] = dn;
        if (resource.TryGetValue("externalId", out var ext)) proj["externalId"] = ext;
        if (resource.TryGetValue("holder", out var h)) proj["holder"] = h;
        return proj;
    }

    static void ApplyScalar(D proj, string path, string op, object? value)
    {
        if (path == "active")
        {
            if (op == "remove") { proj["active"] = true; return; }
            var b = AsBoolean(value) ?? throw new ScimValueException("invalidValue", "`active` must be a boolean");
            proj["active"] = b;
            return;
        }
        if (path == "capabilities")
        {
            if (op == "remove") { proj["capabilities"] = new L(); return; }
            var arr = AsStringArray(value) ?? throw new ScimValueException("invalidValue", "`capabilities` must be a string array");
            if (op == "add")
            {
                var merged = proj.GetValueOrDefault("capabilities") is L cur ? new L(cur) : new L();
                merged.AddRange(arr);
                proj["capabilities"] = merged;
            }
            else proj["capabilities"] = arr;
            return;
        }
        if (op == "remove")
        {
            if (path is "displayName" or "owner") throw new ScimValueException("mutability", $"`{path}` cannot be removed");
            // rebuilt without the key: the projection's key order must not depend on a Remove
            if (path is "externalId" or "holder")
            {
                var keep = proj.Where(e => e.Key != path).ToList();
                proj.Clear();
                foreach (var e in keep) proj[e.Key] = e.Value;
            }
            return;
        }
        var s = AsString(value) ?? throw new ScimValueException("invalidValue", $"`{path}` must be a string");
        proj[path] = s;
    }

    static void ApplyPatchOp(D proj, PatchOp op)
    {
        if (op.Path == null)
        {
            if (op.Op == "remove") throw new ScimValueException("noTarget", "a `remove` op requires a `path`");
            var obj = AsRecord(op.Value) ?? throw new ScimValueException("invalidValue", "a pathless PATCH value must be an object");
            foreach (var key in IntentJs.JsKeys(obj.Keys).ToList())
            {
                if (!MutablePaths.Contains(key)) throw new ScimValueException("mutability", $"attribute is immutable or unknown: {key}");
                ApplyScalar(proj, key, "replace", obj[key]);
            }
            return;
        }
        if (!MutablePaths.Contains(op.Path)) throw new ScimValueException("mutability", $"attribute is immutable or unknown: {op.Path}");
        ApplyScalar(proj, op.Path, op.Op, op.Value);
    }

    // ---- the handler ----

    static ScimResponse Json(int status, object? body, Dictionary<string, string>? extra = null)
    {
        var h = new Dictionary<string, string> { ["content-type"] = ScimContentType };
        if (extra != null) foreach (var e in extra) h[e.Key] = e.Value;
        return new ScimResponse(status, body, true, h);
    }

    static ScimResponse Err(int status, string detail, string? scimType = null) => Json(status, ScimError(status, detail, scimType));

    static ScimResponse ResourceResponse(int status, D resource)
    {
        var meta = (D)resource["meta"]!;
        return Json(status, resource, new() { ["location"] = (string)meta["location"]!, ["etag"] = (string)meta["version"]! });
    }

    static double ParseIntParam(bool present, object? v, double fallback)
    {
        if (!present) return fallback;
        var n = JsJson.ToJsNumber(v);
        return double.IsFinite(n) && n == Math.Floor(n) ? n : fallback;
    }

    static Num NumOf(double d) => new(d == Math.Floor(d) && Math.Abs(d) < 1e21 ? new System.Numerics.BigInteger(d).ToString(CultureInfo.InvariantCulture) : JsJson.NumberToString(d));

    static L Slice(IReadOnlyList<D> items, double start, double? end)
    {
        double len = items.Count;
        var s = Math.Min(Math.Max(start, 0), len);
        var e = end == null ? len : Math.Min(Math.Max(end.Value, 0), len);
        var o = new L();
        for (var k = (int)s; k < (int)e; k++) o.Add(items[k]);
        return o;
    }

    /// <summary>Build a SCIM 2.0 /Agents handler over a store: GET (list, `eq` filter, pagination, by id), POST, PUT, PATCH, DELETE. A request is {method, id?, query?, body?}.</summary>
    public static Func<D, ScimResponse> ScimHandler(IAgentStore store, ScimHandlerOptions? options = null)
    {
        options ??= new ScimHandlerOptions();
        var authenticate = options.Authenticate;
        if (authenticate == null && !options.AllowUnauthenticated)
            throw new ArgumentException("scimHandler: `authenticate` is required (or pass allowUnauthenticated: true explicitly)");
        MetaInput MetaInputOf() => new() { BaseUrl = options.BaseUrl, Now = options.Now };

        ScimResponse HandleList(object? queryObj)
        {
            var q = queryObj as D;
            IReadOnlyList<D> items = store.All().Select(s => s.Resource).ToList();
            if (q != null && q.TryGetValue("filter", out var filter) && !(filter is string fs && fs.Length == 0))
            {
                D parsed;
                try { parsed = ParseFilter(filter); }
                catch (ScimValueException e) { return Err(400, e.Message, e.ScimType); }
                items = items.Where(a => MatchesFilter(a, parsed)).ToList();
            }
            double total = items.Count;
            var startIndex = Math.Max(1, ParseIntParam(q != null && q.ContainsKey("startIndex"), Get(q, "startIndex"), 1));
            double? count = q != null && q.ContainsKey("count") ? Math.Max(0, ParseIntParam(true, q["count"], total)) : null;
            var page = Slice(items, startIndex - 1, count == null ? null : startIndex - 1 + count.Value);
            return Json(200, ScimListResponse(page, NumOf(total), NumOf(startIndex)));
        }

        ScimResponse HandleCreate(object? body)
        {
            D req;
            try { req = ScimToProvisioningRequest(body); }
            catch (ScimValueException e) { return Err(400, e.Message, e.ScimType); }
            var passport = IssuePassport((D)req["identity"]!);
            var pid = (string)passport["id"]!;
            if (store.Get(pid) != null) return Err(409, $"an agent with this attested identity already exists (id {pid})", "uniqueness");
            var resource = PassportToScim(passport, (D)req["projection"]!, MetaInputOf());
            store.Put(new StoredAgent(resource, passport));
            return ResourceResponse(201, resource);
        }

        D Rematerialize(StoredAgent existing, D proj)
        {
            var meta = MetaInputOf();
            meta.Created = (string)((D)existing.Resource["meta"]!)["created"]!;
            return PassportToScim(existing.Passport, proj, meta);
        }

        ScimResponse HandleReplace(object? id, object? body)
        {
            var existing = id is string s ? store.Get(s) : null;
            if (existing == null) return Err(404, $"Agent {JsJson.ToJsString(id)} not found");
            var body0 = AsRecord(body);
            if (body0 == null) return Err(400, "request body must be a JSON object", "invalidSyntax");
            var proj = ReadProjection(body0);
            if (proj["owner"] as string == "") proj["owner"] = existing.Resource["owner"];
            var resource = Rematerialize(existing, proj);
            store.Put(new StoredAgent(resource, existing.Passport));
            return ResourceResponse(200, resource);
        }

        ScimResponse HandlePatch(object? id, object? body)
        {
            var existing = id is string s ? store.Get(s) : null;
            if (existing == null) return Err(404, $"Agent {JsJson.ToJsString(id)} not found");
            var proj = ProjectionOf(existing.Resource);
            try
            {
                var ops = ReadPatchOps(body);
                foreach (var op in ops) ApplyPatchOp(proj, op);
            }
            catch (ScimValueException e) { return Err(400, e.Message, e.ScimType); }
            var resource = Rematerialize(existing, proj);
            store.Put(new StoredAgent(resource, existing.Passport));
            return ResourceResponse(200, resource);
        }

        ScimResponse HandleDelete(object? id)
        {
            if (!(id is string s && store.Delete(s))) return Err(404, $"Agent {JsJson.ToJsString(id)} not found");
            return new ScimResponse(204, null, false, new Dictionary<string, string>());
        }

        ScimResponse HandleGetOne(object? id)
        {
            var existing = id is string s ? store.Get(s) : null;
            return existing == null ? Err(404, $"Agent {JsJson.ToJsString(id)} not found") : ResourceResponse(200, existing.Resource);
        }

        return req =>
        {
            if (authenticate != null)
            {
                var ok = false;
                try { ok = authenticate(req) is true; } catch (Exception) { ok = false; }
                if (!ok)
                {
                    var e = Err(401, "authentication required");
                    return e with { Headers = new Dictionary<string, string> { ["content-type"] = ScimContentType, ["www-authenticate"] = "Bearer" } };
                }
            }
            var hasId = req.TryGetValue("id", out var id);
            var query = Get(req, "query");
            var body = Get(req, "body");
            var method = req.TryGetValue("method", out var m) ? m as string : null;
            switch (method)
            {
                case "GET": return !hasId ? HandleList(query) : HandleGetOne(id);
                case "POST":
                    if (hasId) return Err(405, "POST is not allowed on an individual Agent");
                    return HandleCreate(body);
                case "PUT":
                    if (!hasId) return Err(405, "PUT requires an Agent id");
                    return HandleReplace(id, body);
                case "PATCH":
                    if (!hasId) return Err(405, "PATCH requires an Agent id");
                    return HandlePatch(id, body);
                case "DELETE":
                    if (!hasId) return Err(405, "DELETE requires an Agent id");
                    return HandleDelete(id);
                default:
                    return Err(405, $"method not allowed: {(req.TryGetValue("method", out var mv) ? JsJson.ToJsString(mv) : "undefined")}");
            }
        };
    }

    // ---- push adapters ----

    static D ExtensionAttributes(D agent)
    {
        var p = (D)agent["passport"]!;
        var a = new D { ["owner"] = agent.GetValueOrDefault("owner") };
        a["model"] = p.GetValueOrDefault("model_id");
        a["operator"] = p.GetValueOrDefault("operator");
        a["hardwareRooted"] = p.GetValueOrDefault("hardware_rooted");
        a["capabilities"] = new L((L)agent["capabilities"]!);
        a["passportRef"] = agent.GetValueOrDefault("passportRef");
        if (agent.TryGetValue("holder", out var h)) a["holder"] = h;
        return a;
    }

    /// <summary>The outbound body for Microsoft Entra Agent ID.</summary>
    public static D ToEntraAgentPayload(D agent) => new()
    {
        ["schemas"] = new L { AgentSchemaUrn, EntraAgentExtensionUrn },
        ["externalId"] = agent.GetValueOrDefault("externalId") ?? agent.GetValueOrDefault("passportRef"),
        ["displayName"] = agent.GetValueOrDefault("displayName"),
        ["active"] = agent.GetValueOrDefault("active"),
        [EntraAgentExtensionUrn] = ExtensionAttributes(agent),
    };

    /// <summary>The outbound body for Okta (User-shaped with a custom agent extension).</summary>
    public static D ToOktaScimPayload(D agent) => new()
    {
        ["schemas"] = new L { AgentSchemaUrn, OktaAgentExtensionUrn },
        ["userName"] = agent.GetValueOrDefault("passportRef"),
        ["externalId"] = agent.GetValueOrDefault("externalId") ?? agent.GetValueOrDefault("passportRef"),
        ["displayName"] = agent.GetValueOrDefault("displayName"),
        ["active"] = agent.GetValueOrDefault("active"),
        [OktaAgentExtensionUrn] = ExtensionAttributes(agent),
    };

    public sealed record PushInit(string Method, IReadOnlyDictionary<string, string> Headers, string Body);
    /// <summary>The reply of an injected fetch; <c>Json</c> reads the body (and may throw).</summary>
    public sealed record PushReply(bool Ok, int Status, Func<Task<object?>> Json);
    public delegate Task<PushReply> FetchLike(string url, PushInit init);
    public sealed class PushTarget
    {
        public string Endpoint { get; set; } = "";
        public string Token { get; set; } = "";
        public FetchLike? Fetch { get; set; }
    }
    public sealed record PushResult(bool Ok, int Status, object? Body);

    static readonly HttpClient DefaultHttp = new();

    static async Task<PushReply> DefaultFetch(string url, PushInit init)
    {
        using var req = new HttpRequestMessage(new HttpMethod(init.Method), url);
        foreach (var h in init.Headers) if (!h.Key.Equals("content-type", StringComparison.OrdinalIgnoreCase)) req.Headers.TryAddWithoutValidation(h.Key, h.Value);
        req.Content = new StringContent(init.Body, System.Text.Encoding.UTF8, ScimContentType);
        var res = await DefaultHttp.SendAsync(req).ConfigureAwait(false);
        var text = await res.Content.ReadAsStringAsync().ConfigureAwait(false);
        return new PushReply(res.IsSuccessStatusCode, (int)res.StatusCode, () => Task.FromResult(Pca.ParseJson(text)));
    }

    /// <summary>POST an already-shaped provisioning payload to a directory endpoint (injectable fetch).</summary>
    public static async Task<PushResult> PushProvision(D payload, PushTarget target)
    {
        var f = target.Fetch ?? new FetchLike(DefaultFetch);
        var res = await f(target.Endpoint, new PushInit("POST",
            new Dictionary<string, string> { ["authorization"] = $"Bearer {target.Token}", ["content-type"] = ScimContentType }, JsJson.Stringify(payload))).ConfigureAwait(false);
        object? body;
        try { body = await res.Json().ConfigureAwait(false); } catch (Exception) { body = null; }
        return new PushResult(res.Ok, res.Status, body);
    }

    public static Task<PushResult> PushToEntra(D agent, PushTarget target) => PushProvision(ToEntraAgentPayload(agent), target);
    public static Task<PushResult> PushToOkta(D agent, PushTarget target) => PushProvision(ToOktaScimPayload(agent), target);
}
