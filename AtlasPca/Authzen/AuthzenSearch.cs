using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Authzen;

/// <summary>The host-supplied search provider: each function takes the (id-stripped) request and returns {results, page?, context?}.</summary>
public sealed class AuthzenSearchProvider
{
    public Func<D, Task<D>>? SearchSubject { get; init; }
    public Func<D, Task<D>>? SearchResource { get; init; }
    public Func<D, Task<D>>? SearchAction { get; init; }
}

/// <summary>AuthZEN 1.0 Search APIs (subject, resource, action): the member table per search type, page handling, the entity-type contract of results and fail-closed error mapping.</summary>
public static class AuthzenSearch
{
    public const string SearchSubjectPath = "/access/v1/search/subject";
    public const string SearchResourcePath = "/access/v1/search/resource";
    public const string SearchActionPath = "/access/v1/search/action";
    public const int MaxSearchLimit = 1000;

    static bool IsRec(object? x) => x is D;
    static object? G(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : Jx.Undef;
    static bool Str(object? x) => x is string s && s.Length > 0;
    static bool Entity(object? x, bool needId) => IsRec(x) && Str(G(x, "type")) && (!needId || Str(G(x, "id"))) && (Jx.IsUndef(G(x, "properties")) || IsRec(G(x, "properties")));
    static bool ActionOk(object? x) => IsRec(x) && Str(G(x, "name")) && (Jx.IsUndef(G(x, "properties")) || IsRec(G(x, "properties")));

    static bool PageOk(object? p)
    {
        if (Jx.IsUndef(p)) return true;
        if (!IsRec(p)) return false;
        var token = G(p, "token");
        if (!Jx.IsUndef(token) && token is not string) return false;
        var limit = G(p, "limit");
        if (!Jx.IsUndef(limit) && !(Jx.IsNum(limit) && JsX.SafeInt(limit) && IntentJs.NumOf(limit)!.Value >= 0 && !IntentJs.IsNegZero(IntentJs.NumOf(limit)!.Value))) return false;
        var props = G(p, "properties");
        return Jx.IsUndef(props) || IsRec(props);
    }

    static bool Base(object? b) => IsRec(b) && (Jx.IsUndef(G(b, "context")) || IsRec(G(b, "context"))) && PageOk(G(b, "page"));

    public static bool IsSubjectSearch(object? b) => IsRec(b) && Base(b) && Entity(G(b, "subject"), false) && ActionOk(G(b, "action")) && Entity(G(b, "resource"), true);
    public static bool IsResourceSearch(object? b) => IsRec(b) && Base(b) && Entity(G(b, "subject"), true) && ActionOk(G(b, "action")) && Entity(G(b, "resource"), false);
    public static bool IsActionSearch(object? b) => IsRec(b) && Base(b) && !((D)b!).ContainsKey("action") && Entity(G(b, "subject"), true) && Entity(G(b, "resource"), true);

    static D StripId(D req, string key)
    {
        var e = JsX.Spread(G(req, key)); e.Remove("id");
        var o = JsX.Spread(req); o[key] = e;
        return o;
    }

    static D Shape(D r, double? limit, Func<object?, bool> typeOk)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        if (G(r, "results") is not L list) throw JsX.TypeError("results.filter is not a function");
        var results = new L();
        foreach (var t in list)
        {
            var k = JsJson.Stringify(t);
            if (!typeOk(t) || !seen.Add(k)) continue;
            results.Add(t);
        }
        var capped = limit != null && limit > 0 ? new L(results.Take((int)Math.Min(limit.Value, int.MaxValue))) : results;
        if (capped.Count < results.Count) throw new InvalidOperationException("provider returned more than the page limit");
        var o = new D();
        var rp = G(r, "page");
        if (Jx.Truthy(rp))
        {
            var page = new D(); Jx.Set(page, "next_token", Jx.Prop(rp, "next_token")); page["count"] = Jx.N(capped.Count);
            var total = Jx.Prop(rp, "total"); if (!Jx.IsUndef(total)) page["total"] = total;
            var props = Jx.Prop(rp, "properties"); if (Jx.Truthy(props)) page["properties"] = props;
            o["page"] = page;
        }
        var ctx = G(r, "context"); if (Jx.Truthy(ctx)) o["context"] = ctx;
        o["results"] = capped;
        return o;
    }

    static D Res(int status, object? body) => new() { ["status"] = Jx.N(status), ["body"] = body };
    static D Err(int status, string msg) => Res(status, new D { ["error"] = msg });

    /// <summary>searchMetadata: the discovery fragment (a missing endpoint means that search is unsupported).</summary>
    public static D SearchMetadata(string baseUrl, AuthzenSearchProvider p)
    {
        var o = new D();
        if (p.SearchSubject != null) o["search_subject_endpoint"] = baseUrl + SearchSubjectPath;
        if (p.SearchResource != null) o["search_resource_endpoint"] = baseUrl + SearchResourcePath;
        if (p.SearchAction != null) o["search_action_endpoint"] = baseUrl + SearchActionPath;
        return o;
    }

    /// <summary>The search handler: returns null for a path that is not a search path (so it chains after the evaluation handler).</summary>
    public static async Task<D?> Handle(AuthzenSearchProvider p, D req)
    {
        try
        {
            var body = G(req, "body");
            var limitO = G(G(body, "page"), "limit");
            double? limit = Jx.IsUndef(limitO) ? null : IntentJs.NumOf(limitO);
            switch (G(req, "path") as string)
            {
                case SearchSubjectPath:
                {
                    if (p.SearchSubject == null) return Err(404, "subject search is not supported");
                    if (!IsSubjectSearch(body)) return Err(400, "invalid AuthZEN subject search request");
                    var type = G(G(body, "subject"), "type");
                    var r = await p.SearchSubject(StripId((D)body!, "subject")).ConfigureAwait(false);
                    return Res(200, Shape(r, limit, e => JsX.StrictEq(Jx.Prop(e, "type"), type)));
                }
                case SearchResourcePath:
                {
                    if (p.SearchResource == null) return Err(404, "resource search is not supported");
                    if (!IsResourceSearch(body)) return Err(400, "invalid AuthZEN resource search request");
                    var type = G(G(body, "resource"), "type");
                    var r = await p.SearchResource(StripId((D)body!, "resource")).ConfigureAwait(false);
                    return Res(200, Shape(r, limit, e => JsX.StrictEq(Jx.Prop(e, "type"), type)));
                }
                case SearchActionPath:
                {
                    if (p.SearchAction == null) return Err(404, "action search is not supported");
                    if (!IsActionSearch(body)) return Err(400, "invalid AuthZEN action search request");
                    var r = await p.SearchAction((D)body!).ConfigureAwait(false);
                    return Res(200, Shape(r, limit, _ => true));
                }
                default:
                    return null;
            }
        }
        catch (Exception) { return Err(500, "internal error"); }
    }
}
