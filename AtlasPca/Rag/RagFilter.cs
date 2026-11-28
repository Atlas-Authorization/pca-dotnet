// FGA for RAG: retrieval-time, per-principal document filtering driven by the PCA policy evaluator (the pure core of the reference pca-rag package).
//
// FAIL CLOSED: a document is admitted only when a permit predicate cleanly matches one of its ACL entries (verb = relation, resource = object)
// and no deny predicate matches. Anything unknown (no ACL, a malformed document, an incomplete policy translation, an evaluator error) drops
// the document. Every decision is recorded (Result.Decision), with a content digest of the whole decision set.
//
// JSON values are the core's: Dictionary<string, object?>, List<object?>, string, bool, Num / long. A principal is a string id or a map
// {id, attributes?, env?}. A policy is a list of predicates, a map {openfga: {model, tuples}}, a map {predicates, denies?, report?} or an
// already-compiled policy (CompilePolicy).
using System.Globalization;
using AtlasPca.PolicyBridgeKit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Rag;

public static class RagFilter
{
    /// <summary>The admitted documents (candidate order) and the decision record (the proof trace).</summary>
    public sealed record Result<T>(List<T> Documents, D Decision);

    static D? Map(object? o) => o as D;
    static D Obj(params object?[] kv) { var m = new D(); for (int i = 0; i < kv.Length; i += 2) m[(string)kv[i]!] = kv[i + 1]; return m; }
    static bool NonEmpty(object? o) => o is string s && s.Length > 0;

    // ---- documents and ACLs ----

    static bool IsDocAcl(object? v) => v is D m && NonEmpty(m.GetValueOrDefault("relation")) && NonEmpty(m.GetValueOrDefault("object"));

    static L AclArray(object? acl)
    {
        var o = new L();
        if (acl is L l) { foreach (var a in l) if (IsDocAcl(a)) o.Add(a); }
        else if (IsDocAcl(acl)) o.Add(acl);
        return o;
    }

    // a relation:object tag as an ACL entry; the split is at the FIRST colon, so an object id may contain colons
    static D? TagToAcl(object? tag)
    {
        if (tag is not string t) return null;
        var i = t.IndexOf(':');
        if (i <= 0 || i >= t.Length - 1) return null;
        return Obj("relation", t[..i], "object", t[(i + 1)..]);
    }

    /// <summary>ACL entries from freeform <c>acl</c> (one entry or a list) and <c>tags</c> (<c>relation:object</c> strings) metadata.</summary>
    public static L AclsFromMetadata(object? acl, object? tags)
    {
        var o = AclArray(acl);
        if (tags is L tl) foreach (var t in tl) if (TagToAcl(t) is { } a) o.Add(a);
        return o;
    }

    // ---- principal ----

    /// <summary>The acting identity of a verified PCActn: its LEAF capability holder (map the key to your policy's identity with <c>opts["id"]</c>).
    /// Throws on a PCActn with no capability chain rather than producing an empty principal. opts: {id?, attributes?, env?}, may be null.</summary>
    public static D PrincipalFromPCActn(object? pcactn, D? opts = null)
    {
        object? holder = null;
        if (Map(pcactn)?.GetValueOrDefault("cap_chain") is L { Count: > 0 } chain && Map(chain[^1]) is { } leaf) holder = leaf.GetValueOrDefault("holder");
        if (!NonEmpty(holder)) throw new ArgumentException("principalFromPCActn: PCActn has no leaf capability holder");
        var o = new D { ["id"] = opts?.GetValueOrDefault("id") ?? holder };
        if (opts != null && opts.ContainsKey("attributes")) o["attributes"] = opts["attributes"];
        if (opts != null && opts.ContainsKey("env")) o["env"] = opts["env"];
        return o;
    }

    static D? ToPrincipal(object? p) => p switch
    {
        string s => Obj("id", s),
        D m => m,
        L => new D(), // a JavaScript array is an object with no id
        _ => null,
    };

    // ---- policy compilation ----

    static D Incomplete(string reason) => Obj("predicates", new L(), "denies", new L(), "incomplete", true, "incompleteReason", reason);

    /// <summary>Compile any policy into <c>{predicates, denies, incomplete, incompleteReason?, report?}</c> (an already-compiled policy passes through).
    /// A value that is not a policy, or a translation with errors, is INCOMPLETE: nothing is admitted.</summary>
    public static D CompilePolicy(object? policy)
    {
        if (policy is not D && policy is not L) return Incomplete("no usable policy was supplied (fail closed)");
        if (policy is L) return Obj("predicates", policy, "denies", new L(), "incomplete", false);
        var p = (D)policy;
        if (p.GetValueOrDefault("incomplete") is bool) return p;
        if (!p.ContainsKey("openfga") && p.GetValueOrDefault("predicates") is not L) return Incomplete("the policy has no predicates and is not an OpenFGA policy (fail closed)");
        if (p.ContainsKey("openfga"))
        {
            var raw = p["openfga"];
            if (raw is not D && raw is not L) return Incomplete("the OpenFGA policy has no model (fail closed)");
            var f = raw as D ?? new D(); // an array has no model or tuples
            var br = f.ContainsKey("tuples") ? OpenFga.OpenfgaToPca(f.GetValueOrDefault("model"), f["tuples"]) : OpenFga.OpenfgaToPca(f.GetValueOrDefault("model"));
            var rep = Map(br.GetValueOrDefault("report"));
            return Obj("predicates", br["predicates"], "denies", br["denies"], "report", rep, "incomplete", rep?.GetValueOrDefault("errors") is L { Count: > 0 });
        }
        var denies = p.GetValueOrDefault("denies") is L dl ? dl : new L();
        var o = Obj("predicates", p["predicates"], "denies", denies);
        if (p.ContainsKey("report"))
        {
            // the reference reads report.errors.length: a report without errors throws
            if (Map(p["report"]) is not { } report || report.GetValueOrDefault("errors") == null) throw new ArgumentException("compilePolicy: report.errors is required");
            o["report"] = report;
            o["incomplete"] = LengthPositive(report["errors"]);
        }
        else o["incomplete"] = false;
        return o;
    }

    // JavaScript x.length > 0 for a JSON value that is not null
    static bool LengthPositive(object? x) => x switch
    {
        L l => l.Count > 0,
        string s => s.Length > 0,
        D m => m.GetValueOrDefault("length") is Num n && double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && d > 0,
        _ => false,
    };

    // ---- the filter ----

    static D DecideDocument(string id, L acls, D principal, D compiled)
    {
        if (compiled.GetValueOrDefault("incomplete") is true)
            return Obj("id", id, "allowed", false, "reason", compiled.GetValueOrDefault("incompleteReason") is string why ? why : "policy translation incomplete (fail closed)");
        var pid = principal.GetValueOrDefault("id");
        if (!NonEmpty(pid)) return Obj("id", id, "allowed", false, "reason", "no principal identity (fail closed)");
        if (acls.Count == 0) return Obj("id", id, "allowed", false, "reason", "no decidable ACL metadata (fail closed)");
        var last = "no relation grants access (fail closed)";
        var pol = Obj("predicates", compiled.GetValueOrDefault("predicates"), "denies", compiled.GetValueOrDefault("denies"));
        foreach (var a in acls)
        {
            var acl = (D)a!;
            D res;
            try { res = PolicyBridge.Decide(pol, Context(principal, acl)); }
            catch (Exception) { last = "evaluator error (fail closed)"; continue; }
            if (res.GetValueOrDefault("allowed") is true)
            {
                var d = Obj("id", id, "allowed", true, "via", acl, "reason", $"granted: {pid} has {acl["relation"]} on {acl["object"]}");
                if (res.GetValueOrDefault("matched") != null) d["matched"] = res["matched"];
                return d;
            }
            if (res.GetValueOrDefault("reason") is string r) last = r;
        }
        return Obj("id", id, "allowed", false, "reason", last);
    }

    // the evaluation context for ONE ACL entry: the subject is the principal's attributes plus its id
    static D Context(D principal, D acl)
    {
        var subject = new D();
        switch (principal.GetValueOrDefault("attributes"))
        {
            case D m: foreach (var (k, v) in m) subject[k] = v; break;
            case L l: for (int i = 0; i < l.Count; i++) subject[i.ToString(CultureInfo.InvariantCulture)] = l[i]; break; // object spread of an array
            case string s: for (int i = 0; i < s.Length; i++) subject[i.ToString(CultureInfo.InvariantCulture)] = s[i].ToString(); break;
        }
        subject["id"] = principal.GetValueOrDefault("id");
        var ctx = Obj("action", Obj("verb", acl["relation"], "resource", acl["object"]), "subject", subject);
        if (principal.ContainsKey("env")) ctx["env"] = principal["env"];
        return ctx;
    }

    /// <summary>The generic filter. <paramref name="id"/> and <paramref name="acls"/> read a candidate's id (null or empty: positional <c>doc#i</c>) and its ACL
    /// entries (anything that is not a list or entry yields none); either throwing marks the document unreadable and drops it.</summary>
    public static Result<T> Filter<T>(object? principalInput, IReadOnlyList<T>? candidates, object? policy, Func<T, int, object?> id, Func<T, object?> acls)
    {
        var principal = ToPrincipal(principalInput) ?? Obj("id", "");
        var compiled = CompilePolicy(policy);
        var list = candidates ?? new List<T>();
        var documents = new List<T>();
        L decisions = new(), allowedIds = new(), droppedIds = new(), allowedIndexes = new();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < list.Count; i++)
        {
            var doc = list[i];
            object? rawId; L docAcls;
            try { rawId = id(doc, i); docAcls = AclArray(acls(doc)); }
            catch (Exception)
            {
                var fid = "doc#" + i; // metadata that cannot even be read is unknown: fail closed
                decisions.Add(Obj("id", fid, "allowed", false, "reason", "unreadable document metadata (fail closed)"));
                droppedIds.Add(fid);
                continue;
            }
            var docId = NonEmpty(rawId) ? (string)rawId! : "doc#" + i;
            if (seen.Contains(docId)) docId = docId + "#dup" + i; // two candidates with one id must stay distinguishable
            seen.Add(docId);
            var d = DecideDocument(docId, docAcls, principal, compiled);
            decisions.Add(d);
            if (d["allowed"] is true) { documents.Add(doc); allowedIds.Add(docId); allowedIndexes.Add((long)i); }
            else droppedIds.Add(docId);
        }
        var pid = principal.GetValueOrDefault("id");
        var core = Obj("principal", pid is string ps ? ps : "", "considered", (long)list.Count, "allowedIds", allowedIds, "allowedIndexes", allowedIndexes,
            "droppedIds", droppedIds, "policyIncomplete", compiled.GetValueOrDefault("incomplete") is true);
        var hashed = Obj("v", 1L, "kind", "pca-rag/filter");
        foreach (var (k, v) in core) hashed[k] = v;
        var decision = new D(core) { ["decisions"] = decisions, ["digest"] = Pca.HashCanonical(hashed) };
        if (compiled.GetValueOrDefault("report") != null) decision["report"] = compiled["report"];
        return new Result<T>(documents, decision);
    }

    // a JSON document read like a JavaScript object: null throws, any other non-map has no members
    static D Doc(object? d) => d switch { null => throw new ArgumentException("null document"), D m => m, _ => new D() };

    /// <summary>Filter JSON documents (<c>{id, acl?, tags?}</c> maps) with the default readers. A null document is unreadable (dropped).</summary>
    public static Result<object?> FilterDocuments(object? principal, object? candidates, object? policy) =>
        Filter<object?>(principal, candidates as L, policy, (d, _) => Doc(d).GetValueOrDefault("id"), d => AclsFromMetadata(Doc(d).GetValueOrDefault("acl"), Doc(d).GetValueOrDefault("tags")));

    // ---- a retriever whose results are filtered before they reach the model ----

    /// <summary>A retriever whose results are PCA-filtered: every result set is cut to what the principal may see BEFORE it reaches the model, and the decision of the most
    /// recent retrieval is kept for audit (the proof trace).</summary>
    public sealed class FilteredRetriever<T>
    {
        readonly Func<string, int?, Task<IReadOnlyList<T>?>> _retrieve;
        readonly object? _principal;
        readonly D _compiled;
        readonly Func<T, int, object?> _id;
        readonly Func<T, object?> _acls;
        readonly ProvenanceRecorder? _recorder;
        D? _last;

        internal FilteredRetriever(Func<string, int?, Task<IReadOnlyList<T>?>> retrieve, object? principal, D compiled, Func<T, int, object?> id, Func<T, object?> acls, ProvenanceRecorder? recorder)
        {
            _retrieve = retrieve; _principal = principal; _compiled = compiled; _id = id; _acls = acls; _recorder = recorder;
        }

        /// <summary>The admitted documents for <paramref name="query"/> (a retriever that returns nothing yields none). The documents the model will see are recorded as untrusted retrieval content.</summary>
        public async Task<List<T>> Retrieve(string query, int? k = null)
        {
            var docs = await _retrieve(query, k).ConfigureAwait(false);
            var res = Filter(_principal, docs ?? new List<T>(), _compiled, _id, _acls);
            _last = res.Decision;
            if (_recorder != null)
                for (var i = 0; i < res.Documents.Count; i++)
                {
                    object? src;
                    try { src = _id(res.Documents[i], i); } catch (Exception) { src = null; }
                    _recorder.Retrieval(src as string ?? (src == null ? "doc#" + i : Convert.ToString(src, CultureInfo.InvariantCulture)!), res.Documents[i]);
                }
            return res.Documents;
        }

        /// <summary>The decision of the most recent <see cref="Retrieve"/>, or null before the first.</summary>
        public D? LastDecision() => _last;
    }

    /// <summary>Wrap a retriever so every result set is filtered to what <paramref name="principal"/> may see BEFORE it reaches the model. <paramref name="id"/> and
    /// <paramref name="acls"/> read a document's id and ACL entries as in <see cref="Filter{T}"/>; <paramref name="recorder"/>, when given, records every admitted document as untrusted retrieval content.</summary>
    public static FilteredRetriever<T> WithPcaFilter<T>(Func<string, int?, Task<IReadOnlyList<T>?>> retriever, object? principal, object? policy, Func<T, int, object?> id, Func<T, object?> acls, ProvenanceRecorder? recorder = null) =>
        new(retriever, principal, CompilePolicy(policy), id, acls, recorder);

    /// <summary>The same over JSON documents (<c>{id, acl?, tags?}</c> maps) with the default readers.</summary>
    public static FilteredRetriever<object?> WithPcaFilter(Func<string, int?, Task<IReadOnlyList<object?>?>> retriever, object? principal, object? policy, ProvenanceRecorder? recorder = null) =>
        new(retriever, principal, CompilePolicy(policy), (d, _) => Doc(d).GetValueOrDefault("id"), d => AclsFromMetadata(Doc(d).GetValueOrDefault("acl"), Doc(d).GetValueOrDefault("tags")), recorder);
}
