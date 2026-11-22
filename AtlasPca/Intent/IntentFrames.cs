// Frame and side-effect constraints: the monitored state of a site, a per-verb write set, and postconditions over the pre- and post-state and the
// site's effect record. By default intent is frame-closed: a monitored variable outside the write set must not change unless the site's log
// attributes the change to another actor. A violation is a negative runtime observation (it vetoes the cell). Specs, snapshots and reports are
// JSON trees.
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentFrames
{
    public const string FrameStateDomain = "atlas-pca/intent-frame-state/v1";

    /// <summary>Digest of a state value (site-local: the lenient canonical form; an absent value is null).</summary>
    public static string StateDigest(object? value)
    {
        var m = new D { ["d"] = FrameStateDomain, ["v"] = value };
        var text = JsCanon.Lenient(IntentJs.Normalize(m)) ?? throw new ArgumentException("stateDigest: value is not canonicalizable");
        return Pca.B64u(Pca.Sha(System.Text.Encoding.UTF8.GetBytes(text)));
    }

    /// <summary>Snapshot already-read values: variable to {digest, value?}.</summary>
    public static D SnapshotState(D values, bool keepValues = true)
    {
        var o = new D();
        foreach (var (k, v) in values)
        {
            var s = new D { ["digest"] = StateDigest(v) };
            if (keepValues) s["value"] = v;
            o[k] = s;
        }
        return o;
    }

    /// <summary>Read every monitored variable through its reader (sorted by name) and snapshot it: the middleware hook, called before and after the action.</summary>
    public static D CaptureState(IReadOnlyDictionary<string, Func<object?>> readers, bool keepValues = true)
    {
        var values = new D();
        foreach (var k in IntentJs.SortedUtf8(readers.Keys)) values[k] = readers[k]();
        return SnapshotState(values, keepValues);
    }

    static readonly Regex IndexRe = new(@"^(?:0|[1-9][0-9]{0,8})\z", RegexOptions.CultureInvariant);

    static bool Walk(object? root, string path, out object? found)
    {
        var cur = root;
        foreach (var s in path.Split('.'))
        {
            if (cur is D m)
            {
                if (!m.TryGetValue(s, out var next)) { found = null; return false; }
                cur = next;
            }
            else if (cur is L l && IndexRe.IsMatch(s) && int.Parse(s, System.Globalization.CultureInfo.InvariantCulture) < l.Count) cur = l[int.Parse(s, System.Globalization.CultureInfo.InvariantCulture)];
            else { found = null; return false; }
        }
        found = cur;
        return true;
    }

    static object? Get(object? root, string path) => Walk(root, path, out var f) ? f : null;
    static bool Present(object? root, string path) => Walk(root, path, out _);

    static bool Eq(object? a, object? b) => (a == null && b == null) || (a != null && b != null && IntentJs.JsonEquals(a, b));

    /// <summary>W(action): the declared write list, or the parameter-selected list (an unknown parameter value: the default, else empty).</summary>
    public static List<string> WriteSetOf(D spec, D action)
    {
        var writes = Obj(spec.GetValueOrDefault("writes"));
        var verb = action.GetValueOrDefault("verb");
        var d = verb is string vs && writes.ContainsKey(vs) ? writes[vs] : null;
        var o = new List<string>();
        if (d == null) return o;
        if (d is L dl) { foreach (var x in dl) o.Add((string)x!); return o; }
        var dm = Obj(d);
        var param = (string)dm["param"]!;
        var v = Get(action.GetValueOrDefault("params") ?? new D(), param.StartsWith("action.params.", StringComparison.Ordinal) ? param.Substring("action.params.".Length) : param);
        string? key = v is string sv ? sv : v is bool bv ? (bv ? "true" : "false") : IsNum(v) ? JsX.JsNumString(Dbl(v)) : null;
        var map = Obj(dm.GetValueOrDefault("map"));
        var chosen = key != null && map.ContainsKey(key) ? map[key] : dm.GetValueOrDefault("default");
        if (chosen != null) foreach (var x in Arr(chosen)) o.Add((string)x!);
        return o;
    }

    static void EnvReads(object? c, List<string> o)
    {
        if (c is not D m) return;
        if (m.ContainsKey("all_of") || m.ContainsKey("any_of") || m.ContainsKey("not"))
        {
            if (m.ContainsKey("all_of") && m["all_of"] is L a) foreach (var x in a) EnvReads(x, o);
            else if (m.ContainsKey("any_of") && m["any_of"] is L b) foreach (var x in b) EnvReads(x, o);
            else if (m.ContainsKey("not")) EnvReads(m["not"], o);
            return;
        }
        if (m.GetValueOrDefault("field") is string f)
        {
            if (f.StartsWith("env.", StringComparison.Ordinal)) o.Add(f);
            if (m.GetValueOrDefault("ref") is string r && r.StartsWith("env.", StringComparison.Ordinal)) o.Add(r);
        }
    }

    static D Nest(D s)
    {
        var root = new D();
        foreach (var e in s)
        {
            var v = Obj(e.Value);
            if (!v.ContainsKey("value")) continue;
            var segs = e.Key.Split('.');
            var cur = root;
            for (int i = 0; i < segs.Length - 1; i++)
            {
                if (!(cur.GetValueOrDefault(segs[i]) is D)) cur[segs[i]] = new D();
                cur = (D)cur[segs[i]]!;
            }
            cur[segs[^1]] = v["value"];
        }
        return root;
    }

    static List<string> UniqSorted(List<string> xs) => IntentJs.SortedUtf8(xs.Distinct(StringComparer.Ordinal));

    static object? IdOf(D pc) => pc.TryGetValue("id", out var id) ? id : JsX.Undef;

    /// <summary>Check one executed action: the frame condition over the monitored state outside its write set and the verb's postconditions. opts: effect?,
    /// attributions? ([{var, actor}]), self?. Returns {status, outOfFrame, attributed, postViolated, missing, unmonitored}; never throws.</summary>
    public static D CheckFrame(object? specO, object? actionO, object? preO, object? postO, D? opts)
    {
        var outOfFrame = new List<string>();
        var attributed = new List<string>();
        var postViolated = new List<string>();
        var missing = new List<string>();
        bool unmonitored = false;
        try
        {
            if (specO is not D spec || spec.GetValueOrDefault("state") is not L state || actionO is not D action || preO is not D pre || postO is not D post)
                throw new ArgumentException("spec, action, pre and post must be objects (spec.state an array)");
            unmonitored = state.Count == 0;
            var w = new HashSet<string>(WriteSetOf(spec, action), StringComparer.Ordinal);
            var sortedState = IntentJs.SortedUtf8(state.Select(v => (string)v!));
            var attrs = opts != null && opts.GetValueOrDefault("attributions") != null ? Arr(opts["attributions"]) : new L();
            var self = opts?.GetValueOrDefault("self");
            foreach (var v in sortedState)
            {
                if (w.Contains(v)) continue;
                var a = pre.GetValueOrDefault(v);
                var b = post.GetValueOrDefault(v);
                if (a == null || b == null) { missing.Add(v); continue; }
                if (Eq(Obj(a).GetValueOrDefault("digest"), Obj(b).GetValueOrDefault("digest"))) continue;
                bool other = false;
                foreach (var xo in attrs)
                {
                    var x = Obj(xo);
                    if (Eq(x.GetValueOrDefault("var"), v) && !Eq(x.GetValueOrDefault("actor"), self)) other = true;
                }
                (other ? attributed : outOfFrame).Add(v);
            }
            var env = new D { ["pre"] = Nest(pre), ["post"] = Nest(post), ["effect"] = opts != null && opts.GetValueOrDefault("effect") != null ? opts["effect"] : new D() };
            var act = new D
            {
                ["verb"] = action.GetValueOrDefault("verb"), ["resource"] = action.GetValueOrDefault("resource"), ["params"] = action.GetValueOrDefault("params") ?? new D(),
            };
            var ctx = new D { ["action"] = act, ["env"] = env };
            var envRoot = new D { ["env"] = env };
            var posts = spec.GetValueOrDefault("post") == null ? new L() : Arr(spec["post"]);
            foreach (var pco in posts)
            {
                var pc = Obj(pco);
                if (!Eq(pc.GetValueOrDefault("verb"), action.GetValueOrDefault("verb"))) continue;
                bool pending = false;
                var deltas = pc.GetValueOrDefault("deltas") == null ? new L() : Arr(pc["deltas"]);
                foreach (var dO in deltas)
                {
                    var d = Obj(dO);
                    var x = Get(env["pre"], (string)d["path"]!);
                    var y = Get(env["post"], (string)d["path"]!);
                    if (!IsNum(x) || !IsNum(y))
                    {
                        missing.Add(JsX.Str(IdOf(pc)) + ":" + JsX.Str(d["path"]));
                        pending = true;
                    }
                    else if (Dbl(y) != Dbl(x) + Dbl(d.GetValueOrDefault("by")))
                    {
                        postViolated.Add((string)pc["id"]!);
                        pending = true;
                        break;
                    }
                }
                if (pending) continue;
                var reads = new List<string>();
                var where = pc.GetValueOrDefault("where") == null ? new L() : Arr(pc["where"]);
                foreach (var c in where) EnvReads(c, reads);
                var absent = reads.Where(r => !Present(envRoot, r)).ToList();
                if (absent.Count > 0)
                {
                    foreach (var r in absent) missing.Add(JsX.Str(IdOf(pc)) + ":" + r);
                    continue;
                }
                if (where.Count > 0)
                {
                    var pred = new D { ["verb"] = action.GetValueOrDefault("verb"), ["where"] = where };
                    if (!Predicates.EvaluatePredicates(new L { pred }, ctx)) postViolated.Add((string)pc["id"]!);
                }
            }
        }
        catch (Exception e)
        {
            missing.Add("error: " + (e is ArgumentException && e.Message.StartsWith("spec, action", StringComparison.Ordinal) ? e.Message : "error"));
        }
        var miss = UniqSorted(missing);
        var pv = UniqSorted(postViolated);
        return new D
        {
            ["status"] = outOfFrame.Count > 0 || pv.Count > 0 ? "violated" : miss.Count > 0 ? "pending" : "ok",
            ["outOfFrame"] = outOfFrame.Select(x => (object?)x).ToList(),
            ["attributed"] = attributed.Select(x => (object?)x).ToList(),
            ["postViolated"] = pv.Select(x => (object?)x).ToList(),
            ["missing"] = miss.Select(x => (object?)x).ToList(),
            ["unmonitored"] = unmonitored,
        };
    }

    /// <summary>Feed a frame report back: a violation is a negative runtime observation that vetoes the outcome's cell; ok and pending change nothing.</summary>
    public static D ApplyFrameReport(IntentLearner l, Outcome o, object? report)
    {
        var r = new D();
        if (report is not D rm || (rm.GetValueOrDefault("status") as string) != "violated") return r;
        r["signal"] = "postcondition-violation";
        r["divergence"] = IntentMapKit.ApplyDivergence(l, o, 0);
        return r;
    }
}
