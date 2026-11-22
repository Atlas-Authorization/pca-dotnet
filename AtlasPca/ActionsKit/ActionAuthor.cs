// Authoring forms of an ActionDef: the param and resource shorthands, the entry expansion, the document loader over an already parsed
// value and the typed param constructors. One action has one digest whichever way it was written; every expanded def is checked by
// ValidateDef. The YAML text loader is not ported (parse the text and call LoadActionsValue).
using System.Globalization;
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionAuthor
{
    public const int MaxAuthorBytes = 1 << 20;
    public const string IdempotencyParam = "idempotency_key";
    static readonly string[] AutoIdempotentEffects = { "send", "pay", "create", "provision", "publish" };
    static readonly string[] ProvenanceLevels = { "first_party", "tool", "agent" };
    static readonly string[] BlastRadii = { "one", "bounded", "tenant", "global" };
    static readonly string[] ResourceScopes = { "one", "set", "tenant", "global" };
    static readonly string[] IdClasses = { "digits", "hex", "alnum", "slug", "uuid", "any_safe" };
    static readonly string[] EntryKeys =
    {
        "v", "kind", "verb", "aliases", "title", "description", "effects", "resource", "params", "reversibility", "blast", "side_effects", "idempotency",
        "context", "traits", "audience", "compensates", "bindings", "examples", "review", "source", "since",
    };
    static readonly string[] FileKeys = { "ns", "since", "actions" };
    const RegexOptions Ro = RegexOptions.CultureInvariant;
    static Regex ShorthandRe => Rx.Get(@"\A([a-z_]+(?::[a-z0-9_]+(?:\.[a-z0-9_]+){0,3})?)(?:\(([^\n\r\u2028\u2029]*)\))?(\?)?\z", Ro);
    static Regex IntArgRe => Rx.Get(@"\A-?[0-9]{1,15}\z", Ro);
    static Regex IntRangeRe => Rx.Get(@"\A(-?[0-9]{1,15})\.\.(-?[0-9]{1,15})\z", Ro);
    static Regex AtRe => Rx.Get(@"@([a-z]+)\z", Ro);
    static Regex IdRestRe => Rx.Get(@"\A\{([a-z_]+),([0-9]{1,3})\.\.([0-9]{1,3})\}\z", Ro);
    static Regex NsRe => Rx.Get(@"\A[a-z][a-z0-9_]{0,31}\z", Ro);

    static ActionKitError Bs(string msg) => new("bad_shorthand", msg);
    static ActionKitError Ba(string msg) => new("bad_action", msg);
    static string Trim(string s) => JsX.JsTrim(s);

    /// <summary>Number(s) of an integer literal: "-0" stays negative zero (the strict profile refuses it), everything else is its value.</summary>
    static Num NumOfText(string s) => new(s.TrimStart('-').TrimStart('0') == "" ? (s.StartsWith('-') ? "-0" : "0") : long.Parse(s, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture));

    static (List<string> Pos, Dictionary<string, string> Named) SplitArgs(string s)
    {
        var pos = new List<string>(); var named = new Dictionary<string, string>();
        foreach (var raw in s.Split(','))
        {
            var a = Trim(raw);
            if (a == "") continue;
            var eq = a.IndexOf('=');
            if (eq > 0) named[Trim(a[..eq])] = Trim(a[(eq + 1)..]);
            else pos.Add(a);
        }
        return (pos, named);
    }

    static Num? IntArg(string? s, string what)
    {
        if (s == null) return null;
        if (!IntArgRe.IsMatch(s)) throw Bs($"{what} must be an integer, got '{s}'");
        return NumOfText(s);
    }

    static void Only(List<string> pos, Dictionary<string, string> named, int n, string[] names, string shorthand)
    {
        if (pos.Count > n) throw Bs($"'{shorthand}' takes at most {n} positional argument(s)");
        foreach (var k in named.Keys) if (!names.Contains(k)) throw Bs($"'{shorthand}' has no option '{k}'");
    }

    static L ListArg(string s, string shorthand)
    {
        var xs = s.Split('|').Select(Trim).ToList();
        if (xs.Count == 0 || xs.Any(x => x == "")) throw Bs($"'{shorthand}' needs values separated by |");
        return Ak.ToL(xs);
    }

    /// <summary>Expand one param shorthand (email phone url uuid ccy country secret bool date datetime duration text(N) string(N) message(N)
    /// int(MIN..MAX) count(MAX) money(CCY|@param, max=, min=, exp=, provenance=) id:&lt;type&gt; enum(a|b) set(a|b) array(items, max=, min=)); a trailing ? makes it optional.</summary>
    public static D ParseParamShorthand(string src)
    {
        var m = ShorthandRe.Match(Trim(src));
        if (!m.Success) throw Bs($"unknown param shorthand '{src}'");
        var name = m.Groups[1].Value;
        string? inner = m.Groups[2].Success ? m.Groups[2].Value : null;
        var optional = m.Groups[3].Success && m.Groups[3].Value == "?";
        var (pos, named) = SplitArgs(inner ?? "");
        void Bare() { if (inner != null) throw Bs($"'{name}' takes no arguments"); }
        D p;
        switch (name)
        {
            case "email": Bare(); p = new D { ["type"] = "string", ["role"] = "contact.email", ["format"] = "email", ["tags"] = new L { "pii" }, ["max_len"] = 254L }; break;
            case "phone": Bare(); p = new D { ["type"] = "string", ["role"] = "contact.phone", ["format"] = "phone_e164", ["tags"] = new L { "pii" }, ["max_len"] = 16L }; break;
            case "url": Bare(); p = new D { ["type"] = "string", ["role"] = "url.target", ["format"] = "url", ["max_len"] = 2048L }; break;
            case "uuid": Bare(); p = new D { ["type"] = "string", ["format"] = "uuid", ["max_len"] = 36L }; break;
            case "ccy": Bare(); p = new D { ["type"] = "string", ["role"] = "money.currency", ["format"] = "iso_currency", ["max_len"] = 3L }; break;
            case "country": Bare(); p = new D { ["type"] = "string", ["format"] = "iso_country", ["max_len"] = 2L }; break;
            case "secret": Bare(); p = new D { ["type"] = "string", ["role"] = "credential.secret", ["tags"] = new L { "secret" }, ["max_len"] = 512L }; break;
            case "bool": Bare(); p = new D { ["type"] = "boolean" }; break;
            case "date": Bare(); p = new D { ["type"] = "date" }; break;
            case "datetime": Bare(); p = new D { ["type"] = "datetime" }; break;
            case "duration":
                {
                    Only(pos, named, 1, Array.Empty<string>(), "duration");
                    var mx = IntArg(pos.Count > 0 ? pos[0] : null, "duration max (ms)");
                    p = new D { ["type"] = "duration" };
                    if (mx != null) { p["min"] = 0L; p["max"] = mx; }
                    break;
                }
            case "text":
            case "string":
                {
                    Only(pos, named, 1, Array.Empty<string>(), name);
                    var n = IntArg(pos.Count > 0 ? pos[0] : null, $"{name} length");
                    p = new D { ["type"] = "string" };
                    if (n != null) p["max_len"] = n;
                    break;
                }
            case "message":
                {
                    Only(pos, named, 1, Array.Empty<string>(), "message");
                    var ml = IntArg(pos.Count > 0 ? pos[0] : null, "message length");
                    p = new D { ["type"] = "string", ["role"] = "text.message", ["tags"] = new L { "free_text_outbound" }, ["max_len"] = (object?)ml ?? 1024L };
                    break;
                }
            case "int":
                {
                    Only(pos, named, 1, Array.Empty<string>(), "int");
                    var r = pos.Count == 0 ? null : IntRangeRe.Match(pos[0]);
                    if (pos.Count > 0 && !r!.Success) throw Bs("int takes MIN..MAX, for example int(0..100)");
                    p = new D { ["type"] = "integer" };
                    if (r != null) { p["min"] = NumOfText(r.Groups[1].Value); p["max"] = NumOfText(r.Groups[2].Value); }
                    break;
                }
            case "count":
                {
                    Only(pos, named, 1, Array.Empty<string>(), "count");
                    var mx = IntArg(pos.Count > 0 ? pos[0] : null, "count max");
                    p = new D { ["type"] = "integer", ["role"] = "count.limit", ["min"] = 1L };
                    if (mx != null) p["max"] = mx;
                    p["unit"] = new D { ["kind"] = "count" };
                    break;
                }
            case "money":
                {
                    Only(pos, named, 1, new[] { "max", "min", "exp", "provenance" }, "money");
                    var c = pos.Count > 0 ? pos[0] : null;
                    if (c == null) throw Bs("money needs a currency: money(USD) or money(@currency_param)");
                    object ccy = c.StartsWith('@') ? new D { ["from"] = c[1..] } : c;
                    var mx = IntArg(named.GetValueOrDefault("max"), "money max");
                    var prov = named.GetValueOrDefault("provenance") ?? "first_party"; // an amount defaults to provenance first_party
                    if (!ProvenanceLevels.Contains(prov)) throw Bs($"money provenance must be one of {string.Join(", ", ProvenanceLevels)}");
                    var mn = IntArg(named.GetValueOrDefault("min"), "money min");
                    var ex = IntArg(named.GetValueOrDefault("exp"), "money exp");
                    p = new D { ["type"] = "integer", ["role"] = "money.amount", ["min"] = (object?)mn ?? 1L };
                    if (mx != null) p["max"] = mx;
                    p["unit"] = new D { ["kind"] = "money", ["ccy"] = ccy, ["exp"] = (object?)ex ?? 2L };
                    p["provenance_min"] = prov;
                    break;
                }
            case "enum":
            case "set":
                if (inner == null) throw Bs($"{name} needs values: {name}(a|b|c)");
                p = new D { ["type"] = name == "enum" ? "string" : "set", ["values"] = ListArg(inner, name) };
                break;
            case "array":
                {
                    Only(pos, named, 1, new[] { "max", "min" }, "array");
                    var items = pos.Count > 0 ? pos[0] : null;
                    if (items is not ("string" or "integer")) throw Bs("array(items): items is string or integer");
                    var mx = IntArg(named.GetValueOrDefault("max"), "array max");
                    var mn = IntArg(named.GetValueOrDefault("min"), "array min");
                    p = new D { ["type"] = "array", ["items"] = items };
                    if (mn != null) p["min_items"] = mn;
                    if (mx != null) p["max_items"] = mx;
                    break;
                }
            default:
                if (name.StartsWith("id:", StringComparison.Ordinal)) { Bare(); p = new D { ["type"] = "string", ["role"] = "id." + name[3..], ["max_len"] = 64L }; break; }
                throw Bs($"unknown param shorthand '{name}'");
        }
        if (optional) p["required"] = false;
        return p;
    }

    /// <summary>"type", "type:*", "type:exact", "type:prefix*" or "type:prefix*{class,min..max}", with an optional "@one|set|tenant|global".</summary>
    public static D ParseResourceShorthand(string src)
    {
        var s = Trim(src);
        string? scope = null;
        var at = AtRe.Match(s);
        if (at.Success)
        {
            var name = at.Groups[1].Value;
            if (!ResourceScopes.Contains(name)) throw Bs($"unknown resource scope '@{name}'");
            scope = name;
            s = s[..at.Index];
        }
        var colon = s.IndexOf(':');
        if (colon < 0) return new D { ["type"] = s, ["id"] = "*", ["scope"] = scope ?? "tenant" };
        var type = s[..colon]; var idsrc = s[(colon + 1)..];
        if (idsrc == "*") return new D { ["type"] = type, ["id"] = "*", ["scope"] = scope ?? "set" };
        var star = idsrc.IndexOf('*');
        if (star < 0) return new D { ["type"] = type, ["id"] = new D { ["exact"] = idsrc }, ["scope"] = scope ?? "one" };
        var prefix = idsrc[..star]; var rest = idsrc[(star + 1)..];
        var cls = "alnum"; var len = new L { 8L, 32L };
        if (rest != "")
        {
            var r = IdRestRe.Match(rest);
            if (!r.Success || !IdClasses.Contains(r.Groups[1].Value)) throw Bs($"resource id '{idsrc}': expected prefix*{{class,min..max}}");
            cls = r.Groups[1].Value;
            len = new L { long.Parse(r.Groups[2].Value, CultureInfo.InvariantCulture), long.Parse(r.Groups[3].Value, CultureInfo.InvariantCulture) };
        }
        return new D { ["type"] = type, ["id"] = new D { ["prefix"] = prefix, ["class"] = cls, ["len"] = len }, ["scope"] = scope ?? "one" };
    }

    /// <summary>The title an action gets when it names none: "acme.invoice.send" becomes "Send invoice".</summary>
    public static string DefaultTitle(string verb)
    {
        var parts = verb.Split('.').Skip(1).ToList();
        var act = parts.Count > 0 ? parts[^1] : verb;
        var t = string.Join(" ", new[] { act }.Concat(parts.Take(Math.Max(parts.Count - 1, 0)))).Replace('_', ' ');
        if (t.Length == 0) return t;
        var first = t[0] == 'ß' ? "SS" : t[..1].ToUpperInvariant(); // charAt(0).toUpperCase()
        return first + t[1..];
    }

    static object? AsList(object? v) => v is string s ? new L { s } : v;
    static bool IsObj(object? v) => v is D;

    /// <summary>Expand one authoring entry (shorthands or full def members) to {def, notes}. Throws bad_action / bad_shorthand for a malformed entry.</summary>
    public static D ExpandAction(object? entryO, string? since = null)
    {
        if (entryO is not D entry) throw Ba("an action must be an object");
        foreach (var k in entry.Keys) if (!EntryKeys.Contains(k)) throw Ba($"unknown member '{k}'");
        if (entry.ContainsKey("v") && !(IntentJs.NumOf(entry["v"]) is double vv && vv == 1.0)) throw Ba("unsupported def version");
        if (entry.ContainsKey("kind") && !(entry["kind"] is string kd && kd == Actions.ActionDefKind)) throw Ba($"kind must be '{Actions.ActionDefKind}'");
        if (entry.GetValueOrDefault("verb") is not string verb) throw Ba("verb is required");
        var notes = new L();
        if (entry.ContainsKey("kind"))
        {
            // the full form (a kind member) is taken exactly as written: no shorthands, no defaults, ValidateDef decides
            var full = new D { ["v"] = 1L };
            foreach (var (k, v) in entry) full[k] = v;
            var je0 = Actions.JsonProfileError(full);
            if (je0 != null) throw Ba($"not strict JSON: {je0}");
            return new D { ["def"] = full, ["notes"] = notes };
        }
        var o = new D { ["v"] = 1L, ["kind"] = Actions.ActionDefKind, ["verb"] = verb };
        if (entry.ContainsKey("aliases")) o["aliases"] = AsList(entry["aliases"]);
        o["title"] = Ak.G(entry, "title") ?? DefaultTitle(verb);
        if (entry.ContainsKey("description")) o["description"] = entry["description"];
        // an absent effects or resource stays an undefined member (the strict JSON check below refuses it), as in the reference
        o["effects"] = entry.ContainsKey("effects") ? AsList(entry["effects"]) : Undef;
        o["resource"] = !entry.ContainsKey("resource") ? Undef : entry["resource"] is string rs ? ParseResourceShorthand(rs) : entry["resource"];
        var ps = new D();
        if (entry.ContainsKey("params"))
        {
            if (entry["params"] is not D pd) throw Ba("params must be an object");
            foreach (var (k, v) in pd) ps[k] = v is string vs ? ParseParamShorthand(vs) : v;
        }
        if (entry.ContainsKey("reversibility")) o["reversibility"] = entry["reversibility"];
        if (entry.ContainsKey("blast")) o["blast"] = entry["blast"] is string br ? new D { ["radius"] = br } : entry["blast"];
        if (entry.GetValueOrDefault("blast") is string bs && !BlastRadii.Contains(bs)) throw Ba($"unknown blast radius '{bs}'");
        if (entry.ContainsKey("side_effects")) o["side_effects"] = entry["side_effects"];
        var effects = o.GetValueOrDefault("effects") is L el ? el : new L();
        object? idem = entry.ContainsKey("idempotency") ? entry["idempotency"] : Undef;
        if (idem is string ims) idem = ims == "key_param" ? new D { ["mode"] = "key_param", ["param"] = IdempotencyParam } : new D { ["mode"] = ims };
        if (ReferenceEquals(idem, Undef) && effects.Any(e => e is string es && AutoIdempotentEffects.Contains(es)))
        {
            idem = new D { ["mode"] = "key_param", ["param"] = IdempotencyParam };
            notes.Add(new D { ["verb"] = verb, ["message"] = $"{IdempotencyParam} auto-added" });
        }
        if (idem is D idd && Ak.S(idd, "mode") == "key_param" && Ak.S(idd, "param") == IdempotencyParam && !ps.ContainsKey(IdempotencyParam))
            ps[IdempotencyParam] = new D { ["type"] = "string", ["max_len"] = 64L };
        if (!ReferenceEquals(idem, Undef)) o["idempotency"] = idem;
        o["params"] = ps;
        foreach (var k in new[] { "context", "traits" }) if (entry.ContainsKey(k)) o[k] = AsList(entry[k]);
        foreach (var k in new[] { "audience", "compensates", "bindings", "examples", "source" }) if (entry.ContainsKey(k)) o[k] = entry[k];
        o["review"] = Ak.G(entry, "review") ?? new D { ["state"] = "authored" };
        var sn = Ak.G(entry, "since") ?? since;
        if (sn != null) o["since"] = sn;
        var je = Actions.JsonProfileError(o);
        if (je != null) throw Ba($"not strict JSON: {je}");
        return new D { ["def"] = o, ["notes"] = notes };
    }
    static readonly object Undef = JsX.Undef;

    static bool HasProtoKey(object? v, int depth = 0)
    {
        if (depth > 40 || (v is not D && v is not L)) return depth > 40;
        if (v is L l) return l.Any(x => HasProtoKey(x, depth + 1));
        return ((D)v!).Any(kv => kv.Key == "__proto__" || HasProtoKey(kv.Value, depth + 1));
    }

    /// <summary>Expand an already parsed document ({ns, since?, actions: [...]}, or one raw def) to {defs, notes, errors, locs, rules[, ns]}. Never throws.</summary>
    public static D LoadActionsValue(object? doc)
    {
        var res = new D { ["defs"] = new L(), ["notes"] = new L(), ["errors"] = new L(), ["locs"] = new D(), ["rules"] = new D() };
        D Fail(string msg) { var o = new D(res); o["errors"] = new L { new D { ["message"] = msg } }; return o; }
        if (HasProtoKey(doc)) return Fail("the document contains a '__proto__' member or nests deeper than 40");
        if (doc is not D dd) return Fail("the document must be an object");
        string? since = null;
        L entries;
        if (Ak.S(dd, "kind") == Actions.ActionDefKind) entries = new L { dd };
        else
        {
            foreach (var k in dd.Keys) if (!FileKeys.Contains(k)) return Fail($"unknown top-level member '{k}' (expected ns, since, actions)");
            if (dd.GetValueOrDefault("ns") is not string ns || !NsRe.IsMatch(ns)) return Fail("ns must be a lowercase identifier");
            res["ns"] = ns;
            if (dd.GetValueOrDefault("since") is string sn) since = sn;
            else if (dd.ContainsKey("since")) return Fail("since must be a string");
            if (dd.GetValueOrDefault("actions") is not L acts) return Fail("actions must be a list");
            entries = acts;
        }
        var errors = (L)res["errors"]!; var defs = (L)res["defs"]!; var notesAll = (L)res["notes"]!; var rulesAll = (D)res["rules"]!;
        for (int index = 0; index < entries.Count; index++)
        {
            var e = entries[index];
            var verb = e is D ed && ed.GetValueOrDefault("verb") is string vs && vs.Length > 0 ? vs : null;
            void Err(string message)
            {
                var x = new D { ["index"] = (long)index };
                if (verb != null) x["verb"] = verb;
                x["message"] = message;
                errors.Add(x);
            }
            try
            {
                object? rules = null; var hasRules = false;
                object? entry = e;
                if (e is D ed2 && ed2.ContainsKey("rules"))
                {
                    rules = ed2["rules"]; hasRules = true;
                    var rest = new D(); foreach (var (k, v) in ed2) if (k != "rules") rest[k] = v;
                    entry = rest;
                }
                var ex = ExpandAction(entry, since);
                var d = (D)ex["def"]!;
                var bad = Actions.ValidateDef(d);
                if (bad != null) { Err(bad); continue; }
                if (hasRules)
                {
                    var re = ActionBusinessRules.BusinessRulesError(d, rules);
                    if (!string.IsNullOrEmpty(re)) { Err(re); continue; }
                    rulesAll[(string)d["verb"]!] = rules;
                }
                defs.Add(d);
                notesAll.AddRange((L)ex["notes"]!);
            }
            catch (Exception x) { Err(x is ActionKitError ? x.Message : "malformed action: " + x.Message); }
        }
        return res;
    }

    /// <summary>The typed constructor over the JSON form: the same expansion as the loader (so the same digest); throws bad_action on a malformed spec.</summary>
    public static D Action(string verb, D spec)
    {
        var entry = new D { ["verb"] = verb };
        foreach (var (k, v) in spec) entry[k] = v;
        var def = (D)ExpandAction(entry)["def"]!;
        var bad = Actions.ValidateDef(def);
        if (bad != null) throw Ba($"{verb}: {bad}");
        return def;
    }

    /// <summary>Typed param constructors; each returns the same param the matching shorthand expands to. x merges extra members over it.</summary>
    public static class P
    {
        static D With(D p, D? x) { var o = new D(p); if (x != null) foreach (var (k, v) in x) o[k] = v; return o; }
        static D Sh(string s, D? x) => With(ParseParamShorthand(s), x);
        public static D Email(D? x = null) => Sh("email", x);
        public static D Phone(D? x = null) => Sh("phone", x);
        public static D Url(D? x = null) => Sh("url", x);
        public static D Uuid(D? x = null) => Sh("uuid", x);
        public static D Ccy(D? x = null) => Sh("ccy", x);
        public static D Country(D? x = null) => Sh("country", x);
        public static D Secret(D? x = null) => Sh("secret", x);
        public static D Bool(D? x = null) => Sh("bool", x);
        public static D Date(D? x = null) => Sh("date", x);
        public static D Datetime(D? x = null) => Sh("datetime", x);
        public static D Duration(object? maxMs = null, D? x = null) => Sh(maxMs == null ? "duration" : $"duration({Ak.JsStr(maxMs)})", x);
        public static D Message(object? maxLen = null, D? x = null) => Sh(maxLen == null ? "message" : $"message({Ak.JsStr(maxLen)})", x);
        public static D Text(object? maxLen = null, D? x = null) => Sh(maxLen == null ? "text" : $"text({Ak.JsStr(maxLen)})", x);
        public static D IntRange(object? min = null, object? max = null, D? x = null) => Sh(min == null || max == null ? "int" : $"int({Ak.JsStr(min)}..{Ak.JsStr(max)})", x);
        public static D Count(object? max = null, D? x = null) => Sh(max == null ? "count" : $"count({Ak.JsStr(max)})", x);
        /// <summary>ccy is a literal ISO code (string), or {from: "param"} naming the currency param.</summary>
        public static D Money(object ccy, D? o = null, D? x = null) =>
            Sh($"money({(ccy is string cs ? cs : "@" + Ak.JsStr(Ak.G(ccy, "from")))}{(Ak.G(o, "max") != null ? ", max=" + Ak.JsStr(o!["max"]) : "")}{(Ak.G(o, "min") != null ? ", min=" + Ak.JsStr(o!["min"]) : "")}{(Ak.G(o, "exp") != null ? ", exp=" + Ak.JsStr(o!["exp"]) : "")})", x);
        public static D Id(string type, D? x = null) => Sh("id:" + type, x);
        public static D EnumOf(IEnumerable<string> values, D? x = null) => Sh($"enum({string.Join("|", values)})", x);
        public static D SetOf(IEnumerable<string> values, D? x = null) => Sh($"set({string.Join("|", values)})", x);
        public static D ArrayOf(string items, object? max = null, D? x = null) => Sh(max == null ? $"array({items})" : $"array({items}, max={Ak.JsStr(max)})", x);
        public static D Optional(D d) { var o = new D(d); o["required"] = false; return o; }
    }
}
