// The trusted question card of the wallet and agent-initiated clarification (PCA Intent Layer v2). Rendering is deterministic: the card is
// a pure function of the wallet's own outcome space, the cell coordinates, the verified site identity, the principal's own signed
// statement, schema units, the friction tier and (for a clarification) a closed-enum reason. The input has NO field for agent-authored text.
// Values of the concrete action are shown only in fixed slots: numbers formatted by unit, and a string only when the outcome space
// names it (otherwise only its last four letters or digits). The digest of the card goes into the signed answer, so an auditor can
// re-render it and see what the human saw. Values are JSON trees (Dictionary / List / Num / string / bool / null).
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.IntentPkg;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Wallet;

/// <summary>The wallet's view of the effective grant: p_k(c), vetoes, the ceilings and the cells currently in the grant.</summary>
public interface IGrantView
{
    double P(string verb, int[] idx);
    bool Vetoed(string verb, int[] idx);
    /// <summary>Outside the organisation, site and standard ceilings: never a question (the principal cannot widen a ceiling).</summary>
    bool OutsideCeiling(string verb, int[] idx);
    /// <summary>Cells currently in the effective grant (for near-boundary canaries).</summary>
    IReadOnlyList<WalletCore.CellRef> Confirmed();
}

/// <summary>One dry-run verdict of a clarification candidate. It never carries p.</summary>
public sealed record ClarifyVerdict(int Index, string Verdict);

/// <summary>The cell a clarification asks.</summary>
public sealed record ClarifyAsk(int Index, string Verb, int[] Idx, double P, double Ig);

public sealed record ClarifyPlan(List<ClarifyVerdict> Verdicts, ClarifyAsk? Ask)
{
    public D ToJson() => new()
    {
        ["verdicts"] = Verdicts.Select(v => (object?)new D { ["index"] = WalletCore.N(v.Index), ["verdict"] = v.Verdict }).ToList(),
        ["ask"] = Ask == null ? null : new D
        {
            ["index"] = WalletCore.N(Ask.Index), ["verb"] = Ask.Verb, ["idx"] = Ask.Idx.Select(i => WalletCore.N(i)).ToList(), ["p"] = WalletCore.N(Ask.P), ["ig"] = WalletCore.N(Ask.Ig),
        },
    };
}

public static class WalletCard
{
    public const string CardDomain = "atlas-pca/intent-card/v2";
    public const int MaxCandidates = 8;
    const int MaxValues = 64;
    const int MaxString = 256;

    /// <summary>The closed reason enum of an agent clarification, with the fixed label the card shows.</summary>
    public static readonly string[] ClarifyReasons = { "ambiguous_parameter", "multiple_options", "price_changed", "constraint_conflict", "missing_value", "other" };

    static readonly Dictionary<string, string> ReasonLabelMap = new()
    {
        ["ambiguous_parameter"] = "Your agent found a detail your request did not settle.",
        ["multiple_options"] = "Your agent found several options that match.",
        ["price_changed"] = "Your agent found that a price changed.",
        ["constraint_conflict"] = "Your agent found that two parts of your request conflict.",
        ["missing_value"] = "Your agent needs a value your request did not give.",
        ["other"] = "Your agent needs a decision before it continues.",
    };

    public static D ReasonLabels() { var o = new D(); foreach (var (k, v) in ReasonLabelMap) o[k] = v; return o; }

    static readonly object U = JsX.Undef;
    static object? G(object? o, string k) => WalletCore.G(o, k);
    static object? Nul(object? v) => WalletCore.Nul(v);
    static bool Truthy(object? v) => JsX.Truthy(Nul(v));
    static string Str(object? v) => JsX.Str(v);
    static readonly Catalog DefaultCatalog = Catalog.Default;

    // ---- text helpers ----

    static bool IsCtl(char c) => c <= '\u001f' || (c >= '\u007f' && c <= '\u009f') || (c >= '​' && c <= '‏') || (c >= '\u2028' && c <= '‮') || (c >= '⁦' && c <= '⁩');

    /// <summary>Strip control characters, collapse whitespace, cap length (UTF-16 units). For the principal's own words and the site's name.</summary>
    public static string CleanText(object? s, int max)
    {
        if (s is not string str) throw JsX.TypeError("s.replace is not a function");
        var sb = new StringBuilder(str.Length);
        bool inWs = false;
        foreach (var c0 in str)
        {
            var c = IsCtl(c0) ? ' ' : c0;
            if (JsJson.IsJsSpace(c)) { if (!inWs) sb.Append(' '); inWs = true; }
            else { sb.Append(c); inWs = false; }
        }
        var t = sb.ToString().Trim(' '); // every white-space run is one space now, so only spaces remain at the ends
        return t.Length <= max ? t : t[..(max - 1)] + "…";
    }

    static bool IsAlnum(char c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    static string Alnum(string s) { var sb = new StringBuilder(); foreach (var c in s) if (IsAlnum(c)) sb.Append(c); return sb.ToString(); }

    /// <summary>The last four letters or digits of a string (all a card ever shows of a string the outcome space does not name).</summary>
    public static string Last4(object? s)
    {
        if (s is not string str) throw JsX.TypeError("s.replace is not a function");
        var t = Alnum(str);
        return (t.Length > 4 ? t[^4..] : t).ToUpperInvariant();
    }

    static readonly Regex GroupRe = new(@"\B(?=(\d{3})+(?!\d))", RegexOptions.CultureInvariant);
    /// <summary>Thousands grouping with commas, independent of any locale data.</summary>
    static string Group(double n) => GroupRe.Replace(JsJson.NumberToString(n), ",");

    static readonly Dictionary<string, string> CurrencySymbol = new() { ["USD"] = "$", ["EUR"] = "€", ["GBP"] = "£", ["JPY"] = "¥" };

    static bool IsMoney(object? unit) => unit is D m && m.TryGetValue("kind", out var k) && k is string s && s == "money";

    /// <summary>Math.max(0, Math.min(6, Math.floor(unit.exponent))): NaN for an exponent that is no number.</summary>
    static double ExponentOf(object? unit)
    {
        var raw = G(unit, "exponent");
        double e = ReferenceEquals(raw, U) ? double.NaN : JsJson.ToJsNumber(raw);
        return Math.Max(0, Math.Min(6, Math.Floor(e)));
    }

    /// <summary>A number as the card shows it: grouped, with the currency symbol and minor-unit decimals for money.</summary>
    public static string FormatNumber(double x, object? unit = null)
    {
        if (IsMoney(unit))
        {
            double e = ExponentOf(unit);
            bool neg = x < 0;
            double a = Math.Abs(Math.Truncate(x));
            string whole, frac = "";
            if (double.IsNaN(e)) whole = "NaN";
            else
            {
                double div = Math.Pow(10, e);
                whole = Group(Math.Floor(a / div));
                if (e > 0) frac = "." + JsJson.NumberToString(a % div).PadLeft((int)e, '0');
            }
            var key = Str(G(unit, "currency"));
            var sym = CurrencySymbol.TryGetValue(key, out var s) ? s : key + " ";
            return (neg ? "-" : "") + sym + whole + frac;
        }
        return (x < 0 ? "-" : "") + Group(Math.Abs(Math.Truncate(x)));
    }

    static readonly Regex AccRe = new(@"\Aenv\.acc\.([A-Za-z0-9_.-]+)\.post\z", RegexOptions.CultureInvariant);
    static readonly Regex WorldRe = new(@"\Aenv\.world\.([A-Za-z0-9_.-]+)\z", RegexOptions.CultureInvariant);
    static readonly Regex MonRe = new(@"\Aenv\.mon\.([A-Za-z0-9_.-]+)\.state\z", RegexOptions.CultureInvariant);
    static string Spaced(string s) => s.Replace('_', ' ').Replace('.', ' ');

    static string DimLabel(string path)
    {
        Match m;
        if ((m = AccRe.Match(path)).Success) return Spaced(m.Groups[1].Value) + " (running total for this task)";
        if ((m = WorldRe.Match(path)).Success) return Spaced(m.Groups[1].Value) + " (from a signed fact)";
        if ((m = MonRe.Match(path)).Success) return "state of " + Spaced(m.Groups[1].Value);
        return IntentRender.LabelOf(path);
    }

    static bool IsProvPath(string p) => p.StartsWith("env.prov.", StringComparison.Ordinal);

    static string NumFact(IntentOmega.NumDim d, List<int> ids, object? unit, object? actionValue)
    {
        var cells = IntentOmega.NumCells(d);
        double lo = cells[ids[0]].Lo, hi = cells[ids[^1]].Hi;
        string range;
        if (lo == hi) range = "exactly " + FormatNumber(lo, unit);
        else if (lo == d.Lo && hi == d.Hi) range = "any value";
        else if (hi == d.Hi) range = FormatNumber(lo, unit) + " or more";
        else if (lo == d.Lo) range = "up to " + FormatNumber(hi, unit);
        else range = FormatNumber(lo, unit) + " – " + FormatNumber(hi, unit);
        var ex = WalletCore.IsFin(actionValue) ? " (this action: " + FormatNumber(WalletCore.Dn(actionValue), unit) + ")" : "";
        return range + ex;
    }

    static string CatValueText(IntentOmega.CatDim d, int i)
    {
        var v = d.Values[i];
        if (v.Kind == "exact") return "\"" + CleanText(v.Value, 64) + "\"";
        if (v.Kind == "prefix") return "anything starting with \"" + CleanText(v.Value, 64) + "\"";
        return "a value not named in your request";
    }

    static string CatFact(IntentOmega.CatDim d, List<int> ids, object? actionValue)
    {
        var parts = ids.Select(i => CatValueText(d, i)).ToList();
        var set = parts.Count == 1 ? parts[0] : string.Join(", ", parts.Take(parts.Count - 1)) + " or " + (parts.Count > 0 ? parts[^1] : "undefined");
        if (actionValue is not string av) return set;
        bool named = d.Values.Any(v => v.Kind == "exact" && v.Value == av);
        return set + " (this action: " + (named ? "\"" + CleanText(av, 64) + "\"" : "a value ending in \"" + Last4(av) + "\"") + ")";
    }

    static string? BannerFor(string path, List<string> levels)
    {
        var w = WalletCore.WorstProvenance(levels.Select(x => (object?)x).ToList());
        var label = DimLabel(path);
        if (w == "web") return "This " + label + " was suggested by content on a web page, not by you.";
        if (w == "tool") return "This " + label + " came from a tool result, not from you.";
        if (w == "agent") return "This " + label + " was chosen by your agent, not taken from your request or from the site.";
        return null;
    }

    /// <summary>Labels of a provenance coordinate: a level, or a group "tool|web|agent". Anything else is agent (fail closed).</summary>
    static List<string> ProvLevels(IntentOmega.CatDim d, List<int> ids) =>
        ids.SelectMany(i => WalletCore.CatLabel(d, i).Split('|', ',')).ToList();

    /// <summary>action.values[path]: a missing or null values throws, a non-object has no members.</summary>
    static object? Vget(object? values, string path)
    {
        if (values == null || ReferenceEquals(values, U)) throw JsX.TypeError("Cannot read properties of undefined");
        return G(values, path);
    }

    static D? TypedTarget(IntentOmega.VerbSpace vs, object? action, object? units)
    {
        if (!Truthy(action)) return null;
        var values = G(action, "values");
        var dims = vs.Dims.Where(d => !IsProvPath(d.Path)).ToList();
        var nums = dims.Where(d => d is IntentOmega.NumDim && WalletCore.IsNum(Vget(values, d.Path))).ToList();
        var pick = nums.FirstOrDefault(d => IsMoney(G(units, d.Path))) ?? nums.FirstOrDefault();
        if (pick != null) return new D { ["path"] = pick.Path, ["mode"] = "number", ["prompt"] = "To allow it, type the " + DimLabel(pick.Path) + " of this action shown above." };
        var cat = dims.FirstOrDefault(d => d is IntentOmega.CatDim && Vget(values, d.Path) is string sv && Last4(sv).Length == 4);
        if (cat != null) return new D { ["path"] = cat.Path, ["mode"] = "last4", ["prompt"] = "To allow it, type the last 4 letters or digits of the " + DimLabel(cat.Path) + "." };
        return null;
    }

    static L Answers(string yes) => new()
    {
        new D { ["id"] = "no", ["label"] = "No" }, new D { ["id"] = "partly", ["label"] = "Partly…" }, new D { ["id"] = "yes", ["label"] = yes },
    };

    static L? AnswersFor(object? friction) => Str(friction) switch
    {
        "tap" => Answers("Yes"),
        "hold" => Answers("Press and hold to allow"),
        "typed" => Answers("Yes, type the value to confirm"),
        "device" => Answers("Yes, confirm with your security key"),
        _ => null,
    };

    static string RevText(object? rev) => Str(rev) switch
    {
        "reversible" => "that can be undone",
        "rate_limited" => "that is rate-limited",
        "irreversible" => "that cannot be undone",
        _ => "undefined",
    };

    static D Refuse(string reason) => new() { ["ok"] = false, ["reason"] = reason };

    /// <summary>JSON.parse(JSON.stringify(v)): numbers spelled as JavaScript prints them, -0 as 0, non-finite as null.</summary>
    internal static object? Plain(object? v)
    {
        switch (v)
        {
            case Num or double or int or long:
                {
                    var d = IntentJs.NumOf(v)!.Value;
                    if (!double.IsFinite(d)) return null;
                    return d == 0 ? new Num("0") : IntentJs.NormNum(v is Num n ? n.Raw : JsJson.NumberToString(d));
                }
            case D m: { var o = new D(); foreach (var (k, x) in m) o[k] = Plain(x); return o; }
            case L l: return l.Select(Plain).ToList();
            default: return v;
        }
    }

    /// <summary>Render the trusted card of a question: {ok: true, card} or {ok: false, reason}. The input is a JSON object with the reference's
    /// member names (omega as an <see cref="IntentOmega.Omega"/>, verb, coords, site {origin, name}, statementText, reversibility, units, action,
    /// friction, kind, reason, locale, catalog as a <see cref="Catalog"/>).</summary>
    public static D RenderCard(D input)
    {
        var loc = G(input, "locale");
        var locEff = loc == null || ReferenceEquals(loc, U) ? "en" : loc;
        if (!(locEff is string ls && ls == "en")) return Refuse("unsupported locale " + Str(loc));
        var kind = G(input, "kind");
        var reason = G(input, "reason");
        bool isClar = kind is string ks && ks == "clarification";
        if (isClar && ReferenceEquals(reason, U)) return Refuse("a clarification card needs a reason");
        if (!ReferenceEquals(reason, U) && !(reason is string rs && Array.IndexOf(ClarifyReasons, rs) >= 0)) return Refuse("unknown clarification reason");
        var omega = G(input, "omega") as IntentOmega.Omega ?? throw JsX.TypeError("Cannot read properties of undefined (reading 'verbs')");
        var r = WalletCore.ResolveCoords(omega, G(input, "verb"), G(input, "coords"));
        if (!r.Ok) return Refuse(r.Reason!);
        var vs = r.Vs!;
        var box = r.Box!;
        var action = G(input, "action");
        if (Truthy(action) && !JsX.StrictEq(G(action, "verb"), vs.Verb)) return Refuse("the action is for another verb");
        var catalog = G(input, "catalog") is { } c0 && !ReferenceEquals(c0, U) ? (Catalog)c0 : DefaultCatalog;
        var site = G(input, "site");
        var siteName = CleanText(JsX.At(site, "name"), 64);
        if (siteName.Length == 0) siteName = CleanText(JsX.At(site, "origin"), 64);
        var said = WalletCore.Has(input, "statementText") ? CleanText(input["statementText"], 280) : "";
        string header = isClar
            ? (said.Length > 0 ? "Your agent needs a decision for your request \"" + said + "\"" : "Your agent needs a decision")
            : (said.Length > 0 ? siteName + " asks on behalf of your request \"" + said + "\"" : siteName + " asks for your confirmation");
        var spec = catalog.Get(vs.Verb);
        string what;
        if (spec != null)
        {
            var desc = spec.Description.EndsWith('.') ? spec.Description[..^1] : spec.Description;
            what = desc.Length > 0 && desc[0] is not ('\n' or '\r' or '\u2028' or '\u2029') ? char.ToLowerInvariant(desc[0]) + desc[1..] : desc;
        }
        else what = "the action \"" + CleanText(vs.Verb, 64) + "\" on " + siteName;
        var revO = Nul(G(input, "reversibility"));
        var rev = revO ?? vs.Reversibility;
        var sentence = "Allow " + what + ", " + RevText(rev) + ", with:";
        var units = G(input, "units");
        var facts = new L();
        var banners = new L();
        var partial = new L();
        for (int k = 0; k < vs.Dims.Count; k++)
        {
            var d = vs.Dims[k];
            var ids = box[k];
            if (IsProvPath(d.Path))
            {
                if (d is not IntentOmega.CatDim pd) continue;
                var b = BannerFor(d.Path["env.prov.".Length..], ProvLevels(pd, ids));
                if (b != null) banners.Add(b);
                continue;
            }
            object? av = U;
            if (action != null && !ReferenceEquals(action, U)) av = Vget(G(action, "values"), d.Path);
            if (d is IntentOmega.NumDim nd)
            {
                facts.Add(new D { ["key"] = d.Path, ["label"] = DimLabel(d.Path), ["text"] = NumFact(nd, ids, G(units, d.Path), av) });
                var cells = IntentOmega.NumCells(nd);
                partial.Add(new D { ["path"] = d.Path, ["kind"] = "num", ["lo"] = WalletCore.N(cells[ids[0]].Lo), ["hi"] = WalletCore.N(cells[ids[^1]].Hi) });
            }
            else
            {
                var cd = (IntentOmega.CatDim)d;
                facts.Add(new D { ["key"] = d.Path, ["label"] = DimLabel(d.Path), ["text"] = CatFact(cd, ids, av) });
                var options = ids.Where(i => cd.Values[i].Kind == "exact").Select(i => (object?)cd.Values[i].Value).ToList();
                if (options.Count > 1) partial.Add(new D { ["path"] = d.Path, ["kind"] = "cat", ["options"] = options });
            }
        }
        var friction = G(input, "friction");
        var typed = WalletCore.FrictionRank(friction) >= WalletCore.FrictionRank("typed") ? TypedTarget(vs, action, units) : null;
        var body = new D { ["v"] = new Num("2") };
        if (!ReferenceEquals(kind, U)) body["kind"] = kind;
        body["verb"] = vs.Verb;
        body["coords"] = Plain(G(input, "coords"));
        body["locale"] = "en";
        body["site"] = new D { ["origin"] = CleanText(JsX.At(site, "origin"), 256), ["name"] = siteName };
        body["header"] = header;
        if (!ReferenceEquals(reason, U)) body["reason_label"] = ReasonLabelMap[(string)reason!];
        body["sentence"] = sentence;
        body["facts"] = facts;
        body["banners"] = banners;
        if (!ReferenceEquals(friction, U)) body["friction"] = friction;
        if (AnswersFor(friction) is { } ans) body["answers"] = ans;
        if (typed != null) body["typed"] = typed;
        body["partial"] = partial;
        var card = new D(body) { ["rendered_digest"] = CardDigest(body) };
        return new D { ["ok"] = true, ["card"] = card };
    }

    /// <summary>The content address of a card body (everything but rendered_digest).</summary>
    public static string CardDigest(D body) => Pca.HashCanonical(new D { ["d"] = CardDomain, ["c"] = Plain(body) });

    /// <summary>Recompute a card's digest and compare: an auditor's check that the stored card is the one that was hashed.</summary>
    public static bool CardDigestMatches(D card)
    {
        var body = new D();
        foreach (var (k, v) in card) if (k != "rendered_digest") body[k] = v;
        return G(card, "rendered_digest") is string rd && CardDigest(body) == rd;
    }

    /// <summary>The elements of a JavaScript iterable (array, or string by code point); anything else is not iterable.</summary>
    static IEnumerable<object?> Spread(object? v)
    {
        if (v is L l) return l;
        if (v is string s)
        {
            var o = new List<object?>();
            for (int i = 0; i < s.Length; i++)
            {
                int n = char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]) ? 2 : 1;
                o.Add(s.Substring(i, n));
                i += n - 1;
            }
            return o;
        }
        throw JsX.TypeError("is not iterable");
    }

    /// <summary>Array.prototype.join element: null and undefined are empty.</summary>
    static string JoinStr(object? v) => v == null || ReferenceEquals(v, U) ? "" : Str(v);

    /// <summary>The plain text of a card, line by line (what a screen reader or a text channel shows).</summary>
    public static string CardText(D card)
    {
        var lines = new List<string> { JoinStr(G(card, "header")) };
        if (Truthy(G(card, "reason_label"))) lines.Add(JoinStr(G(card, "reason_label")));
        lines.Add(JoinStr(G(card, "sentence")));
        if (G(card, "facts") is not L facts) throw JsX.TypeError("card.facts.map is not a function");
        foreach (var f in facts) lines.Add("- " + Str(JsX.At(f, "label")) + ": " + Str(JsX.At(f, "text")));
        foreach (var b in Spread(G(card, "banners"))) lines.Add(JoinStr(b));
        var typed = G(card, "typed");
        if (Truthy(typed)) lines.Add(JoinStr(G(typed, "prompt")));
        if (G(card, "answers") is not L answers) throw JsX.TypeError("card.answers.map is not a function");
        lines.Add(string.Join(" ", answers.Select(a => "[" + Str(JsX.At(a, "label")) + "]")));
        return string.Join("\n", lines);
    }

    // ---- responses ----

    /// <summary>The <c>in</c> operator over a JSON value: a primitive throws.</summary>
    static bool In(object? o, string key) => o switch
    {
        D m => m.ContainsKey(key),
        L => false,
        _ => throw JsX.TypeError("Cannot use 'in' operator"),
    };

    static bool SameValueZero(object? a, object? b)
    {
        if (a == null || b == null) return a == null && b == null;
        if (a is string x && b is string y) return x == y;
        if (a is bool p && b is bool q) return p == q;
        if (WalletCore.IsNum(a) && WalletCore.IsNum(b)) { double u = WalletCore.Dn(a), w = WalletCore.Dn(b); return u == w || (double.IsNaN(u) && double.IsNaN(w)); }
        return ReferenceEquals(a, b);
    }

    /// <summary>Validate a "Partly…" answer against the card: a structured restriction of the shown ranges and values only.</summary>
    public static string? PartialError(D card, object? p)
    {
        if (G(card, "partial") is not L slots) throw JsX.TypeError("card.partial.find is not a function");
        object? slot = null;
        foreach (var s in slots)
            if (JsX.StrictEq(JsX.At(s, "path"), JsX.At(p, "path"))) { slot = s; break; }
        if (slot == null) return "the card has no field " + Str(JsX.At(p, "path"));
        if (G(slot, "kind") is string sk && sk == "num")
        {
            double lo = WalletCore.Dn(G(slot, "lo")), hi = WalletCore.Dn(G(slot, "hi"));
            bool InRange(object? x) => WalletCore.IsIntegral(x) && !WalletCore.IsNegZero(x) && WalletCore.Dn(x) >= lo && WalletCore.Dn(x) <= hi;
            string J(double d) => JsJson.NumberToString(d);
            if (In(p, "upTo")) return InRange(G(p, "upTo")) && WalletCore.Dn(G(p, "upTo")) < hi ? null : $"upTo must be an integer in [{J(lo)}, {J(hi - 1)}]";
            if (In(p, "from")) return InRange(G(p, "from")) && WalletCore.Dn(G(p, "from")) > lo ? null : $"from must be an integer in [{J(lo + 1)}, {J(hi)}]";
            if (In(p, "except"))
            {
                var ex = G(p, "except");
                bool ok;
                if (ex == null) throw JsX.TypeError("Cannot read properties of null (reading 'length')");
                else if (ex is L el) ok = el.Count > 0 && el.All(InRange);
                else if (ex is string es && es.Length > 0) throw JsX.TypeError("p.except.every is not a function");
                else ok = false;
                return ok ? null : $"except values must be integers in [{J(lo)}, {J(hi)}]";
            }
            return "a numeric partly answer needs upTo, from or except";
        }
        if (!In(p, "notFor")) return "a categorical partly answer needs notFor";
        var nf = G(p, "notFor");
        var vals = new List<object?>();
        if (nf != null) foreach (var v in Spread(nf)) if (!vals.Any(w => SameValueZero(v, w))) vals.Add(v);
        var options = G(slot, "options") as L ?? throw JsX.TypeError("slot.options.includes is not a function");
        if (vals.Count == 0 || !vals.All(v => options.Any(o => SameValueZero(o, v)))) return "notFor must name values shown on the card";
        if (vals.Count == options.Count) return "excluding every value is a \"No\"";
        return null;
    }

    static readonly Regex NumRe = new(@"\A(-?)([0-9]+)(?:\.([0-9]+))?\z", RegexOptions.CultureInvariant);

    /// <summary>Normalize what the human typed for comparison with the action value (digits for numbers, minor units for money).</summary>
    public static string? NormalizeTyped(object? input, object? mode, object? unit = null)
    {
        if (input is not string str) throw JsX.TypeError("input.replace is not a function");
        if (mode is string m && m == "last4")
        {
            var t4 = Alnum(str).ToUpperInvariant();
            return t4.Length == 4 ? t4 : null;
        }
        var sb = new StringBuilder();
        foreach (var c in str) if (!(JsJson.IsJsSpace(c) || c is ',' or '$' or '€' or '£' or '¥')) sb.Append(c);
        var t = sb.ToString();
        if (t.Length >= 3 && IsAsciiLetter(t[0]) && IsAsciiLetter(t[1]) && IsAsciiLetter(t[2])) t = t[3..];
        var mt = NumRe.Match(t);
        if (!mt.Success) return null;
        double e = IsMoney(unit) ? ExponentOf(unit) : 0;
        var frac = mt.Groups[3].Success ? mt.Groups[3].Value : "";
        if (frac.Length > e) return null;
        if (double.IsNaN(e)) throw JsX.TypeError("RangeError: The number NaN cannot be converted to a BigInt");
        int ei = (int)e;
        var minor = BigInteger.Parse(mt.Groups[2].Value) * BigInteger.Pow(10, ei) + (frac.Length > 0 ? BigInteger.Parse(frac.PadRight(ei, '0')) : BigInteger.Zero);
        return (mt.Groups[1].Value == "-" && !minor.IsZero ? "-" : "") + minor.ToString();
    }

    static bool IsAsciiLetter(char c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');

    /// <summary>The normalized value the human must type for this card and action (what a site or auditor recomputes); null when none.</summary>
    public static string? ExpectedTyped(D card, object? action)
    {
        var typed = G(card, "typed");
        if (!Truthy(typed)) return null;
        var v = Vget(JsX.At(action, "values"), Str(G(typed, "path")));
        if (G(typed, "mode") is string m && m == "last4") return v is string s && Last4(s).Length == 4 ? Last4(s) : null;
        return WalletCore.IsNum(v) && JsX.SafeInt(v) && !WalletCore.IsNegZero(v) ? JsJson.NumberToString(WalletCore.Dn(v)) : null;
    }

    // ---- agent-initiated clarification ----

    static readonly Regex PathRe = new(@"\A[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*\z", RegexOptions.CultureInvariant);

    static D PErr(string e) => new() { ["ok"] = false, ["error"] = e };

    /// <summary>Strict parse of a clarification body: {ok: true, request} or {ok: false, error}. Never throws.</summary>
    public static D ParseClarifyRequest(object? body)
    {
        if (!WalletCore.IsObj(body)) return PErr("body must be an object");
        foreach (var k in JsX.Keys(body)) if (k != "candidates" && k != "reason") return PErr($"unknown member \"{k}\" (clarifications carry no text)");
        var reason = G(body, "reason");
        if (!(reason is string rs && Array.IndexOf(ClarifyReasons, rs) >= 0)) return PErr("reason must be one of " + string.Join(", ", ClarifyReasons));
        var cands = G(body, "candidates");
        if (cands is not L cl || cl.Count == 0 || cl.Count > MaxCandidates) return PErr($"candidates must be 1..{MaxCandidates} structured actions");
        var outL = new L();
        for (int i = 0; i < cl.Count; i++)
        {
            var c = cl[i];
            if (!WalletCore.IsObj(c)) return PErr($"candidates[{i}] must be an object");
            foreach (var k in JsX.Keys(c)) if (k != "verb" && k != "values") return PErr($"candidates[{i}] has an unknown member \"{k}\"");
            if (!(G(c, "verb") is string verb && verb.Length > 0 && verb.Length <= 128)) return PErr($"candidates[{i}].verb must be a non-empty string");
            var vals = G(c, "values");
            if (!WalletCore.IsObj(vals)) return PErr($"candidates[{i}].values must be an object");
            var keys = JsX.Keys(vals);
            if (keys.Count > MaxValues) return PErr($"candidates[{i}] has too many values");
            var values = new D();
            foreach (var p in keys)
            {
                var v = JsX.ValueOf(vals, p);
                if (!PathRe.IsMatch(p)) return PErr($"candidates[{i}] has a malformed path");
                // The agent names only the action: lifted dimensions are computed by the wallet and the verifier, never taken from the agent.
                if (!(p == "action.resource" || p.StartsWith("action.params.", StringComparison.Ordinal))) return PErr($"candidates[{i}].values may only name action.params.* or action.resource");
                if (WalletCore.IsNum(v))
                {
                    if (!JsX.SafeInt(v) || WalletCore.IsNegZero(v)) return PErr($"candidates[{i}].values.{p} must be a safe integer");
                }
                else if (!(v is string vs && vs.Length <= MaxString)) return PErr($"candidates[{i}].values.{p} must be a string (≤ {MaxString}) or an integer");
                values[p] = v;
            }
            outL.Add(new D { ["verb"] = verb, ["values"] = values });
        }
        return new D { ["ok"] = true, ["request"] = new D { ["candidates"] = outL, ["reason"] = reason } };
    }

    /// <summary>Expected information gain of asking a cell with acceptance p under asymmetric noise (bits).</summary>
    public static double InformationGain(double p, double etaPos, double etaNeg)
    {
        double py = p * (1 - etaNeg) + (1 - p) * etaPos;
        return WalletCore.BinEnt(py) - (p * WalletCore.BinEnt(etaNeg) + (1 - p) * WalletCore.BinEnt(etaPos));
    }

    /// <summary>Dry-run verdicts for each candidate and the one cell worth asking, if any (max expected information gain; ties by risk weight
    /// mass * harm descending, then cell index, then candidate position). <paramref name="lift"/> lifts a candidate into the wallet's space.</summary>
    public static ClarifyPlan PlanClarification(IntentOmega.Omega omega, IGrantView view, IReadOnlyList<object?> candidates, Func<object?, object?>? lift,
        ISet<string> asked, double etaPos, double etaNeg, IntentOmega.HarmModel? harm = null)
    {
        harm ??= IntentOmega.DefaultHarmModel;
        var verdicts = new List<ClarifyVerdict>();
        (int Index, string Verb, int[] Idx, double P, double Ig, double Weight, double Flat)? best = null;
        var seen = new HashSet<string>();
        for (int index = 0; index < candidates.Count; index++)
        {
            var cand = candidates[index];
            var at = WalletCore.CellOfAction(omega, lift != null ? lift(cand) : cand);
            if (at == null) { verdicts.Add(new(index, "outside")); continue; }
            var (vs, idx) = at.Value;
            if (view.OutsideCeiling(vs.Verb, idx) || view.Vetoed(vs.Verb, idx)) { verdicts.Add(new(index, "denied")); continue; }
            double p = view.P(vs.Verb, idx);
            if (p <= 0) { verdicts.Add(new(index, "denied")); continue; }
            if (p >= 1) { verdicts.Add(new(index, "admitted")); continue; }
            var key = WalletCore.CellKey(vs.Verb, idx);
            if (asked.Contains(key)) { verdicts.Add(new(index, "asked")); continue; }
            verdicts.Add(new(index, "uncertain"));
            if (!seen.Add(key)) continue;
            double ig = InformationGain(p, etaPos, etaNeg);
            var s = IntentOmega.CellStats(vs, idx, harm);
            var c2 = (Index: index, Verb: vs.Verb, Idx: idx, P: p, Ig: ig, Weight: s.Mass * s.Harm, Flat: WalletCore.FlatIndex(vs, idx));
            if (best == null || c2.Ig > best.Value.Ig + 1e-12
                || (Math.Abs(c2.Ig - best.Value.Ig) <= 1e-12 && (c2.Weight > best.Value.Weight || (c2.Weight == best.Value.Weight && c2.Flat < best.Value.Flat)))) best = c2;
        }
        return new ClarifyPlan(verdicts, best is { } b ? new ClarifyAsk(b.Index, b.Verb, b.Idx, b.P, b.Ig) : null);
    }
}
