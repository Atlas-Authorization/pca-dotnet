// What you see is what you sign (track K7): a port of packages/pca/src/approval-render.ts (render shape, H(R), the approval
// challenge, the speakable match code) and packages/pca-actions/src/approval-render.ts + approval-profiles.ts (the canonical render of
// an action, the PSD2 RTS Art. 5 linking view, the batch commitment). A render that cannot be made completely throws
// ActionKitError rather than returning something partial.
using System.Security.Cryptography;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class Approval
{
    public const string RenderDomain = "atlas-pca/approval-render/v1";
    public const string ChallengeDomain = "atlas-pca/approval-challenge/v1\0";
    public const string BatchDomain = "atlas-pca/approval-batch/v1";
    const string ItemDomain = "atlas-pca/approval-batch-item/v1";
    const string PayeeDomain = "atlas-pca/approval-payee/v1";
    const int MaxFields = 64, MaxDepth = 3;
    const long MaxSafe = 9007199254740991;

    public static readonly string[] Words =
    {
        "able", "acid", "aged", "also", "area", "army", "atom", "aunt",
        "away", "baby", "back", "ball", "band", "bank", "base", "bath",
        "bear", "beat", "beef", "bell", "belt", "bend", "bird", "blue",
        "boat", "body", "bold", "bone", "book", "boot", "born", "both",
        "bowl", "bulb", "burn", "bush", "busy", "cafe", "cake", "calm",
        "camp", "card", "care", "cart", "case", "cash", "cast", "cave",
        "cell", "chat", "chef", "chip", "city", "clay", "clip", "club",
        "coal", "coat", "code", "coin", "cold", "cook", "cool", "cope",
        "copy", "cord", "core", "cost", "crew", "crop", "dark", "data",
        "date", "dawn", "deal", "dear", "deck", "deep", "deer", "desk",
        "dial", "dice", "diet", "dish", "dive", "door", "dose", "down",
        "draw", "drop", "drum", "duck", "dust", "duty", "each", "earn",
        "east", "easy", "edge", "echo", "else", "even", "ever", "exit",
        "face", "fact", "fair", "fall", "farm", "fast", "fate", "fern",
        "file", "fill", "film", "find", "fine", "fire", "firm", "fish",
        "five", "flag", "flat", "flow", "foam", "fold", "folk", "food",
        "foot", "fork", "form", "fort", "four", "free", "frog", "fuel",
        "full", "fund", "gain", "game", "gate", "gear", "gift", "girl",
        "glad", "glow", "goat", "gold", "golf", "good", "grab", "gray",
        "grid", "grip", "grow", "gulf", "hair", "half", "hall", "hand",
        "hard", "harp", "hawk", "head", "heat", "help", "herb", "hill",
        "hint", "hold", "hole", "home", "hood", "hook", "hope", "horn",
        "host", "hour", "huge", "hunt", "idea", "inch", "iron", "isle",
        "item", "jade", "jazz", "join", "joke", "jump", "jury", "just",
        "keen", "keep", "kind", "king", "kite", "knee", "knot", "lake",
        "lamp", "land", "lane", "last", "late", "lawn", "lead", "leaf",
        "lean", "left", "lens", "less", "lift", "lime", "line", "link",
        "lion", "list", "live", "load", "loan", "lock", "logo", "long",
        "loop", "lord", "loud", "love", "luck", "lung", "made", "mail",
        "main", "mask", "mass", "mate", "meal", "melt", "menu", "mild",
        "milk", "mind", "mint", "mole", "moon", "more", "moss", "move",
        "much", "nail", "navy", "neat", "neck", "nest", "news", "nice",
    };

    static object? N(long v) => IntentJs.OfLong(v);
    static bool DigestOk(object? v) => v is string s && Pca.B64uDecode(s, 32) != null;
    static bool Bounded(object? v, int max) => v is string s && s.Length > 0 && Encoding.UTF8.GetByteCount(s) <= max;
    static bool Lone(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) i++;
            else if (char.IsSurrogate(s[i])) return true;
        }
        return false;
    }
    static string? Closed(D o, string[] required, string[] optional)
    {
        foreach (var k in o.Keys) if (!required.Contains(k) && !optional.Contains(k)) return $"unknown member '{k}'";
        foreach (var k in required) if (!o.ContainsKey(k)) return $"missing member '{k}'";
        return null;
    }

    /// <summary>Null if <paramref name="r"/> is a well-formed render (closed members, sorted unique ids, bounded), else the reason.</summary>
    public static string? RenderShapeError(object? r)
    {
        if (r is not D o) return "render must be an object";
        var e = Closed(o, new[] { "v", "kind", "verb", "def_digest", "unreviewed", "fields" }, Array.Empty<string>());
        if (e != null) return e;
        if (!(IntentJs.IsInt(o["v"]) && IntentJs.NumOf(o["v"]) == 1) || o["kind"] is not "pca-approval-render") return "not a pca-approval-render v1";
        if (!Bounded(o["verb"], 128)) return "verb must be a bounded string";
        if (!DigestOk(o["def_digest"])) return "def_digest must be canonical base64url (32 bytes)";
        if (o["unreviewed"] is not bool) return "unreviewed must be a boolean";
        if (o["fields"] is not L fs || fs.Count > MaxFields) return $"fields must be an array of at most {MaxFields}";
        string? prev = null;
        foreach (var fo in fs)
        {
            if (fo is not D f) return "a field must be an object";
            e = Closed(f, new[] { "id", "class", "value" }, new[] { "unit" });
            if (e != null) return e;
            if (!Bounded(f["id"], 192) || !Bounded(f["class"], 128)) return "field id and class must be bounded strings";
            var id = (string)f["id"]!;
            if (prev != null && string.CompareOrdinal(prev, id) >= 0) return "fields must be sorted by id and unique";
            prev = id;
            if (f.ContainsKey("unit"))
            {
                if (f["unit"] is not D u) return "unit must be an object";
                if (u.GetValueOrDefault("kind") is "money")
                {
                    if (Closed(u, new[] { "kind", "ccy", "exp" }, Array.Empty<string>()) != null || !Bounded(u["ccy"], 16) || !IntentJs.IsInt(u["exp"])
                        || IntentJs.NumOf(u["exp"])!.Value < 0 || IntentJs.NumOf(u["exp"])!.Value > 18) return "a money unit needs ccy and exp";
                }
                else if (u.GetValueOrDefault("kind") is not ("count" or "bytes" or "duration" or "ratio") || Closed(u, new[] { "kind" }, Array.Empty<string>()) != null) return "unknown unit";
            }
        }
        return null;
    }

    /// <summary>H(R). A malformed render throws (a digest is never made over a shapeless value).</summary>
    public static string RenderDigest(object? render)
    {
        var e = RenderShapeError(render);
        if (e != null) throw new ArgumentException("approvalRenderDigest: " + e);
        return Pca.HashCanonical(new D { ["d"] = RenderDomain, ["render"] = render });
    }

    /// <summary>b64u(SHA-256(domain || action_digest || H(R))); both digests must be canonical 32-byte values.</summary>
    public static string Challenge(object? actionDigest, object? renderDigest)
    {
        var a = actionDigest is string x ? Pca.B64uDecode(x, 32) : null;
        var r = renderDigest is string y ? Pca.B64uDecode(y, 32) : null;
        if (a == null || r == null) throw new ArgumentException("approvalChallenge: both digests must be canonical 32-byte values");
        return Pca.B64u(SHA256.HashData(Encoding.UTF8.GetBytes(ChallengeDomain).Concat(a).Concat(r).ToArray()));
    }

    public static string BindingWords(object? renderDigest)
    {
        var r = renderDigest is string x ? Pca.B64uDecode(x, 32) : null;
        if (r == null) throw new ArgumentException("bindingWords: render digest must be a canonical 32-byte value");
        return string.Join("-", Enumerable.Range(0, 6).Select(i => Words[r[i]]));
    }

    // ---- the render ----------------------------------------------------------------------------------------------------

    static void Flatten(D output, string prefix, int depth, object? v)
    {
        if (v is D m && depth < MaxDepth && m.Count > 0)
        {
            foreach (var (k, x) in m)
            {
                if (k.Contains('.')) throw new ActionKitError("render_bad_params", $"the parameter key '{k}' contains a dot");
                Flatten(output, prefix.Length == 0 ? k : prefix + "." + k, depth + 1, x);
            }
        }
        else output[prefix] = v;
    }

    static bool LeafOk(object? v) => v switch
    {
        string s => !Lone(s),
        bool => true,
        L l => l.All(LeafOk),
        _ => IntentJs.IsInt(v),
    };

    static bool ValueOk(string type, object? v) => type switch
    {
        "integer" or "duration" => IntentJs.IsInt(v),
        "boolean" => v is bool,
        "string" or "date" or "datetime" or "object_ref" => v is string s && !Lone(s),
        "set" or "array" => v is L && LeafOk(v),
        _ => false,
    };

    /// <summary>The canonical approval render of <paramref name="def"/> for <paramref name="parms"/>. <paramref name="confirmed"/>: whether the
    /// definition carries a valid signed confirmation (the caller decides, as for Effective); an unconfirmed render carries unreviewed: true.</summary>
    public static D Render(D def, object? parms, bool confirmed = false)
    {
        if (parms is not D p) throw new ActionKitError("render_bad_params", "params must be an object");
        var n = Actions.Normalize(def);
        var np = (D)n["params"]!;
        var flat = new D();
        foreach (var (k, v) in p)
        {
            if (k.Contains('.')) throw new ActionKitError("render_bad_params", $"the parameter key '{k}' contains a dot");
            Flatten(flat, k, 1, v);
        }
        foreach (var k in flat.Keys) if (!np.ContainsKey(k)) throw new ActionKitError("render_undeclared_param", $"'{k}' is not a parameter of {n["verb"]}");
        foreach (var (k, pv) in np) if (((D)pv!).GetValueOrDefault("required") is true && !flat.ContainsKey(k)) throw new ActionKitError("render_missing_param", $"required parameter '{k}' of {n["verb"]} is missing");
        var fields = new L();
        foreach (var id in flat.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            var pd = (D)np[id]!;
            if (!ValueOk((string)pd["type"]!, flat[id])) throw new ActionKitError("render_bad_value", $"'{id}' is not a {pd["type"]} in the canonical domain");
            var f = new D { ["id"] = id, ["class"] = pd.TryGetValue("role", out var role) ? role : "param", ["value"] = flat[id] };
            if (pd.GetValueOrDefault("unit") is D u)
            {
                if (u.GetValueOrDefault("kind") is "money")
                {
                    var c = u["ccy"];
                    var ccy = c is string cs ? cs : c is D cd && cd.GetValueOrDefault("from") is string fromKey ? flat.GetValueOrDefault(fromKey) : null;
                    if (ccy is not string css || css.Length == 0) throw new ActionKitError("render_unresolved_currency", $"the currency of '{id}' is not a string");
                    f["unit"] = new D { ["kind"] = "money", ["ccy"] = css, ["exp"] = u["exp"] };
                }
                else f["unit"] = new D { ["kind"] = u["kind"] };
            }
            fields.Add(f);
        }
        return new D { ["v"] = N(1), ["kind"] = "pca-approval-render", ["verb"] = n["verb"], ["def_digest"] = Actions.DefDigest(def), ["unreviewed"] = !confirmed, ["fields"] = fields };
    }

    // ---- PSD2 RTS Art. 5 -----------------------------------------------------------------------------------------------

    static ActionKitError Unlinkable(string m) => new("psd2_unlinkable", m);

    /// <summary>The amount and the payee of a payment render (Art. 5(1)).</summary>
    public static D Psd2Linking(D r)
    {
        if (r.GetValueOrDefault("unreviewed") is true) throw Unlinkable("an unreviewed definition cannot be a payment approval");
        var fs = ((L)r["fields"]!).Cast<D>().ToList();
        var amts = fs.Where(f => f["class"] is "money.amount").ToList();
        var payees = fs.Where(f => f["class"] is "party.payee").ToList();
        if (amts.Count != 1) throw Unlinkable("a payment approval needs exactly one money.amount parameter");
        var a = amts[0];
        if (a.GetValueOrDefault("unit") is not D u || u.GetValueOrDefault("kind") is not "money") throw Unlinkable("the money.amount parameter has no money unit");
        if (!IntentJs.IsInt(a["value"]) || IntentJs.NumOf(a["value"])!.Value < 0) throw Unlinkable("the amount must be a non-negative integer in minor units");
        if (payees.Count != 1 || payees[0]["value"] is not string ps || ps.Length == 0) throw Unlinkable("a payment approval needs exactly one non-empty party.payee parameter");
        return new D { ["amount_minor"] = a["value"], ["currency"] = u["ccy"], ["exp"] = u["exp"], ["payee"] = ps };
    }

    /// <summary>Minor units as the decimal string of the major unit, without floating point.</summary>
    public static string MinorToDecimal(long minor, long exp)
    {
        if (minor < 0 || exp < 0 || exp > 18) throw Unlinkable("minor units must be a non-negative safe integer");
        var s = minor.ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (exp == 0) return s;
        s = s.PadLeft((int)exp + 1, '0');
        return s[..^(int)exp] + "." + s[^(int)exp..];
    }

    /// <summary>One approval over N payments: per-currency totals, the payee set and every item (Art. 5(3)(b)). Items are {action_digest, render}.</summary>
    public static D Batch(IReadOnlyList<object?> items)
    {
        if (items.Count == 0) throw Unlinkable("a batch needs at least one payment");
        var totals = new SortedDictionary<string, (long Exp, long Minor)>(StringComparer.Ordinal);
        var payees = new SortedSet<string>(StringComparer.Ordinal);
        var leaves = new List<object?>();
        foreach (var io in items)
        {
            var it = (D)io!;
            var link = Psd2Linking((D)it["render"]!);
            var ccy = (string)link["currency"]!;
            long exp = IntentJs.Lng(link["exp"]), amt = IntentJs.Lng(link["amount_minor"]);
            if (totals.TryGetValue(ccy, out var t) && t.Exp != exp) throw Unlinkable($"currency {ccy} appears with two exponents");
            long minor = (totals.TryGetValue(ccy, out var t2) ? t2.Minor : 0) + amt;
            if (minor > MaxSafe) throw Unlinkable("the batch total exceeds the safe integer range");
            totals[ccy] = (exp, minor);
            payees.Add((string)link["payee"]!);
            leaves.Add(new D { ["d"] = ItemDomain, ["a"] = it["action_digest"], ["r"] = RenderDigest(it["render"]) });
        }
        var tl = new L(totals.Select(kv => (object?)new D { ["ccy"] = kv.Key, ["exp"] = N(kv.Value.Exp), ["minor"] = N(kv.Value.Minor) }));
        var pl = payees.Select(p => (object?)new D { ["d"] = PayeeDomain, ["payee"] = p }).ToList();
        var batch = new D { ["v"] = N(1), ["kind"] = "pca-approval-batch", ["n"] = N(items.Count), ["totals"] = tl, ["payees_root"] = Pca.MerkleRoot(pl), ["items_root"] = Pca.MerkleRoot(leaves) };
        var rd = Pca.HashCanonical(new D { ["d"] = BatchDomain, ["batch"] = batch });
        return new D { ["batch"] = batch, ["action_digest"] = batch["items_root"], ["render_digest"] = rd, ["challenge"] = Challenge(batch["items_root"], rd), ["words"] = BindingWords(rd) };
    }
}
