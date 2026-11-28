// Question cards (a deterministic, structured form of a cell question: the sentence, one fact line per dimension, the verb's reversibility, the
// three answers and the typed "partly" slots) and the parser that turns card input into the learner's answer. Cards and inputs are JSON trees.
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentUx
{
    static readonly Regex FieldRe = new(@"^(?:action\.params\.[a-z_][a-z0-9_]*|action\.resource)\z", RegexOptions.CultureInvariant);

    static string Ns(double d) => JsX.JsNumString(d);

    static D Fact(Dim d, int i)
    {
        var m = new D { ["path"] = d.Path, ["label"] = IntentRender.LabelOf(d.Path) };
        if (d is NumDim nd)
        {
            var c = NumCells(nd)[i];
            m["text"] = c.Lo == c.Hi ? "exactly " + Ns(c.Lo) : "any value from " + Ns(c.Lo) + " to " + Ns(c.Hi) + " (for example " + Ns(NumRep(nd, i)) + ")";
        }
        else
        {
            var v = ((CatDim)d).Values[i];
            m["text"] = v.Kind == "exact" ? "\"" + v.Value + "\"" : v.Kind == "prefix" ? "anything under \"" + v.Value + "\" not named elsewhere" : "any value not named anywhere in the grant or your request";
        }
        return m;
    }

    public static D QuestionCard(Omega omega, string verb, int[] cell, Catalog? catalog = null)
    {
        var vs = VerbSpaceOf(omega, verb) ?? throw new ArgumentException("questionCard: no verb " + verb);
        var facts = new L();
        var partial = new L();
        for (int k = 0; k < vs.Dims.Count; k++)
        {
            var d = vs.Dims[k];
            facts.Add(Fact(d, cell[k]));
            var slot = new D { ["path"] = d.Path };
            if (d is NumDim nd)
            {
                var c = NumCells(nd)[cell[k]];
                slot["kind"] = "num";
                slot["lo"] = N(c.Lo);
                slot["hi"] = N(c.Hi);
            }
            else
            {
                slot["kind"] = "cat";
                slot["options"] = ((CatDim)d).Values.Where(v => v.Kind == "exact").Select(v => (object?)v.Value).ToList();
            }
            partial.Add(slot);
        }
        var body = new D
        {
            ["v"] = new Num("1"),
            ["verb"] = verb,
            ["cell"] = cell.Select(x => (object?)new Num(x.ToString(System.Globalization.CultureInfo.InvariantCulture))).ToList(),
            ["sentence"] = IntentRender.RenderQuestion(vs, cell, catalog),
            ["facts"] = facts,
            ["reversibility"] = vs.Reversibility,
            ["answers"] = new L { "yes", "no", "partly" },
            ["partial"] = partial,
        };
        var card = new D(body) { ["digest"] = Pca.HashCanonical(new D { ["d"] = "atlas-pca/intent-card/v1", ["c"] = IntentRuntime.JsonNums(body) }) };
        return card;
    }

    static D Res(object? answer) => new() { ["ok"] = true, ["answer"] = answer };
    static D Err(string e) => new() { ["ok"] = false, ["error"] = e };

    static D Part(params object?[] kv)
    {
        var m = new D();
        for (int i = 0; i + 1 < kv.Length; i += 2) m[(string)kv[i]!] = kv[i + 1];
        return m;
    }

    /// <summary>The distinct non-empty strings of the list in first-seen order; throws when it is not an array (the reference calls .filter).</summary>
    static L NamedValues(object? list)
    {
        if (list is not L l) throw new ArgumentException("filter is not a function");
        var o = new L();
        foreach (var x in l) if (x is string s && s.Length > 0 && !o.Contains(s)) o.Add(s);
        return o;
    }

    static bool Has(object? o, string k) => o is D m && m.ContainsKey(k);
    static object? Get(object? o, string k) => o is D m ? m.GetValueOrDefault(k) : null;

    static bool InRange(object? x, double lo, double hi)
    {
        if (!IsNum(x)) return false;
        double v = Dbl(x);
        return double.IsFinite(v) && v == Math.Round(v) && BitConverter.DoubleToInt64Bits(v) != BitConverter.DoubleToInt64Bits(-0.0) && v >= lo && v <= hi;
    }

    static object? Nm(double d) => N(d);

    /// <summary>Turn the UI input into the learner's answer: {ok: true, answer} or {ok: false, error}.</summary>
    public static D ParseCardAnswer(object? card, object? input)
    {
        if ((Get(input, "answer") as string) != "partly") return Res(Get(input, "answer") is string a && a == "yes" ? N(1) : N(0));
        var slots = Arr(Get(card, "partial"));
        if (Has(input, "newField"))
        {
            string nf = JsX.Str(Get(input, "newField"));
            if (!FieldRe.IsMatch(nf)) return Err("unknown field " + nf);
            foreach (var s in slots) if (Get(s, "path") is string sp0 && sp0 == nf) return Err(nf + " is already on the card; answer partly for it directly");
            var vals = NamedValues(Get(input, "notFor"));
            if (vals.Count == 0) return Err("name at least one value");
            var dvals = new L();
            foreach (var v in vals) dvals.Add(Part("kind", "exact", "value", v));
            dvals.Add(Part("kind", "other", "value", Other));
            return Res(Part("kind", "partial", "path", nf, "newDim", Part("kind", "cat", "path", nf, "values", dvals),
                "parts", new L { Part("values", vals, "y", N(0)), Part("other", true, "y", N(1)) }));
        }
        var path = Get(input, "path");
        object? slot = null;
        if (path is string ps) foreach (var s in slots) if (Get(s, "path") is string sp1 && sp1 == ps) { slot = s; break; }
        if (slot == null) return Err("the card has no field " + (Has(input, "path") ? JsX.Str(path) : "undefined"));
        var sp = (string)Get(slot, "path")!;
        if ((Get(slot, "kind") as string) == "num")
        {
            double lo = Dbl(Get(slot, "lo")), hi = Dbl(Get(slot, "hi"));
            if (Has(input, "upTo"))
            {
                var x = Get(input, "upTo");
                if (!InRange(x, lo, hi) || Dbl(x) == hi) return Err("upTo must be an integer in [" + Ns(lo) + ", " + Ns(hi - 1) + "]");
                double u = Dbl(x);
                return Res(Part("kind", "partial", "path", sp, "cuts", new L { N(u) },
                    "parts", new L { Part("lo", N(lo), "hi", N(u), "y", N(1)), Part("lo", N(u + 1), "hi", N(hi), "y", N(0)) }));
            }
            if (Has(input, "from"))
            {
                var x = Get(input, "from");
                if (!InRange(x, lo, hi) || Dbl(x) == lo) return Err("from must be an integer in [" + Ns(lo + 1) + ", " + Ns(hi) + "]");
                double f = Dbl(x);
                return Res(Part("kind", "partial", "path", sp, "cuts", new L { N(f) },
                    "parts", new L { Part("lo", N(lo), "hi", N(f - 1), "y", N(0)), Part("lo", N(f), "hi", N(hi), "y", N(1)) }));
            }
            if (Has(input, "except"))
            {
                var ex0 = Get(input, "except");
                if (ex0 != null && ex0 is not L && ex0 is not string) throw new ArgumentException("not iterable");
                var ex = new List<double>();
                bool allIn = true;
                if (ex0 is L exl)
                {
                    var seen = new List<double>();
                    foreach (var x in exl)
                    {
                        if (!InRange(x, lo, hi)) allIn = false;
                        else { double dv = Dbl(x) + 0.0; if (!seen.Contains(dv)) seen.Add(dv); }
                    }
                    ex.AddRange(seen);
                    ex.Sort();
                }
                else allIn = false;
                if ((ex0 is L e2 && e2.Count == 0) || ex0 == null || !allIn) return Err("except values must be integers in [" + Ns(lo) + ", " + Ns(hi) + "]");
                var parts = new L();
                foreach (double x in ex) parts.Add(Part("lo", N(x), "hi", N(x), "y", N(0)));
                parts.Add(Part("lo", N(lo), "hi", N(hi), "y", N(1)));
                return Res(Part("kind", "partial", "path", sp, "cuts", ex.Select(Nm).ToList(), "parts", parts));
            }
            return Err("a numeric partly answer needs upTo, from or except");
        }
        if (!Has(input, "notFor")) return Err("a categorical partly answer needs notFor");
        var nv = NamedValues(Get(input, "notFor"));
        if (nv.Count == 0) return Err("name at least one value");
        return Res(Part("kind", "partial", "path", sp, "values", nv, "parts", new L { Part("values", nv, "y", N(0)), Part("other", true, "y", N(1)) }));
    }
}
