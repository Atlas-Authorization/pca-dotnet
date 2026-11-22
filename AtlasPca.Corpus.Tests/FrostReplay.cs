using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Shared machinery of the networked-FROST and FROST-DKG replays: corpus values to runtime values ({"$bytes"}, {"$share"} dealer shares, {"$num"}), the scripted randomness of a case ({"$rng"}), the typed-error
/// capture (class and fields compared exactly, message text informative) and the comparison with the reference output ("reasonOpen": a refusal that wraps an inner primitive error must refuse, its text is not compared).</summary>
static class FrostReplay
{
    /// <summary>The 32-byte draws the reference made, in order; a draw beyond the script is a failure.</summary>
    public sealed class Rng(IEnumerable<byte[]> vals)
    {
        readonly Queue<byte[]> _q = new(vals);
        public byte[] Next() => _q.Count > 0 ? _q.Dequeue().ToArray() : throw new InvalidOperationException("unscripted randomness draw");
        public int Left => _q.Count;
    }

    static readonly Dictionary<string, byte[]> ShareCache = new();

    /// <summary>The dealer share of participant <c>id</c>: the lane's own trusted-dealer keygen on the descriptor's seeds (no share value is in a corpus).</summary>
    static byte[] DealerShare(D d)
    {
        var key = Base.Show(d);
        lock (ShareCache)
        {
            if (ShareCache.TryGetValue(key, out var s)) return s.ToArray();
            var o = new Frost.FrostKeygenOpts();
            if (d.GetValueOrDefault("secret") is { } sec) o.Secret = Base.Bytes(sec);
            if (d.GetValueOrDefault("coefficients") is L cs) o.Coefficients = cs.Select(Base.Bytes).ToList();
            if (d.GetValueOrDefault("identifiers") is L ids) o.Identifiers = ids.Select(Base.Long).ToArray();
            var kg = Frost.TrustedDealerKeygen((int)Base.Long(d["t"]), (int)Base.Long(d["n"]), o);
            var id = Base.Long(d["id"]);
            s = kg.ParticipantShares.First(p => p.Identifier == id).Share;
            ShareCache[key] = s;
            return s.ToArray();
        }
    }

    /// <summary>Corpus form to runtime form: byte strings and dealer shares become byte[], {"$num"} a double; objects and lists are rebuilt (numbers stay as parsed).</summary>
    public static object? Un(object? v) => v switch
    {
        D m when m.Count == 1 && m.ContainsKey("$bytes") => Base.Bytes(m),
        D m when m.Count == 1 && m.ContainsKey("$share") => DealerShare((D)m["$share"]!),
        D m when m.Count == 1 && m.ContainsKey("$num") => (string)m["$num"]! == "NaN" ? double.NaN : (string)m["$num"]! == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m => m.ToDictionary(e => e.Key, e => Un(e.Value)),
        L l => l.Select(Un).ToList(),
        _ => v,
    };

    /// <summary>A refusal as the reference prints it: {"$throws": message} plus, for a typed error, its class and fields.</summary>
    public static D ErrOut(Exception e, Action<Exception, D>? extra = null)
    {
        var o = new D { ["$throws"] = e.Message };
        switch (e)
        {
            case PoPError p:
                o["class"] = "PoPError";
                if (p.Identifier != null) o["identifier"] = p.Identifier;
                break;
            case EquivocationError q:
                o["class"] = "EquivocationError";
                o["session_id"] = q.SessionId; o["round"] = q.Round; o["identifier"] = q.Identifier; o["previousDigest"] = q.PreviousDigest; o["offendingDigest"] = q.OffendingDigest;
                break;
            case CoordinatorTimeoutError t:
                o["class"] = "CoordinatorTimeoutError"; o["refusals"] = t.Refusals.ToList(); o["timeoutMs"] = t.TimeoutMs;
                break;
            case CoordinatorError c:
                o["class"] = "CoordinatorError"; o["refusals"] = c.Refusals.ToList();
                break;
            default: extra?.Invoke(e, o); break;
        }
        return o;
    }

    static bool Keys(D w, D h, HashSet<string> skipW, HashSet<string> skipH, out string why)
    {
        var wk = w.Keys.Where(k => !skipW.Contains(k)).OrderBy(k => k, StringComparer.Ordinal).ToList();
        var hk = h.Keys.Where(k => !skipH.Contains(k)).OrderBy(k => k, StringComparer.Ordinal).ToList();
        why = "";
        if (!wk.SequenceEqual(hk)) { why = $"members differ: want [{string.Join(",", wk)}] have [{string.Join(",", hk)}]"; return false; }
        foreach (var k in wk)
            if (!Match(w[k], h[k], out var inner)) { why = k + ": " + inner; return false; }
        return true;
    }

    /// <summary>Does <paramref name="have"/> (already a JSON tree) match the reference output? A refusal ("$throws") matches a refusal with the same class and fields; "reasonOpen" objects need only refuse.</summary>
    public static bool Match(object? want, object? have, out string why)
    {
        why = "";
        if (want is D w)
        {
            if (have is not D h) { why = "want an object"; return false; }
            if (w.ContainsKey("$throws"))
            {
                if (!h.ContainsKey("$throws")) { why = "want a refusal"; return false; }
                return Keys(w, h, ["$throws"], ["$throws"], out why);
            }
            if (w.GetValueOrDefault("reasonOpen") is true)
            {
                if (!h.ContainsKey("reason")) { why = "want a refusal reason"; return false; }
                return Keys(w, h, ["reason", "reasonOpen"], ["reason", "reasonOpen"], out why);
            }
            return Keys(w, h, [], [], out why);
        }
        if (want is L wl)
        {
            if (have is not L hl || hl.Count != wl.Count) { why = "list length differs"; return false; }
            for (int i = 0; i < wl.Count; i++)
                if (!Match(wl[i], hl[i], out var inner)) { why = $"[{i}]: " + inner; return false; }
            return true;
        }
        if (Base.Show(want) == Base.Show(have)) return true;
        why = "value differs";
        return false;
    }

    /// <summary>Replay every case of (module, fn). <paramref name="run"/> gets the runtime-form arguments (the trailing {"$rng"} stripped into a <see cref="Rng"/>) and returns the native result, which
    /// is turned into a JSON tree; a thrown exception is captured as a refusal. Returns the number of cases compared.</summary>
    public static int Replay(string module, string fn, Func<L, Rng?, object?> run, int min, Action<Exception, D>? extra = null)
    {
        var bad = new List<string>();
        int n = 0;
        foreach (var c in Base.Of(module, fn))
        {
            n++;
            var items = Base.Args(c).ToList();
            Rng? rng = null;
            if (items.Count > 0 && items[^1] is D last && last.Count == 1 && last.ContainsKey("$rng"))
            {
                rng = new Rng(((L)last["$rng"]!).Select(Base.Bytes));
                items.RemoveAt(items.Count - 1);
            }
            object? have;
            try { have = Base.Json(run((L)Un(items)!, rng)); }
            catch (Exception e) { have = Base.Json(ErrOut(e, extra)); }
            if (!Match(c["out"], have, out var why)) bad.Add($"{c["name"]}\n   {why}\n   want {Base.Show(c["out"])}\n   have {Base.Show(have)}");
        }
        Assert.True(bad.Count == 0, $"{module}/{fn}: {bad.Count} of {n} divergent:\n" + string.Join("\n", bad.Take(30)));
        Assert.True(n >= min, $"{module}/{fn}: only {n} cases compared");
        return n;
    }

    // ---- argument typing shared by the harnesses (a JavaScript number is a double; anything else is refused as the static types refuse it) ----
    public static double Dbl(object? v) => v is not string && IntentJs.NumOf(v) is double d ? d : throw new ArgumentException("a number was expected");
    public static double? DblOpt(object? v) => v == null ? null : Dbl(v);
    public static long Lng(object? v) => v is not string && IntentJs.IsSafeInteger(v) ? IntentJs.Lng(v) : throw new ArgumentException("a safe integer was expected");
    public static byte[]? Bin(object? v) => v as byte[];
    public static string Flip(string s)
    {
        var b = Pca.B64uDecode(s) ?? throw new ArgumentException("not base64url");
        b[0] ^= 1;
        return Pca.B64u(b);
    }
}
