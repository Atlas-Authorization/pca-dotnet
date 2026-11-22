using System.Globalization;
using AtlasPca;
using AtlasPca.Spiffe;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Argument mapping shared by the two SPIFFE oracle replays: the oracle's option objects to the native option classes.</summary>
static class RefSpiffeKit
{
    /// <summary>A failure carrying the reference's code (the SpiffeError code, or "jose" for any other failure of a JWT / key step).</summary>
    public sealed class Coded : Exception
    {
        public string Code { get; }
        public Coded(string code, Exception cause) : base(cause.Message, cause) { Code = code; }
    }

    public static T W<T>(Func<T> f)
    {
        try { return f(); }
        catch (SpiffeError e) { throw new Coded(e.Code, e); }
        catch (Exception e) { throw new Coded("jose", e); }
    }

    public static object? Unbytes(object? o) => Base.IsBytes(o) ? Base.Bytes(o) : o;

    public static object? Chain(object? c) => c is L l ? l.Select(Unbytes).ToList() : c;

    public static long N(object? o) => long.Parse(((Num)o!).Raw, CultureInfo.InvariantCulture);

    /// <summary>A revocation check scripted by mode; every subject it sees is appended to <paramref name="calls"/> as JSON.</summary>
    static object? Verdict(string mode, int position)
    {
        switch (mode)
        {
            case "false": case "async-false": return false;
            case "true": case "async-true": return true;
            case "throw": case "async-throw": throw new InvalidOperationException("boom");
            case "one": return new Num("1");
            default:
                if (mode.StartsWith("true@", StringComparison.Ordinal)) return position == int.Parse(mode[5..], CultureInfo.InvariantCulture);
                if (mode.StartsWith("at:", StringComparison.Ordinal)) return position == int.Parse(mode[3..], CultureInfo.InvariantCulture);
                return new object(); // nonbool / undef / promise: not a boolean
        }
    }

    public static object? X509Rev(string? mode, L calls)
    {
        if (mode == null) return null;
        if (mode == "notfn") return SpiffeBridge.NotAFunction;
        return (X509RevocationCheck)(s => { calls.Add(s.ToJson()); return Verdict(mode, s.Position); });
    }

    public static object? JwtRev(string? mode, L calls)
    {
        if (mode == null) return null;
        if (mode == "notfn") return SpiffeBridge.NotAFunction;
        return (JwtRevocationCheck)(s => { calls.Add(s.ToJson()); return Verdict(mode, 0); });
    }

    /// <summary>The option object's "revocation": absent = not checked; <paramref name="nullIsNotAFunction"/>: an explicit null is an option that is not a function.</summary>
    static object? RevOf(D o, L calls, bool jwt, bool nullIsNotAFunction)
    {
        if (!o.TryGetValue("revocation", out var m)) return null;
        if (m == null) return nullIsNotAFunction ? SpiffeBridge.NotAFunction : null;
        return jwt ? JwtRev((string)m, calls) : X509Rev((string)m, calls);
    }

    public static VerifyX509SvidOptions X509Opts(D o, L calls, bool nullIsNotAFunction)
    {
        var v = new VerifyX509SvidOptions { TrustDomain = o.GetValueOrDefault("trustDomain") as string };
        if (o.GetValueOrDefault("roots") is L roots) foreach (var r in roots) v.Roots.Add(Unbytes(r));
        if (o.GetValueOrDefault("nowMs") is Num nm) v.NowMs = long.Parse(nm.Raw, CultureInfo.InvariantCulture);
        if (o.GetValueOrDefault("maxChainLength") is Num mc) v.MaxChainLength = long.Parse(mc.Raw, CultureInfo.InvariantCulture);
        v.Revocation = RevOf(o, calls, false, nullIsNotAFunction);
        return v;
    }

    /// <summary>Options for a JWT-SVID verification; an option of the wrong JSON type is refused the way the reference refuses it (an error without a code).</summary>
    public static VerifyJwtSvidOptions JwtOpts(D s, object? key, L calls, bool nullIsNotAFunction)
    {
        var o = new VerifyJwtSvidOptions { Key = key, TrustDomain = s.GetValueOrDefault("trustDomain") as string };
        var aud = s.GetValueOrDefault("audience");
        if (aud is string a) o.Audience.Add(a);
        else if (aud is L al) foreach (var x in al) o.Audience.Add(x as string ?? throw new ArgumentException("audience entries must be strings"));
        else throw new ArgumentException("audience must be a string or an array");
        if (s.GetValueOrDefault("currentDateMs") is Num cd) o.CurrentDateMs = double.Parse(cd.Raw, CultureInfo.InvariantCulture);
        else if (s.GetValueOrDefault("currentSec") is Num cs) o.CurrentDateMs = double.Parse(cs.Raw, CultureInfo.InvariantCulture) * 1000;
        if (s.ContainsKey("algorithms") && s["algorithms"] != null)
        {
            if (s["algorithms"] is not L algs) throw new ArgumentException("algorithms must be an array");
            o.Algorithms = algs.Select(x => x as string ?? throw new ArgumentException("algorithm entries must be strings")).ToList();
        }
        if (s.ContainsKey("clockTolerance")) o.ClockTolerance = s["clockTolerance"];
        o.Revocation = RevOf(s, calls, true, nullIsNotAFunction);
        return o;
    }

    public static SvidToHolderOptions Bind(D? b) => b == null ? new SvidToHolderOptions() : new SvidToHolderOptions { Proof = b.GetValueOrDefault("proof"), AcceptUnboundJwtHolder = b.GetValueOrDefault("acceptUnbound") is true || b.GetValueOrDefault("acceptUnboundJwtHolder") is true };

    public static double Ms(object? v) => v is Num n ? double.Parse(n.Raw, CultureInfo.InvariantCulture) : double.NaN;
}
