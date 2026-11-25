// The shared frame of the per-store conformance suites (bond store, ledger store, budget ledger, mesh witness store): a named check with a claim, a
// run that reports pass / fail / skip per check, and the assertion helpers the checks use. A check passes by returning and fails by throwing; the
// report carries the first line of the failure.
using System.Globalization;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>What a check runs against: one isolated backend plus the means to reconnect to it.</summary>
public interface ISuiteHandle
{
    /// <summary>True when a crash is implemented (a check that needs a crash is skipped otherwise).</summary>
    bool CanCrash => false;

    /// <summary>Release the backend (never drop shared data of another handle).</summary>
    void Close() { }
}

/// <summary>One claim about a store, driven through an adapter's handle. <see cref="Needs"/> is null, <c>"durable"</c> or <c>"crash"</c>.</summary>
public sealed class SuiteCheck<H> where H : ISuiteHandle
{
    public string Name { get; }
    public string Claim { get; }
    public string? Needs { get; }
    public Action<H> Body { get; }

    public SuiteCheck(string name, string claim, string? needs, Action<H> body) { Name = name; Claim = claim; Needs = needs; Body = body; }

    public SuiteCheck(string name, string claim, Action<H> body) : this(name, claim, null, body) { }
}

/// <summary>One check's outcome: <c>pass</c>, <c>fail</c> or <c>skip</c>.</summary>
public sealed record SuiteResult(string Name, string Status, string? Detail);

/// <summary>A suite run's report.</summary>
public sealed class SuiteReport
{
    public string Adapter { get; }
    public string Suite { get; }
    public string Status { get; }
    public IReadOnlyList<SuiteResult> Checks { get; }

    internal SuiteReport(string suite, string adapter, List<SuiteResult> checks)
    {
        Suite = suite;
        Adapter = adapter;
        Checks = checks;
        Status = checks.Any(r => r.Status == "fail") ? "fail" : "pass";
    }

    /// <summary>Whether no check failed.</summary>
    public bool Ok => Status == "pass";

    public SuiteResult Check(string name) => Checks.FirstOrDefault(r => r.Name == name) ?? throw new ArgumentException("no check " + name);

    public int Count(string status) => Checks.Count(r => r.Status == status);

    /// <summary>The text report.</summary>
    public string Format()
    {
        var sb = new System.Text.StringBuilder($"pca-store-conformance ({Suite}): {Adapter} -> {Status.ToUpperInvariant()}");
        foreach (var c in Checks)
        {
            sb.Append("\n  [").Append(c.Status.ToUpperInvariant()).Append("] ").Append(c.Name);
            if (c.Detail != null) sb.Append(": ").Append(c.Detail.Split('\n')[0]);
        }
        return sb.ToString();
    }

    public override string ToString() => Format();
}

/// <summary>A failed assertion of a suite check.</summary>
public sealed class SuiteAssertionException(string message) : Exception(message);

public static class StoreSuite
{
    /// <summary>Run <paramref name="checks"/> (only those named in <paramref name="only"/> when non-null) against fresh handles from <paramref name="make"/>. A check that
    /// needs durability is skipped when <paramref name="durable"/> is false; one that needs a crash is skipped when the handle cannot crash.</summary>
    public static SuiteReport Run<H>(string suite, string adapter, bool durable, Func<H> make, IEnumerable<SuiteCheck<H>> checks, ICollection<string>? only = null)
        where H : ISuiteHandle
    {
        var output = new List<SuiteResult>();
        foreach (var c in checks)
        {
            if (only != null && !only.Contains(c.Name)) continue;
            if (c.Needs == "durable" && !durable)
            {
                output.Add(new SuiteResult(c.Name, "skip", "the adapter declares durable: false"));
                continue;
            }
            H? h = default;
            try
            {
                h = make();
                if (c.Needs == "crash" && !h.CanCrash)
                {
                    output.Add(new SuiteResult(c.Name, "skip", "the adapter has no crash()"));
                    continue;
                }
                c.Body(h);
                output.Add(new SuiteResult(c.Name, "pass", null));
            }
            catch (Exception e)
            {
                output.Add(new SuiteResult(c.Name, "fail", string.IsNullOrEmpty(e.Message) ? e.ToString() : e.Message));
            }
            finally
            {
                if (h != null) { try { h.Close(); } catch (Exception) { /* closing is best effort */ } }
            }
        }
        return new SuiteReport(suite, adapter, output);
    }

    // ---- assertions ----

    /// <summary>Numbers print as JavaScript prints them; everything else is kept.</summary>
    public static object? Norm(object? v)
    {
        switch (v)
        {
            case Num n: return IntentJs.NumOf(n) is double d ? StoreJs.Number(d) : v;
            case int or long or short or byte or float or double: return StoreJs.Number(Convert.ToDouble(v, CultureInfo.InvariantCulture));
            case D m:
                {
                    var o = new D();
                    foreach (var e in m) o[e.Key] = Norm(e.Value);
                    return o;
                }
            case System.Collections.IEnumerable en when v is not string: return en.Cast<object?>().Select(Norm).ToList();
            default: return v;
        }
    }

    static string Text(object? v) => JsCanon.Lenient(Norm(v)) ?? "<not canonicalizable>";

    /// <summary>Deep JSON equality (numbers by value, objects by member).</summary>
    public static void Eq(object? want, object? got, string? what = null)
    {
        string a = Text(want), b = Text(got);
        if (a != b) throw new SuiteAssertionException((what == null ? "" : what + ": ") + "expected " + a + " but got " + b);
    }

    public static void Ok(bool cond, string what)
    {
        if (!cond) throw new SuiteAssertionException(what);
    }

    /// <summary>The call must throw <typeparamref name="T"/>; anything else (including no throw) fails.</summary>
    public static void Rejects<T>(Action f, string what) where T : Exception
    {
        try { f(); }
        catch (Exception t)
        {
            if (t is T) return;
            throw new SuiteAssertionException($"{what}: expected {typeof(T).Name} but got {t}");
        }
        throw new SuiteAssertionException($"{what}: expected {typeof(T).Name} but nothing was thrown");
    }

    /// <summary>The call must throw (any exception).</summary>
    public static void Rejects(Action f, string what) => Rejects<Exception>(f, what);

    /// <summary>The message of the exception <paramref name="f"/> throws, or the empty string when it does not.</summary>
    public static string Thrown(Action f)
    {
        try { f(); return ""; }
        catch (Exception e) { return e.Message ?? ""; }
    }

    /// <summary>Run the tasks concurrently (the reference's Promise.all) and return their results in order; a failure rethrows.</summary>
    public static List<T> Parallel<T>(IReadOnlyList<Func<T>> tasks)
    {
        var ts = tasks.Select(f => Task.Factory.StartNew(f, TaskCreationOptions.LongRunning)).ToArray();
        try { Task.WaitAll(ts); }
        catch (AggregateException e) { throw e.InnerExceptions[0]; }
        return ts.Select(t => t.Result).ToList();
    }
}
