using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using Xunit.Sdk;

[assembly: AtlasPca.Corpus.Tests.TrackCurrentTest]

namespace AtlasPca.Corpus.Tests;

/// <summary>Mutation-gate honesty: a mutant "killed" only because the test host hit its GC heap cap is a RUN ERROR, not a kill.
/// When PCA_RUNERR_LOG names a file (the mutation workflow only), every OutOfMemoryException raised in this test host, caught
/// or not, appends one line "OOM &lt;test class&gt;.&lt;test method&gt;" (or the running test when the stack names none, as on an SDK continuation or with no memory left for the trace, or "OOM ?" outside any test) to it, so the
/// shard report can tell such a mutant apart from one an assertion decided. Off (no handler) when the variable is unset.</summary>
static class RunErrorProbe
{
    [ThreadStatic] static bool _busy;
    /// <summary>The running test; the assembly runs its tests serially (AssemblyInfo.cs), so one field is enough.</summary>
    internal static volatile string? Current;
    /// <summary>Memory given back before the trace is taken: an OOM's first-chance handler runs before the stack unwinds, so whatever
    /// filled the heap is still live and the trace would fail for want of memory (run 42149070759 shard 19: "OOM ?").</summary>
    static byte[]? _ballast;

    internal static void Rearm()
    {
        if (_ballast != null || !_on) return;
        try { _ballast = GC.AllocateUninitializedArray<byte>(64 << 20); } catch (OutOfMemoryException) { }
    }

    static bool _on;

    [ModuleInitializer]
    internal static void Init()
    {
        var path = Environment.GetEnvironmentVariable("PCA_RUNERR_LOG");
        if (string.IsNullOrEmpty(path)) return;
        _on = true;
        Rearm();
        AppDomain.CurrentDomain.FirstChanceException += (_, e) =>
        {
            if (e.Exception is not OutOfMemoryException || _busy) return;
            _busy = true;
            _ballast = null;
            try
            {
                string test = Current ?? "?";
                try
                {
                    foreach (var f in new StackTrace(false).GetFrames())
                        if (f.GetMethod() is { DeclaringType: { } t } m && t.Namespace == "AtlasPca.Corpus.Tests" && t != typeof(RunErrorProbe))
                            test = $"{t.FullName}.{m.Name}";
                }
                catch (Exception) { }
                if (test == "?")
                {
                    // no test is running yet (class or theory-data setup): name the frames so the log says where
                    string where = "";
                    try { where = string.Join(" < ", new StackTrace(false).GetFrames().Take(12).Select(f => f.GetMethod() is { } m ? $"{m.DeclaringType?.FullName}.{m.Name}" : "?")); }
                    catch (Exception) { }
                    File.AppendAllText(path, "OOM-TRACE " + where + "\n");
                }
                File.AppendAllText(path, "OOM " + test + "\n");
            }
            catch (Exception) { }
            finally { _busy = false; }
        };
    }
}

[AttributeUsage(AttributeTargets.Assembly)]
public sealed class TrackCurrentTestAttribute : BeforeAfterTestAttribute
{
    public override void Before(MethodInfo methodUnderTest)
    {
        RunErrorProbe.Current = $"{methodUnderTest.ReflectedType!.FullName}.{methodUnderTest.Name}";
        RunErrorProbe.Rearm();
    }
}

public class RunErrorProbeTests
{
    [Xunit.Fact]
    public void TheProbeKnowsTheRunningTest() => Xunit.Assert.Equal(typeof(RunErrorProbeTests).FullName + "." + nameof(TheProbeKnowsTheRunningTest), RunErrorProbe.Current);
}
