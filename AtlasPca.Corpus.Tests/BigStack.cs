using System.Runtime.ExceptionServices;

namespace AtlasPca.Corpus.Tests;

/// <summary>Runs a corpus test body on a 512 MiB-stack thread. The corpus carries 100000-level nesting vectors; under a Stryker mutant
/// that removes a depth cap they would recurse 100000 frames and, on the default ~1 MiB test thread, overflow the stack, which in .NET
/// kills the whole (shared) test host and poisons every other mutant in that session (reported as spurious Timeout / Survived). On a
/// big stack the mutant instead produces a wrong verdict and the assertion kills it. The unmutated verifier never recurses past the
/// cap (Category=Huge tests check that on a SMALL stack).</summary>
static class BigStack
{
    public static void Run(Action body)
    {
        ExceptionDispatchInfo? err = null;
        var t = new Thread(() => { try { body(); } catch (Exception e) { err = ExceptionDispatchInfo.Capture(e); } }, 512 * 1024 * 1024);
        t.Start();
        t.Join();
        err?.Throw();
    }
}
