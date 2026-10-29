using System;
using System.Linq;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>Provenance by default in the test harnesses (shared by the test projects): every operation the existing suites authorize comes
/// straight from the principal, so they present a principal-direct bundle (<see cref="ArgProvenance.PrincipalDirect"/>) under the
/// conformance harness pin (Ed25519 seed 32 x 0x01, mediator <c>conformance-harness</c>, kid <c>k1</c>), exactly as the TypeScript harnesses
/// do. The provenance gate then passes and the recorded outcomes are those of the rules under test. The gate is never turned off here.</summary>
internal static class ProvHarness
{
    static readonly SuiteKey Key = SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)1, 32).ToArray()));
    internal static ProvenanceRecorder Recorder() => new("conformance-harness", "k1", Key);
    internal static readonly ProvMediatorPin Pin = Recorder().Pin;
    internal static ArgProvenanceOptions Options => new() { Mediators = new[] { Pin } };

    /// <summary>The principal-direct bundle of an operation; null when the operation is not one (a test of a refused operation).</summary>
    internal static JD? Bundle(Operation? op)
    {
        if (op == null) return null;
        try { return ArgProvenance.PrincipalDirect(Recorder(), op.Verb, op.Resource, op.Params); }
        catch (Exception) { return null; }
    }

    /// <summary>The <c>PCA-Provenance</c> header value for an operation.</summary>
    internal static string Header(Operation op) => ProvenanceRecorder.HeaderValue(Bundle(op)!);

    /// <summary>Pin the harness mediator (when no gate configuration is set) and present the bundle of the input's operation (when none is set).</summary>
    internal static AuthorizeInput WithProv(this AuthorizeInput i)
    {
        i.ProvenanceFlow ??= Options;
        i.Provenance ??= Bundle(i.Operation);
        return i;
    }
}
