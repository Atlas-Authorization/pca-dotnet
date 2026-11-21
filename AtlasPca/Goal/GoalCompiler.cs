using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;


/**
 * The pure parts of the typed compiler front door. The compiler itself (typecheck, compile, the Dafny-extracted decision
 * functions) is the proved reference and is not re-implemented here: the native decision semantics live in
 * {@code net.atlasauth.pca.GoalSemantics} and {@link GoalRefsem}; this class holds the policy canonical form and digest
 * and the tape codec entry points.
 */
public static class GoalCompiler {

    /** Canonical bytes of a policy (sorted-key JSON, no floats): the input of the policy digest. */
    public static string CanonicalPolicy(D p) { return G.stable(p); }

    public static string PolicyDigest(D p) {
        return Pca.B64u(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalPolicy(p))));
    }

    /** The goal as a token tape: the proved kernel's rendering (GoalKernel.RenderTape); decodeGoal(RenderTape(g)) equals g. */
    public static L RenderTape(D goal) { return GoalKernel.RenderTape(goal); }
}
