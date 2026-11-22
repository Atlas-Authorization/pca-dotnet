using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;


/** The content digests of the goal-to-decision flow (strict canonical JSON: safe integers only; a float or cycle throws). */
public static class GoalDigests {

    /** Digest of the whole signed Goal. */
    public static string GoalDigest(object? goal) { return Pca.HashCanonical(G.map("d", "atlas-pca/goal-ir/v1", "goal", goal)); }

    /** Digest of the instruction text a goal was interpreted from. */
    public static string NlDigest(string instruction) { return Pca.HashCanonical(G.map("d", "atlas-pca/goal-nl/v1", "text", instruction)); }

    /** Digest of the model set: sorted (code-unit order), de-duplicated ids. */
    public static string ModelSetDigest(List<string> models) {
        return Pca.HashCanonical(G.map("d", "atlas-pca/goal-model-set/v1", "models", SortedSet(models)));
    }

    /** Digest of an approval's covered fields (the digests it pins plus its expiry). */
    static L SortedSet(List<string> xs) { var l = new List<string>(new HashSet<string>(xs)); l.Sort(string.CompareOrdinal); return new L(l); }

    public static string ApprovalDigest(D body) { return Pca.HashCanonical(G.map("d", "atlas-pca/goal-approval-body/v1", "body", body)); }
}
