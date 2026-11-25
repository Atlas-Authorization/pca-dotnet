using AtlasPca.Scitt;
using ScittApi = AtlasPca.Scitt.Scitt;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Evidence;

/// <summary>Registration of an evidence bundle: its digest names it in the intent anchor log (kind <c>evidence</c>) and in a SCITT signed
/// statement. The bundle itself stays with the site (it holds personal data); only its reference is public.</summary>
public static class EvidenceScitt
{
    public const string EvidenceContentType = "application/pca-intent-evidence+json";

    /// <summary><c>{kind: "pca-intent-evidence-ref", digest, subject}</c> for a bundle.</summary>
    public static D EvidenceRef(object? bundle)
    {
        var digest = EvidenceBundle.EvidenceDigest(bundle);
        var subject = new D();
        if (bundle is D b && b.TryGetValue("subject", out var s) && s is D sd) foreach (var kv in sd) subject[kv.Key] = kv.Value;
        return new D { ["kind"] = "pca-intent-evidence-ref", ["digest"] = digest, ["subject"] = subject };
    }

    /// <summary>A COSE Signed Statement over the bundle reference, ready to register with a SCITT service. The content type is always <see cref="EvidenceContentType"/>; the subject
    /// is <paramref name="opts"/>.Subject, else the digest of the PCActn the bundle is about (an explicitly empty subject stays empty).</summary>
    public static byte[] EvidenceSignedStatement(object? bundle, SignStatementOpts opts)
    {
        var r = EvidenceRef(bundle);
        var subject = opts.Subject ?? ((D)r["subject"]!).GetValueOrDefault("pcactn_digest") as string;
        return ScittApi.SignStatement(r, opts with { Subject = subject, ContentType = EvidenceContentType });
    }

    /// <summary>The intent-anchor-log leaf for a bundle digest (kind <c>evidence</c>).</summary>
    public static string EvidenceAnchorCommit(string digest) => EvidenceVerify.AnchorCommit("evidence", digest);
}
