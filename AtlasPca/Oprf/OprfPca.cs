// The PCA layer over the OPRF (mirrors @atlasauth/pca-oprf pca.ts): private revocation checks (the checker never reveals the capability id, the
// service never learns which id was checked) and private per-window rate-limit tokens via POPRF, plus the in-memory window counter.
using System.Text;

namespace AtlasPca.Oprf;

/// <summary>A set of revoked capability ids as OPRF outputs (hex) under the service key; the key itself is not retained.</summary>
public sealed record RevocationSet(HashSet<string> Outputs, string Mode, byte[]? PublicKey = null);

public static class OprfPca
{
    /// <summary>UTF-8 encode STRICTLY: an unpaired surrogate is refused (a lenient encoder maps distinct ill-formed strings to the same bytes, aliasing revocation entries and rate counters).</summary>
    static byte[] EncodeStrict(string? s, string what)
    {
        if (s == null) throw new ArgumentException($"{what} must be a string");
        for (int i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) i++;
                else throw new ArgumentException($"{what} contains an unpaired surrogate (ill-formed UTF-16)");
            }
            else if (char.IsLowSurrogate(c)) throw new ArgumentException($"{what} contains an unpaired surrogate (ill-formed UTF-16)");
        }
        return Encoding.UTF8.GetBytes(s);
    }

    public static RevocationSet BuildRevocationSet(byte[] secretKey, IEnumerable<string> revokedCapIds, string mode = "oprf")
    {
        var outputs = new HashSet<string>(StringComparer.Ordinal);
        foreach (var id in revokedCapIds) outputs.Add(Oprf.ToHex(Oprf.Evaluate(secretKey, EncodeStrict(id, "capability id"), mode)));
        return new RevocationSet(outputs, mode, mode == "voprf" ? Oprf.PublicKeyFor(secretKey) : null);
    }

    /// <summary>The service side: answers a blinded element (with a DLEQ proof in voprf mode).</summary>
    public static Func<byte[], EvaluateResult> MakeRevocationEvaluator(byte[] secretKey, string mode = "oprf")
    {
        var publicKey = mode == "voprf" ? Oprf.PublicKeyFor(secretKey) : null;
        return blinded => Oprf.BlindEvaluate(secretKey, blinded, mode, publicKey);
    }

    /// <summary>Private membership check: blind the id, have the service evaluate, unblind (verifying the proof in voprf mode), look the output up.</summary>
    public static bool IsRevokedPrivate(string? capId, Func<byte[], EvaluateResult> blindEval, RevocationSet revokedSet)
    {
        var input = EncodeStrict(capId, "capability id");
        var mode = revokedSet.Mode;
        var b = Oprf.Blind(input, mode);
        var res = blindEval(b.BlindedElement);
        byte[] output;
        if (mode == "voprf")
        {
            if (res.Proof == null || revokedSet.PublicKey == null) throw new InvalidOperationException("isRevokedPrivate(voprf): missing DLEQ proof or service public key");
            output = Oprf.Finalize(input, b.Blind, res.EvaluatedElement, "voprf", res.Proof, revokedSet.PublicKey, b.BlindedElement);
        }
        else output = Oprf.Finalize(input, b.Blind, res.EvaluatedElement, "oprf");
        return revokedSet.Outputs.Contains(Oprf.ToHex(output));
    }

    /// <summary>The deterministic rate token (key holder side): the POPRF output for (identifier, window).</summary>
    public static byte[] RateToken(byte[] secretKey, string? identifier, string? window) =>
        Oprf.EvaluatePoprf(secretKey, EncodeStrict(identifier, "identifier"), EncodeStrict(window, "window"));

    public static string RateTokenHex(byte[] secretKey, string? identifier, string? window) => Oprf.ToHex(RateToken(secretKey, identifier, window));

    public static Func<byte[], string, EvaluateResult> MakeRateEvaluator(byte[] secretKey) =>
        (blinded, window) => Oprf.BlindEvaluatePoprf(secretKey, blinded, EncodeStrict(window, "window"));

    /// <summary>The client side of the private rate token: the service sees neither the identifier nor the token, only the public window.</summary>
    public static byte[] PrivateRateToken(string? identifier, string? window, Func<byte[], string, EvaluateResult> blindEval, byte[] publicKey)
    {
        var input = EncodeStrict(identifier, "identifier");
        var info = EncodeStrict(window, "window");
        var b = Oprf.BlindPoprf(input, info, publicKey);
        var res = blindEval(b.BlindedElement, window!);
        if (res.Proof == null) throw new InvalidOperationException("privateRateToken: POPRF blind-evaluation did not return a DLEQ proof");
        return Oprf.FinalizePoprf(input, b.Blind, res.EvaluatedElement, info, res.Proof, b.BlindedElement, b.TweakedKey);
    }
}

/// <summary>In-memory per-window hit counter keyed by token.</summary>
public sealed class RateWindowCounter
{
    readonly Dictionary<string, int> _counts = new(StringComparer.Ordinal);
    readonly double _limit;

    public RateWindowCounter(double limit)
    {
        if (!(double.IsFinite(limit) && limit == Math.Round(limit) && limit >= 1)) throw new ArgumentException("RateWindowCounter: limit must be a positive integer");
        _limit = limit;
    }

    public (int Count, bool Allowed) Hit(byte[] token)
    {
        var key = Oprf.ToHex(token);
        var count = (_counts.TryGetValue(key, out var c) ? c : 0) + 1;
        _counts[key] = count;
        return (count, count <= _limit);
    }

    public int Count(byte[] token) => _counts.TryGetValue(Oprf.ToHex(token), out var c) ? c : 0;
    public void Reset() => _counts.Clear();
}
