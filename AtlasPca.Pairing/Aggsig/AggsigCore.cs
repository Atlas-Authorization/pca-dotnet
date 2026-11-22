using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Pairing;
using static supranational.blst;
using BlstPairing = supranational.blst.Pairing;

namespace AtlasPca.Aggsig;

/// <summary>
/// BLS signatures on BLS12-381, aggregation-ready (draft-irtf-cfrg-bls-signature, proof-of-possession ciphersuite,
/// minimal-pubkey-size: 48-byte G1 public keys, 96-byte G2 signatures). Every curve operation is blst's; nothing
/// here implements a pairing or a field. INTERNAL: the raw aggregate verifiers take unvetted public keys and are only
/// sound after a proof-of-possession check; the public surface is <see cref="Aggsig"/>, which takes only <see cref="RegisteredKey"/>s.
/// Verification is total: any malformed input is a false, never an exception.
/// </summary>
internal static class AggsigCore
{
    internal const string SigDst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    internal const string PopDst = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    internal const int PublicKeyLength = 48;
    internal const int SignatureLength = 96;

    static bool IsCompressed(byte[]? b, int len) => b != null && b.Length == len && (b[0] & 0x80) != 0;

    /// <summary>A 96-byte compressed G2 point that is exactly the re-encoding of the point it decodes to (no second encoding per signature).</summary>
    internal static bool IsCanonicalSignature(byte[]? sig)
    {
        if (!IsCompressed(sig, SignatureLength)) return false;
        // in the prime-order subgroup too (the reference's decoder refuses a torsion point): every verify path relies on this check, since
        // the blst pairing aggregate does not group-check the signature itself
        try { var p = new P2_Affine(sig!); return p.compress().AsSpan().SequenceEqual(sig!) && p.in_group(); }
        catch (System.Exception t) when (!Bls12.Fatal(t)) { return false; }
    }

    /// <summary>KeyValidate (draft 2.5): canonical compressed G1 point, not the identity, in the prime-order subgroup.</summary>
    internal static bool KeyValidate(byte[]? pk)
    {
        if (!IsCompressed(pk, PublicKeyLength)) return false;
        try
        {
            var p = new P1_Affine(pk!);
            if (p.is_inf() || !p.on_curve() || !p.compress().AsSpan().SequenceEqual(pk!)) return false;
            return p.in_group();
        }
        catch (System.Exception t) when (!Bls12.Fatal(t)) { return false; }
    }

    internal static BigInteger SecretScalar(byte[]? sk)
    {
        if (sk == null || sk.Length != 32) throw new ArgumentException("secret key must be 32 bytes");
        var s = Bls12.Os2ip(sk);
        if (s.IsZero || s >= Bls12.R) throw new ArgumentException("secret key must be a scalar in [1, r-1]");
        return s;
    }

    internal static byte[] PublicKeyOf(byte[]? sk) => Bls12.Mul(P1.generator(), SecretScalar(sk)).compress();

    /// <summary>A fresh key pair; refuses the degenerate key 1 (a stuck entropy source).</summary>
    internal static Aggsig.KeyPair KeyGen(Func<int, byte[]> rng)
    {
        var s = Bls12.Os2ip(rng(64)) % (Bls12.R - BigInteger.One) + BigInteger.One;
        if (s.IsOne) throw new InvalidOperationException("keyGen: entropy source produced the degenerate key 1 (RNG failure); refusing to continue");
        var sk = Bls12.I2osp(s, 32);
        return new Aggsig.KeyPair(sk, PublicKeyOf(sk));
    }

    internal static byte[] SignWith(string dst, byte[]? sk, byte[]? msg)
    {
        var s = SecretScalar(sk);
        if (msg == null) throw new ArgumentException("msg is required");
        return Bls12.Mul(new P2().hash_to(msg, dst), s).compress();
    }

    internal static byte[] Sign(byte[]? sk, byte[]? msg) => SignWith(SigDst, sk, msg);

    // blst's own core_verify is not public in the C# binding; one pairing aggregate + final verify is the same check
    static bool CoreVerify(P1_Affine pk, P2_Affine sig, byte[] msg, string dst)
    {
        var ctx = new BlstPairing(true, dst);
        if (ctx.aggregate(pk, sig, msg) != ERROR.SUCCESS) return false;
        ctx.commit();
        return ctx.finalverify();
    }

    internal static bool VerifyWith(string dst, byte[]? pk, byte[]? msg, byte[]? sig)
    {
        try
        {
            if (!IsCanonicalSignature(sig)) return false;
            if (!KeyValidate(pk)) return false;
            if (msg == null) return false;
            return CoreVerify(new P1_Affine(pk!), new P2_Affine(sig!), msg, dst);
        }
        catch (System.Exception t) when (!Bls12.Fatal(t)) { return false; }
    }

    internal static bool Verify(byte[]? pk, byte[]? msg, byte[]? sig) => VerifyWith(SigDst, pk, msg, sig);

    internal static byte[] Aggregate(IReadOnlyList<byte[]> sigs)
    {
        if (sigs.Count == 0) throw new ArgumentException("aggregate: need at least one signature");
        foreach (var s in sigs)
            if (!IsCanonicalSignature(s)) throw new ArgumentException("aggregate: every signature must be a 96-byte compressed G2 point");
        var sum = Bls12.Id2();
        foreach (var s in sigs) sum.add(new P2_Affine(s));
        return sum.compress();
    }

    static bool Distinct(IReadOnlyList<byte[]> msgs)
    {
        var seen = new HashSet<string>();
        foreach (var m in msgs) if (!seen.Add(Aggsig.Hex(m))) return false;
        return true;
    }

    /// <summary>AggregateVerify (draft 3.1.1) over pairwise-distinct messages: one pairing-product check.</summary>
    internal static bool AggregateVerify(IReadOnlyList<byte[]> pks, IReadOnlyList<byte[]> msgs, byte[]? aggSig)
    {
        try
        {
            if (!IsCanonicalSignature(aggSig)) return false;
            if (pks.Count == 0 || pks.Count != msgs.Count) return false;
            if (!Distinct(msgs)) return false;
            foreach (var pk in pks) if (!KeyValidate(pk)) return false;
            var ctx = new BlstPairing(true, SigDst);
            var sig = new P2_Affine(aggSig!);
            for (int i = 0; i < pks.Count; i++)
            {
                var e = ctx.aggregate(new P1_Affine(pks[i]), i == 0 ? sig : null, msgs[i]);
                if (e != ERROR.SUCCESS) return false;
            }
            ctx.commit();
            return ctx.finalverify();
        }
        catch (System.Exception t) when (!Bls12.Fatal(t)) { return false; }
    }

    /// <summary>FastAggregateVerify (draft 3.3.4): one message, many signers; the aggregate key is KeyValidate'd too ({P,-P} sums to the identity).</summary>
    internal static bool FastAggregateVerify(IReadOnlyList<byte[]> pks, byte[]? msg, byte[]? aggSig)
    {
        try
        {
            if (!IsCanonicalSignature(aggSig)) return false;
            if (pks.Count == 0 || msg == null) return false;
            var agg = Bls12.Id1();
            foreach (var pk in pks)
            {
                if (!KeyValidate(pk)) return false;
                agg.add(new P1_Affine(pk));
            }
            if (agg.is_inf()) return false;
            var aggPk = agg.compress();
            if (!KeyValidate(aggPk)) return false;
            return CoreVerify(new P1_Affine(aggPk), new P2_Affine(aggSig!), msg, SigDst);
        }
        catch (System.Exception t) when (!Bls12.Fatal(t)) { return false; }
    }

    internal static byte[] PopProve(byte[]? sk) => SignWith(PopDst, sk, PublicKeyOf(sk));

    internal static bool PopVerify(byte[]? pk, byte[]? pop) => VerifyWith(PopDst, pk, pk, pop);

    internal static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
}
