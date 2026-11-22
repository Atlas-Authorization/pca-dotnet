using System.Reflection;
using System.Runtime.InteropServices;

namespace AtlasPca.Mpc.LweOt;

/// <summary>
/// The endemic OT's lattice core: Kyber-768 K-PKE keygen, CPA encrypt and decrypt, ring add and subtract, and the hash to a uniform ring vector.
/// Every operation is the audited pqc_kyber reference reached through the C library (pca_lwe_ot.h); nothing lattice-related is implemented here.
/// A wrong size is refused before the call and again by the library.
/// </summary>
public static class Lattice
{
    public const int PkBytes = 1184, SkBytes = 1152, CtBytes = 1088, TvecBytes = 1152, SymBytes = 32, HashinCap = 4096;

    public sealed record KeyPair(byte[] PublicKey, byte[] SecretKey);

    const string Lib = "lweot";

    static Lattice()
    {
        NativeLibrary.SetDllImportResolver(typeof(Lattice).Assembly, (name, asm, path) =>
        {
            if (name != Lib) return IntPtr.Zero;
            var p = Environment.GetEnvironmentVariable("ATLAS_LWEOT_LIB");
            return !string.IsNullOrEmpty(p) && NativeLibrary.TryLoad(p, out var h) ? h : IntPtr.Zero;
        });
    }

    [DllImport(Lib)] static extern nuint lweot_len_pk();
    [DllImport(Lib)] static extern nuint lweot_len_sk();
    [DllImport(Lib)] static extern nuint lweot_len_ct();
    [DllImport(Lib)] static extern nuint lweot_len_tvec();
    [DllImport(Lib)] static extern nuint lweot_len_sym();
    [DllImport(Lib)] static extern nuint lweot_hashin_cap();
    [DllImport(Lib)] static extern int lweot_kpke_keygen_fips203(byte[] seed, nuint seedLen, byte[] pk, nuint pkLen, byte[] sk, nuint skLen);
    [DllImport(Lib)] static extern int lweot_kpke_keygen(byte[] seed, nuint seedLen, byte[] pk, nuint pkLen, byte[] sk, nuint skLen);
    [DllImport(Lib)] static extern int lweot_kpke_enc(byte[] pk, nuint pkLen, byte[] msg, nuint msgLen, byte[] coins, nuint coinsLen, byte[] ct, nuint ctLen);
    [DllImport(Lib)] static extern int lweot_kpke_dec(byte[] sk, nuint skLen, byte[] ct, nuint ctLen, byte[] msg, nuint msgLen);
    [DllImport(Lib)] static extern int lweot_ring_add(byte[] a, nuint aLen, byte[] b, nuint bLen, byte[] o, nuint oLen);
    [DllImport(Lib)] static extern int lweot_ring_sub(byte[] a, nuint aLen, byte[] b, nuint bLen, byte[] o, nuint oLen);
    [DllImport(Lib)] static extern int lweot_hash_to_ring(byte[] input, nuint inputLen, byte[] o, nuint oLen);

    static readonly Lazy<bool> SizesChecked = new(() =>
    {
        // the sizes this class hard-codes must be the ones the library was built with, or nothing is safe
        if (lweot_len_pk() != PkBytes || lweot_len_sk() != SkBytes || lweot_len_ct() != CtBytes || lweot_len_tvec() != TvecBytes
            || lweot_len_sym() != SymBytes || lweot_hashin_cap() != HashinCap)
            throw new InvalidOperationException("liblweot reports different Kyber-768 sizes");
        return true;
    });

    /// <summary>True when liblweot can be loaded (tests skip, or fail when required, on false).</summary>
    public static bool Available()
    {
        try { return SizesChecked.Value; }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException) { return false; }
    }

    static byte[] Need(byte[]? b, int len, string what) =>
        b is { } x && x.Length == len ? x : throw new ArgumentException($"lattice: {what} must be exactly {len} bytes");

    static void Ok(int rc, string op)
    {
        if (rc != 0) throw new InvalidOperationException($"lattice: {op} refused ({rc})");
    }

    /// <summary>The key pair exactly as FIPS 203 Algorithm 13 derives it (the derivation the endemic receiver uses).</summary>
    public static KeyPair KeygenFips203(byte[] seed)
    {
        _ = SizesChecked.Value;
        Need(seed, SymBytes, "seed");
        var pk = new byte[PkBytes]; var sk = new byte[SkBytes];
        Ok(lweot_kpke_keygen_fips203(seed, SymBytes, pk, PkBytes, sk, SkBytes), "keygen (FIPS 203)");
        return new KeyPair(pk, sk);
    }

    public static KeyPair Keygen(byte[] seed)
    {
        _ = SizesChecked.Value;
        Need(seed, SymBytes, "seed");
        var pk = new byte[PkBytes]; var sk = new byte[SkBytes];
        Ok(lweot_kpke_keygen(seed, SymBytes, pk, PkBytes, sk, SkBytes), "keygen");
        return new KeyPair(pk, sk);
    }

    public static byte[] Enc(byte[] publicKey, byte[] message, byte[] coins)
    {
        _ = SizesChecked.Value;
        Need(publicKey, PkBytes, "public key"); Need(message, SymBytes, "message"); Need(coins, SymBytes, "coins");
        var ct = new byte[CtBytes];
        Ok(lweot_kpke_enc(publicKey, PkBytes, message, SymBytes, coins, SymBytes, ct, CtBytes), "enc");
        return ct;
    }

    public static byte[] Dec(byte[] secretKey, byte[] ciphertext)
    {
        _ = SizesChecked.Value;
        Need(secretKey, SkBytes, "secret key"); Need(ciphertext, CtBytes, "ciphertext");
        var msg = new byte[SymBytes];
        Ok(lweot_kpke_dec(secretKey, SkBytes, ciphertext, CtBytes, msg, SymBytes), "dec");
        return msg;
    }

    public static byte[] RingAdd(byte[] a, byte[] b)
    {
        _ = SizesChecked.Value;
        Need(a, TvecBytes, "a"); Need(b, TvecBytes, "b");
        var o = new byte[TvecBytes];
        Ok(lweot_ring_add(a, TvecBytes, b, TvecBytes, o, TvecBytes), "ring add");
        return o;
    }

    public static byte[] RingSub(byte[] a, byte[] b)
    {
        _ = SizesChecked.Value;
        Need(a, TvecBytes, "a"); Need(b, TvecBytes, "b");
        var o = new byte[TvecBytes];
        Ok(lweot_ring_sub(a, TvecBytes, b, TvecBytes, o, TvecBytes), "ring sub");
        return o;
    }

    /// <summary>SHAKE128 then the FIPS 203 SampleNTT sampler: a uniform ring vector. At most 4096 input bytes.</summary>
    public static byte[] HashToRing(byte[] input)
    {
        _ = SizesChecked.Value;
        if (input is null || input.Length > HashinCap) throw new ArgumentException($"lattice: hash input must be at most {HashinCap} bytes");
        var o = new byte[TvecBytes];
        Ok(lweot_hash_to_ring(input, (nuint)input.Length, o, TvecBytes), "hash to ring");
        return o;
    }
}
