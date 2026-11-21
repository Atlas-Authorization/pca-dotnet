// The only place group arithmetic happens: P/Invoke into libsodium (the official `libsodium` NuGet native package, pinned exact in the csproj).
// Every secret-scalar point multiplication is libsodium's constant-time one; nothing in this assembly hand-rolls field or group math.
using System.Runtime.InteropServices;

namespace AtlasPca.Native;

internal static class Sodium
{
    const string Lib = "libsodium";

    [DllImport(Lib)] static extern int sodium_init();
    [DllImport(Lib)] static extern int crypto_core_ed25519_add(byte[] r, byte[] p, byte[] q);
    [DllImport(Lib)] static extern int crypto_core_ed25519_sub(byte[] r, byte[] p, byte[] q);
    [DllImport(Lib)] static extern int crypto_core_ed25519_is_valid_point(byte[] p);
    [DllImport(Lib)] static extern int crypto_scalarmult_ed25519_noclamp(byte[] q, byte[] n, byte[] p);
    [DllImport(Lib)] static extern int crypto_scalarmult_ed25519_base_noclamp(byte[] q, byte[] n);
    [DllImport(Lib)] static extern int crypto_core_ristretto255_is_valid_point(byte[] p);
    [DllImport(Lib)] static extern int crypto_core_ristretto255_from_hash(byte[] p, byte[] h64);
    [DllImport(Lib)] static extern int crypto_core_ristretto255_add(byte[] r, byte[] p, byte[] q);
    [DllImport(Lib)] static extern int crypto_core_ristretto255_sub(byte[] r, byte[] p, byte[] q);
    [DllImport(Lib)] static extern int crypto_scalarmult_ristretto255(byte[] q, byte[] n, byte[] p);
    [DllImport(Lib)] static extern int crypto_scalarmult_ristretto255_base(byte[] q, byte[] n);
    [DllImport(Lib)] static extern void crypto_core_ristretto255_scalar_reduce(byte[] r, byte[] s64);
    [DllImport(Lib)] static extern void crypto_core_ristretto255_scalar_add(byte[] z, byte[] x, byte[] y);
    [DllImport(Lib)] static extern void crypto_core_ristretto255_scalar_sub(byte[] z, byte[] x, byte[] y);
    [DllImport(Lib)] static extern void crypto_core_ristretto255_scalar_mul(byte[] z, byte[] x, byte[] y);
    [DllImport(Lib)] static extern void crypto_core_ristretto255_scalar_negate(byte[] neg, byte[] s);
    [DllImport(Lib)] static extern int crypto_core_ristretto255_scalar_invert(byte[] recip, byte[] s);

    static Sodium()
    {
        // 0 = initialised now, 1 = already initialised, -1 = failure
        if (sodium_init() < 0) throw new InvalidOperationException("libsodium: sodium_init failed");
    }

    /// <summary>Force the native library to load (and sodium_init to run) before any use.</summary>
    internal static void Ensure() { }

    // ---- Ed25519 group (32-byte RFC 8032 encodings) ----

    /// <summary>p + q; null when either is not a valid curve point encoding. Torsion points are accepted; the result is the canonical encoding.</summary>
    internal static byte[]? Ed25519Add(byte[] p, byte[] q)
    {
        var r = new byte[32];
        return crypto_core_ed25519_add(r, p, q) == 0 ? r : null;
    }

    /// <summary>p - q; null when either is not a valid curve point encoding.</summary>
    internal static byte[]? Ed25519Sub(byte[] p, byte[] q)
    {
        var r = new byte[32];
        return crypto_core_ed25519_sub(r, p, q) == 0 ? r : null;
    }

    /// <summary>Canonical, on the curve, in the prime-order subgroup and not small order (so the identity is false).</summary>
    internal static bool Ed25519IsValidPoint(byte[] p) => crypto_core_ed25519_is_valid_point(p) == 1;

    /// <summary>Reduce a little-endian integer (up to 64 bytes) modulo the group order L.</summary>
    internal static byte[] ScalarReduce(byte[] le)
    {
        var s = new byte[64];
        Array.Copy(le, s, le.Length);
        var r = new byte[32];
        crypto_core_ristretto255_scalar_reduce(r, s);
        return r;
    }

    /// <summary>n * p without clamping, constant time in n. Null when p is not a non-identity prime-order point, or n is 0 mod L.</summary>
    internal static byte[]? Ed25519Mul(byte[] n, byte[] p)
    {
        var q = new byte[32];
        return crypto_scalarmult_ed25519_noclamp(q, n, p) == 0 ? q : null;
    }

    /// <summary>n * B for the Ed25519 base point; null when n is 0 mod L.</summary>
    internal static byte[]? Ed25519MulBase(byte[] n)
    {
        var q = new byte[32];
        return crypto_scalarmult_ed25519_base_noclamp(q, n) == 0 ? q : null;
    }

    // ---- ristretto255 (canonical 32-byte encodings, 32-byte little-endian scalars mod L) ----

    // RFC 9496: bit 255 must be clear; libsodium 1.0.18 (the Ubuntu package) ignores it, so it is checked here
    internal static bool RistrettoIsValidPoint(byte[] p) => p.Length == 32 && (p[31] & 0x80) == 0 && crypto_core_ristretto255_is_valid_point(p) == 1;

    internal static byte[] RistrettoFromHash(byte[] h64)
    {
        var r = new byte[32];
        if (crypto_core_ristretto255_from_hash(r, h64) != 0) throw new InvalidOperationException("ristretto255: from_hash failed");
        return r;
    }

    internal static byte[] RistrettoAdd(byte[] p, byte[] q)
    {
        var r = new byte[32];
        if (crypto_core_ristretto255_add(r, p, q) != 0) throw new InvalidOperationException("ristretto255: add failed");
        return r;
    }

    internal static byte[] RistrettoSub(byte[] p, byte[] q)
    {
        var r = new byte[32];
        if (crypto_core_ristretto255_sub(r, p, q) != 0) throw new InvalidOperationException("ristretto255: sub failed");
        return r;
    }

    /// <summary>n * p; null when the result is the identity (libsodium refuses it) or p is invalid.</summary>
    internal static byte[]? RistrettoMul(byte[] n, byte[] p)
    {
        var q = new byte[32];
        return crypto_scalarmult_ristretto255(q, n, p) == 0 ? q : null;
    }

    internal static byte[]? RistrettoMulBase(byte[] n)
    {
        var q = new byte[32];
        return crypto_scalarmult_ristretto255_base(q, n) == 0 ? q : null;
    }

    internal static byte[] ScalarAdd(byte[] x, byte[] y) { var z = new byte[32]; crypto_core_ristretto255_scalar_add(z, x, y); return z; }
    internal static byte[] ScalarSub(byte[] x, byte[] y) { var z = new byte[32]; crypto_core_ristretto255_scalar_sub(z, x, y); return z; }
    internal static byte[] ScalarMul(byte[] x, byte[] y) { var z = new byte[32]; crypto_core_ristretto255_scalar_mul(z, x, y); return z; }
    internal static byte[] ScalarNegate(byte[] s) { var z = new byte[32]; crypto_core_ristretto255_scalar_negate(z, s); return z; }
    /// <summary>1/s mod L; null for s = 0.</summary>
    internal static byte[]? ScalarInvert(byte[] s) { var z = new byte[32]; return crypto_core_ristretto255_scalar_invert(z, s) == 0 ? z : null; }
}
