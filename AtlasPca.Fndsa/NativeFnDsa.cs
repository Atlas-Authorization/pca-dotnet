using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Core = AtlasPca.Fndsa.Fndsa;

namespace AtlasPca.Fndsa.Native;

/// <summary>libfndsa could not be loaded or reported different sizes. Never mapped to "invalid signature": a missing library fails loudly.</summary>
public sealed class FnDsaNativeException(string message, Exception? inner = null) : InvalidOperationException(message, inner);

/// <summary>
/// FN-DSA over libfndsa (Pornin's fn-dsa 0.4.0 through its C ABI). FIPS 206 is unpublished: this is a draft best-guess pinned in lockstep with the
/// TypeScript reference. BouncyCastle's Falcon is the round-3 submission and is NOT interoperable. Variants "fn-dsa-512" and "fn-dsa-1024" only.
/// Register with <see cref="Register"/>; the library path comes from ATLAS_PCA_LIBFNDSA, else libfndsa beside the assembly or on the loader path.
/// </summary>
public static unsafe class NativeFnDsa
{
    const string Lib = "fndsa";
    const int SeedBytes = 32, MsgCap = 8192;

    static NativeFnDsa()
    {
        NativeLibrary.SetDllImportResolver(typeof(NativeFnDsa).Assembly, (name, asm, path) =>
        {
            if (name != Lib) return IntPtr.Zero;
            var p = Environment.GetEnvironmentVariable("ATLAS_PCA_LIBFNDSA");
            if (!string.IsNullOrEmpty(p)) return NativeLibrary.TryLoad(p, out var h) ? h : IntPtr.Zero;
            foreach (var f in new[] { "libfndsa.so", "libfndsa.dylib", "fndsa.dll" })
                if (NativeLibrary.TryLoad(Path.Combine(AppContext.BaseDirectory, f), out var b)) return b;
            return IntPtr.Zero; // default probing
        });
    }

    [DllImport(Lib)] static extern nint fndsa_len_vk(int tag);
    [DllImport(Lib)] static extern nint fndsa_len_sk(int tag);
    [DllImport(Lib)] static extern nint fndsa_len_sig(int tag);
    [DllImport(Lib)] static extern nuint fndsa_len_seed();
    [DllImport(Lib)] static extern nuint fndsa_cap_msg();
    [DllImport(Lib)] static extern int fndsa_c_keygen(int tag, byte* seed, nuint seedLen, byte* sk, nuint skLen, byte* vk, nuint vkLen);
    [DllImport(Lib)] static extern int fndsa_c_sign(int tag, byte* sk, nuint skLen, byte* msg, nuint msgLen, byte* seed, nuint seedLen, byte* sig, nuint sigLen);
    [DllImport(Lib)] static extern int fndsa_c_verify(int tag, byte* vk, nuint vkLen, byte* sig, nuint sigLen, byte* msg, nuint msgLen);

    sealed record Sizes(int Vk, int Sk, int Sig);

    static readonly Lazy<(Sizes S512, Sizes S1024)> Checked = new(() =>
    {
        try
        {
            if (fndsa_len_seed() != SeedBytes || fndsa_cap_msg() != MsgCap) throw new FnDsaNativeException("libfndsa reports a different seed length or message cap");
            Sizes Of(int t, int vk, int sig) =>
                fndsa_len_vk(t) == vk && fndsa_len_sig(t) == sig && fndsa_len_sk(t) > 0
                    ? new Sizes(vk, (int)fndsa_len_sk(t), sig)
                    : throw new FnDsaNativeException("libfndsa reports different FN-DSA sizes");
            return (Of(512, Core.FnDsa512PublicKeyBytes, Core.FnDsa512SignatureBytes), Of(1024, Core.FnDsa1024PublicKeyBytes, Core.FnDsa1024SignatureBytes));
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            throw new FnDsaNativeException("libfndsa could not be loaded (set ATLAS_PCA_LIBFNDSA to the shared library): " + e.Message, e);
        }
    });

    /// <summary>True when libfndsa loads and reports the expected sizes.</summary>
    public static bool Available()
    {
        try { _ = Checked.Value; return true; } catch (FnDsaNativeException) { return false; }
    }

    static (int Tag, Sizes S) Tag(string? variant) => variant switch
    {
        "fn-dsa-512" => (512, Checked.Value.S512),
        "fn-dsa-1024" => (1024, Checked.Value.S1024),
        _ => throw new ArgumentOutOfRangeException(nameof(variant), $"unknown FN-DSA variant '{variant}'"),
    };

    /// <summary>Deterministic key generation from a 32-byte seed.</summary>
    public static FalconKeyPair Keygen(string variant, byte[] seed)
    {
        var (tag, s) = Tag(variant);
        if (seed == null || seed.Length != SeedBytes) throw new ArgumentException("keygen seed must be 32 bytes", nameof(seed));
        var sk = new byte[s.Sk]; var vk = new byte[s.Vk];
        int rc;
        fixed (byte* ps = seed, pk = sk, pv = vk) rc = fndsa_c_keygen(tag, ps, (nuint)seed.Length, pk, (nuint)sk.Length, pv, (nuint)vk.Length);
        if (rc != 0) throw new FnDsaNativeException($"fndsa_c_keygen refused ({rc})");
        return new FalconKeyPair(vk, sk);
    }

    /// <summary>Sign msg with sk; the signing seed is 32 fresh CSPRNG bytes unless one is supplied (deterministic, tests only).</summary>
    public static byte[] Sign(string variant, byte[] sk, byte[] msg, byte[]? seed = null)
    {
        var (tag, s) = Tag(variant);
        if (sk == null || sk.Length != s.Sk) throw new ArgumentException($"secret key must be {s.Sk} bytes for '{variant}'", nameof(sk));
        if (msg == null || msg.Length > MsgCap) throw new ArgumentException($"message must be a byte array of at most {MsgCap} bytes", nameof(msg));
        seed ??= RandomNumberGenerator.GetBytes(SeedBytes);
        if (seed.Length != SeedBytes) throw new ArgumentException("signing seed must be 32 bytes", nameof(seed));
        var sig = new byte[s.Sig];
        int rc;
        fixed (byte* pk = sk, pm = msg, ps = seed, pg = sig) rc = fndsa_c_sign(tag, pk, (nuint)sk.Length, pm, (nuint)msg.Length, ps, (nuint)seed.Length, pg, (nuint)sig.Length);
        if (rc != 0) throw new FnDsaNativeException($"fndsa_c_sign refused ({rc})");
        return sig;
    }

    /// <summary>True only when the C library returns 0. Any bad length, oversize message or non-zero return is false; a missing library throws.</summary>
    public static bool Verify(string variant, byte[]? vk, byte[]? msg, byte[]? sig)
    {
        var (tag, s) = Tag(variant);
        if (vk == null || vk.Length != s.Vk || sig == null || sig.Length != s.Sig || msg == null || msg.Length > MsgCap) return false;
        int rc;
        fixed (byte* pv = vk, pm = msg, pg = sig) rc = fndsa_c_verify(tag, pv, (nuint)vk.Length, pg, (nuint)sig.Length, pm, (nuint)msg.Length);
        return rc == 0;
    }

    static string VariantOfPk(byte[] pk) => pk.Length == Core.FnDsa512PublicKeyBytes ? "fn-dsa-512" : pk.Length == Core.FnDsa1024PublicKeyBytes ? "fn-dsa-1024" : "";

    /// <summary>The backend for the core seam. Sign infers the variant from the secret-key length; Keygen mints fn-dsa-512 from CSPRNG bytes
    /// (use <see cref="Keygen"/> for 1024).</summary>
    public static FalconBackend Backend() => new()
    {
        Verify = (pk, msg, sig) => VariantOfPk(pk) is { Length: > 0 } v && Verify(v, pk, msg, sig),
        Sign = (sk, msg) =>
        {
            var v = sk.Length == Checked.Value.S512.Sk ? "fn-dsa-512" : sk.Length == Checked.Value.S1024.Sk ? "fn-dsa-1024" : throw new ArgumentException("secret key length matches no FN-DSA variant");
            return Sign(v, sk, msg);
        },
        Keygen = () => Keygen("fn-dsa-512", RandomNumberGenerator.GetBytes(SeedBytes)),
        KeygenFromSeed = Keygen,
        SignSeeded = (sk, msg, seed) =>
        {
            var v = sk.Length == Checked.Value.S512.Sk ? "fn-dsa-512" : sk.Length == Checked.Value.S1024.Sk ? "fn-dsa-1024" : throw new ArgumentException("secret key length matches no FN-DSA variant");
            return Sign(v, sk, msg, seed);
        },
    };

    /// <summary>Install the native backend into the core seam; throws FnDsaNativeException when the library is absent.</summary>
    public static FalconBackend Register()
    {
        _ = Checked.Value;
        var b = Backend();
        Core.SetFalconBackend(b);
        return b;
    }
}
