// LESS (less-252-45, the `less-cat1` / `hybrid-ed25519-less-cat1` suites; a NIST additional-signature round-2 candidate, not a
// standard) through P/Invoke to `libatlas_less`, the patched LESS reference C of the repository's sdks/pca-less-c built as a
// shared library (sdks/pca-less-c/build.sh).
using System.Runtime.InteropServices;

namespace AtlasPca;

/// <summary>The LESS backend. The library is found at <c>ATLAS_PCA_LIBLESS</c> (one path, or several separated by the
/// platform path separator), else in the repository's <c>sdks/pca-less-c/build/</c> (searched upward from the application
/// directory). It counts only if it reports the less-252-45 sizes; without one the LESS suites are not in
/// <see cref="Pq.Suites"/> and fail closed with <c>unsupported_suite</c>. The detached signature is variable-length
/// (1,153..1,329 bytes in steps of 16). Never throws.</summary>
public static class LessNative
{
    public const int PublicKeyBytes = 97484;
    public const int SignatureMinBytes = 1153;
    public const int SignatureMaxBytes = 1329;
    public const int SignatureStepBytes = 16;

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate nuint SizeFn();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int VerifyFn(byte[] pk, nuint pkLen, byte[] msg, nuint msgLen, byte[] sig, nuint sigLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int KeygenFn(byte[] pk, nuint pkCap, byte[] sk, nuint skCap, byte[] seed, nuint seedLen);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int SignFn(byte[] sk, nuint skLen, byte[] msg, nuint msgLen, byte[] seed, nuint seedLen, byte[] sig, nuint sigCap, out nuint sigLen);

    /// <summary>LESS secret key: the 32-byte seed the public key is expanded from.</summary>
    public const int SecretKeyBytes = 32;
    /// <summary>Entropy seed length of keygen and signing (the library takes at least this many bytes).</summary>
    public const int SeedBytes = 32;

    static IntPtr _handle;
    static readonly VerifyFn? Fn = Load();

    /// <summary>True iff a usable libatlas_less is loaded.</summary>
    public static bool Available => Fn != null;

    /// <summary>Candidate library paths, in order. Internal for tests.</summary>
    internal static IEnumerable<string> Candidates()
    {
        var env = Environment.GetEnvironmentVariable("ATLAS_PCA_LIBLESS");
        if (!string.IsNullOrEmpty(env))
            foreach (var p in env.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)) yield return p;
        // the package's own copy: beside the app (rid-specific publish) or under runtimes/<rid>/native (framework-dependent build)
        var rid = (OperatingSystem.IsWindows() ? "win" : OperatingSystem.IsMacOS() ? "osx" : "linux") + "-" + RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant();
        foreach (var n in new[] { "libatlas_less.so", "libatlas_less.dylib", "atlas_less.dll" })
        {
            yield return Path.Combine(AppContext.BaseDirectory, "runtimes", rid, "native", n);
            yield return Path.Combine(AppContext.BaseDirectory, n);
        }
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent)
        {
            var build = Path.Combine(d.FullName, "sdks", "pca-less-c", "build");
            if (!Directory.Exists(build)) continue;
            foreach (var n in new[] { "libatlas_less.so", "libatlas_less.dylib", "atlas_less.dll" }) yield return Path.Combine(build, n);
            yield break;
        }
    }

    static VerifyFn? Load()
    {
        try
        {
            foreach (var path in Candidates())
            {
                if (!File.Exists(path) || !NativeLibrary.TryLoad(path, out var h)) continue;
                nuint Size(string name) => NativeLibrary.TryGetExport(h, name, out var f) ? Marshal.GetDelegateForFunctionPointer<SizeFn>(f)() : 0;
                if (Size("atlas_less_cat1_public_key_bytes") != PublicKeyBytes || Size("atlas_less_cat1_signature_min_bytes") != SignatureMinBytes
                    || Size("atlas_less_cat1_signature_max_bytes") != SignatureMaxBytes || !NativeLibrary.TryGetExport(h, "atlas_less_cat1_verify", out var v))
                    continue;
                _handle = h;
                return Marshal.GetDelegateForFunctionPointer<VerifyFn>(v);
            }
        }
        catch { /* no backend: LESS is unsupported */ }
        return null;
    }

    /// <summary><paramref name="n"/> is a signature length the parameter set produces.</summary>
    public static bool SigLenOk(int n) => n >= SignatureMinBytes && n <= SignatureMaxBytes && (SignatureMaxBytes - n) % SignatureStepBytes == 0;

    /// <summary>The detached signature opens under <paramref name="pk"/> and yields exactly <paramref name="msg"/>.</summary>
    public static bool Verify(byte[] pk, byte[] msg, byte[] sig) => VerifyWith(Fn, pk, msg, sig);

    // the native wrapper accepts (msg == NULL, msg_len == 0), so an empty message is passed as is
    internal static bool VerifyWith(VerifyFn? fn, byte[] pk, byte[] msg, byte[] sig)
    {
        if (fn == null || pk.Length != PublicKeyBytes || !SigLenOk(sig.Length)) return false;
        try { return fn(pk, (nuint)pk.Length, msg, (nuint)msg.Length, sig, (nuint)sig.Length) == 1; }
        catch { return false; }
    }

    static T? Export<T>(string name) where T : class =>
        _handle != IntPtr.Zero && NativeLibrary.TryGetExport(_handle, name, out var f) ? Marshal.GetDelegateForFunctionPointer<T>(f) : null;

    /// <summary>Deterministic keygen from a <see cref="SeedBytes"/> seed (the library's SHAKE generator is seeded with it): (secret key, public key).
    /// Throws when no library with signing is loaded.</summary>
    public static (byte[] Sk, byte[] Pk) Keygen(byte[] seed)
    {
        if (seed == null || seed.Length != SeedBytes) throw new ArgumentException($"lessCat1Keygen: seed must be {SeedBytes} bytes");
        var fn = Export<KeygenFn>("atlas_less_cat1_keygen") ?? throw new InvalidOperationException("lessCat1Keygen: LESS suites are unsupported (no libatlas_less with signing)");
        var pk = new byte[PublicKeyBytes];
        var sk = new byte[SecretKeyBytes];
        if (fn(pk, (nuint)pk.Length, sk, (nuint)sk.Length, seed, (nuint)seed.Length) != 1) throw new InvalidOperationException("lessCat1Keygen: key generation failed");
        return (sk, pk);
    }

    /// <summary>Detached signature (1,153..1,329 bytes) of <paramref name="msg"/> with an explicit <see cref="SeedBytes"/> RNG seed (a fixed seed makes it
    /// reproducible; use CSPRNG bytes in production and never reuse a seed). Throws when unavailable or on failure.</summary>
    public static byte[] Sign(byte[] sk, byte[] msg, byte[] seed)
    {
        if (seed == null || seed.Length != SeedBytes) throw new ArgumentException($"lessCat1Sign: seed must be {SeedBytes} bytes");
        if (sk == null || sk.Length != SecretKeyBytes) throw new ArgumentException($"lessCat1Sign: secret key must be {SecretKeyBytes} bytes");
        var fn = Export<SignFn>("atlas_less_cat1_sign") ?? throw new InvalidOperationException("lessCat1Sign: LESS suites are unsupported (no libatlas_less with signing)");
        var buf = new byte[SignatureMaxBytes];
        if (fn(sk, (nuint)sk.Length, msg, (nuint)msg.Length, seed, (nuint)seed.Length, buf, (nuint)buf.Length, out var n) != 1 || !SigLenOk((int)n))
            throw new InvalidOperationException("lessCat1Sign: signing failed");
        return buf[..(int)n];
    }
}
