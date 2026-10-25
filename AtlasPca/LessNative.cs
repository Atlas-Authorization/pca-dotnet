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
    const int SignatureStepBytes = 16;

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate nuint SizeFn();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int VerifyFn(byte[] pk, nuint pkLen, byte[] msg, nuint msgLen, byte[] sig, nuint sigLen);

    static readonly VerifyFn? Fn = Load();

    /// <summary>True iff a usable libatlas_less is loaded.</summary>
    public static bool Available => Fn != null;

    /// <summary>Candidate library paths, in order. Internal for tests.</summary>
    internal static IEnumerable<string> Candidates()
    {
        var env = Environment.GetEnvironmentVariable("ATLAS_PCA_LIBLESS");
        if (!string.IsNullOrEmpty(env))
            foreach (var p in env.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)) yield return p;
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
                return Marshal.GetDelegateForFunctionPointer<VerifyFn>(v);
            }
        }
        catch { /* no backend: LESS is unsupported */ }
        return null;
    }

    /// <summary><paramref name="n"/> is a signature length the parameter set produces.</summary>
    public static bool SigLenOk(int n) => n >= SignatureMinBytes && n <= SignatureMaxBytes && (SignatureMaxBytes - n) % SignatureStepBytes == 0;

    /// <summary>The detached signature opens under <paramref name="pk"/> and yields exactly <paramref name="msg"/>.</summary>
    public static bool Verify(byte[] pk, byte[] msg, byte[] sig)
    {
        if (Fn == null || pk.Length != PublicKeyBytes || !SigLenOk(sig.Length)) return false;
        try { return Fn(pk, (nuint)pk.Length, msg.Length == 0 ? new byte[1] : msg, (nuint)msg.Length, sig, (nuint)sig.Length) == 1; }
        catch { return false; }
    }
}
