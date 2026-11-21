using System.Runtime.InteropServices;
using System.Text;

namespace AtlasPca.Ciba;

/// <summary>
/// The WHATWG host parser's domain-to-ASCII (UTS 46, as Node's url.domainToASCII) on Ada, through a small C shim (libatlasada). The library path comes
/// from ATLAS_PCA_LIBADA (strict: a path that does not load means not loaded), else libatlasada beside the assembly, else the package's runtimes/<rid>/native copy (linux-x64, linux-arm64, osx-x64, osx-arm64, win-x64), else the loader path. Without the
/// library a host that needs IDNA processing is refused unless the built-in approximation is opted into (ATLAS_PCA_IDNA_FALLBACK=1 or <see cref="AllowFallback"/>).
/// </summary>
internal static class AdaIdna
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int ToAsciiFn(byte[] input, nuint inputLen, byte[] output, nuint cap, out nuint outLen);

    const int Cap = 2048;
    static readonly UTF8Encoding Strict = new(false, true);

    static readonly Lazy<ToAsciiFn?> Fn = new(Load);

    /// <summary>Opt in to the built-in approximation when libatlasada is not loadable (default: the ATLAS_PCA_IDNA_FALLBACK=1 environment switch).</summary>
    internal static bool AllowFallback { get; set; } = Environment.GetEnvironmentVariable("ATLAS_PCA_IDNA_FALLBACK") == "1";

    internal static bool Loaded => Fn.Value != null;

    static ToAsciiFn? Load()
    {
        try
        {
            IntPtr h = IntPtr.Zero;
            var p = Environment.GetEnvironmentVariable("ATLAS_PCA_LIBADA");
            if (!string.IsNullOrEmpty(p)) { if (!NativeLibrary.TryLoad(p, out h)) return null; }
            else
            {
                foreach (var f in new[] { "libatlasada.so", "libatlasada.dylib", "atlasada.dll" })
                    if (NativeLibrary.TryLoad(Path.Combine(AppContext.BaseDirectory, f), out h)) break;
                if (h == IntPtr.Zero && !NativeLibrary.TryLoad("atlasada", typeof(AdaIdna).Assembly, null, out h)) return null; // the assembly-aware probe finds the NuGet runtimes/<rid>/native copy
            }
            if (!NativeLibrary.TryGetExport(h, "atlas_ada_domain_to_ascii", out var fp)) return null;
            return Marshal.GetDelegateForFunctionPointer<ToAsciiFn>(fp);
        }
        catch (Exception e) when (e is DllNotFoundException or BadImageFormatException or EntryPointNotFoundException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>False when libatlasada is not loaded. True with <paramref name="ascii"/> the host as Node returns it, "" when the host is refused.</summary>
    internal static bool TryToAscii(string word, out string ascii)
    {
        ascii = "";
        var fn = Fn.Value;
        if (fn == null) return false;
        byte[] input;
        try { input = Strict.GetBytes(word); } catch (EncoderFallbackException) { return true; } // a lone surrogate: refused
        if (input.Length == 0) return true;
        var buf = new byte[Cap];
        if (fn(input, (nuint)input.Length, buf, (nuint)buf.Length, out var n) != 1 || n == 0 || n > (nuint)buf.Length) return true;
        ascii = Encoding.ASCII.GetString(buf, 0, (int)n);
        return true;
    }

    /// <summary>The ASCII form of an already percent-decoded, non-ASCII host for the URL parsers (Jose and Oauth WhatwgUrl), or null when it is refused. With
    /// libatlasada this is Node's host: Ada answers every host. Without it the host is refused unless the built-in approximation is opted into, in which case
    /// the platform's IdnMapping (ICU or NLS, so not byte-identical to Node) stands in.</summary>
    internal static string? HostToAscii(string host)
    {
        if (TryToAscii(host, out var viaAda)) return viaAda.Length == 0 ? null : viaAda;
        if (!AllowFallback) return null;
        try { return new System.Globalization.IdnMapping { AllowUnassigned = true }.GetAscii(host); }
        catch (ArgumentException) { return null; }
    }

    /// <summary>True when the word needs IDNA processing: a non-ASCII character, a percent escape (which may decode to one) or an xn-- label.</summary>
    internal static bool NeedsIdna(string word) =>
        word.Any(c => c >= 0x80 || c == '%') || word.Contains("xn--", StringComparison.OrdinalIgnoreCase);
}
