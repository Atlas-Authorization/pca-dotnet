using Xunit;

namespace AtlasPca.Pairing.Tests;

/// <summary>The native lookup order: the override variable wins when it loads, otherwise the default probing runs.</summary>
public class NativeResolverTests
{
    [Fact]
    public void OverrideIsStrictAndOnlyForBlst()
    {
        var old = Environment.GetEnvironmentVariable("ATLAS_PCA_LIBBLST");
        try
        {
            Environment.SetEnvironmentVariable("ATLAS_PCA_LIBBLST", null);
            Assert.Equal(IntPtr.Zero, NativeResolver.Resolve("blst.dll", typeof(NativeResolver).Assembly, null)); // default probing
            Environment.SetEnvironmentVariable("ATLAS_PCA_LIBBLST", "/no/such/libblst");
            Assert.Equal(IntPtr.Zero, NativeResolver.Resolve("blst.dll", typeof(NativeResolver).Assembly, null)); // an override that does not load falls to the default probing
            Assert.Equal(IntPtr.Zero, NativeResolver.Resolve("other", typeof(NativeResolver).Assembly, null));
        }
        finally { Environment.SetEnvironmentVariable("ATLAS_PCA_LIBBLST", old); }
    }
}
