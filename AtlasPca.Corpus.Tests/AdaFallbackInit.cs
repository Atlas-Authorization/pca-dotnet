using System.Runtime.CompilerServices;
using AtlasPca.Ciba;

namespace AtlasPca.Corpus.Tests;

/// <summary>The corpus replays run without libatlasada (the dedicated Ada workflow replays them on it): the built-in host approximation is opted into here
/// only, for the CIBA word parser and the Jose / Oauth URL parsers alike.</summary>
internal static class AdaFallbackInit
{
    [ModuleInitializer]
    internal static void Init() { if (!AdaIdna.Loaded) AdaIdna.AllowFallback = true; }
}
