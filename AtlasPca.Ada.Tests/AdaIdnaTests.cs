using System.IO.Compression;
using System.Text.Json;
using AtlasPca.Ciba;
using Xunit;
using Cb = AtlasPca.Ciba.Ciba;

namespace AtlasPca.Ada.Tests;

/// <summary>CIBA host IDNA on Ada. The library-dependent tests fail (not skip) under CI=true or ATLAS_PCA_ADA_REQUIRED=1 when libatlasada is missing.</summary>
[Collection("ada-global-fallback")]
public class AdaIdnaTests
{
    static bool Required => Environment.GetEnvironmentVariable("CI") == "true" || Environment.GetEnvironmentVariable("ATLAS_PCA_ADA_REQUIRED") == "1";

    static bool Have()
    {
        if (AdaIdna.Loaded) return true;
        if (Required) Assert.Fail("libatlasada must load (set ATLAS_PCA_LIBADA)");
        Console.WriteLine("SKIP: libatlasada not found (set ATLAS_PCA_LIBADA)");
        return false;
    }

    [Fact]
    public void CorpusDomainToAscii()
    {
        if (!Have()) return;
        var path = Path.Combine(AppContext.BaseDirectory, "test-data", "ref-idna-kotlin.json.gz");
        using var gz = new GZipStream(File.OpenRead(path), CompressionMode.Decompress);
        using var doc = JsonDocument.Parse(gz);
        int n = 0, unreadable = 0;
        foreach (var c in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            if (c.GetProperty("fn").GetString() != "domainToAscii") continue;
            if (Text(c.GetProperty("args")[0]) is not { } word || Text(c.GetProperty("out")) is not { } want) { unreadable++; continue; }
            Assert.True(AdaIdna.TryToAscii(word, out var got));
            Assert.Equal(want, got);
            Assert.Equal(want, Cb.DomainToAscii(word));
            n++;
        }
        Assert.True(n > 50, "corpus has domainToAscii cases");
        Assert.True(unreadable <= 2, $"{unreadable} cases could not be read");
    }

    static List<JsonElement> Corpus(string name)
    {
        using var gz = new GZipStream(File.OpenRead(Path.Combine(AppContext.BaseDirectory, "test-data", name + ".json.gz")), CompressionMode.Decompress);
        var root = JsonDocument.Parse(gz).RootElement;
        Assert.Equal(root.GetProperty("count").GetInt32(), root.GetProperty("cases").GetArrayLength());
        return root.GetProperty("cases").EnumerateArray().ToList();
    }

    // a word with a lone surrogate cannot be read as a string here: null (the corpus has one such host, counted by the callers)
    static string? Text(JsonElement e)
    {
        try { return e.GetString(); } catch (InvalidOperationException) { return null; }
    }

    /// <summary>The URL-host cases of the same corpus: the host of https://word as the URL parser reports it, null when the URL does not parse.</summary>
    [Fact]
    public void CorpusUrlHost()
    {
        if (!Have()) return;
        var bad = new List<string>();
        int n = 0, unreadable = 0;
        foreach (var c in Corpus("ref-idna-kotlin").Where(c => c.GetProperty("fn").GetString() == "urlHost"))
        {
            if (Text(c.GetProperty("args")[0]) is not { } word) { unreadable++; continue; }
            var want = c.GetProperty("out").ValueKind == JsonValueKind.Null ? null : c.GetProperty("out").GetString();
            var got = AtlasPca.Jose.WhatwgUrl.TryParse("https://" + word)?.Host;
            if (got != want) bad.Add($"{c.GetProperty("name").GetString()}: want {want ?? "null"}, have {got ?? "null"}");
            n++;
        }
        Assert.True(bad.Count == 0, string.Join("\n", bad));
        Assert.Equal(100, n + unreadable);
        Assert.True(unreadable <= 1, $"{unreadable} hosts could not be read");
    }

    /// <summary>The second host corpus (whole URLs): the parser's host, or its refusal with the reference's code; and the domain-to-ASCII words.</summary>
    [Fact]
    public void CorpusOfWholeUrls()
    {
        if (!Have()) return;
        var bad = new List<string>();
        int n = 0, unreadable = 0;
        foreach (var c in Corpus("ref-idna"))
        {
            var name = c.GetProperty("name").GetString()!;
            if (Text(c.GetProperty("args")[0]) is not { } arg) { unreadable++; continue; }
            var want = c.GetProperty("out");
            n++;
            switch (c.GetProperty("fn").GetString())
            {
                case "urlHost":
                    if (want.ValueKind == JsonValueKind.String)
                    {
                        var got = AtlasPca.Jose.WhatwgUrl.TryParse(arg)?.Host;
                        if (got != want.GetString()) bad.Add($"{name}: want {want.GetString()}, have {got ?? "refused"}");
                    }
                    else
                    {
                        var e = Record.Exception(() => AtlasPca.Jose.WhatwgUrl.Require(arg));
                        if (e is not AtlasPca.Jose.InvalidUrlException { Code: "ERR_INVALID_URL" }) bad.Add($"{name}: want a refusal, have {e?.GetType().Name ?? "a host"}");
                    }
                    break;
                case "domainToAscii":
                    if (Cb.DomainToAscii(arg) != want.GetString()) bad.Add($"{name}: want {want.GetString()}, have {Cb.DomainToAscii(arg)}");
                    break;
                default:
                    bad.Add(name + ": no test for this function");
                    break;
            }
        }
        Assert.True(bad.Count == 0, string.Join("\n", bad));
        Assert.Equal(144, n + unreadable);
        Assert.True(unreadable <= 2, $"{unreadable} arguments could not be read");
    }

    [Theory]
    [InlineData("bücher.example", "xn--bcher-kva.example")]
    [InlineData("faß.de", "xn--fa-hia.de")]
    [InlineData("EXAMPLE.com", "example.com")]
    public void KnownHosts(string word, string want)
    {
        if (!Have()) return;
        Assert.Equal(want, Cb.DomainToAscii(word));
    }

    [Fact]
    public void WithoutLibraryIdnaHostsAreRefusedAndAsciiHostsWork()
    {
        if (AdaIdna.Loaded) return; // the library answers every host; the refusal path only exists without it
        var before = AdaIdna.AllowFallback;
        try
        {
            AdaIdna.AllowFallback = false;
            Assert.Equal("", Cb.DomainToAscii("bücher.example"));
            Assert.Equal("", Cb.DomainToAscii("xn--bcher-kva.example"));
            Assert.Equal("", Cb.DomainToAscii("%C3%A9.example"));
            Assert.Equal("example.com", Cb.DomainToAscii("EXAMPLE.com"));
            AdaIdna.AllowFallback = true;
            Assert.Equal("xn--bcher-kva.example", Cb.DomainToAscii("bücher.example"));
        }
        finally { AdaIdna.AllowFallback = before; }
    }

    /// <summary>The URL parsers (Jose and Oauth WhatwgUrl) take their A-labels from Ada, as Node's does.</summary>
    [Fact]
    public void UrlParsersUseAda()
    {
        if (!Have()) return;
        Assert.Equal("xn--bcher-kva.example", AtlasPca.Jose.WhatwgUrl.TryParse("https://b\u00fccher.example/p")!.Host);
        Assert.Null(AtlasPca.Jose.WhatwgUrl.TryParse("https://b\u00fc%20cher.example/"));
        Assert.Equal("xn--bcher-kva.example", AdaIdna.HostToAscii("b\u00fccher.example"));
        Assert.Equal("xn--9ca..xn--9ca", AdaIdna.HostToAscii("\u00e9..\u00e9")); // empty labels pass UTS 46 as Node's host parser does
    }

    [Fact]
    public void UrlParsersRefuseNonAsciiHostsWithoutTheLibrary()
    {
        if (AdaIdna.Loaded) return;
        var before = AdaIdna.AllowFallback;
        try
        {
            AdaIdna.AllowFallback = false;
            Assert.Null(AtlasPca.Jose.WhatwgUrl.TryParse("https://b\u00fccher.example/"));
            Assert.Equal("https://example.com/", AtlasPca.Jose.WhatwgUrl.NormalizeHtu("https://EXAMPLE.com/"));
        }
        finally { AdaIdna.AllowFallback = before; }
    }
}
