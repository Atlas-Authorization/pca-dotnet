using AtlasPca.Oauth;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>WHATWG URL IPv4 number-form hosts through the OAuth bridge's URL parser (spec examples).</summary>
public class OauthWhatwgIpv4Tests
{
    [Theory]
    [InlineData("http://0x7f.1/", "http://127.0.0.1")]
    [InlineData("http://2130706433/", "http://127.0.0.1")]
    [InlineData("http://0177.0.0.01/", "http://127.0.0.1")]
    [InlineData("http://127.1:8080/x", "http://127.0.0.1:8080")]
    [InlineData("http://192.168.0.257.", null)]
    [InlineData("http://1.2.3.4.5/", null)]
    [InlineData("http://256.1.1.1/", null)]
    [InlineData("http://4294967296/", null)]
    [InlineData("http://example.0x/", null)]
    [InlineData("http://example.com./", "http://example.com.")]
    [InlineData("http://1.example/", "http://1.example")]
    public void HostForms(string url, string? origin) => Assert.Equal(origin, WhatwgUrl.TryParse(url)?.Origin);
}
