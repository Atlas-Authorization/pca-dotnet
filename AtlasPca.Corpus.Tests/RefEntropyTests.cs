using System.Security.Cryptography;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the entropy module against the reference (test-data/ref-entropy.json.gz, 562 cases): the health-test cutoffs and verdicts, the
/// response parsers, the HKDF combiner, SecureSeed and the key-pair helper with the local CSPRNG, the QRNG source and the error hook injected by each case, and the
/// HTTP source over an injected transport (request URL, headers, refusals, timeout, key scrubbing). A reference refusal must be a refusal here; messages of this
/// module (those starting with QRNG, HttpQrngSource, mixEntropy or secureSeed) and their error class are compared exactly.</summary>
public class RefEntropyTests
{
    const string M = "ref-entropy";
    static readonly string[] Pinned = { "QRNG", "HttpQrngSource", "mixEntropy", "secureSeed" };

    /// <summary>A rejection with a bare string (the reference can reject with a value that is not an error).</summary>
    sealed class BareString : Exception { public BareString(string m) : base(m) { } }

    static string Cls(Exception e) => e switch
    {
        EntropyError => "EntropyError", BareString => "string", ArgumentOutOfRangeException => "RangeError", ArgumentException => "TypeError", _ => "Error",
    };

    static D Thrown(Exception e)
    {
        var d = new D { ["$throws"] = e.Message, ["cls"] = Cls(e) };
        if (e.GetType().GetProperty("Code")?.GetValue(e) is string code) d["code"] = code;
        return d;
    }

    static D ErrRec(Exception e)
    {
        var d = Thrown(e);
        d["message"] = d["$throws"];
        d.Remove("$throws");
        return d;
    }

    /// <summary>A reference throw needs a throw here with every recorded member equal; the message and class are compared for this module's own messages only
    /// (the others are JavaScript runtime text).</summary>
    static bool Same(object? want, object? have)
    {
        bool threw = have is D hd && hd.ContainsKey("$throws");
        if (want is not D w || w.GetValueOrDefault("$throws") is not string msg) return !threw && Base.Eq(want, have);
        if (!threw) return false;
        var h = (D)have!;
        bool pinned = Pinned.Any(p => msg.StartsWith(p, StringComparison.Ordinal));
        foreach (var (k, v) in w)
        {
            if (k is "$throws" or "cls") { if (pinned && !Base.Eq(v, h.GetValueOrDefault(k))) return false; }
            else if (!Base.Eq(v, h.GetValueOrDefault(k))) return false;
        }
        return true;
    }

    /// <summary>Replays every case of <paramref name="fn"/> (the named ones excepted; none is today); the case total is asserted. Inputs of a type the typed API
    /// cannot be given go through an untyped entry of this test that answers as the reference does.</summary>
    static async Task Replay(string fn, Func<L, Task<object?>> run, int total, params string[] skip)
    {
        var bad = new List<string>();
        int n = 0, skipped = 0;
        foreach (var c in Base.Of(M, fn).ToList())
        {
            var name = (string)c["name"]!;
            n++;
            if (skip.Contains(name)) { skipped++; continue; }
            object? have;
            try { have = await run(Base.Args(c)); }
            catch (Exception e) { have = Thrown(e); }
            if (!Same(c["out"], have)) bad.Add($"{name}\n   want {Base.Show(c["out"])}\n   have {Base.Show(Base.Json(have))}");
        }
        Assert.True(bad.Count == 0, $"{M}/{fn}: {bad.Count} of {n} divergent:\n" + string.Join("\n", bad.Take(30)));
        Assert.Equal(total, n);
        Assert.Equal(skip.Length, skipped);
    }

    static Task ReplaySync(string fn, Func<L, object?> run, int total, params string[] skip) => Replay(fn, a => Task.FromResult(run(a)), total, skip);

    // ---- argument forms ----

    static byte[]? B(object? a) => a is D d && Base.IsBytes(d) ? Base.Bytes(d) : null;

    static double Dbl(object? v) => v is D d && d.GetValueOrDefault("$num") is string s
        ? s switch { "NaN" => double.NaN, "Infinity" => double.PositiveInfinity, "-Infinity" => double.NegativeInfinity, _ => throw new ArgumentException("$num") }
        : IntentJs.NumOf(v) ?? throw new ArgumentException("not a number");

    static double? DblOpt(D o, string k) => o.GetValueOrDefault(k) == null ? null : Dbl(o[k]);

    /// <summary>An integer option: absent or null is "not given"; anything that is not an int (a fraction, a non-finite number, a string) becomes -1, which every
    /// integer option of the module refuses with the reference's own message.</summary>
    static int? IntOpt(D o, string k)
    {
        var v = o.GetValueOrDefault(k);
        if (v == null) return null;
        return v is not D && v is not string && IntentJs.NumOf(v) is double d && d == Math.Floor(d) && Math.Abs(d) < int.MaxValue ? (int)d : -1;
    }

    static object Out(double v) => double.IsNaN(v) ? new D { ["$num"] = "NaN" } : double.IsInfinity(v) ? new D { ["$num"] = v > 0 ? "Infinity" : "-Infinity" } : (object)v;

    static HealthTestOptions Health(D o) => new(DblOpt(o, "h"), DblOpt(o, "window"));

    [Fact]
    public Task Constants() => ReplaySync("constants", _ => new D
    {
        ["MAX_HKDF_OUTPUT"] = Entropy.MaxHkdfOutput, ["MIN_LOCAL_BYTES"] = Entropy.MinLocalBytes, ["DEFAULT_SEED_BYTES"] = Entropy.DefaultSeedBytes,
        ["DEFAULT_MAX_QRNG_BYTES"] = Entropy.DefaultMaxQrngBytes, ["DEFAULT_TIMEOUT_MS"] = Entropy.DefaultTimeoutMs,
    }, 1);

    [Fact] public Task RepetitionCutoff() => ReplaySync("repetitionCutoff", a => Out(Entropy.RepetitionCutoff(Dbl(a[0]))), 21);
    [Fact] public Task ProportionCutoff() => ReplaySync("proportionCutoff", a => Out(Entropy.ProportionCutoff(Dbl(a[0]), Dbl(a[1]))), 65);

    [Fact]
    public Task HealthTestBytes() => ReplaySync("healthTestBytes", a =>
    {
        // untyped entry: an options argument that is given but is not an object is a type error in the reference
        if (a.Count > 1 && a[1] is not D) throw new ArgumentException("the options are not an object");
        var v = Entropy.HealthTestBytes(B(a[0])!, a.Count > 1 ? Health((D)a[1]!) : null);
        var o = new D { ["ok"] = v.Ok };
        if (v.Test != null) o["test"] = v.Test;
        return o;
    }, 110);

    [Fact] public Task ParseAnuUint8() => ReplaySync("parseAnuUint8", a => Entropy.ParseAnuUint8(a[0]), 31);
    // untyped entries for the text parsers: the reference tests the text form of whatever it is given (null reads as "null"); a number has no length, which its
    // hex parser refuses, while its base64 parser decodes the number's text
    static byte[] UntypedHex(object? v) => v switch
    {
        string s => Entropy.ParseHex(s),
        null => Entropy.ParseHex("null"),
        _ => throw new InvalidOperationException("QRNG: malformed hex payload"),
    };

    [Fact] public Task ParseHex() => ReplaySync("parseHex", a => UntypedHex(a[0]), 23);
    [Fact] public Task ParseBase64() => ReplaySync("parseBase64", a => Entropy.ParseBase64(InteropJs.JsX.Str(a[0])), 52);

    [Fact]
    public Task MixEntropy() => ReplaySync("mixEntropy", a =>
    {
        var o = a.Count > 2 ? (D)a[2]! : new D();
        // a null context is read for its length in the reference (a TypeError); the typed parameter cannot hold one
        if (o.TryGetValue("context", out var cx) && cx is null) throw new ArgumentException("Cannot read properties of null (reading 'length')");
        return Entropy.MixEntropy(B(a[0])!, B(a[1])!, IntOpt(o, "length"), o.GetValueOrDefault("context") as string);
    }, 71);

    // ---- SecureSeed and the key pair: the source, the local CSPRNG and the hook come from the case ----

    sealed class SpecSource : IQrngSource
    {
        readonly D _spec;
        readonly List<int> _log;
        public SpecSource(D spec, List<int> log) { _spec = spec; _log = log; }
        public string Name => _spec.GetValueOrDefault("name") as string ?? "test-src";
        public Task<byte[]> FetchAsync(int numBytes)
        {
            _log.Add(numBytes);
            var message = _spec.GetValueOrDefault("message") as string ?? "";
            return (string)_spec["kind"]! switch
            {
                "bytes" => Task.FromResult(B(_spec["value"])!),
                "reject" => Task.FromException<byte[]>(new Exception(message)),
                "rejectString" => Task.FromException<byte[]>(new BareString(message)),
                "nonbytes" => Task.FromResult<byte[]>(null!),
                "throwSync" => throw new Exception(message),
                _ => throw new InvalidDataException("source spec"),
            };
        }
    }

    static async Task<object?> SeedRun(L a, bool keyPair)
    {
        var spec = (D)a[0]!;
        var requests = new List<int>();
        var locals = new List<int>();
        var errors = new L();
        var o = new SecureSeedOptions
        {
            Length = IntOpt(spec, "length"), LocalBytes = IntOpt(spec, "localBytes"), QuantumBytes = IntOpt(spec, "quantumBytes"), Context = spec.GetValueOrDefault("context") as string,
            RequireQuantum = spec.GetValueOrDefault("requireQuantum") is true, DisableHealthTest = spec.GetValueOrDefault("healthTest") is false,
            HealthTest = spec.GetValueOrDefault("healthTest") is D h ? Health(h) : null,
            Source = spec.GetValueOrDefault("source") is D s ? new SpecSource(s, requests) : null,
        };
        if (spec.GetValueOrDefault("local") is D local)
            o.RandomBytesImpl = n =>
            {
                locals.Add(n);
                return (string)local["kind"]! switch { "fixed" => B(local["value"]), "throw" => throw new Exception((string)local["message"]!), _ => null };
            };
        var hook = spec.GetValueOrDefault("hook") as string ?? "none";
        if (hook != "none") o.OnQrngError = e => { errors.Add(ErrRec(e)); if (hook == "throw") throw new Exception("hook boom"); };
        D res;
        try
        {
            if (keyPair)
            {
                var kp = await Entropy.GenerateKeyPairWithEntropyAsync(o);
                res = new D { ["publicKey"] = kp.PublicKey, ["secretKeySha256"] = Convert.ToHexString(SHA256.HashData(kp.SecretKey)).ToLowerInvariant(), ["usedQuantum"] = kp.UsedQuantum };
            }
            else
            {
                var r = await Entropy.SecureSeedAsync(o);
                res = new D { ["seed"] = r.Seed, ["usedQuantum"] = r.UsedQuantum, ["quantumByteCount"] = r.QuantumByteCount, ["source"] = r.Source };
            }
        }
        catch (Exception e) { res = Thrown(e); }
        res["qrngErrors"] = errors;
        res["localRequested"] = locals.Count > 0 ? (object?)locals[0] : null;
        res["requests"] = requests;
        return res;
    }

    [Fact] public Task SecureSeed() => Replay("secureSeed", a => SeedRun(a, false), 64);
    [Fact] public Task GenerateKeyPairWithEntropy() => Replay("generateKeyPairWithEntropy", a => SeedRun(a, true), 11);

    static async Task<object?> Unavailable(IQrngSource src, int n)
    {
        try { await src.FetchAsync(n); return new D { ["name"] = src.Name, ["ok"] = true }; }
        catch (Exception e) { return new D { ["name"] = src.Name, ["$throws"] = e.Message }; }
    }

    [Fact]
    public Task NullQrng() => Replay("nullQrng", a => Unavailable(a[0] is string r ? new NullQrngSource(r) : new NullQrngSource(), (int)Base.Long(a[1])), 5);

    [Fact]
    public Task UnavailableSource() => Replay("unavailableSource", a => Unavailable(a[0] is string r ? Entropy.UnavailableSource(r) : Entropy.UnavailableSource(), (int)Base.Long(a[1])), 5);

    [Fact]
    public Task EntropyErrorCarriesItsCode() => ReplaySync("entropyError", a =>
    {
        var e = new EntropyError((string)a[0]!, (string)a[1]!);
        return new D { ["name"] = e.GetType().Name, ["code"] = e.Code, ["message"] = e.Message, ["isError"] = e is Exception };
    }, 4);

    // ---- the HTTP source over the case's transport ----

    static QrngTransport? Transport(D spec, L log)
    {
        var kind = (string)spec["kind"]!;
        if (kind == "none") return null;
        int status = spec.ContainsKey("status") ? (int)Base.Long(spec["status"]) : 200;
        bool ok = spec.GetValueOrDefault("ok") is bool b ? b : status >= 200 && status <= 299;
        return async (req, cancel) =>
        {
            log.Add(new D { ["url"] = req.Url, ["headers"] = req.Headers.ToDictionary(e => e.Key, e => (object?)e.Value), ["redirect"] = req.Redirect, ["signal"] = cancel.CanBeCanceled });
            switch (kind)
            {
                case "json": return new QrngResponse { Ok = ok, Status = status, Json = () => Task.FromResult(spec.GetValueOrDefault("body")), Text = () => throw new Exception("text unused") };
                case "text": return new QrngResponse { Ok = ok, Status = status, Json = () => throw new Exception("json unused"), Text = () => Task.FromResult((string)spec["text"]!) };
                case "jsonThrows": return new QrngResponse { Ok = ok, Status = status, Json = () => Task.FromException<object?>(new FormatException("bad json")), Text = () => Task.FromResult("") };
                case "textThrows": return new QrngResponse { Ok = ok, Status = status, Json = () => Task.FromResult<object?>(new D()), Text = () => Task.FromException<string>(new Exception("read failed")) };
                case "throw": throw new Exception((string)spec["message"]!);
                // untyped entry: a rejection that is not an error has no message, which the reference reports as "unknown error"
                case "throwString": throw new BareString("unknown error");
                case "hang": await Task.Delay(Timeout.Infinite, cancel).ConfigureAwait(false); throw new InvalidOperationException("unreachable");
                default: throw new InvalidDataException("transport spec");
            }
        };
    }

    static async Task<object?> HttpRun(L a)
    {
        var cfg = (D)a[0]!;
        var log = new L();
        var c = new HttpQrngConfig
        {
            Url = cfg.GetValueOrDefault("url") as string, ApiKey = cfg.GetValueOrDefault("apiKey") as string, ApiKeyHeader = cfg.GetValueOrDefault("apiKeyHeader") as string,
            Format = cfg.GetValueOrDefault("format") as string, TimeoutMs = IntOpt(cfg, "timeoutMs"), MaxBytes = IntOpt(cfg, "maxBytes"), LengthParam = cfg.GetValueOrDefault("lengthParam") as string,
            ExtraParams = (cfg.GetValueOrDefault("extraParams") as D)?.Select(e => new KeyValuePair<string, string>(e.Key, (string)e.Value!)).ToList(),
            AllowInsecureLoopback = cfg.GetValueOrDefault("allowInsecureLoopback") is true, Transport = Transport((D)a[2]!, log),
        };
        if (cfg.GetValueOrDefault("buildUrl") is D bu) c.BuildUrl = (b, n) => b + "/" + n.ToString(System.Globalization.CultureInfo.InvariantCulture) + (string)bu["suffix"]!;
        HttpQrngSource src;
        try { src = new HttpQrngSource(c); }
        catch (Exception e) { return Thrown(e); }
        try
        {
            // untyped entry: a byte count that is not an integer number never reaches the source; the reference refuses it with the count as text
            if (a[1] is string || a[1] is null || a[1] is D || !IntentJs.IsSafeInteger(a[1]))
                throw new ArgumentException("QRNG: numBytes must be a positive integer, got " + (a[1] is D nd ? (string)nd["$num"]! : InteropJs.JsX.Str(a[1])));
            var bytes = await src.FetchAsync((int)Base.Long(a[1]));
            return new D { ["name"] = src.Name, ["bytes"] = bytes, ["requests"] = log };
        }
        catch (Exception e)
        {
            var d = Thrown(e);
            d["name"] = src.Name;
            d["requests"] = log;
            d["leaksKey"] = !string.IsNullOrEmpty(c.ApiKey) && e.Message.Contains(c.ApiKey, StringComparison.Ordinal);
            return d;
        }
    }

    [Fact] public Task HttpQrng() => Replay("httpQrng", HttpRun, 99);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[]
        {
            "constants", "repetitionCutoff", "proportionCutoff", "healthTestBytes", "parseAnuUint8", "parseHex", "parseBase64", "mixEntropy", "secureSeed", "generateKeyPairWithEntropy",
            "nullQrng", "unavailableSource", "entropyError", "httpQrng",
        });
        Assert.Equal(562, Base.Cases(M).Count);
    }

    // ---- outside the corpus ----

    [Fact]
    public void ThePowRoutineIsTheReferenceOne()
    {
        Assert.Equal(1024.0, FdLibm.Pow(2, 10));
        Assert.Equal(9.5367431640625e-07, FdLibm.Pow(2, -20));
        Assert.Equal(Math.Sqrt(2), FdLibm.Pow(2, 0.5));
        Assert.Equal(-8.0, FdLibm.Pow(-2, 3));
        Assert.Equal(0.25, FdLibm.Pow(-2, -2));
        Assert.Equal(1.0, FdLibm.Pow(double.NaN, 0));
        Assert.True(double.IsNaN(FdLibm.Pow(-8, 1.0 / 3)));
        Assert.True(double.IsNaN(FdLibm.Pow(1, double.PositiveInfinity)));
        Assert.True(double.IsNaN(FdLibm.Pow(-1, double.NegativeInfinity)));
        Assert.True(double.IsNaN(FdLibm.Pow(2, double.NaN)));
        Assert.Equal(double.PositiveInfinity, FdLibm.Pow(2, 1024));
        Assert.Equal(0.0, FdLibm.Pow(2, -1075));
        Assert.Equal(double.Epsilon, FdLibm.Pow(2, -1074));
        Assert.Equal(double.PositiveInfinity, FdLibm.Pow(0, -1));
        Assert.Equal(double.NegativeInfinity, FdLibm.Pow(-0.0, -3));
        Assert.Equal(0.0, FdLibm.Pow(0.5, double.PositiveInfinity));
        Assert.Equal(1.0, FdLibm.Pow(1 - 1.0 / 256, 0));
        Assert.Equal(Math.Pow(0.99609375, 512), FdLibm.Pow(0.99609375, 512), 12);
    }

    [Fact]
    public async Task TheDefaultCsprngGivesFreshSeedsAndKeys()
    {
        var a = await Entropy.SecureSeedAsync();
        var b = await Entropy.SecureSeedAsync();
        Assert.Equal(32, a.Seed.Length);
        Assert.False(a.UsedQuantum);
        Assert.Equal(0, a.QuantumByteCount);
        Assert.Null(a.Source);
        Assert.NotEqual(a.Seed, b.Seed);
        var kp = await Entropy.GenerateKeyPairWithEntropyAsync();
        Assert.Equal(32, kp.SecretKey.Length);
        using var key = EdKey.FromSeed(kp.SecretKey);
        Assert.Equal(key.Pub, kp.PublicKey);
        Assert.NotEqual(kp.PublicKey, (await Entropy.GenerateKeyPairWithEntropyAsync()).PublicKey);
        var withNull = await Entropy.SecureSeedAsync(new SecureSeedOptions { Source = new NullQrngSource() });
        Assert.False(withNull.UsedQuantum);
        Assert.Equal("null-qrng", withNull.Source);
        var refused = await Assert.ThrowsAsync<EntropyError>(() => Entropy.SecureSeedAsync(new SecureSeedOptions { Source = Entropy.UnavailableSource(), RequireQuantum = true }));
        Assert.Equal("quantum_required", refused.Code);
    }

    [Fact]
    public async Task CredentialsArePercentEncodedAndASchemeOtherThanHttpsNeverReachesTheTransport()
    {
        int calls = 0;
        var urls = new List<string>();
        QrngTransport transport = (req, _) => { calls++; urls.Add(req.Url); return Task.FromResult(new QrngResponse { Ok = true, Status = 200, Json = () => Task.FromResult<object?>(new D { ["data"] = new L { new Num("1") } }) }); };
        // the user name ends at the first colon, the credentials at the last at sign; the characters of the userinfo set are percent-encoded, a percent sign is kept
        foreach (var (url, want) in new[]
        {
            ("https://us;er:p@ss:w=rd@qrng.example/x", "https://us%3Ber:p%40ss%3Aw%3Drd@qrng.example/x?length=1"),
            ("https://a b|c:%41[\u00e9]@qrng.example/x", "https://a%20b%7Cc:%41%5B%C3%A9%5D@qrng.example/x?length=1"),
            ("https://user@qrng.example/x", "https://user@qrng.example/x?length=1"),
            ("https://:pw@qrng.example/x", "https://:pw@qrng.example/x?length=1"),
            ("https://user:@qrng.example/x", "https://user@qrng.example/x?length=1"),
        })
        {
            await new HttpQrngSource(new HttpQrngConfig { Url = url, Transport = transport }).FetchAsync(1);
            Assert.Equal(want, urls[^1]);
        }
        Assert.Equal(5, calls);
        calls = 0;
        foreach (var url in new[] { "mailto:x@qrng.example", "ws://qrng.example/x", "file:///etc/passwd" })
            Assert.Equal("insecure_transport", (await Assert.ThrowsAsync<EntropyError>(() => new HttpQrngSource(new HttpQrngConfig { Url = url, Transport = transport }).FetchAsync(1))).Code);
        Assert.Equal(0, calls);
        Assert.Equal(new byte[] { 1 }, await new HttpQrngSource(new HttpQrngConfig { Url = "https://@qrng.example/x#a b", Transport = transport }).FetchAsync(1));
        Assert.Equal(1, calls);
    }
}
