using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.AspNetCore.Tests;

// H13 (the revocation-epoch rollback pin is automatic) and H16 (multiInstance refuses a process-scoped store).
public class K05H13H16Tests
{
    static readonly string FixText = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "authorize-fixtures.json"));
    static JD Fix => (JD)Pca.ParseJson(FixText)!;
    static readonly string Aud = System.Text.Json.JsonDocument.Parse(FixText).RootElement.GetProperty("audience").GetString()!;
    static readonly long Now = long.Parse(System.Text.Json.JsonDocument.Parse(FixText).RootElement.GetProperty("now").GetRawText(), CultureInfo.InvariantCulture);
    static JD Case => ((JL)Fix["cases"]!).Cast<JD>().First(c => (string)c["name"]! == "envelope-max-spend-within");
    static JD Grant => (JD)Case["grant"]!;
    static JD Step => (JD)((JL)Case["steps"]!)[0]!;
    static JD Pcactn => (JD)Step["pcactn"]!;
    static Operation Op => new((string)((JD)Step["operation"]!)["verb"]!, (string)((JD)Step["operation"]!)["resource"]!, ((JD)Step["operation"]!)["params"]);
    static readonly byte[] Seed = Enumerable.Repeat((byte)11, 32).ToArray();
    static string GrantRef => (string)Pcactn["grant_ref"]!;
    static string PinKey => (string)Grant["id"]! + ":epoch";

    static JD Epoch() => RevocationFreshness.SignEpoch(Seed, new RevocationEpochBody("i", GrantRef, 0, 0, "root-1", Now - 1_000, Now + 300_000));
    static string Guardian => (string)Epoch()["guardian"]!;

    /// <summary>A store whose replay claims are private to it but whose pins are the shared one: the same PCActn can be presented again.</summary>
    sealed class SharedPins : IStateStore, IPinStore
    {
        readonly MemoryStateStore _own = new();
        readonly MemoryStateStore _pins;
        public SharedPins(MemoryStateStore pins) { _pins = pins; }
        public ClaimResult? Claim(string key, long counter) => _own.Claim(key, counter);
        public long? Pin(string key) => _pins.Pin(key);
        public long RaisePin(string key, long value) => _pins.RaisePin(key, value);
    }

    sealed class NoPins : IStateStore { public ClaimResult? Claim(string key, long counter) => new MemoryStateStore().Claim(key, counter); }
    sealed class Declared : IStateStore { public StoreScope Scope => StoreScope.Shared; public ClaimResult? Claim(string key, long counter) => new ClaimResult(true); }
    sealed class ThrowingPins : IStateStore, IPinStore
    {
        public ClaimResult? Claim(string key, long counter) => new ClaimResult(true);
        public long? Pin(string key) => null;
        public long RaisePin(string key, long value) => throw new InvalidOperationException("down");
    }

    static AuthorizeInput Input(IStateStore store, bool revoked = false, bool? multi = null) => new AuthorizeInput
    {
        Operation = Op, Audience = Aud, ResolveGrant = r => r == (string)Grant["id"]! ? Grant : null, StateStore = store, IsRevoked = (_, _) => revoked,
        Now = Now, Plan = "single-step", RevocationStaleness = new RevocationStalenessPolicy(MaxRevocationAgeMs: 300_000),
        RevocationState = (_, _) => new RevocationState(Epoch: Epoch()), GuardianPublic = Guardian, RevocationIds = _ => Array.Empty<string>(), MultiInstance = multi,
    }.WithProv();

    [Fact]
    public void AStoredPinMakesAnOlderEpochARollbackWithNoHostValue()
    {
        var pins = new MemoryStateStore();
        pins.RaisePin(PinKey, 5);
        var r = Pca.Authorize(Pcactn, Input(new SharedPins(pins)));
        Assert.False(r.Allow);
        Assert.Equal("freshness: revocation epoch 0 is older than the last accepted 5 (rollback)", r.Reason);
        Assert.Equal(5, pins.Pin(PinKey));
    }

    [Fact]
    public void AnAllowedFreshnessPassRaisesThePinAndADeniedActionDoesNot()
    {
        var pins = new MemoryStateStore();
        var denied = Pca.Authorize(Pcactn, Input(new SharedPins(pins), revoked: true));
        Assert.False(denied.Allow);
        Assert.Null(pins.Pin(PinKey));
        var ok = Pca.Authorize(Pcactn, Input(new SharedPins(pins)));
        Assert.True(ok.Allow, ok.Reason);
        Assert.Equal(0, pins.Pin(PinKey));
    }

    [Fact]
    public void ThePinIsMonotoneAndAtomicUnderConcurrentRaises()
    {
        var s = new MemoryStateStore();
        Parallel.For(0, 200, i => s.RaisePin("k", i));
        Assert.Equal(199, s.Pin("k"));
        Assert.Equal(199, s.RaisePin("k", 3));
        Assert.Equal(199, s.Pin("k"));
        Assert.Throws<ArgumentException>(() => s.RaisePin("", 1));
        Assert.Throws<ArgumentException>(() => s.RaisePin("k", -1));
        Assert.Null(s.Pin("other"));
    }

    [Fact]
    public void AStoreThatCannotRaiseThePinDeniesAfterTheAllow()
    {
        var r = Pca.Authorize(Pcactn, Input(new ThrowingPins()));
        Assert.False(r.Allow);
        Assert.Equal("freshness: the revocation epoch pin could not be raised (fail closed)", r.Reason);
    }

    [Fact]
    public void StalenessWithAStoreWithoutPinsIsAConfigurationError()
    {
        var r = Pca.Authorize(Pcactn, Input(new NoPins()));
        Assert.False(r.Allow);
        Assert.Contains("revocation staleness needs a state store that implements pins (rollback protection)", r.Missing!);
        var o = new PcaOptions
        {
            Audience = Aud, GrantResolver = _ => Task.FromResult<JD?>(Grant), Authorize = new PcaAuthorizeOptions { StateStore = new NoPins(), RevocationStaleness = new RevocationStalenessPolicy(MaxRevocationAgeMs: 1) },
        };
        var ex = Assert.Throws<InvalidOperationException>(() => o.Validate());
        Assert.Equal("revocation staleness needs a state store that implements pins (rollback protection)", ex.Message);
    }

    [Fact]
    public void MultiInstanceRefusesAProcessScopedStoreAndAcceptsASharedOne()
    {
        const string text = "multiInstance requires a shared state store (a process-scoped store lets one PCActn replay once per instance)";
        var bad = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), multi: true));
        Assert.False(bad.Allow);
        Assert.Contains(text, bad.Missing!);
        var undeclared = Pca.Authorize(Pcactn, new AuthorizeInput { StateStore = new NoPins(), MultiInstance = true });
        Assert.Contains(text, undeclared.Missing!);
        Assert.DoesNotContain(text, Pca.MissingAuthorizeComponents(new AuthorizeInput { StateStore = new Declared(), MultiInstance = true }));
        Assert.DoesNotContain(text, Pca.MissingAuthorizeComponents(new AuthorizeInput { StateStore = new MemoryStateStore(), MultiInstance = false }));
        Assert.DoesNotContain(text, Pca.MissingAuthorizeComponents(new AuthorizeInput { StateStore = new MemoryStateStore() }));
        var o = new PcaOptions { Audience = Aud, GrantResolver = _ => Task.FromResult<JD?>(Grant), Authorize = new PcaAuthorizeOptions { StateStore = new MemoryStateStore(), MultiInstance = true } };
        Assert.Equal(text, Assert.Throws<InvalidOperationException>(() => o.Validate()).Message);
        Assert.Equal(StoreScope.Shared, new SqlStateStore(() => throw new InvalidOperationException()).Scope);
        Assert.Equal(StoreScope.Process, new MemoryStateStore().Scope);
    }
}
