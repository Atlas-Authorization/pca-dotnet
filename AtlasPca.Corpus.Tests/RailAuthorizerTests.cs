using AtlasPca.Payments;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

public class RailAuthorizerTests
{
    static D Mandate() => AtlasPca.Payments.Payments.BuildPaymentMandate(new D
    {
        ["principalSecret"] = Enumerable.Repeat((byte)5, 32).ToArray(), ["agentPublic"] = EdKey.FromSeed(Enumerable.Repeat((byte)6, 32).ToArray()).Id, ["merchants"] = new L { "merchant_1" },
        ["categories"] = new L(), ["currency"] = "USD", ["perTransactionCap"] = new Num("50000"), ["autoApproveThreshold"] = new Num("5000"), ["cumulativeCap"] = new Num("100000"),
        ["goalSalt"] = "c2FsdC0wMDAx", ["now"] = new Num("1800000000000"),
    });

    static D Auth(long amount, string merchant = "merchant_1") => new() { ["id"] = "a1", ["instrumentId"] = "card_1", ["amount"] = new Num(amount.ToString()), ["currency"] = "usd", ["merchantId"] = merchant };

    static Func<D, Task<D>> Make(Func<D, D, Task>? onStepUp = null, double budget = 1500, bool known = true)
    {
        var m = Mandate();
        return Rails.CreateRailAuthorizer(new RailAuthorizerOptions
        {
            Instruments = id => Task.FromResult<InstrumentBinding?>(known && id == "card_1" ? new InstrumentBinding(m, (D)m["grant"]!) : null),
            Store = new MemoryChargeBudgetStore(), LatencyBudgetMs = budget, Now = () => 1_800_000_001_000, OnStepUp = onStepUp,
        });
    }

    static string Why(D v) => string.Join(",", ((L)v["reasons"]!).Cast<string>());

    [Fact]
    public async Task OnlyAnAutoDecisionApproves()
    {
        var az = Make();
        Assert.Equal(true, (await az(Auth(3000)))["approved"]);
        Assert.Equal("malformed_authorization", Why(await az(new D { ["id"] = "" })));
        Assert.Equal("amount_not_positive_minor_units", Why(await az(Auth(0))));
        Assert.Equal("merchant_unknown", Why(await az(new D(Auth(10)) { ["merchantId"] = "" })));
        Assert.Equal("currency_missing", Why(await az(new D(Auth(10)) { ["currency"] = "" })));
        Assert.Equal("instrument_unknown", Why(await Make(known: false)(Auth(10))));
    }

    [Fact]
    public async Task AStepUpIsDeclinedAndNotifiesTheHook()
    {
        D? seen = null;
        var v = await Make((a, d) => { seen = d; return Task.CompletedTask; })(Auth(20000));
        Assert.Equal(false, v["approved"]);
        Assert.StartsWith("step_up_required", Why(v));
        Assert.NotNull(seen);
        var v2 = await Make((a, d) => throw new InvalidOperationException("notifier down"))(Auth(20000));
        Assert.Equal(false, v2["approved"]);   // a failing notifier does not change the answer
        Assert.Equal(false, (await Make()(Auth(3000, "merchant_2")))["approved"]);   // a merchant outside the mandate
    }

    [Fact]
    public async Task ASlowDecisionDeclinesInsideTheLatencyBudget()
    {
        var m = Mandate();
        var az = Rails.CreateRailAuthorizer(new RailAuthorizerOptions
        {
            Instruments = async _ => { await Task.Delay(400); return new InstrumentBinding(m, (D)m["grant"]!); }, Store = new MemoryChargeBudgetStore(), LatencyBudgetMs = 30,
        });
        Assert.Equal("latency_budget_exceeded", Why(await az(Auth(10))));
        Assert.Throws<ArgumentOutOfRangeException>(() => Rails.CreateRailAuthorizer(new RailAuthorizerOptions { Store = new MemoryChargeBudgetStore(), LatencyBudgetMs = 0 }));
        Assert.Matches(@"^mcc\.c(\d{4})$", "mcc.c5734");
        Assert.True(Rails.MccTraitRe.IsMatch("mcc.c5734")); Assert.False(Rails.MccTraitRe.IsMatch("mcc.c57"));
    }
}
