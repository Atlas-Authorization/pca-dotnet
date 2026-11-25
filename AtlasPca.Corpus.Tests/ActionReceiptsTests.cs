using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

public class ActionReceiptsTests
{
    static JD Actn(string verb, long iat) => new()
    {
        ["ver"] = new Num("2"), ["action"] = new JD { ["verb"] = verb, ["resource"] = "r/1" }, ["iat"] = new Num(iat.ToString()),
    };

    [Fact]
    public void ChainAppendsHeadsAndDetectsTamper()
    {
        var log = new List<JD>();
        Assert.Equal("", ActionReceipts.ReceiptHead(log));
        Assert.True(ActionReceipts.VerifyReceiptChain(log).Ok);
        log = ActionReceipts.AppendReceipt(log, Actn("pay", 10), true);
        log = ActionReceipts.AppendReceipt(log, Actn("pay", 20), false, new Dictionary<string, string> { ["replay"] = "fail" }, 25);
        log = ActionReceipts.AppendReceipt(log, Actn("read", 30), true);
        Assert.Equal(3, log.Count);
        Assert.Equal((string)log[2]["hash"]!, ActionReceipts.ReceiptHead(log));
        Assert.Equal(log[0]["hash"], log[1]["prev"]);
        Assert.Equal("deny", log[1]["outcome"]);
        Assert.Equal("25", ((Num)log[1]["at"]!).Raw);
        Assert.True(ActionReceipts.VerifyReceiptChain(log).Ok);

        var tampered = new List<JD>(log) { [1] = new JD(log[1]) { ["outcome"] = "allow" } };
        var t = ActionReceipts.VerifyReceiptChain(tampered);
        Assert.False(t.Ok); Assert.Equal(1, t.BrokenAt); Assert.Contains("tampered", t.Reason);
        var dropped = new List<JD> { log[0], log[2] };
        Assert.False(ActionReceipts.VerifyReceiptChain(dropped).Ok);
        Assert.Throws<ArgumentException>(() => ActionReceipts.ReceiptFor("", 0, new JD(), true));
    }
}
