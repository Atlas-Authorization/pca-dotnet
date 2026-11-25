using AtlasPca.Mpc;
using AtlasPca.Mpc.LweOt;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.MpcLweOt.Tests;

/// <summary>Wire-shape checks of the network OT messages (no sockets): the receiver's 'ot-recv' payload must survive the strict parser and drive the sender.</summary>
public class EndemicOtNetTests
{
    static List<object?> Pair(byte[][] p) => new() { NetCodec.B64(p[0]), NetCodec.B64(p[1]) };

    static JD Wire(ReceiverMessage m) => new()
    {
        ["rn"] = NetCodec.B64(m.Rn),
        ["points"] = m.Points.Select(p => (object?)Pair(p)).ToList(),
        ["rhos"] = m.Rhos.Select(r => (object?)NetCodec.B64(r)).ToList(),
    };

    [Fact]
    public void ReceiverMessageRoundTripsAndPadsAgree()
    {
        Assert.True(Lattice.Available(), "liblweot must load (ATLAS_LWEOT_LIB)");
        int[] choices = { 0, 1, 1, 0 };
        IOtRandom rng = OtRandom.Secure();
        ReceiveResult rv = EndemicOt.Receive(choices, rng);
        ReceiverMessage parsed = EndemicOtNet.ParseReceiver(Wire(rv.Message), choices.Length);
        SenderMessage sm = EndemicOt.SendRandom(parsed, rng);
        byte[][] got = EndemicOt.RecoverRandom(rv.State, sm);
        for (int i = 0; i < choices.Length; i++) Assert.Equal(sm.SenderPads[i][choices[i]], got[i]);
    }

    [Fact]
    public void ParserRefusesMalformedMessages()
    {
        string z32 = NetCodec.B64(new byte[32]);
        JD Ok() => new() { ["rn"] = z32, ["points"] = new List<object?> { new List<object?> { z32, z32 } }, ["rhos"] = new List<object?> { z32 } };
        EndemicOtNet.ParseReceiver(Ok(), 1);
        Assert.Throws<ArgumentException>(() => EndemicOtNet.ParseReceiver(Ok(), 2));
        Assert.Throws<ArgumentException>(() => EndemicOtNet.ParseReceiver("x", 1));
        JD d = Ok(); d["rn"] = NetCodec.B64(new byte[31]);
        Assert.Throws<ArgumentException>(() => EndemicOtNet.ParseReceiver(d, 1));
        d = Ok(); d["rhos"] = new List<object?> { NetCodec.B64(new byte[31]) };
        Assert.Throws<ArgumentException>(() => EndemicOtNet.ParseReceiver(d, 1));
        d = Ok(); d["rn"] = z32[..^2] + "B="; // non-canonical alias
        Assert.Throws<ArgumentException>(() => EndemicOtNet.ParseReceiver(d, 1));
        d = Ok(); d["points"] = new List<object?> { new List<object?> { z32 } };
        Assert.Throws<ArgumentException>(() => EndemicOtNet.ParseReceiver(d, 1));
    }
}
