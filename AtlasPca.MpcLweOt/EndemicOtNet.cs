using AtlasPca.Mpc;
using AtlasPca.Mpc.Net;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Mpc.LweOt;

using Mesh = AtlasPca.Mpc.Net.Mesh;

/// <summary>
/// The endemic-LWE base OT over the mutual-TLS mesh, wire-compatible with the reference: the receiver sends 'ot-recv' {rn, points, rhos},
/// the sender answers 'ot-ct', then the same demo-only 'ot-verify' / 'ot-done' round as the Ed25519 variant.
/// The party program finds this class by reflection (this assembly depends on the core, never the other way round).
/// </summary>
public static class EndemicOtNet
{
    private static NetWire.NetAbort Abort(Mesh mesh, int peer, string msg)
    {
        var ne = new NetWire.NetAbort("malformed", peer, mesh.SelfId, msg);
        mesh.Fail(ne, null);
        return ne;
    }

    // never fall back to ec: no liblweot is a local abort
    private static void RequireLib(Mesh mesh)
    {
        if (!Lattice.Available()) throw new NetWire.NetAbort("local", null, mesh.SelfId, "ot kind 'lwe' is not available in this build (liblweot not loaded)");
    }

    private static List<object?> Pair(byte[][] p) => new() { NetCodec.B64(p[0]), NetCodec.B64(p[1]) };

    private static byte[][] ParsePair(object? o)
    {
        if (o is not List<object?> l || l.Count != 2) throw new ArgumentException("bad pair");
        return new[] { NetCodec.Unb64(l[0], -1), NetCodec.Unb64(l[1], -1) };
    }

    public static OtNet.Result RunOtSender(Mesh mesh, int peer, int count)
    {
        RequireLib(mesh);
        IOtRandom rng = OtRandom.Secure();
        object? m = mesh.Recv(peer, "ot-recv");
        ReceiverMessage msg = OtNet.Parsing(mesh, peer, "ot-recv", () => ParseReceiver(m, count));
        SenderMessage sm;
        try { sm = EndemicOt.SendRandom(msg, rng); }
        catch (Exception e) { throw Abort(mesh, peer, "lwe sender: " + e.Message); }
        mesh.Send(peer, "ot-ct", sm.Ciphertexts.Select(p => (object?)Pair(p)).ToList());
        byte[][][] pads = sm.SenderPads;
        // demo-only verification: the receiver reveals choices + pad hashes
        object? v = mesh.Recv(peer, "ot-verify");
        bool ok = OtNet.Parsing(mesh, peer, "ot-verify", () =>
        {
            if (v is not JD o || o.GetValueOrDefault("choices") is not List<object?> cs || o.GetValueOrDefault("padHashes") is not List<object?> hs
                || cs.Count != count || hs.Count != count) throw new ArgumentException("bad verify message");
            for (int i = 0; i < count; i++)
            {
                int c = OtNet.Bit(cs[i]);
                if (c < 0 || hs[i] is not string h || OtNet.Hex(OtNet.Sha(pads[i][c])) != h) return false;
            }
            return true;
        });
        mesh.Send(peer, "ot-done", new JD { ["matched"] = ok });
        mesh.Finish();
        var flat = new byte[count * 2][];
        for (int i = 0; i < count; i++) { flat[2 * i] = pads[i][0]; flat[2 * i + 1] = pads[i][1]; }
        return new OtNet.Result("sender", count, ok, OtNet.Digest(flat), "lwe");
    }

    public static OtNet.Result RunOtReceiver(Mesh mesh, int peer, int count)
    {
        RequireLib(mesh);
        IOtRandom rng = OtRandom.Secure();
        byte[] cb = rng.Bytes(count);
        var choices = new int[count];
        for (int i = 0; i < count; i++) choices[i] = cb[i] & 1;
        ReceiveResult rv = EndemicOt.Receive(choices, rng);
        mesh.Send(peer, "ot-recv", new JD
        {
            ["rn"] = NetCodec.B64(rv.Message.Rn),
            ["points"] = rv.Message.Points.Select(p => (object?)Pair(p)).ToList(),
            ["rhos"] = rv.Message.Rhos.Select(r => (object?)NetCodec.B64(r)).ToList(),
        });
        object? ctRaw = mesh.Recv(peer, "ot-ct");
        byte[][][] cts = OtNet.Parsing(mesh, peer, "ot-ct", () =>
        {
            if (ctRaw is not List<object?> l || l.Count != count) throw new ArgumentException("bad ciphertext array");
            return l.Select(ParsePair).ToArray();
        });
        byte[][] recvPads = OtNet.Parsing(mesh, peer, "ot-ct", () => EndemicOt.RecoverRandom(rv.State, new SenderMessage(cts, Array.Empty<byte[][]>())));
        mesh.Send(peer, "ot-verify", new JD
        {
            ["choices"] = choices.Select(c => (object?)c).ToList(),
            ["padHashes"] = recvPads.Select(p => (object?)OtNet.Hex(OtNet.Sha(p))).ToList(),
        });
        object? d = mesh.Recv(peer, "ot-done");
        bool matched = d is JD dm && dm.GetValueOrDefault("matched") is true;
        mesh.Finish();
        return new OtNet.Result("receiver", count, matched, OtNet.Digest(recvPads), "lwe");
    }

    /// <summary>Strict parse of the receiver's 'ot-recv' payload (same shape and canonical-base64 rules as the reference).</summary>
    public static ReceiverMessage ParseReceiver(object? m, int count)
    {
        if (m is not JD o || o.GetValueOrDefault("points") is not List<object?> pts || o.GetValueOrDefault("rhos") is not List<object?> rh
            || pts.Count != count || rh.Count != count) throw new ArgumentException("bad receiver message");
        var points = new byte[count][][];
        var rhos = new byte[count][];
        for (int i = 0; i < count; i++)
        {
            points[i] = ParsePair(pts[i]);
            rhos[i] = NetCodec.Unb64(rh[i], 32);
        }
        return new ReceiverMessage(NetCodec.Unb64(o.GetValueOrDefault("rn"), 32), points, rhos);
    }
}
