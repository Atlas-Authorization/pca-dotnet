using System.Security.Cryptography;
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Mpc.Net;

/// <summary>
/// Pairwise base oblivious transfer OVER THE NETWORK: the malicious-secure Chou-Orlandi-style base OT on Ed25519 with a Schnorr
/// proof of knowledge and subgroup validation of every received point. A FUNCTIONAL-CORRECTNESS demonstration: afterwards the
/// receiver reveals its choice bits and a hash of each received pad (a demo-only step, NOT part of the OT) so the sender can
/// check the pads over a real network. The post-quantum endemic-LWE variant lives in the separate lwe-ot adapter (found by reflection, see PartyMain).
/// </summary>
public static class OtNet
{
    public sealed record Result(string Role, int Count, bool Matched, string PadDigest, string Kind = "ec");

    public static byte[] Sha(params byte[][] parts)
    {
        using var ms = new MemoryStream();
        foreach (byte[] p in parts) ms.Write(p, 0, p.Length);
        return SHA256.HashData(ms.ToArray());
    }

    public static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    /// <summary>Binding of a base OT on this mesh: session (hashed to a fixed length), who sends, who receives, which round.</summary>
    public static Ot.BaseOtBinding NetBinding(Mesh mesh, int senderIndex, int receiverIndex, string round)
    {
        byte[] sid = Sha(Encoding.UTF8.GetBytes("atlas-pca-mpc/net-session/v2"), Encoding.UTF8.GetBytes(mesh.SessionId()));
        return new Ot.BaseOtBinding(sid, senderIndex, receiverIndex, round);
    }

    public static T Parsing<T>(Mesh mesh, int peer, string rd, Func<T> f)
    {
        try
        {
            return f();
        }
        catch (Exception e)
        {
            var ne = new NetWire.NetAbort("malformed", peer, mesh.SelfId, "round '" + rd + "': " + e.Message);
            mesh.Fail(ne, null);
            throw ne;
        }
    }

    public static int Bit(object? o)
    {
        if (o is Num n && n.Raw == "0") return 0;
        if (o is Num m && m.Raw == "1") return 1;
        return -1;
    }

    public static string Digest(byte[][] pads)
    {
        using var ms = new MemoryStream();
        foreach (byte[] p in pads) ms.Write(p, 0, p.Length);
        return Hex(SHA256.HashData(ms.ToArray()));
    }

    public static Result RunOtSender(Mesh mesh, int peer, int count)
    {
        Ot.IOtRandom rng = Ot.SecureOtRandom();
        Ot.BaseOtBinding binding = NetBinding(mesh, mesh.SelfId, peer, "ot-ec");
        Ot.SenderSetup setup = Ot.MalBaseOtSenderSetup(rng, binding);
        var sm = new JD { ["S"] = NetCodec.PtJ(setup.S), ["U"] = NetCodec.PtJ(setup.Proof.U), ["z"] = NetWire.Hx(setup.Proof.Z) };
        mesh.Send(peer, "ot-S", sm);
        object? rRaw = mesh.Recv(peer, "ot-R");
        Ec.Point[] R = Parsing(mesh, peer, "ot-R", () =>
        {
            if (rRaw is not List<object?> list || list.Count != count) throw new ArgumentException("bad R array");
            var pts = new Ec.Point[count];
            for (int i = 0; i < count; i++) pts[i] = NetCodec.JPt(list[i]);
            return pts;
        });
        byte[][][] pads;
        try
        {
            pads = Ot.MalBaseOtSenderDerive(setup.Y, setup.T, R, setup.S, binding);
        }
        catch (Exception e)
        {
            var ne = new NetWire.NetAbort("malformed", peer, mesh.SelfId, e.Message);
            mesh.Fail(ne, null);
            throw ne;
        }
        byte[][][] padsF = pads;
        // demo-only verification: the receiver reveals choices + pad hashes
        object? v = mesh.Recv(peer, "ot-verify");
        bool ok = Parsing(mesh, peer, "ot-verify", () =>
        {
            if (v is not JD o || o.GetValueOrDefault("choices") is not List<object?> choices || o.GetValueOrDefault("padHashes") is not List<object?> hashes
                || choices.Count != count || hashes.Count != count) throw new ArgumentException("bad verify message");
            for (int i = 0; i < count; i++)
            {
                int c = Bit(choices[i]);
                if (c < 0 || !(hashes[i] is string h) || Hex(Sha(padsF[i][c])) != h) return false;
            }
            return true;
        });
        mesh.Send(peer, "ot-done", new JD { ["matched"] = ok });
        mesh.Finish();
        var flat = new byte[count * 2][];
        for (int i = 0; i < count; i++)
        {
            flat[2 * i] = pads[i][0];
            flat[2 * i + 1] = pads[i][1];
        }
        return new Result("sender", count, ok, Digest(flat));
    }

    public static Result RunOtReceiver(Mesh mesh, int peer, int count)
    {
        Ot.IOtRandom rng = Ot.SecureOtRandom();
        byte[] cb = rng.Bytes(count);
        var choices = new int[count];
        for (int i = 0; i < count; i++) choices[i] = cb[i] & 1;
        object? sRaw = mesh.Recv(peer, "ot-S");
        var S = new Ec.Point[1];
        Ec.SchnorrProof proof = Parsing(mesh, peer, "ot-S", () =>
        {
            if (sRaw is not JD o) throw new ArgumentException("bad S message");
            var pr = new Ec.SchnorrProof(NetCodec.JPt(o.GetValueOrDefault("U")), NetCodec.HexBig(o.GetValueOrDefault("z")));
            S[0] = NetCodec.JPt(o.GetValueOrDefault("S"));
            return pr;
        });
        Ot.ReceiverResponse res;
        try
        {
            res = Ot.MalBaseOtReceiverRespond(S[0], proof, choices, rng, NetBinding(mesh, peer, mesh.SelfId, "ot-ec"));
        }
        catch (Exception e)
        {
            var ne = new NetWire.NetAbort(e is Ot.BaseOtAbort ? "commitment" : "malformed", peer, mesh.SelfId, e.Message);
            mesh.Fail(ne, null);
            throw ne;
        }
        var rs = new List<object?>();
        foreach (Ec.Point r in res.R) rs.Add(NetCodec.PtJ(r));
        mesh.Send(peer, "ot-R", rs);
        var cs = new List<object?>();
        var hs = new List<object?>();
        for (int i = 0; i < count; i++)
        {
            cs.Add(choices[i]);
            hs.Add(Hex(Sha(res.RecvPads[i])));
        }
        mesh.Send(peer, "ot-verify", new JD { ["choices"] = cs, ["padHashes"] = hs });
        object? d = mesh.Recv(peer, "ot-done");
        bool matched = d is JD dm && dm.GetValueOrDefault("matched") is true;
        mesh.Finish();
        return new Result("receiver", count, matched, Digest(res.RecvPads));
    }
}
