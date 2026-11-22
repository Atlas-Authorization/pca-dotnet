// Trustless FROST distributed key generation (the PedPoP two-round DKG of the FROST paper, with Pedersen VSS) with a justified-complaint blame round, session binding and an echo-broadcast agreement
// round. Every participant contributes a secret polynomial, nobody ever holds the group secret, and the group key is the sum of the QUALIFIED participants' constant-term commitments. The output is
// a drop-in for the core FROST module: a signing share has the shape of a trusted-dealer share and the group key is f(0)*B.
//
// Session binding: a caller-supplied ceremony id is folded into the proof-of-possession challenge and stamped on every package and share, so nothing captured from one run replays into another.
// Non-repudiable shares: every round-2 share is signed by its sender under its VSS constant-term key C_0 over (session, sender, recipient, share, C_0); a complaint is justified only when it exhibits the
// ACCUSED's own signature over a share that fails VSS, so fabricated bytes cannot frame an honest party and a false accusation convicts the accuser.
//
// This module produces and verifies the protocol messages. It assumes an authenticated broadcast channel for round 1, rebuttals and complaints and private authenticated point-to-point delivery of shares;
// the channel module states that assumption as an interface and enforces what the protocol can enforce on top of it. Wire values are the JSON tree (a package, share, complaint, rebuttal and echo is a
// Dictionary of base64url text; raw share bytes and keys are byte[]).
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Js;
using AtlasPca.Ratchet;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The retained SECRET state of a participant after round 1: its polynomial and its own package. Never broadcast.</summary>
public sealed class DkgState
{
    public long Identifier;
    public int T, N;
    public byte[] SessionId = [];
    /// <summary>The secret coefficients a_0..a_(t-1) as 32-byte little-endian scalars.</summary>
    public List<byte[]> Coefficients = [];
    /// <summary>This participant's own public round-1 package.</summary>
    public D Package = new();
}

public sealed record DkgRound1Result(D Package, DkgState State);

/// <summary>The options of <see cref="FrostDkg.Simulate"/>.</summary>
public sealed class DkgSimulateOpts
{
    /// <summary>Participant identifiers (default 1..n): n distinct positive integers.</summary>
    public IReadOnlyList<long>? Identifiers;
    /// <summary>Per-participant fixed polynomial coefficients (each of length t), for deterministic runs; a missing entry is drawn.</summary>
    public IReadOnlyList<IReadOnlyList<byte[]>?>? CoefficientsByParticipant;
    /// <summary>The ceremony id (random 32 bytes if omitted).</summary>
    public byte[]? SessionId;
    /// <summary>Participants that act as a cheating dealer: they send every recipient a share inconsistent with their commitments, signed.</summary>
    public IReadOnlyList<long>? Cheaters;
    /// <summary>The participant whose echo is computed over a tampered view (exercises the agreement round).</summary>
    public long? EquivocateEchoFor;
    public Func<byte[]>? Random;
}

public static class FrostDkg
{
    static readonly byte[] Ctx = Encoding.UTF8.GetBytes(Frost.ContextString);
    static readonly byte[] PopDst = Encoding.UTF8.GetBytes("dkg-pop"), ShareDst = Encoding.UTF8.GetBytes("dkg-share"), ShareNonceDst = Encoding.UTF8.GetBytes("dkg-share-nonce");
    static readonly object Undef = new(); // an absent member: the strict canonical form refuses it, as it refuses undefined

    // ---- helpers ----
    static byte[] Cat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();
    static BigInteger LeToBig(byte[] b) => new(b, isUnsigned: true, isBigEndian: false);
    static BigInteger HashToScalar(byte[] m) => Frost.BytesToScalar(SHA512.HashData(m));
    static BigInteger Mod(BigInteger a) { var r = a % Frost.L; return r.Sign >= 0 ? r : r + Frost.L; }
    static byte[] IdBytes(BigInteger id) => Frost.ScalarToBytes(id);
    static byte[] Unb64u(object? s) => Pca.B64uDecode(s) ?? throw new ArgumentException("base64url: invalid encoding");
    static object? Get(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : null;
    static object? Fld(object? o, string k) => o is D d ? d.GetValueOrDefault(k) : throw new ArgumentException("not an object");
    static object? Need(object? o, string k) => o is D d ? (d.TryGetValue(k, out var v) ? v : Undef) : throw new ArgumentException("not an object");
    static bool Eq(object? a, object? b) => IntentJs.JsonEquals(a, b);

    /// <summary>BigInt(value) of a JSON number: an integral finite value, else a refusal.</summary>
    internal static BigInteger Big(object? v) =>
        v is not string && IntentJs.NumOf(v) is double d && double.IsFinite(d) && d == Math.Floor(d) ? new BigInteger(d) : throw new ArgumentException("not an integer");

    static bool IsPosInt(object? v) => v is not string && IntentJs.NumOf(v) is double d && double.IsFinite(d) && d == Math.Floor(d) && d > 0;

    /// <summary>The key the reference's Map gives a value: numbers by value, anything else by itself.</summary>
    static string K(object? v) => v is not string && IntentJs.NumOf(v) is double d ? "n" + JsJson.NumberToString(d) : v is string s ? "s" + s : "o" + JsJson.ToJsString(v);

    sealed record CommitVec(EdwardsPoint C0, byte[] Bytes);

    /// <summary>The FULL VSS commitment vector as bound into every challenge: u32be(count) || each 32-byte point.</summary>
    static CommitVec CommitVecOf(object? commitments)
    {
        if (commitments is not L l || l.Count == 0) throw new ArgumentException("dkg: empty commitment vector");
        var pts = l.Select(c => Frost.DecodeSafePoint(Unb64u(c))).ToList();
        var hdr = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(hdr, (uint)pts.Count);
        return new CommitVec(pts[0], Cat([hdr, .. pts.Select(p => p.ToBytes())]));
    }

    static BigInteger CanonicalScalar(byte[] b) => Frost.IsCanonicalScalar(b) ? Frost.BytesToScalar(b) : throw new ArgumentException("dkg: scalar must be 32 bytes and < the group order");

    /// <summary>f(x) = sum of coeffs[j]*x^j by Horner on the fixed-width secret-scalar path; the 32-byte scalar.</summary>
    static byte[] EvalPoly(IReadOnlyList<BigInteger> coeffs, BigInteger x)
    {
        var xb = Frost.ScalarToBytes(x);
        var acc = new byte[32];
        for (int j = coeffs.Count - 1; j >= 0; j--) acc = CtScalar.Add(CtScalar.Mul(acc, xb), Frost.ScalarToBytes(coeffs[j]));
        return acc;
    }

    /// <summary>Pedersen-VSS: g^share == product of commitments[k]^(atId^k). Shared by share verification and complaint adjudication so detection and blame use the SAME predicate.</summary>
    static bool VssCheck(BigInteger share, object? commitments, BigInteger atId)
    {
        if (commitments is not L l) throw new ArgumentException("not a list");
        if (l.Count == 0) return false;
        var lhs = Frost.MulBase(share);
        var rhs = EdwardsPoint.Zero;
        var xk = BigInteger.One;
        foreach (var c in l)
        {
            rhs = rhs.Add(Frost.MulPoint(Frost.DecodeSafePoint(Unb64u(c)), xk));
            xk = Mod(xk * atId);
        }
        return lhs.SameAs(rhs);
    }

    // ---- proof of possession ----
    static BigInteger PopChallenge(byte[] sid, BigInteger id, CommitVec cv, EdwardsPoint r) => HashToScalar(Cat(Ctx, PopDst, sid, IdBytes(id), cv.Bytes, r.ToBytes()));

    // ---- non-repudiable share signatures ----
    static BigInteger ShareChallenge(byte[] sid, BigInteger from, BigInteger to, byte[] share, CommitVec cv, EdwardsPoint rs) =>
        HashToScalar(Cat(Ctx, ShareDst, sid, IdBytes(from), IdBytes(to), share, cv.Bytes, rs.ToBytes()));

    /// <summary>Deterministic per-share nonce from the secret a_0 and the full share binding: unique per (session, from, to, share), so a nonce is never reused across two shares signed by one a_0.</summary>
    static BigInteger ShareNonce(BigInteger a0, byte[] sid, BigInteger from, BigInteger to, byte[] share, CommitVec cv) =>
        HashToScalar(Cat(Ctx, ShareNonceDst, Frost.ScalarToBytes(a0), sid, IdBytes(from), IdBytes(to), share, cv.Bytes));

    static string SignShareScalar(BigInteger a0, CommitVec cv, byte[] sid, BigInteger from, BigInteger to, byte[] share)
    {
        var k = ShareNonce(a0, sid, from, to, share, cv);
        var rs = Frost.MulBase(k);
        var e = ShareChallenge(sid, from, to, share, cv, rs);
        var s = CtScalar.Add(Frost.ScalarToBytes(k), CtScalar.Mul(Frost.ScalarToBytes(a0), Frost.ScalarToBytes(e)));
        return Pca.B64u(Cat(rs.ToBytes(), s));
    }

    static bool VerifyShareSig(string sig, byte[] sid, BigInteger from, BigInteger to, byte[] share, CommitVec cv)
    {
        try
        {
            var raw = Unb64u(sig);
            if (raw.Length != 64) return false;
            var rs = Frost.DecodeSafePoint(raw[..32]);
            var s = CanonicalScalar(raw[32..]);
            var e = ShareChallenge(sid, from, to, share, cv, rs);
            return Frost.MulBase(s).SameAs(rs.Add(Frost.MulPoint(cv.C0, e)));
        }
        catch (Exception) { return false; }
    }

    /// <summary>Verify a share signature under the SENDER's broadcast round-1 package (its C_0). Never throws.</summary>
    static bool VerifyShareSigAgainstPackage(object? sig, byte[] sid, object? from, object? to, byte[] share, object? senderPackage)
    {
        try
        {
            if (sig is not string s) return false;
            var cv = CommitVecOf(Get(senderPackage, "coefficientCommitments"));
            return VerifyShareSig(s, sid, Big(from), Big(to), share, cv);
        }
        catch (Exception) { return false; }
    }

    /// <summary>Sign the share this participant sends to <paramref name="to"/> as the sender's non-repudiable token; exposed so the accused can reproduce the exact signature round 2 attaches. Uses the retained a_0.</summary>
    public static string SignShare(DkgState state, long to, byte[] shareBytes)
    {
        var a0 = Frost.BytesToScalar(state.Coefficients[0]);
        var cv = CommitVecOf(Get(state.Package, "coefficientCommitments"));
        ArgumentNullException.ThrowIfNull(shareBytes);
        return SignShareScalar(a0, cv, state.SessionId, state.Identifier, to, shareBytes);
    }

    // ---- round 1 ----

    /// <summary>ROUND 1. Participant <paramref name="identifier"/> samples a degree-(t-1) secret polynomial, publishes VSS commitments to its coefficients and a Schnorr proof of possession of the constant term bound
    /// to the session. Returns the PUBLIC package and the SECRET state. Coefficients and the PoP nonce are fixed only for reproducible vectors; otherwise they are drawn (t coefficients, then the nonce).</summary>
    public static DkgRound1Result Round1(long identifier, int t, int n, byte[]? sessionId, IReadOnlyList<byte[]>? coefficients = null, byte[]? popNonce = null, Func<byte[]>? random = null)
    {
        var rnd = random ?? FrostNet.DefaultRandom;
        if (identifier <= 0) throw new ArgumentException("dkgRound1: identifier must be a positive integer");
        if (t < 1 || n < t) throw new ArgumentException($"dkgRound1: need 1 <= t <= n (got t={t}, n={n})");
        if (sessionId is not { Length: > 0 }) throw new ArgumentException("dkgRound1: sessionId must be a non-empty byte string");
        var coeffs = new List<BigInteger>();
        var coeffBytes = new List<byte[]>();
        if (coefficients != null)
        {
            if (coefficients.Count != t) throw new ArgumentException($"dkgRound1: coefficients.length must equal t ({t})");
            foreach (var c in coefficients) { var s = Frost.BytesToScalar(c); coeffs.Add(s); coeffBytes.Add(Frost.ScalarToBytes(s)); }
        }
        else
            for (int j = 0; j < t; j++) { var s = Frost.BytesToScalar(rnd()); coeffs.Add(s); coeffBytes.Add(Frost.ScalarToBytes(s)); }

        var commitments = coeffs.Select(Frost.MulBase).Select(p => (object?)Pca.B64u(p.ToBytes())).ToList();
        var cv = CommitVecOf(commitments);
        var k = popNonce != null ? Frost.BytesToScalar(popNonce) : Frost.BytesToScalar(rnd());
        var r = Frost.MulBase(k);
        var c0 = PopChallenge(sessionId, identifier, cv, r);
        var mu = CtScalar.Add(Frost.ScalarToBytes(k), CtScalar.Mul(Frost.ScalarToBytes(coeffs[0]), Frost.ScalarToBytes(c0)));
        var pkg = new D
        {
            ["identifier"] = identifier, ["sessionId"] = Pca.B64u(sessionId), ["coefficientCommitments"] = commitments,
            ["proofOfKnowledge"] = new D { ["R"] = Pca.B64u(r.ToBytes()), ["mu"] = Pca.B64u(Frost.ScalarToBytes(LeToBig(mu))) },
        };
        return new DkgRound1Result(pkg, new DkgState { Identifier = identifier, T = t, N = n, SessionId = (byte[])sessionId.Clone(), Coefficients = coeffBytes, Package = pkg });
    }

    /// <summary>Verify a peer's round-1 proof of possession against the constant-term commitment in the SAME package and the expected session: the stamped session must match and mu*B == R + c*C_0, where the
    /// challenge binds the identifier and the session. Never throws.</summary>
    public static bool VerifyRound1(object? fromIdentifier, object? pkg, byte[]? sessionId)
    {
        try
        {
            if (!(Get(pkg, "sessionId") is string ps && ps == Pca.B64u(sessionId!))) return false;
            var cvs = Get(pkg, "coefficientCommitments");
            if (cvs is L { Count: 0 }) return false;
            var cv = CommitVecOf(cvs);
            var pok = Get(pkg, "proofOfKnowledge");
            var r = Frost.DecodeSafePoint(Unb64u(Get(pok, "R")));
            var mu = CanonicalScalar(Unb64u(Get(pok, "mu")));
            var c = PopChallenge(sessionId!, Big(fromIdentifier), cv, r);
            return Frost.MulBase(mu).SameAs(r.Add(Frost.MulPoint(cv.C0, c)));
        }
        catch (Exception) { return false; }
    }

    // ---- round 2 ----

    /// <summary>ROUND 2. The secret share f_i(j) for EACH OTHER participant j of <paramref name="allRound1Packages"/> (which must include this participant's own), in package order, stamped with the session and SIGNED
    /// by the sender under C_0. Deliver each over a private authenticated channel.</summary>
    public static List<D> Round2(DkgState state, object? allRound1Packages)
    {
        if (allRound1Packages is not L pkgs) throw new ArgumentException("not a list");
        var ids = pkgs.Select(p => Need(p, "identifier")).ToList();
        if (ids.Select(K).Distinct().Count() != ids.Count) throw new ArgumentException("dkgRound2: duplicate identifiers in round-1 packages");
        if (!ids.Any(i => Eq(i, state.Identifier))) throw new ArgumentException("dkgRound2: my own round-1 package is missing");
        var sidB64 = Pca.B64u(state.SessionId);
        foreach (var p in pkgs)
            if (!(Get(p, "sessionId") is string s && s == sidB64)) throw new ArgumentException($"dkgRound2: participant {JsJson.ToJsString(Get(p, "identifier"))} round-1 package is from a different session");
        var coeffs = state.Coefficients.Select(Frost.BytesToScalar).ToList();
        var cv = CommitVecOf(Get(state.Package, "coefficientCommitments"));
        var outp = new List<D>();
        foreach (var j in ids)
        {
            if (Eq(j, state.Identifier)) continue;
            var jb = Big(j);
            var share = EvalPoly(coeffs, jb);
            var sig = SignShareScalar(coeffs[0], cv, state.SessionId, state.Identifier, jb, share);
            outp.Add(new D { ["from"] = state.Identifier, ["to"] = j, ["sessionId"] = sidB64, ["share"] = share, ["sig"] = sig });
        }
        return outp;
    }

    /// <summary>Verify a received share {from, share (byte[]), sig} against the sender's published package: the package is a valid round-1 package for THIS session, the sender's signature over (session, from, me, share)
    /// verifies under its C_0 (a share without it is rejected), and the Pedersen-VSS check holds. Never throws.</summary>
    public static bool VerifyShare(object? received, object? senderPackage, long myIdentifier, byte[]? sessionId)
    {
        try
        {
            if (received is not D r || r.GetValueOrDefault("share") is not byte[] share) return false;
            if (!VerifyRound1(Get(senderPackage, "identifier"), senderPackage, sessionId)) return false;
            if (!VerifyShareSigAgainstPackage(r.GetValueOrDefault("sig"), sessionId!, r.GetValueOrDefault("from"), myIdentifier, share, senderPackage)) return false;
            return VssCheck(CanonicalScalar(share), Get(senderPackage, "coefficientCommitments"), myIdentifier);
        }
        catch (Exception) { return false; }
    }

    // ---- complaint / blame round ----

    /// <summary>Build a complaint: the accuser reveals the share it received AND the accused's signature over it, so any party can confirm both that the accused signed it and that it fails VSS. The authoritative
    /// commitments at adjudication come from the broadcast packages, never from the complaint.</summary>
    public static D FileComplaint(long accused, long accuser, byte[]? receivedShare, string? shareSig, byte[]? sessionId)
    {
        if (accused <= 0) throw new ArgumentException("dkgFileComplaint: accused must be a positive integer");
        if (accuser <= 0) throw new ArgumentException("dkgFileComplaint: accuser must be a positive integer");
        if (accused == accuser) throw new ArgumentException("dkgFileComplaint: cannot file a complaint against yourself");
        if (string.IsNullOrEmpty(shareSig)) throw new ArgumentException("dkgFileComplaint: shareSig (the accused-signed share) is required");
        if (sessionId is not { Length: > 0 }) throw new ArgumentException("dkgFileComplaint: sessionId must be a non-empty byte string");
        ArgumentNullException.ThrowIfNull(receivedShare);
        return new D { ["accused"] = accused, ["accuser"] = accuser, ["sessionId"] = Pca.B64u(sessionId), ["revealedShare"] = Pca.B64u(Frost.ScalarToBytes(Frost.BytesToScalar(receivedShare))), ["shareSig"] = shareSig };
    }

    static object? FindPackage(object? packages, object? accused)
    {
        if (packages is not L l) throw new ArgumentException("not a list");
        foreach (var p in l) if (Eq(Fld(p, "identifier"), accused)) return p;
        return null;
    }

    /// <summary>Adjudicate a complaint INDEPENDENTLY against the accused's broadcast package: justified iff the revealed share is validly signed by the ACCUSED and fails VSS (disqualify the accused); a validly signed
    /// share that passes VSS is a false accusation and an unsigned or foreign one is inadmissible (both at fault: the accuser). Never throws.</summary>
    public static D VerifyComplaint(object? complaint, object? round1Packages)
    {
        try
        {
            var accused = Fld(complaint, "accused");
            var accuser = Fld(complaint, "accuser");
            var accusedPkg = FindPackage(round1Packages, accused);
            if (accusedPkg == null) return new D { ["justified"] = false, ["reason"] = $"accused {JsJson.ToJsString(accused)} has no round-1 package to adjudicate against" };
            if (!Eq(Fld(accusedPkg, "sessionId"), Fld(complaint, "sessionId"))) return new D { ["justified"] = false, ["reason"] = "complaint sessionId does not match the accused round-1 package session" };
            var sid = Unb64u(Get(complaint, "sessionId"));
            var share = Unb64u(Get(complaint, "revealedShare"));
            if (!VerifyShareSigAgainstPackage(Get(complaint, "shareSig"), sid, accused, accuser, share, accusedPkg))
                return new D { ["justified"] = false, ["atFault"] = accuser, ["reason"] = "revealed share is not validly signed by the accused — inadmissible (cannot frame an honest party)" };
            if (VssCheck(CanonicalScalar(share), Get(accusedPkg, "coefficientCommitments"), Big(accuser)))
                return new D { ["justified"] = false, ["atFault"] = accuser, ["reason"] = "accused-signed share is VALID against the accused commitments — false accusation" };
            return new D { ["justified"] = true, ["disqualify"] = accused, ["reason"] = "accused non-repudiably signed a share that FAILS VSS against its broadcast commitments" };
        }
        catch (Exception) { return new D { ["justified"] = false, ["reason"] = "malformed complaint" }; }
    }

    /// <summary>The accused's REBUTTAL: re-present the share it actually signed and sent to the complaint's recipient (recomputed from its retained polynomial, re-signed under C_0).</summary>
    public static D Rebut(long accused, object? complaint, DkgState myRound2State)
    {
        if (myRound2State.Identifier != accused) throw new ArgumentException("dkgRebut: myRound2State is not the accused");
        if (!Eq(Fld(complaint, "accused"), accused)) throw new ArgumentException("dkgRebut: complaint does not name this accused");
        if (!Eq(Pca.B64u(myRound2State.SessionId), Fld(complaint, "sessionId"))) throw new ArgumentException("dkgRebut: complaint is scoped to a different session than my state");
        var coeffs = myRound2State.Coefficients.Select(Frost.BytesToScalar).ToList();
        var accuser = Big(Fld(complaint, "accuser"));
        var share = EvalPoly(coeffs, accuser);
        var cv = CommitVecOf(Get(myRound2State.Package, "coefficientCommitments"));
        var shareSig = SignShareScalar(coeffs[0], cv, myRound2State.SessionId, myRound2State.Identifier, accuser, share);
        return new D { ["accused"] = accused, ["accuser"] = Get(complaint, "accuser"), ["sessionId"] = Get(complaint, "sessionId"), ["presentedShare"] = Pca.B64u(share), ["shareSig"] = shareSig };
    }

    /// <summary>Adjudicate a complaint, optionally with the accused's rebuttal, to a single guilty party from the signatures and VSS alone. Never throws: a malformed complaint is inadmissible (the accuser is guilty).</summary>
    public static D ResolveBlame(object? complaint, object? rebuttal, object? round1Packages)
    {
        try
        {
            var accused = Fld(complaint, "accused");
            var accuser = Fld(complaint, "accuser");
            var accusedPkg = FindPackage(round1Packages, accused);
            if (accusedPkg == null) return new D { ["guilty"] = accused, ["reason"] = $"accused {JsJson.ToJsString(accused)} has no round-1 package to defend with" };
            if (!Eq(Fld(accusedPkg, "sessionId"), Fld(complaint, "sessionId"))) return new D { ["guilty"] = accuser, ["reason"] = "complaint names a session the accused did not run — inadmissible" };
            var sid = Unb64u(Get(complaint, "sessionId"));
            var share = Unb64u(Get(complaint, "revealedShare"));
            var commitments = Get(accusedPkg, "coefficientCommitments");
            if (VerifyShareSigAgainstPackage(Get(complaint, "shareSig"), sid, accused, accuser, share, accusedPkg))
            {
                if (!VssCheck(CanonicalScalar(share), commitments, Big(accuser))) return new D { ["guilty"] = accused, ["reason"] = "accused non-repudiably signed a share that fails VSS" };
                return new D { ["guilty"] = accuser, ["reason"] = "accused-signed share is valid against its commitments — false accusation" };
            }
            // inadmissible: the complaint carries no accused-signed bad share (a non-receipt or fabrication claim)
            if (rebuttal is D rb && Eq(rb.GetValueOrDefault("accused"), accused) && Eq(rb.GetValueOrDefault("accuser"), accuser) && Eq(rb.GetValueOrDefault("sessionId"), Get(complaint, "sessionId")))
            {
                var rShare = Unb64u(rb.GetValueOrDefault("presentedShare"));
                var valid = VerifyShareSigAgainstPackage(rb.GetValueOrDefault("shareSig"), sid, accused, accuser, rShare, accusedPkg) && VssCheck(CanonicalScalar(rShare), commitments, Big(accuser));
                if (valid) return new D { ["guilty"] = accuser, ["reason"] = "accused produced a validly-signed, VSS-correct share for the recipient — the non-receipt/fabrication complaint is refuted" };
                return new D { ["guilty"] = accused, ["reason"] = "accused could not present a validly-signed, VSS-correct share on rebuttal" };
            }
            return new D { ["guilty"] = accuser, ["reason"] = "complaint carries no accused-signed share and the accused offered no rebuttal — inadmissible, cannot frame the accused" };
        }
        catch (Exception) { return new D { ["guilty"] = Get(complaint, "accuser"), ["reason"] = "malformed complaint — inadmissible" }; }
    }

    /// <summary>The QUALIFIED set: participants with a round-1 package whose PoK verifies under the run's session (the plurality session of the broadcast packages; a divergent one does not qualify) and who are not
    /// convicted AS THE ACCUSED DEALER by a resolved complaint (a resolved-guilty accuser removes nobody). Sorted ascending.</summary>
    public static List<long> QualifiedSet(object? participants, object? complaints, object? round1Packages, object? rebuttals = null)
    {
        if (participants is not L parts || round1Packages is not L pkgs) throw new ArgumentException("not a list");
        var pkgById = new Dictionary<string, object?>();
        foreach (var p in pkgs) pkgById[K(Fld(p, "identifier"))] = p;
        // the run's session: the one the broadcast packages agree on (plurality; the first seen wins a tie)
        var counts = new List<(object? Sid, int N)>();
        foreach (var p in pkgs)
        {
            var sid = Fld(p, "sessionId");
            var i = counts.FindIndex(c => Eq(c.Sid, sid));
            if (i < 0) counts.Add((sid, 1)); else counts[i] = (sid, counts[i].N + 1);
        }
        object? runSession = "";
        int best = -1;
        foreach (var (s, c) in counts) if (c > best) { best = c; runSession = s; }

        var qualified = new Dictionary<string, long>();
        foreach (var p in parts)
        {
            if (!pkgById.TryGetValue(K(p), out var pkg)) continue;
            if (!Eq(Fld(pkg, "sessionId"), runSession)) continue;
            byte[] sid;
            try { sid = Unb64u(Get(pkg, "sessionId")); } catch (Exception) { continue; }
            if (VerifyRound1(p, pkg, sid)) qualified[K(p)] = (long)IntentJs.NumOf(p)!.Value;
        }
        if (complaints is not L cs) throw new ArgumentException("not a list");
        var rebs = rebuttals as L ?? new L();
        foreach (var c in cs)
        {
            var reb = rebs.FirstOrDefault(r => Eq(Fld(r, "accused"), Fld(c, "accused")) && Eq(Fld(r, "accuser"), Fld(c, "accuser")) && Eq(Fld(r, "sessionId"), Fld(c, "sessionId")));
            var res = ResolveBlame(c, reb, round1Packages);
            if (Eq(res["guilty"], Get(c, "accused"))) qualified.Remove(K(res["guilty"]));
        }
        return qualified.Values.OrderBy(x => x).ToList();
    }

    // ---- echo-broadcast agreement ----

    static string Round1PackageDigest(object? p) => Pca.HashCanonical(new D
    {
        ["identifier"] = Need(p, "identifier"), ["sessionId"] = Need(p, "sessionId"), ["coefficientCommitments"] = Need(p, "coefficientCommitments"),
        ["proofOfKnowledge"] = new D { ["R"] = Need(Need(p, "proofOfKnowledge"), "R"), ["mu"] = Need(Need(p, "proofOfKnowledge"), "mu") },
    });

    static string ComplaintDigest(object? c) => Pca.HashCanonical(new D
    {
        ["accused"] = Need(c, "accused"), ["accuser"] = Need(c, "accuser"), ["sessionId"] = Need(c, "sessionId"), ["revealedShare"] = Need(c, "revealedShare"), ["shareSig"] = Need(c, "shareSig"),
    });

    /// <summary>The CANONICAL, order-independent transcript digest a party commits to in its echo: a hash over the sorted package digests, the sorted complaint digests, the sorted qualified set and the session id.</summary>
    public static string TranscriptDigest(object? round1Packages, object? complaints, object? qualified, byte[]? sessionId)
    {
        if (round1Packages is not L pkgs || complaints is not L cs || qualified is not L q) throw new ArgumentException("not a list");
        var r1 = pkgs.Select(Round1PackageDigest).ToList();
        r1.Sort(string.CompareOrdinal);
        var cd = cs.Select(ComplaintDigest).ToList();
        cd.Sort(string.CompareOrdinal);
        var qs = q.OrderBy(x => IntentJs.NumOf(x) ?? throw new ArgumentException("not a number")).ToList();
        return Pca.HashCanonical(new D { ["sessionId"] = Pca.B64u(sessionId!), ["round1"] = r1.Cast<object?>().ToList(), ["complaints"] = cd.Cast<object?>().ToList(), ["qualified"] = qs });
    }

    /// <summary>This party's ECHO over its transcript view {identifier, sessionId, transcriptDigest}.</summary>
    public static D Echo(object? identifier, object? round1Packages, object? complaints, object? qualified, byte[]? sessionId) =>
        new() { ["identifier"] = identifier, ["sessionId"] = Pca.B64u(sessionId!), ["transcriptDigest"] = TranscriptDigest(round1Packages, complaints, qualified, sessionId) };

    /// <summary>Check the echo round: EVERY qualified party contributed exactly one echo bound to the session, all with the SAME digest. Echoes from non-qualified parties are ignored. {agreed, digest} or {agreed: false, reason}; never throws.</summary>
    public static D CheckEchoes(object? qualified, object? echoes, byte[]? sessionId)
    {
        D No(string reason) => new() { ["agreed"] = false, ["reason"] = reason };
        try
        {
            var sidB64 = Pca.B64u(sessionId!);
            var qSet = new List<object?>();
            foreach (var x in (L)qualified!) if (!qSet.Any(y => K(y) == K(x))) qSet.Add(x);
            var byId = new Dictionary<string, object?>();
            foreach (var e in (L)echoes!)
            {
                var id = Need(e, "identifier");
                if (!qSet.Any(y => K(y) == K(id))) continue; // a non-qualified party's echo does not count
                if (!(Get(e, "sessionId") is string es && es == sidB64)) return No($"echo from {JsJson.ToJsString(id)} is bound to a different session");
                if (byId.ContainsKey(K(id))) return No($"duplicate echo from qualified participant {JsJson.ToJsString(id)}");
                byId[K(id)] = e;
            }
            object? agreed = Undef;
            foreach (var j in qSet)
            {
                if (!byId.TryGetValue(K(j), out var e)) return No($"missing echo from qualified participant {JsJson.ToJsString(j)}");
                var digest = Get(e, "transcriptDigest");
                if (ReferenceEquals(agreed, Undef)) agreed = digest;
                else if (!Eq(digest, agreed)) return No($"qualified participant {JsJson.ToJsString(j)} echoed a DIFFERENT transcript (equivocation detected)");
            }
            if (ReferenceEquals(agreed, Undef)) return No("no qualified echoes to agree on");
            return new D { ["agreed"] = true, ["digest"] = agreed };
        }
        catch (Exception) { return No("malformed echoes"); }
    }

    // ---- finalize ----

    /// <summary>FINALIZE over the QUALIFIED set (default: every participant of <paramref name="allCommitments"/>; at least t, the finalizer among them). Combines the participant's own polynomial with the shares of all
    /// qualified peers: s_i = f_i(i) + sum f_j(i), Y = sum C_j0, plus the public key package. Every package and share must name the state's session. With <paramref name="agreement"/> ({echoes, complaints?}) the echo round
    /// runs first and any divergent transcript aborts. <paramref name="receivedShares"/> is a list of {from, sessionId, share (byte[]), sig?}.</summary>
    public static D Finalize(long myIdentifier, DkgState myState, object? receivedShares, object? allCommitments, object? qualified = null, object? agreement = null)
    {
        if (myState.Identifier != myIdentifier) throw new ArgumentException("dkgFinalize: myState.identifier != myIdentifier");
        if (allCommitments is not L all) throw new ArgumentException("not a list");
        var ids = all.Select(p => Need(p, "identifier")).ToList();
        if (ids.Select(K).Distinct().Count() != ids.Count) throw new ArgumentException("dkgFinalize: duplicate identifiers in commitments");
        if (!ids.Any(i => Eq(i, myIdentifier))) throw new ArgumentException("dkgFinalize: my own package is missing from allCommitments");
        var sidB64 = Pca.B64u(myState.SessionId);
        foreach (var p in all)
            if (!(Get(p, "sessionId") is string ps && ps == sidB64)) throw new ArgumentException($"dkgFinalize: participant {JsJson.ToJsString(Get(p, "identifier"))} round-1 package is from a different session");

        var idKeys = ids.Select(K).ToHashSet();
        if (qualified != null && qualified is not L) throw new ArgumentException("not a list");
        var qset = ((qualified as L) ?? ids).Where(i => idKeys.Contains(K(i))).ToList();
        var qKeys = qset.Select(K).ToHashSet();
        if (!qKeys.Contains(K(myIdentifier))) throw new ArgumentException("dkgFinalize: myIdentifier is not in the qualified set");
        if (qKeys.Count < myState.T) throw new ArgumentException($"dkgFinalize: qualified set ({qKeys.Count}) is smaller than the threshold t={myState.T}");
        var t = myState.T;
        foreach (var p in all)
        {
            if (!qKeys.Contains(K(Get(p, "identifier")))) continue; // a disqualified participant may be malformed; ignore it
            if (Get(p, "coefficientCommitments") is not L cc || cc.Count != t) throw new ArgumentException($"dkgFinalize: participant {JsJson.ToJsString(Get(p, "identifier"))} committed to a wrong number of coefficients, expected t={t}");
        }

        // the echo-broadcast agreement round (opt-in): before any key material is derived every qualified party must have echoed an IDENTICAL transcript
        if (agreement is D ag && ag.TryGetValue("echoes", out var echoes))
        {
            var qsorted = qset.GroupBy(K).Select(g => g.First()).OrderBy(x => IntentJs.NumOf(x)!.Value).ToList();
            var check = CheckEchoes(qsorted, echoes, myState.SessionId);
            if (check["agreed"] is not true) throw new ArgumentException($"dkgFinalize: echo-broadcast agreement failed — {check["reason"]}");
            var myDigest = TranscriptDigest(all, ag.GetValueOrDefault("complaints") ?? new L(), qsorted, myState.SessionId);
            if (!Eq(check["digest"], myDigest)) throw new ArgumentException("dkgFinalize: echo-broadcast agreement failed — my transcript view diverges from the agreed echo digest (equivocation)");
        }

        // exactly one received share from every OTHER QUALIFIED participant; ignore the rest
        var recvBy = new Dictionary<string, byte[]?>();
        if (receivedShares is not L recv) throw new ArgumentException("not a list");
        foreach (var r in recv)
        {
            var from = Need(r, "from");
            if (Eq(from, myIdentifier)) continue;
            if (!qKeys.Contains(K(from))) continue; // drop shares from disqualified senders
            if (!(Get(r, "sessionId") is string rs && rs == sidB64)) throw new ArgumentException($"dkgFinalize: received share from {JsJson.ToJsString(from)} is from a different session");
            if (recvBy.ContainsKey(K(from))) throw new ArgumentException($"dkgFinalize: duplicate received share from {JsJson.ToJsString(from)}");
            recvBy[K(from)] = Get(r, "share") as byte[];
        }
        foreach (var j in qset)
        {
            if (Eq(j, myIdentifier)) continue;
            if (!recvBy.ContainsKey(K(j))) throw new ArgumentException($"dkgFinalize: missing received share from qualified participant {JsJson.ToJsString(j)}");
        }

        // signingShare s_i = f_i(i) + sum over qualified j != i of f_j(i)
        var myCoeffs = myState.Coefficients.Select(Frost.BytesToScalar).ToList();
        var signingShare = EvalPoly(myCoeffs, myIdentifier);
        foreach (var share in recvBy.Values) signingShare = CtScalar.Add(signingShare, CtScalar.Reduce(share ?? throw new ArgumentException("ct-scalar: reduce takes 1..64 bytes")));

        // group VSS coefficients Phi_k = sum over qualified of C_lk (index 0 is the group public key)
        var groupCoeff = new List<EdwardsPoint>();
        for (int k = 0; k < t; k++)
        {
            var acc = EdwardsPoint.Zero;
            foreach (var p in all)
                if (qKeys.Contains(K(Get(p, "identifier")))) acc = acc.Add(Frost.DecodeSafePoint(Unb64u(((L)Get(p, "coefficientCommitments")!)[k])));
            groupCoeff.Add(acc);
        }
        var groupPublicKey = groupCoeff[0].ToBytes();
        var groupCommitment = groupCoeff.Select(p => (object?)p.ToBytes()).ToList();

        // verifying shares Y_j = sum_k Phi_k * j^k for every QUALIFIED participant
        var verifyingShares = qset.Select(j =>
        {
            var acc = EdwardsPoint.Zero;
            var x = Big(j);
            var xk = BigInteger.One;
            foreach (var phi in groupCoeff)
            {
                acc = acc.Add(Frost.MulPoint(phi, xk));
                xk = Mod(xk * x);
            }
            return (Id: j, Key: acc.ToBytes());
        }).ToList();

        var s = LeToBig(signingShare);
        var verifyingShare = Frost.MulBase(s).ToBytes();
        // consistency: my signing share must be exactly the share the group polynomial predicts for me
        var mine = verifyingShares.FirstOrDefault(v => Eq(v.Id, myIdentifier));
        if (mine.Key == null || !Frost.MulBase(s).SameAs(Frost.DecodeSafePoint(mine.Key))) throw new ArgumentException("dkgFinalize: signing share is inconsistent with the group verifying share (bad dealer share)");

        return new D
        {
            ["identifier"] = myIdentifier, ["signingShare"] = signingShare, ["groupPublicKey"] = groupPublicKey, ["verifyingShare"] = verifyingShare,
            ["publicKeyPackage"] = new D
            {
                ["groupPublicKey"] = groupPublicKey, ["groupCommitment"] = groupCommitment,
                ["verifyingShares"] = verifyingShares.Select(v => (object?)new D { ["identifier"] = v.Id, ["publicKey"] = v.Key }).ToList(),
            },
        };
    }

    // ---- in-process simulation ----

    /// <summary>Run the whole ceremony in-process across n participants and return the shared group key plus per-participant shares ({groupPublicKey, participantShares, groupCommitment, keyPackages, round1Packages,
    /// qualified, complaints, rebuttals, echoes, sessionId}), a literal drop-in for the trusted-dealer keygen. It exercises every public step: round 1 and its PoPs, signed round-2 shares, share verification, complaints
    /// against cheaters, rebuttals, blame, the qualified set, the echo agreement and finalize.</summary>
    public static D Simulate(long t, long n, DkgSimulateOpts? opts = null)
    {
        opts ??= new DkgSimulateOpts();
        var rnd = opts.Random ?? FrostNet.DefaultRandom;
        if (t < 1 || n < t) throw new ArgumentException($"frostDkgSimulate: need 1 <= t <= n (got t={t}, n={n})");
        var ids = opts.Identifiers?.ToList() ?? Enumerable.Range(1, (int)n).Select(i => (long)i).ToList();
        if (ids.Count != n) throw new ArgumentException("frostDkgSimulate: identifiers.length must equal n");
        if (ids.Distinct().Count() != n) throw new ArgumentException("frostDkgSimulate: identifiers must be distinct");
        if (ids.Any(x => x <= 0)) throw new ArgumentException("frostDkgSimulate: identifiers must be positive integers");
        var sessionId = opts.SessionId ?? rnd();
        var cheaters = new HashSet<long>(opts.Cheaters ?? Array.Empty<long>());

        // round 1: every participant samples a polynomial and broadcasts its session-bound package
        var states = new List<DkgState>();
        for (int idx = 0; idx < ids.Count; idx++)
        {
            var coeffs = opts.CoefficientsByParticipant != null && idx < opts.CoefficientsByParticipant.Count ? opts.CoefficientsByParticipant[idx] : null;
            states.Add(Round1(ids[idx], (int)t, (int)n, sessionId, coeffs, null, rnd).State);
        }
        var round1Packages = states.Select(s => (object?)s.Package).ToList();
        foreach (var pkg in round1Packages)
            if (!VerifyRound1(Get(pkg, "identifier"), pkg, sessionId)) throw new ArgumentException($"frostDkgSimulate: PoP verification failed for participant {JsJson.ToJsString(Get(pkg, "identifier"))}");

        // round 2 over "private" channels: a cheater corrupts the share it sends (and signs it); each recipient verifies and complains on failure
        var inbox = ids.ToDictionary(id => id, _ => new L());
        var complaints = new L();
        var stateById = states.ToDictionary(s => s.Identifier);
        foreach (var st in states)
            foreach (var outgoing in Round2(st, round1Packages))
            {
                var from = IntentJs.Lng(outgoing["from"]);
                var to = IntentJs.Lng(outgoing["to"]);
                var shareBytes = (byte[])outgoing["share"]!;
                var shareSig = (string)outgoing["sig"]!;
                if (cheaters.Contains(from))
                {
                    var bad = (byte[])shareBytes.Clone();
                    bad[0] ^= 0x01; // inconsistent with the broadcast commitments
                    shareBytes = bad;
                    shareSig = SignShare(st, to, bad); // the cheater SIGNS what it actually sends: the recipient holds a non-repudiable bad share
                }
                var senderPkg = round1Packages.First(p => Eq(Get(p, "identifier"), from));
                if (VerifyShare(new D { ["from"] = from, ["share"] = shareBytes, ["sig"] = shareSig }, senderPkg, to, sessionId))
                    inbox[to].Add(new D { ["from"] = from, ["sessionId"] = outgoing["sessionId"], ["share"] = shareBytes, ["sig"] = shareSig });
                else
                    complaints.Add(FileComplaint(from, to, shareBytes, shareSig, sessionId));
            }

        // the accused may rebut each complaint by re-presenting the share it actually signed and sent
        var rebuttals = complaints.Select(c => (object?)Rebut(IntentJs.Lng(Get(c, "accused")), c, stateById[IntentJs.Lng(Get(c, "accused"))])).ToList();
        var qualified = QualifiedSet(ids.Cast<object?>().ToList(), complaints, round1Packages, rebuttals);
        if (qualified.Count < t) throw new ArgumentException($"frostDkgSimulate: only {qualified.Count} qualified participants (< t={t}) after the blame round");

        // echo-broadcast agreement: every qualified party commits to its transcript view; a tampered view echoes a divergent qualified set
        var qualifiedL = qualified.Cast<object?>().ToList();
        var echoes = qualified.Select(id =>
        {
            var view = id == opts.EquivocateEchoFor ? qualified.Where(q => q != qualified[^1]).Cast<object?>().ToList() : qualifiedL;
            return (object?)Echo(id, round1Packages, complaints, view, sessionId);
        }).ToList();

        var keyPackages = states.Where(s => qualified.Contains(s.Identifier))
            .Select(s => Finalize(s.Identifier, s, inbox[s.Identifier], round1Packages, qualifiedL, new D { ["echoes"] = echoes, ["complaints"] = complaints })).ToList();

        var groupPublicKey = (byte[])keyPackages[0]["groupPublicKey"]!;
        foreach (var kp in keyPackages)
            if (!((byte[])kp["groupPublicKey"]!).AsSpan().SequenceEqual(groupPublicKey)) throw new ArgumentException("frostDkgSimulate: participants disagree on the group public key");

        return new D
        {
            ["groupPublicKey"] = groupPublicKey,
            ["participantShares"] = keyPackages.Select(kp => (object?)new D { ["identifier"] = kp["identifier"], ["share"] = kp["signingShare"], ["publicKey"] = kp["verifyingShare"] }).ToList(),
            ["groupCommitment"] = ((D)keyPackages[0]["publicKeyPackage"]!)["groupCommitment"],
            ["keyPackages"] = keyPackages.Cast<object?>().ToList(), ["round1Packages"] = round1Packages, ["qualified"] = qualifiedL, ["complaints"] = complaints,
            ["rebuttals"] = rebuttals, ["echoes"] = echoes, ["sessionId"] = sessionId,
        };
    }
}
