using System.Globalization;
using System.Numerics;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The functions of the zk reference corpus (test-data/ref-zk.json.gz) that end in a pairing check, replayed through <see cref="ZkCompliance"/>: one
/// dispatch shared by the core tests (the engine is a recording of the reference: it answers each case with the verdict the corpus records) and by
/// AtlasPca.Zk.Tests (the engine is the real library). Either way every result must equal the corpus, a case the reference accepts must have asked the
/// engine, and a case the reference refuses in front of the pairing must be refused without asking it; an engine that says yes to everything cannot pass.</summary>
static class ZkReplay
{
    public const string M = "ref-zk";

    public static readonly string[] EngineFns =
    {
        "verifyPolicyVmProof", "createPolicyVmSnarkBackend", "createPolicyVmSnarkBackendBls12381", "createGroth16SnarkBackend", "createPolicyVmBoundSnarkBackend", "createZkVerifier",
    };

    /// <summary>An engine that hands every question to a function.</summary>
    public sealed class Probe(Func<string, string, string, string, bool, bool> verify, Func<string, byte[], byte[], string, string>? prove = null) : IGroth16Engine
    {
        public bool Verify(string curve, string vkeyJson, string publicSignalsJson, string proofJson, bool strict) => verify(curve, vkeyJson, publicSignalsJson, proofJson, strict);
        public string Prove(string curve, byte[] wasm, byte[] zkey, string inputJson) => (prove ?? throw new NotSupportedException("this engine does not prove"))(curve, wasm, zkey, inputJson);
    }

    /// <summary>The corpus conventions of an argument: {"$bigint": decimal} is that integer, {"$num": "NaN" | "Infinity" | "-Infinity"} that double, {"$bytes"} bytes.</summary>
    public static object? Rv(object? v) => v switch
    {
        L l => l.Select(Rv).ToList(),
        D { Count: 1 } d when d.GetValueOrDefault("$bigint") is string b => BigInteger.Parse(b, CultureInfo.InvariantCulture),
        D { Count: 1 } d when d.GetValueOrDefault("$num") is string n => n switch
        {
            "NaN" => double.NaN,
            "Infinity" => double.PositiveInfinity,
            "-Infinity" => double.NegativeInfinity,
            _ => double.Parse(n, CultureInfo.InvariantCulture),
        },
        D d when Base.IsBytes(d) => Base.Bytes(d),
        D d => d.ToDictionary(e => e.Key, e => Rv(e.Value)),
        _ => v,
    };

    /// <summary>{"$expectThunk": X} is a function returning X as written ("throw": one that throws); anything else is the expectation itself.</summary>
    public static object? ExpectOf(object? e)
    {
        if (e is not D d || !d.TryGetValue("$expectThunk", out var x)) return e;
        if (x is "throw") return new Func<object?>(() => throw new InvalidOperationException("thunk"));
        return new Func<object?>(() => x);
    }

    /// <summary>The options of a verify or backend case, revived; JSON null (the reference's "not given") is no options.</summary>
    public static D? Opts(object? raw)
    {
        if (raw is not D d) return null;
        var o = (D)Rv(d)!;
        if (d.GetValueOrDefault("expect") is D t && t.ContainsKey("$expectThunk")) o["expect"] = ExpectOf(t);
        return o;
    }

    /// <summary>The assurance label of a backend or hook as the corpus records it (null: none).</summary>
    public static object? Label(object? target)
    {
        if (AssuranceLabels.Of(target) is not { } l) return null;
        var o = new D { ["level"] = l.Level };
        if (l.Vendor != null) o["vendor"] = l.Vendor;
        if (l.AwaitingAudit) o["awaitingAudit"] = true;
        if (l.Ceremony != null) o["ceremony"] = l.Ceremony;
        return o;
    }

    static object? Backend(Func<D?, ISnarkBackend> make, L a)
    {
        var backend = make(Opts(a[0]));
        var input = (D)a[1]!;
        var pub = (D)input["publicInputs"]!;
        var inputs = new ZkPublicInputs((string)pub["action_commit"]!, (string)pub["policy_commit"]!, (string)pub["plan_commit"]!);
        return new D { ["verified"] = backend.Verify(input.GetValueOrDefault("proof"), inputs, null), ["label"] = Label(backend) };
    }

    static List<string>? Strings(object? v) => v is L l ? l.Select(x => (string)x!).ToList() : null;

    const string FailClosed = "zk verification error (fail closed)";

    static object? Verifier(L a)
    {
        var spec = (D)Rv(a[0])!;
        ISnarkBackend? snark = null;
        if (spec.GetValueOrDefault("snark") is D sn)
        {
            var so = sn.GetValueOrDefault("opts") as D;
            var kind = (string)sn["kind"]!;
            snark = kind switch
            {
                "groth16" => ZkCompliance.CreateGroth16SnarkBackend(so),
                "policyvm" => ZkCompliance.CreatePolicyVmSnarkBackend(so),
                "policyvm-bls" => ZkCompliance.CreatePolicyVmSnarkBackendBls12381(so),
                "policyvm-bound" => ZkCompliance.CreatePolicyVmBoundSnarkBackend(so),
                _ => throw new ArgumentException("snark kind " + kind),
            };
        }
        double now = IntentJs.NumOf(spec["nowMs"])!.Value;
        var hook = ZkCompliance.CreateZkVerifier(new ZkVerifierOptions
        {
            TrustedProverKeys = Strings(spec.GetValueOrDefault("trustedProverKeys")),
            PolicyCommitments = Strings(spec.GetValueOrDefault("policyCommitments")),
            RevokedProverKeys = Strings(spec.GetValueOrDefault("revokedProverKeys")),
            ClockSkewMs = IntentJs.NumOf(spec.GetValueOrDefault("clockSkewMs")),
            Now = () => now,
            SnarkBackend = snark,
        });
        var ctx = (D)a[1]!;
        var r = hook(new PcaCore.CoreContext((ctx.GetValueOrDefault("pcactn") as D)!, (ctx.GetValueOrDefault("grant") as D)!, 0));
        var result = new D { ["enforced"] = r.Enforced };
        if (r.Enforced) result["ok"] = r.Ok;
        // the text after the fail-closed prefix is the runtime's own and is not compared
        if (r.Reason != null) result["reason"] = r.Reason.StartsWith(FailClosed + ": ", StringComparison.Ordinal) ? FailClosed : r.Reason;
        return new D { ["result"] = result, ["label"] = Label(hook) };
    }

    /// <summary>The native call of one case of an engine function.</summary>
    public static object? Call(string fn, L a) => fn switch
    {
        "verifyPolicyVmProof" => ZkCompliance.VerifyPolicyVmProof(a[0], Opts(a.Count > 1 ? a[1] : null)),
        "createPolicyVmSnarkBackend" => Backend(ZkCompliance.CreatePolicyVmSnarkBackend, a),
        "createPolicyVmSnarkBackendBls12381" => Backend(ZkCompliance.CreatePolicyVmSnarkBackendBls12381, a),
        "createGroth16SnarkBackend" => Backend(ZkCompliance.CreateGroth16SnarkBackend, a),
        "createPolicyVmBoundSnarkBackend" => Backend(ZkCompliance.CreatePolicyVmBoundSnarkBackend, a),
        "createZkVerifier" => Verifier(a),
        _ => throw new ArgumentException("not an engine function: " + fn),
    };

    /// <summary>The reference's verdict in a recorded result.</summary>
    static bool Accepts(string fn, object? want) => fn switch
    {
        "verifyPolicyVmProof" => want is true,
        "createZkVerifier" => want is D w && w.GetValueOrDefault("result") is D r && r.GetValueOrDefault("ok") is true,
        _ => want is D w && w.GetValueOrDefault("verified") is true,
    };

    // cases the reference refuses in front of the pairing, by the start of the last segment of the case name
    static readonly string[] GateOnlyStems =
    {
        "expect-now-wrong", "expect-thunk-throws", "expectRiskHash", "circuit-", "system-", "extra-key", "proof-extra-key", "signal-count-", "signal9+1", "allow-0", "signal-noncanonical",
        "signal-plus-order", "pi_a.x-hex", "pi_a.x+p", "pi_a.x-leading-zero", "pi_a.z-0", "pi_a-infinity", "pi_a-affine-2", "pi_b-short", "proof-null", "proof-missing", "proof-string",
        "protocol-plonk", "proof-curve-wrong", "shape-", "risk-hash-mismatch", "risk-hash-half", "bls-not-allowed", "15-signals", "now-out-of-range", "context-pin", "action-hash-wrong",
        "policy-hash-wrong", "plan-hash-wrong", "other-circuit", "signals-not-array", "policy-tag-mismatch", "plan-tag-mismatch", "action-tag-mismatch", "wrong-system", "wrong-circuit",
        "signals-6", "signals-8", "null", "noncanonical-signal", "risk-wrong", "action-wrong", "v1-circuit", "signals-missing", "no-proof", "groth16-compliance-garbage",
    };

    public static bool GateOnly(string name)
    {
        var stem = name[(name.LastIndexOf('/') + 1)..];
        return name == "createGroth16SnarkBackend/ceremony-multi-party" || GateOnlyStems.Any(g => stem.StartsWith(g, StringComparison.Ordinal));
    }

    /// <summary>Replays every case of the engine functions with <paramref name="real"/> deciding the pairing, or (null) with the verdict the reference recorded
    /// for the case. Leaves no engine registered.</summary>
    public static void Replay(IGroth16Engine? real)
    {
        bool verdict = false, reached = false;
        ZkCompliance.RegisterGroth16Engine(new Probe((curve, vkey, signals, proof, strict) =>
        {
            reached = true;
            return real?.Verify(curve, vkey, signals, proof, strict) ?? verdict;
        }));
        var bad = new List<string>();
        int cases = 0, asked = 0, pairingRefusals = 0;
        try
        {
            foreach (var fn in EngineFns)
                foreach (var c in Base.Of(M, fn))
                {
                    var name = (string)c["name"]!;
                    var want = c["out"];
                    bool throws = Base.Throws(c, out _);
                    bool ok = !throws && Accepts(fn, want);
                    verdict = ok;
                    reached = false;
                    cases++;
                    object? have;
                    try { have = Call(fn, Base.Args(c)); }
                    catch (Exception e)
                    {
                        if (!throws) bad.Add($"{name}: threw {e.GetType().Name}: {e.Message}");
                        continue;
                    }
                    if (throws) { bad.Add($"{name}: the reference throws, have {Base.Show(Base.Json(have))}"); continue; }
                    if (!Base.Eq(want, have))
                    {
                        bad.Add($"{name}\n   want {Base.Show(want)}\n   have {Base.Show(Base.Json(have))}" + (reached ? " (pairing reached)" : ""));
                        continue;
                    }
                    // an attested-VM statement is accepted without any proof system; every other acceptance must have asked the engine
                    bool proofCase = fn != "createZkVerifier" || name.Contains("/snark/", StringComparison.Ordinal);
                    if (proofCase && ok && !reached) bad.Add(name + ": accepted without a pairing check");
                    if (!ok && reached && GateOnly(name)) bad.Add(name + ": the reference refuses this in front of the pairing, here the pairing was reached");
                    if (reached) asked++;
                    if (!ok && reached) pairingRefusals++;
                }
        }
        finally { ZkCompliance.ResetGroth16Engine(); }
        Assert.True(bad.Count == 0, $"{bad.Count} divergent case(s):\n" + string.Join("\n", bad.Take(40)));
        Assert.Equal(372, cases);
        // 122 cases get as far as the engine: 36 the reference accepts and 86 only the pairing refuses. Every other refusal is made in front of it (6 of
        // them where the engine is chosen: a key that names no known curve)
        Assert.Equal(122, asked);
        Assert.Equal(86, pairingRefusals);
    }
}
