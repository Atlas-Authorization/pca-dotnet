using System.Globalization;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the zk compliance module against the reference (test-data/ref-zk.json.gz, 1429 cases): every function, every case. The
/// functions that never reach a pairing are compared by value. The ones that do (<see cref="ZkReplay"/>) run here with an engine that answers each case
/// with the verdict the corpus records, which checks everything in front of the pairing; AtlasPca.Zk.Tests runs the same cases on the real library. The
/// six ceremony functions are replayed by <see cref="RefZkCeremonyTests"/>.</summary>
public class RefZkTests
{
    const string M = ZkReplay.M;

    /// <summary>Every function of the corpus with its number of cases. A function missing here, or a count that moved, fails the suite.</summary>
    static readonly Dictionary<string, int> Fns = new()
    {
        ["constants"] = 1, ["commitmentField"] = 26, ["policyCommitment"] = 7, ["pinnedPolicyCommitment"] = 7, ["actionCommitment"] = 5, ["proverKeyBinding"] = 7,
        ["policyVmStructHash"] = 23, ["policyVmRiskHash"] = 9, ["quantizeActionStruct"] = 54, ["policyVmCommitmentFromAction"] = 54, ["quantizePlanStruct"] = 11,
        ["quantizePolicyStruct"] = 17, ["quantizePolicyVmInputs"] = 11, ["decodePolicyVmPublic"] = 6, ["decodePolicyVmBoundPublic"] = 3, ["policyVmContextMatches"] = 66,
        ["isCanonicalGroth16Envelope"] = 409, ["circuitVersion"] = 13, ["createAttestedComplianceProver"] = 6, ["provePolicyVmCompliance"] = 1,
        // through the engine (ZkReplay)
        ["verifyPolicyVmProof"] = 169, ["createPolicyVmSnarkBackend"] = 20, ["createPolicyVmSnarkBackendBls12381"] = 15, ["createGroth16SnarkBackend"] = 14,
        ["createPolicyVmBoundSnarkBackend"] = 7, ["createZkVerifier"] = 147,
        // RefZkCeremonyTests
        ["vkId"] = 10, ["circuitProvenance"] = 13, ["checkCircuitProvenance"] = 19, ["transcriptSha256"] = 3, ["checkTranscript"] = 257, ["ceremonyOf"] = 19,
    };

    static object? Arg(L a, int i) => i < a.Count ? a[i] : null;

    /// <summary>A quantized struct as the corpus writes it: every field {"$bigint": decimal}.</summary>
    static object? Big(object? v) => v switch
    {
        ulong[] q => q.Select(x => (object?)new D { ["$bigint"] = x.ToString(CultureInfo.InvariantCulture) }).ToList(),
        D d => d.ToDictionary(e => e.Key, e => Big(e.Value)),
        _ => v,
    };

    /// <summary>The reference throws on options given as null; here null options are no options, so the test refuses those two cases itself.</summary>
    static D? QuantOpts(L a, int i)
    {
        if (i < a.Count && a[i] == null) throw new ArgumentException("null options");
        return (D?)ZkReplay.Rv(Arg(a, i));
    }

    int Check(string fn, Func<L, object?> run) => Base.Check(M, fn, run, min: Fns[fn]);

    [Fact]
    public void EveryFunctionOfTheCorpusIsHandled()
    {
        var have = Base.Cases(M).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(Fns.OrderBy(e => e.Key, StringComparer.Ordinal).Select(e => $"{e.Key}={e.Value}"), have.OrderBy(e => e.Key, StringComparer.Ordinal).Select(e => $"{e.Key}={e.Value}"));
        Assert.Equal(1429, Fns.Values.Sum());
        Assert.Equal(1429, Base.Cases(M).Count);
        Assert.Equal(372, ZkReplay.EngineFns.Sum(f => Fns[f]));
    }

    [Fact]
    public void Constants() => Check("constants", _ => new D
    {
        ["ZK_PROVER_BINDING_REF"] = ZkCompliance.ZkProverBindingRef,
        ["POLICYVM_PUBLIC_SIGNAL"] = ZkCompliance.PolicyVmPublicSignal,
        ["POLICYVM_PUBLIC_SIGNAL_COUNT"] = ZkCompliance.PolicyVmPublicSignalCount,
        ["POLICYVM_BOUND_PUBLIC_SIGNAL"] = ZkCompliance.PolicyVmBoundPublicSignal,
        ["POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT"] = ZkCompliance.PolicyVmBoundPublicSignalCount,
        ["POLICYVM_BOUND_RISK_FIELDS"] = ZkCompliance.PolicyVmBoundRiskFields,
        ["POLICYVM_REVERSIBILITY_ORDER"] = ZkCompliance.PolicyVmReversibilityOrder,
        ["paths"] = new D
        {
            ["DEFAULT_VKEY_PATH"] = ZkCompliance.DefaultVkeyPath,
            ["DEFAULT_WASM_PATH"] = ZkCompliance.DefaultWasmPath,
            ["DEFAULT_ZKEY_PATH"] = ZkCompliance.DefaultZkeyPath,
            ["POLICYVM_VKEY_PATH"] = ZkCompliance.PolicyVmVkeyPath,
            ["POLICYVM_SAMPLE_PROOF_PATH"] = ZkCompliance.PolicyVmSampleProofPath,
            ["POLICYVM_WASM_PATH"] = ZkCompliance.PolicyVmWasmPath,
            ["POLICYVM_ZKEY_PATH"] = ZkCompliance.PolicyVmZkeyPath,
            ["POLICYVM_BLS12381_VKEY_PATH"] = ZkCompliance.PolicyVmBls12381VkeyPath,
            ["POLICYVM_BLS12381_SAMPLE_PROOF_PATH"] = ZkCompliance.PolicyVmBls12381SampleProofPath,
            ["POLICYVM_BOUND_VKEY_PATH"] = ZkCompliance.PolicyVmBoundVkeyPath,
            ["POLICYVM_BOUND_SAMPLE_PROOF_PATH"] = ZkCompliance.PolicyVmBoundSampleProofPath,
            ["POLICYVM_BOUND_WASM_PATH"] = ZkCompliance.PolicyVmBoundWasmPath,
            ["POLICYVM_BOUND_ZKEY_PATH"] = ZkCompliance.PolicyVmBoundZkeyPath,
        },
    });

    [Fact] public void CommitmentField() => Check("commitmentField", a => ZkCompliance.CommitmentField((a[0] as string)!));
    [Fact] public void PolicyCommitment() => Check("policyCommitment", a => ZkCompliance.PolicyCommitment(a[0]));
    [Fact] public void PinnedPolicyCommitment() => Check("pinnedPolicyCommitment", a => ZkCompliance.PinnedPolicyCommitment(a[0]));
    [Fact] public void ActionCommitment() => Check("actionCommitment", a => ZkCompliance.ActionCommitment(a[0]));

    [Fact]
    public void ProverKeyBinding() => Check("proverKeyBinding", a =>
    {
        var b = ZkCompliance.ProverKeyBinding((string)a[0]!, IntentJs.NumOf(a[1])!.Value, (string)a[2]!);
        return new D { ["holderPub"] = b.HolderPub, ["grantRef"] = b.GrantRef, ["epoch"] = b.Epoch, ["nonce"] = b.Nonce };
    });

    [Fact] public void PolicyVmStructHash() => Check("policyVmStructHash", a => ZkCompliance.PolicyVmStructHash((L)ZkReplay.Rv(a[0])!));
    [Fact] public void PolicyVmRiskHash() => Check("policyVmRiskHash", a => ZkCompliance.PolicyVmRiskHash(ZkReplay.Rv(a[0]) as L));
    [Fact] public void QuantizeActionStruct() => Check("quantizeActionStruct", a => Big(ZkCompliance.QuantizeActionStruct(ZkReplay.Rv(Arg(a, 0)), QuantOpts(a, 1))));
    [Fact] public void PolicyVmCommitmentFromAction() => Check("policyVmCommitmentFromAction", a => ZkCompliance.PolicyVmCommitmentFromAction(ZkReplay.Rv(Arg(a, 0)), QuantOpts(a, 1)));
    [Fact] public void QuantizePlanStruct() => Check("quantizePlanStruct", a => Big(ZkCompliance.QuantizePlanStruct(ZkReplay.Rv(Arg(a, 0)), QuantOpts(a, 1))));
    [Fact] public void QuantizePolicyStruct() => Check("quantizePolicyStruct", a => Big(ZkCompliance.QuantizePolicyStruct(ZkReplay.Rv(Arg(a, 0)), QuantOpts(a, 1))));
    [Fact] public void QuantizePolicyVmInputs() => Check("quantizePolicyVmInputs", a => Big(ZkCompliance.QuantizePolicyVmInputs(ZkReplay.Rv(Arg(a, 0)), QuantOpts(a, 1))));
    [Fact] public void DecodePolicyVmPublic() => Check("decodePolicyVmPublic", a => ZkCompliance.DecodePolicyVmPublic((L)a[0]!));
    [Fact] public void DecodePolicyVmBoundPublic() => Check("decodePolicyVmBoundPublic", a => ZkCompliance.DecodePolicyVmBoundPublic((L)a[0]!));

    [Fact]
    public void PolicyVmContextMatches() => Check("policyVmContextMatches", a =>
    {
        // this function's cases carry their pins as written (no revival): "$absent" is no expectation, "bound" the layout of the risk-bound circuit
        var ps = (L)a[0]!;
        bool bound = Arg(a, 2) is "bound";
        return Arg(a, 1) is "$absent" ? ZkCompliance.PolicyVmContextMatches(ps, bound) : ZkCompliance.PolicyVmContextMatches(ps, ZkReplay.ExpectOf(Arg(a, 1)), bound);
    });

    [Fact] public void IsCanonicalGroth16Envelope() => Check("isCanonicalGroth16Envelope", a => ZkCompliance.IsCanonicalGroth16Envelope(a[0], a[1]));
    [Fact] public void CircuitVersion() => Check("circuitVersion", a => ZkCompliance.CircuitVersion(Arg(a, 0)));

    [Fact]
    public void CreateAttestedComplianceProver() => Check("createAttestedComplianceProver", a =>
    {
        var prover = ZkCompliance.CreateAttestedComplianceProver(Base.Bytes(a[0]));
        var o = (D)a[1]!;
        return new D
        {
            ["publicKey"] = prover.PublicKey,
            ["statement"] = prover.Prove(o["pcactn"] as D, o["decideInput"], Base.Long(o["issued_at"]), Base.Long(o["expires_at"])),
        };
    });

    [Fact]
    public void TheEngineFunctionsAgreeWithTheReferenceUnderItsRecordedVerdicts() => ZkReplay.Replay(null);

    static L ArgsOf(string fn, string name) => Base.Args(Base.Of(M, fn).Single(c => (string)c["name"]! == name));

    [Fact]
    public void WithNoKeyGivenTheEngineReceivesTheEmbeddedKeyOfTheProofsCurve()
    {
        foreach (var (curve, engineCurve) in new[] { ("bn", ZkCompliance.CurveBn254), ("bls", ZkCompliance.CurveBls12381) })
        {
            var a = ArgsOf("verifyPolicyVmProof", $"verifyPolicyVmProof/{curve}/valid");
            var env = (D)a[0]!;
            string? key = null, seenCurve = null, signals = null, proof = null;
            var strictSeen = new List<bool>();
            ZkCompliance.RegisterGroth16Engine(new ZkReplay.Probe((c, k, s, p, strict) =>
            {
                (seenCurve, key, signals, proof) = (c, k, s, p);
                strictSeen.Add(strict);
                return true;
            }));
            try
            {
                Assert.True(ZkCompliance.Groth16EngineRegistered);
                Assert.True(ZkCompliance.VerifyPolicyVmProof(env));
                Assert.True(ZkCompliance.VerifyPolicyVmProof(env, new D { ["strict"] = true }));
            }
            finally { ZkCompliance.ResetGroth16Engine(); }
            // the embedded key is the key the corpus carries, and the engine gets the proof and its signals as they are
            Assert.Equal(engineCurve, seenCurve);
            Assert.True(Base.Eq(((D)a[1]!)["verificationKey"], Pca.ParseJson(key!)));
            Assert.True(Base.Eq(env["publicSignals"], Pca.ParseJson(signals!)));
            Assert.True(Base.Eq(env["proof"], Pca.ParseJson(proof!)));
            Assert.Equal(new[] { false, true }, strictSeen);
        }
    }

    [Fact]
    public void WithoutAnEngineAProofIsRefusedAsTheReferenceRefusesWithoutItsProofLibrary()
    {
        ZkCompliance.ResetGroth16Engine();
        Assert.False(ZkCompliance.Groth16EngineRegistered);
        var valid = ArgsOf("verifyPolicyVmProof", "verifyPolicyVmProof/bn/valid");
        Assert.False(ZkCompliance.VerifyPolicyVmProof(valid[0], ZkReplay.Opts(valid[1])));
        // the first-circuit backend surfaces the missing engine; the hook turns that into a denial
        Assert.Throws<InvalidOperationException>(() => ZkReplay.Call("createGroth16SnarkBackend", ArgsOf("createGroth16SnarkBackend", "createGroth16SnarkBackend/bound-wrong-key")));
        var viaHook = (D)((D)ZkReplay.Call("createZkVerifier", ArgsOf("createZkVerifier", "createZkVerifier/snark/policyvm-bn-valid"))!)["result"]!;
        Assert.False((bool)viaHook["ok"]!);
        Assert.Equal("snark backend rejected the proof", (string?)viaHook["reason"]);
        Assert.Throws<ArgumentNullException>(() => ZkCompliance.RegisterGroth16Engine(null!));
        // the risk-bound circuit has no embedded key: with none given its build product is read, and that file is not there
        var v2 = ArgsOf("verifyPolicyVmProof", "verifyPolicyVmProof/v2/valid-shape-wrong-key");
        Assert.ThrowsAny<IOException>(() => ZkCompliance.VerifyPolicyVmProof(v2[0]));
        Assert.EndsWith(Path.Combine("build", "policyvm_bound_vkey.json"), ZkCompliance.CircuitFile(ZkCompliance.PolicyVmBoundVkeyPath).Replace('/', Path.DirectorySeparatorChar));
    }

    [Fact]
    public void TheProverContract()
    {
        var c = Base.Of(M, "provePolicyVmCompliance").Single();
        var witness = (D)Base.Args(c)[0]!;
        var want = (D)c["out"]!;
        var signals = (L)want["publicSignals"]!;
        // the public hash halves of the sample proof are the struct hashes of the sample witness
        D Hash(params string[] names) => ZkCompliance.PolicyVmStructHash(names.Select(n => witness[n]));
        var statement = ZkCompliance.DecodePolicyVmPublic(signals);
        Assert.True(Base.Eq(statement["actionHash"], Hash("verb", "resource", "reversibility", "paramScalar")));
        Assert.True(Base.Eq(statement["planHash"], Hash("planVerb", "planResource", "semanticDist", "planSalt")));
        Assert.True(Base.Eq(statement["policyHash"], Hash("wAlpha", "wBeta", "wGamma", "wDelta", "wEpsilon", "wZeta", "theta1", "theta2", "kappa", "budgetB", "policyVerb", "policyResource",
            "policyParamBound", "expiresAt", "notBefore", "maxBlast", "maxDepth", "revMax", "rateMax", "allocParent")));

        // proving needs the circuit build (not in the repository): here the wrapper is checked around an engine that returns the sample's signals.
        // It hands the engine the witness as text with the two files and wraps what comes back in the envelope of its circuit.
        var dir = Directory.CreateTempSubdirectory("zk-prove").FullName;
        try
        {
            string wasm = Path.Combine(dir, "w.wasm"), zkey = Path.Combine(dir, "k.zkey");
            File.WriteAllBytes(wasm, new byte[] { 1, 2, 3 });
            File.WriteAllBytes(zkey, new byte[] { 1, 2, 3, 4 });
            var files = new D { ["wasmPath"] = wasm, ["zkeyPath"] = zkey };
            string? seen = null;
            ZkCompliance.RegisterGroth16Engine(new ZkReplay.Probe((_, _, _, _, _) => false, (curve, w, k, input) =>
            {
                seen = $"{curve}|{w.Length}|{k.Length}|{input}";
                return "{\"proof\":{\"pi_a\":[]},\"publicSignals\":" + Base.Show(signals) + "}";
            }));
            var made = ZkCompliance.ProvePolicyVmCompliance(witness, files);
            Assert.Equal("groth16-bn254", (string?)made["system"]);
            Assert.Equal((string?)want["sampleProofCircuit"], (string?)made["circuit"]);
            Assert.True(Base.Eq(signals, made["publicSignals"]));
            Assert.True(Base.Eq(new D { ["pi_a"] = new L() }, made["proof"]));
            Assert.StartsWith("bn254|3|4|", seen);
            Assert.True(Base.Eq(witness, Pca.ParseJson(seen!["bn254|3|4|".Length..])));
            Assert.Equal("pca-policyvm-v2", (string?)ZkCompliance.ProvePolicyVmBoundCompliance(witness, files)["circuit"]);
            var commit = Pca.B64u(new byte[32]);
            var first = ZkCompliance.ProveGroth16Compliance(new D { ["action_commit"] = commit, ["policy_commit"] = commit, ["plan_commit"] = commit, ["verb"] = new Num("7"), ["risk"] = 5UL }, files);
            Assert.Equal("pca-compliance-v1", (string?)first["circuit"]);
            var firstInput = (D)Pca.ParseJson(seen!["bn254|3|4|".Length..])!;
            Assert.Equal("7|5|0|1", string.Join("|", new[] { "verb", "risk", "shaAction", "allow" }.Select(member => (string?)firstInput[member])));
        }
        finally
        {
            ZkCompliance.ResetGroth16Engine();
            Directory.Delete(dir, true);
        }
        // without an engine the provers refuse
        Assert.Throws<InvalidOperationException>(() => ZkCompliance.ProvePolicyVmCompliance(witness));
    }

    sealed class FakeHardware(Func<HardwareResult> answer) : IVendorVerifier
    {
        public string Vendor => "test";
        public HardwareResult Verify(D? evidence, AttestationBinding? expected, long nowMs) => answer();
    }

    [Fact]
    public void TheHardwareBindingOfTheProverKey()
    {
        var a = ArgsOf("createZkVerifier", "createZkVerifier/ok");
        var spec = (D)a[0]!;
        var ctx = (D)a[1]!;
        var key = (string)((L)spec["trustedProverKeys"]!)[0]!;
        double now = IntentJs.NumOf(spec["nowMs"])!.Value;
        D Measured(string m) => new() { ["runtime_measurement"] = m };
        HardwareResult answer = new(true, true, null, Measured("m1"));
        var hardware = AssuranceLabels.Set(new FakeHardware(() => answer), new AssuranceLabel("hardware", "test-vendor"));
        PcaCore.Hook Make(IVendorVerifier verifier, params string[] measurements) => ZkCompliance.CreateZkVerifier(new ZkVerifierOptions
        {
            TrustedProverKeys = new[] { key },
            Now = () => now,
            ProverAttestation = new ZkProverAttestation(verifier, _ => null, k => ZkCompliance.ProverKeyBinding(k, 1, "n"), measurements),
        });
        var hook = Make(hardware, "m1");
        PcaCore.HookResult Run() => hook(new PcaCore.CoreContext((D)ctx["pcactn"]!, (D)ctx["grant"]!, 0));
        Assert.Equal(new AssuranceLabel("attested_vm_hw", "hardware-bound:test-vendor"), AssuranceLabels.Of(hook));
        Assert.True(Run().Ok);
        answer = new(true, true, null, Measured("other"));
        Assert.Equal("prover VM measurement is not allowlisted", Run().Reason);
        answer = new(true, true);
        Assert.Equal("prover hardware evidence carries no measured identity", Run().Reason);
        answer = new(true, false, null, Measured("m1"));
        Assert.Equal("prover hardware evidence does not bind the prover key", Run().Reason);
        answer = HardwareResult.Fail("bad quote");
        Assert.Equal("prover hardware evidence invalid: bad quote", Run().Reason);
        // an unlabelled verifier, an empty allowlist and an empty measurement are refused when the verifier is built
        Assert.Throws<ArgumentException>(() => Make(new FakeHardware(() => answer), "m1"));
        Assert.Throws<ArgumentException>(() => Make(hardware));
        Assert.Throws<ArgumentException>(() => Make(hardware, ""));
    }
}
