// Zero-knowledge proof of compliance (the reference zk module), part 1: the commitments to an action, a policy and a plan; the attested-VM compliance
// statement (an Ed25519-signed statement that the Policy VM released the action, carrying commitments only) with its prover and the verifier hook; the
// binding tag of a commitment; the Groth16 engine seam; the bundled verification keys and circuit versions; the prove wrappers.
// The pairing check is not in this assembly: an engine registers through RegisterGroth16Engine (the AtlasPca.Zk package brings one over a native
// library). Without an engine a proof is refused the way the reference refuses without its proof library: VerifyPolicyVmProof answers false, the
// first-circuit backend and the provers throw. Proofs, keys, statements and options are parsed JSON trees (Dictionary<string, object?>,
// List<object?>, string, bool, Num, null) with the reference's member names, read as the reference reads them.
using System.Globalization;
using System.Numerics;
using System.Text;
using AtlasPca.Analyzer;
using AtlasPca.Authzen;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>A Groth16 engine over snarkjs artifacts (decimal-string field elements, G1 [x, y, "1"], G2 [[x0, x1], [y0, y1], ["1", "0"]]). It decides the
/// pairing question only; <see cref="ZkCompliance"/> keeps every other check in front of it.</summary>
public interface IGroth16Engine
{
    /// <summary>The pairing check of one proof. <paramref name="curve"/> is <see cref="ZkCompliance.CurveBn254"/> or <see cref="ZkCompliance.CurveBls12381"/>; the
    /// three texts are the verification key object, the array of public signals and the proof object as JSON. With <paramref name="strict"/> false the engine
    /// accepts what the reference verifier accepts (the key's protocol and nPublic are not read, nor are IC entries beyond the signals); true also requires
    /// those to agree. False = the proof is invalid. An engine that cannot decide (its library is missing) throws.</summary>
    bool Verify(string curve, string vkeyJson, string publicSignalsJson, string proofJson, bool strict);

    /// <summary>Proves: runs the circuit's witness program <paramref name="wasm"/> over the input JSON object and proves under the proving key
    /// <paramref name="zkey"/>. Returns the JSON text <c>{"proof": {...}, "publicSignals": [...]}</c>; throws when the witness does not satisfy the circuit.</summary>
    string Prove(string curve, byte[] wasm, byte[] zkey, string inputJson);
}

/// <summary>The three commitments a proof is checked against: the only public inputs a backend receives.</summary>
public sealed record ZkPublicInputs(string ActionCommit, string PolicyCommit, string PlanCommit);

/// <summary>A proof-system backend of <see cref="ZkCompliance.CreateZkVerifier"/>. Label a custom one with <see cref="AssuranceLabels.Set"/> (its proof system as the
/// level); an unlabelled backend reports <c>unknown</c>.</summary>
public interface ISnarkBackend
{
    /// <summary>True when <paramref name="proof"/> (the opaque value carried in <c>zk_compliance</c>) is valid for the commitments.</summary>
    bool Verify(object? proof, ZkPublicInputs publicInputs, PcaCore.CoreContext? ctx);
}

/// <summary>Binds the attested-VM prover key to hardware evidence of the VM measurement.</summary>
/// <param name="HardwareVerifier">A vendor or multi-root verifier. It must carry a <c>hardware</c> or <c>multi_root</c> assurance label.</param>
/// <param name="Evidence">The hardware evidence of a prover public key (null: none).</param>
/// <param name="ExpectedBinding">The binding the quote must carry for a prover key (see <see cref="ZkCompliance.ProverKeyBinding"/>). Throwing denies.</param>
/// <param name="Measurements">The accepted runtime measurements (the VM image). Required, non-empty.</param>
public sealed record ZkProverAttestation(IVendorVerifier HardwareVerifier, Func<string, D?> Evidence, Func<string, AttestationBinding> ExpectedBinding, IReadOnlyList<string> Measurements);

/// <summary>The configuration of <see cref="ZkCompliance.CreateZkVerifier"/>. It is copied when the verifier is built.</summary>
public sealed class ZkVerifierOptions
{
    /// <summary>The b64u public keys of the attested prover VMs trusted in attested-VM mode.</summary>
    public IEnumerable<string>? TrustedProverKeys { get; init; }
    /// <summary>The expected policy commitments, as bare hashes: the verifier then never reads the policy. Null: the commitment of the context's grant.</summary>
    public IEnumerable<string>? PolicyCommitments { get; init; }
    /// <summary>Set: proof verification is this backend's (the carried value is its proof); the statement checks do not run.</summary>
    public ISnarkBackend? SnarkBackend { get; init; }
    /// <summary>Prover keys that are no longer trusted, even when still listed as trusted.</summary>
    public IEnumerable<string>? RevokedProverKeys { get; init; }
    /// <summary>Attested-VM mode only: require hardware evidence for the prover key.</summary>
    public ZkProverAttestation? ProverAttestation { get; init; }
    /// <summary>The clock, epoch milliseconds (default: the system clock).</summary>
    public Func<double>? Now { get; init; }
    /// <summary>Allowed clock skew in milliseconds (default 0; a negative or non-finite value is 0).</summary>
    public double? ClockSkewMs { get; init; }
}

/// <summary>The attested-VM prover: runs the Policy VM and signs a compliance statement when it releases the action.</summary>
public sealed class AttestedComplianceProver
{
    readonly EdKey _key;

    internal AttestedComplianceProver(byte[] attestorSecret) { _key = EdKey.FromSeed(attestorSecret); }

    /// <summary>The b64u public key a verifier lists in <see cref="ZkVerifierOptions.TrustedProverKeys"/>.</summary>
    public string PublicKey => _key.Id;

    /// <summary>Decides <paramref name="decideInput"/> (the input of <see cref="PolicyVmDecide.Decide"/>) and, only when the guardian share is released, returns
    /// the signed statement {v, mode, action_commit, policy_commit, plan_commit, released, r, issued_at, expires_at, prover, sig}. Throws when the action is not
    /// compliant: a false statement cannot be signed.</summary>
    public D Prove(D? pcactn, object? decideInput, long issuedAt, long expiresAt)
    {
        var decision = PolicyVmDecide.Decide(decideInput);
        if (decision.GetValueOrDefault("releaseGuardianShare") is not true)
            throw new InvalidOperationException("createAttestedComplianceProver: action is not compliant, nothing to prove ("
                + string.Join("; ", (decision.GetValueOrDefault("reasons") as L ?? new L()).Select(JsX.Str)) + ")");
        var body = new D
        {
            ["v"] = new Num("1"),
            ["mode"] = "attested-vm",
            ["action_commit"] = ZkCompliance.ActionCommitment(pcactn),
            ["policy_commit"] = ZkCompliance.PolicyCommitment(JsX.JsonOf(ZkCompliance.M(decideInput, "grant"))),
            ["plan_commit"] = ZkCompliance.PlanCommit(pcactn),
            ["released"] = true,
            ["r"] = decision.GetValueOrDefault("r"),
            ["issued_at"] = IntentJs.OfLong(issuedAt),
            ["expires_at"] = IntentJs.OfLong(expiresAt),
            ["prover"] = PublicKey,
        };
        return new D(body) { ["sig"] = Pca.B64u(_key.Sign(ZkCompliance.StatementMessage(body))) };
    }
}

public static partial class ZkCompliance
{
    const string Domain = "atlas-pca/zk-compliance/v1\0";
    const string NoEngine = "no Groth16 engine is registered (add the AtlasPca.Zk package and call ZkNative.Register())";

    /// <summary><c>grantRef</c> of the binding a prover VM's hardware quote carries.</summary>
    public const string ZkProverBindingRef = "atlas-pca/zk-prover/v1";

    /// <summary>The curve names an <see cref="IGroth16Engine"/> receives.</summary>
    public const string CurveBn254 = "bn254", CurveBls12381 = "bls12-381";

    /// <summary>The BN254 scalar field modulus (the field the public signals of the BN254 circuits live in).</summary>
    static readonly BigInteger Bn254Fr = BigInteger.Parse("21888242871839275222246405745257275088548364400416034343698204186575808495617", CultureInfo.InvariantCulture);

    /// <summary><c>o[k]</c> as the reference reads it: the member of an object, else undefined (also for a value that is not an object).</summary>
    internal static object? M(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : JsX.Undef;

    static object? At(L l, int i) => i < l.Count ? l[i] : JsX.Undef;

    // ---- the Groth16 engine seam ----

    static volatile IGroth16Engine? _engine;

    /// <summary>Installs the engine every Groth16 check and prover of this class uses (process-wide).</summary>
    public static void RegisterGroth16Engine(IGroth16Engine engine) => _engine = engine ?? throw new ArgumentNullException(nameof(engine));

    /// <summary>Removes the engine: Groth16 proofs are refused again.</summary>
    public static void ResetGroth16Engine() => _engine = null;

    /// <summary>True while an engine is registered. Without one <see cref="VerifyPolicyVmProof"/> answers false for every proof.</summary>
    public static bool Groth16EngineRegistered => _engine != null;

    /// <summary>The pairing check as the reference verifier runs it: the curve is the one the KEY names. Throws without an engine and on a key that names no
    /// known curve (callers that must not throw turn that into a refusal).</summary>
    static bool Groth16Verify(object? vkey, L publicSignals, object? proof, bool strict)
    {
        var engine = _engine ?? throw new InvalidOperationException(NoEngine);
        if (vkey is not D vk || vk.GetValueOrDefault("curve") is not string named) throw new ArgumentException("the verification key names no curve");
        var name = new string(named.ToUpperInvariant().Where(char.IsAsciiLetterOrDigit).ToArray());
        bool bn = name is "BN128" or "BN254" or "ALTBN128";
        if (!bn && name != "BLS12381") throw new ArgumentException("the verification key names an unknown curve");
        // the engine gets the one spelling of the curve name the artifacts use
        var key = new D(vk) { ["curve"] = bn ? "bn128" : "bls12381" };
        return engine.Verify(bn ? CurveBn254 : CurveBls12381, AtlasPca.Js.JsJson.Stringify(key), AtlasPca.Js.JsJson.Stringify(publicSignals), AtlasPca.Js.JsJson.Stringify(proof), strict);
    }

    // ---- commitments and the attested-VM statement ----

    /// <summary>The commitment to the policy: the grant's content address (its <c>id</c>, else the hash of its canonical JSON).</summary>
    public static string PolicyCommitment(object? grant) => M(grant, "id") is string id ? id : Pca.HashCanonical(grant);

    /// <summary>The policy commitment a verifier pins when it may not read the grant.</summary>
    public static string PinnedPolicyCommitment(object? grant) => PolicyCommitment(grant);

    /// <summary>The commitment to the action: the content address of the PCActn's action descriptor.</summary>
    public static string ActionCommitment(object? pcactn) => Pca.HashCanonical(JsX.JsonOf(M(pcactn, "action")));

    /// <summary>The commitment to the plan: the PCActn's plan root, empty when it carries none.</summary>
    internal static string PlanCommit(object? pcactn) => M(M(pcactn, "plan"), "root") as string ?? "";

    /// <summary>What the prover signs: the domain tag and the canonical JSON of every member except <c>sig</c>. Throws on a body with no canonical form.</summary>
    internal static byte[] StatementMessage(D body) => Pca.Cat(Encoding.UTF8.GetBytes(Domain), Pca.Canon(body));

    static bool VerifyB64u(string publicKey, byte[] msg, string sig) =>
        Pca.B64uDecode(publicKey, 32) is { } pk && Pca.B64uDecode(sig, 64) is { } sg && Pca.VerifyEd25519Strict(pk, msg, sg);

    /// <summary>The attested-VM prover over the 32-byte Ed25519 secret of the VM.</summary>
    public static AttestedComplianceProver CreateAttestedComplianceProver(byte[] attestorSecret) => new(attestorSecret);

    /// <summary>The binding a prover VM puts in its hardware quote so that the quote vouches for its key.</summary>
    public static AttestationBinding ProverKeyBinding(string proverPublicKey, double epoch, string nonce) => new(proverPublicKey, ZkProverBindingRef, epoch, nonce);

    /// <summary>
    /// The zk hook of the verifier (<c>PcaCore.Hooks.Zk</c>): checks the proof carried in <c>zk_compliance</c> against commitments only. With a
    /// <see cref="ZkVerifierOptions.SnarkBackend"/> the backend decides over the three commitments. Otherwise the carried value is an attested-VM statement:
    /// version and mode, the release claim, a trusted and not revoked prover key, the signature, the validity window, the action, plan and policy
    /// commitments, then the hardware binding when configured. Every fault denies. The hook carries the assurance label of its mode.
    /// </summary>
    public static PcaCore.Hook CreateZkVerifier(ZkVerifierOptions opts)
    {
        ArgumentNullException.ThrowIfNull(opts);
        var backend = opts.SnarkBackend;
        var pa = backend != null ? null : opts.ProverAttestation;
        AssuranceLabel? hw = null;
        if (pa != null)
        {
            hw = AssuranceLabels.Of(pa.HardwareVerifier);
            if (hw?.Level is not ("hardware" or "multi_root")) throw new ArgumentException("createZkVerifier: proverAttestation.hardwareVerifier must carry a hardware or multi_root assurance label");
            if (pa.Measurements == null || pa.Measurements.Count == 0 || pa.Measurements.Any(string.IsNullOrEmpty)) throw new ArgumentException("createZkVerifier: proverAttestation.measurements must be a non-empty allowlist");
            if (pa.ExpectedBinding == null || pa.Evidence == null) throw new ArgumentException("createZkVerifier: proverAttestation.expectedBinding must be a function");
        }
        var label = backend != null ? AssuranceLabels.Of(backend) ?? new AssuranceLabel("unknown")
            : hw != null ? new AssuranceLabel("attested_vm_hw", "hardware-bound:" + (hw.Vendor ?? hw.Level))
            : new AssuranceLabel("attested_vm");
        // the lists are copied here: a later edit by the caller does not change what this verifier enforces
        var trusted = new HashSet<string>(opts.TrustedProverKeys ?? Enumerable.Empty<string>(), StringComparer.Ordinal);
        var revoked = new HashSet<string>(opts.RevokedProverKeys ?? Enumerable.Empty<string>(), StringComparer.Ordinal);
        var expectedPolicy = opts.PolicyCommitments == null ? null : new HashSet<string>(opts.PolicyCommitments, StringComparer.Ordinal);
        var measurements = pa == null ? null : new HashSet<string>(pa.Measurements, StringComparer.Ordinal);
        Func<double> clock = opts.Now ?? (() => (double)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        double skew = opts.ClockSkewMs is double sk && double.IsFinite(sk) ? Math.Max(0, sk) : 0;

        PcaCore.Hook hook = ctx =>
        {
            static PcaCore.HookResult Fail(string reason) => PcaCore.HookResult.Of(false, reason);
            try
            {
                var pcactn = ctx?.Pcactn;
                var proof = M(pcactn, "zk_compliance");
                if (proof == null || Jx.IsUndef(proof)) return Fail("no zk_compliance proof present");
                var actionCommit = ActionCommitment(pcactn);
                var planCommit = PlanCommit(pcactn);
                var wantPolicy = expectedPolicy ?? new HashSet<string>(StringComparer.Ordinal) { PolicyCommitment(ctx!.Grant) };

                if (backend != null)
                {
                    var policyCommit = expectedPolicy is { Count: 1 } ? expectedPolicy.First() : PolicyCommitment(ctx!.Grant);
                    return backend.Verify(proof, new ZkPublicInputs(actionCommit, policyCommit, planCommit), ctx)
                        ? PcaCore.HookResult.Of(true)
                        : Fail("snark backend rejected the proof");
                }

                if (proof is not D st || !Jx.IsNum(st.GetValueOrDefault("v")) || IntentJs.NumOf(st["v"]) != 1 || st.GetValueOrDefault("mode") is not "attested-vm")
                    return Fail("unrecognized compliance statement");
                if (st.GetValueOrDefault("released") is not true) return Fail("statement does not assert release");
                if (st.GetValueOrDefault("prover") is not string prover || !trusted.Contains(prover)) return Fail("prover key is not trusted");
                if (revoked.Contains(prover)) return Fail("prover key is revoked");

                var body = new D(st);
                body.Remove("sig");
                // a signature that is not text is refused before the body is serialized; a body with no canonical form is an error (denied below)
                if (st.GetValueOrDefault("sig") is not string sig || !VerifyB64u(prover, StatementMessage(body), sig))
                    return Fail("compliance statement signature does not verify");

                if (Jx.Fin(st.GetValueOrDefault("issued_at")) is not double issued || Jx.Fin(st.GetValueOrDefault("expires_at")) is not double expires || expires < issued)
                    return Fail("malformed statement validity window");
                var nowMs = clock();
                if (nowMs + skew < issued) return Fail("compliance statement not yet valid");
                if (nowMs - skew > expires) return Fail("compliance statement expired");

                if (st.GetValueOrDefault("action_commit") as string != actionCommit) return Fail("statement does not bind to this action");
                if (st.GetValueOrDefault("plan_commit") as string != planCommit) return Fail("statement does not bind to this plan commitment");
                if (st.GetValueOrDefault("policy_commit") is not string policy || !wantPolicy.Contains(policy)) return Fail("statement policy commitment is not an expected policy");

                // the hardware binding of the prover key, last: anything but a bound, measured, allowlisted identity denies
                if (pa != null)
                {
                    var expected = pa.ExpectedBinding(prover);
                    var res = pa.HardwareVerifier.Verify(pa.Evidence(prover), expected, (long)nowMs);
                    if (res == null || !res.Ok) return Fail("prover hardware evidence invalid: " + (res == null ? "no result" : res.Reason ?? "no reason given"));
                    if (!res.Bound) return Fail("prover hardware evidence does not bind the prover key");
                    if (res.Measured?.GetValueOrDefault("runtime_measurement") is not string measurement) return Fail("prover hardware evidence carries no measured identity");
                    if (!measurements!.Contains(measurement)) return Fail("prover VM measurement is not allowlisted");
                }
                return PcaCore.HookResult.Of(true);
            }
            catch (Exception e)
            {
                return Fail("zk verification error (fail closed): " + e.Message);
            }
        };
        return AssuranceLabels.Set(hook, label);
    }

    // ---- the binding tag ----

    /// <summary>A b64u commitment as an element of the BN254 scalar field, in decimal: the decoded bytes (of any length) as a big-endian integer, reduced
    /// modulo the field. This is the binding tag the compliance circuit exposes. Throws when the text is not strict base64url.</summary>
    public static string CommitmentField(string b64uCommit)
    {
        var bytes = Pca.B64uDecode(b64uCommit) ?? throw new ArgumentException("commitmentField: the commitment is not base64url");
        return (new BigInteger(bytes, isUnsigned: true, isBigEndian: true) % Bn254Fr).ToString(CultureInfo.InvariantCulture);
    }

    // ---- circuit files ----
    // The paths are the reference's, relative to its package root. The two Policy VM verification keys and the circuit versions are embedded in this
    // assembly; every other file (the compliance and risk-bound keys, witness programs, proving keys) is a circuit build product read from disk.

    public const string DefaultVkeyPath = "circuits/build/verification_key.json";
    public const string DefaultWasmPath = "circuits/build/compliance_js/compliance.wasm";
    public const string DefaultZkeyPath = "circuits/build/compliance_final.zkey";
    public const string PolicyVmVkeyPath = "circuits/policyvm_vkey.json";
    public const string PolicyVmSampleProofPath = "circuits/policyvm_sample_proof.json";
    public const string PolicyVmWasmPath = "circuits/build/policyvm_js/policyvm.wasm";
    public const string PolicyVmZkeyPath = "circuits/build/policyvm_final.zkey";
    public const string PolicyVmBls12381VkeyPath = "circuits/policyvm_bls12381_vkey.json";
    public const string PolicyVmBls12381SampleProofPath = "circuits/policyvm_bls12381_sample_proof.json";
    public const string PolicyVmBoundVkeyPath = "circuits/build/policyvm_bound_vkey.json";
    public const string PolicyVmBoundSampleProofPath = "circuits/build/policyvm_bound_sample_proof.json";
    public const string PolicyVmBoundWasmPath = "circuits/build/policyvm_bound_js/policyvm_bound.wasm";
    public const string PolicyVmBoundZkeyPath = "circuits/build/policyvm_bound_final.zkey";

    /// <summary>Where one of the path constants is read from: under <c>ATLAS_PCA_CIRCUITS_DIR</c> (the circuits directory), else <c>circuits</c> beside the application.</summary>
    public static string CircuitFile(string packagePath)
    {
        ArgumentNullException.ThrowIfNull(packagePath);
        var dir = Environment.GetEnvironmentVariable("ATLAS_PCA_CIRCUITS_DIR");
        if (string.IsNullOrEmpty(dir)) dir = Path.Combine(AppContext.BaseDirectory, "circuits");
        return Path.Combine(dir, packagePath.StartsWith("circuits/", StringComparison.Ordinal) ? packagePath["circuits/".Length..] : packagePath);
    }

    static D Embedded(string name)
    {
        using var s = typeof(ZkCompliance).Assembly.GetManifestResourceStream("AtlasPca.ZkCircuits." + name)
            ?? throw new InvalidOperationException("embedded circuit file missing: " + name);
        using var r = new StreamReader(s, Encoding.UTF8);
        return (D)Pca.ParseJson(r.ReadToEnd())!;
    }

    // never handed out, so never edited
    static readonly Lazy<D> PolicyVmKey = new(() => Embedded("policyvm_vkey.json"));
    static readonly Lazy<D> PolicyVmBls12381Key = new(() => Embedded("policyvm_bls12381_vkey.json"));
    static readonly Lazy<D> CircuitVersions = new(() => Embedded("circuit-versions.json"));

    static object? ReadJsonFile(string path) => Pca.ParseJson(File.ReadAllText(path, Encoding.UTF8));

    /// <summary>The key at <paramref name="path"/> when one is given, else the embedded key of the circuit, else the circuit's build product.</summary>
    static object? LoadKey(object? path, D? bundled, string defaultPath) => path switch
    {
        string p => ReadJsonFile(p),
        null => (object?)bundled ?? ReadJsonFile(CircuitFile(defaultPath)),
        _ => throw new ArgumentException("verificationKeyPath must be a string"),
    };

    /// <summary>An explicit key, else the one <see cref="LoadKey"/> finds on first use (kept).</summary>
    static Func<object?> LazyKey(D opts, D? bundled, string defaultPath)
    {
        object? cached = opts.GetValueOrDefault("verificationKey");
        return () => cached ??= LoadKey(opts.GetValueOrDefault("verificationKeyPath"), bundled, defaultPath);
    }

    /// <summary>The committed version of a circuit id (<c>pca-compliance-v1</c>, <c>pca-policyvm-v1</c>, <c>pca-policyvm-v2</c>): {circuit, sourceSha256, circom,
    /// circomlib}, where sourceSha256 covers the circuit's whole source set and the pinned compiler. Throws on an unknown id.</summary>
    public static D CircuitVersion(object? id)
    {
        var v = CircuitVersions.Value;
        if (id is not string s || v.GetValueOrDefault("circuits") is not D circuits || circuits.GetValueOrDefault(s) is not D c)
            throw new ArgumentException("circuitVersion: unknown circuit " + AtlasPca.Js.JsJson.Stringify(id));
        return new D { ["circuit"] = s, ["sourceSha256"] = c.GetValueOrDefault("source_sha256"), ["circom"] = v.GetValueOrDefault("circom"), ["circomlib"] = v.GetValueOrDefault("circomlib") };
    }

    // ---- proving ----

    static string WitnessText(object? v) => v switch
    {
        BigInteger b => b.ToString(CultureInfo.InvariantCulture),
        ulong or long or int or uint => Convert.ToString(v, CultureInfo.InvariantCulture)!,
        _ => JsX.Str(v),
    };

    static D Prove(D input, D? opts, string defaultWasm, string defaultZkey, string circuit)
    {
        var engine = _engine ?? throw new InvalidOperationException(NoEngine);
        var wasm = File.ReadAllBytes(opts?.GetValueOrDefault("wasmPath") as string ?? CircuitFile(defaultWasm));
        var zkey = File.ReadAllBytes(opts?.GetValueOrDefault("zkeyPath") as string ?? CircuitFile(defaultZkey));
        if (Pca.ParseJson(engine.Prove(CurveBn254, wasm, zkey, AtlasPca.Js.JsJson.Stringify(input))) is not D made)
            throw new InvalidOperationException("the Groth16 engine returned no proof");
        return new D { ["system"] = "groth16-bn254", ["circuit"] = circuit, ["proof"] = made.GetValueOrDefault("proof"), ["publicSignals"] = made.GetValueOrDefault("publicSignals") };
    }

    static D WitnessInput(D witness)
    {
        var input = new D();
        foreach (var (k, v) in witness) input[k] = WitnessText(v);
        return input;
    }

    /// <summary>A <c>pca-compliance-v1</c> proof from the private witness {action_commit, policy_commit, plan_commit, verb, resource, planVerb, policySalt,
    /// planSalt, actionSalt, risk, budget}. <paramref name="opts"/> = {wasmPath?, zkeyPath?}. Throws on a non-compliant witness (verb mismatch or risk above
    /// budget) and without an engine.</summary>
    public static D ProveGroth16Compliance(D inp, D? opts = null)
    {
        ArgumentNullException.ThrowIfNull(inp);
        var input = new D();
        foreach (var k in new[] { "verb", "resource", "planVerb", "policySalt", "planSalt", "actionSalt", "risk", "budget" }) input[k] = WitnessText(M(inp, k));
        input["shaPolicy"] = CommitmentField((inp.GetValueOrDefault("policy_commit") as string)!);
        input["shaPlan"] = CommitmentField((inp.GetValueOrDefault("plan_commit") as string)!);
        input["shaAction"] = CommitmentField((inp.GetValueOrDefault("action_commit") as string)!);
        input["allow"] = "1";
        return Prove(input, opts, DefaultWasmPath, DefaultZkeyPath, "pca-compliance-v1");
    }

    /// <summary>A <c>pca-policyvm-v1</c> proof from the complete fixed-point witness (every circuit input, by name). <paramref name="opts"/> = {wasmPath?,
    /// zkeyPath?}. Throws on a witness the Policy VM denies and without an engine.</summary>
    public static D ProvePolicyVmCompliance(D witness, D? opts = null)
    {
        ArgumentNullException.ThrowIfNull(witness);
        return Prove(WitnessInput(witness), opts, PolicyVmWasmPath, PolicyVmZkeyPath, "pca-policyvm-v1");
    }

    /// <summary>A risk-bound <c>pca-policyvm-v2</c> proof; the witness and options of <see cref="ProvePolicyVmCompliance"/>.</summary>
    public static D ProvePolicyVmBoundCompliance(D witness, D? opts = null)
    {
        ArgumentNullException.ThrowIfNull(witness);
        return Prove(WitnessInput(witness), opts, PolicyVmBoundWasmPath, PolicyVmBoundZkeyPath, "pca-policyvm-v2");
    }
}
