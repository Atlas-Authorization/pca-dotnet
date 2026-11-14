using System.Text;
using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The signers' own refusals (a malformed input this SDK refuses before signing, where the reference would throw a bare
/// runtime error or sign anyway), the producer dispatcher's argument refusals, the suite paths of the signers, the PQ key seed
/// replay and the request headers. Keys come from the producer-vector seeds and fixed byte seeds; no key generation loops.</summary>
public class SignerRefusalKillTests
{
    static JD Doc => Load("producer-vectors.json");
    static JD Keys => D(Doc["keys"]);
    static JD J(string json) => D(Pca.ParseJson(json));
    static EdKey Ed(string name) => EdKey.FromSeed(Pca.B64uDecode(D(Keys[name])["seed"], 32)!);
    static PqKey Ml65() => PqKey.FromSeed(Pq.Prim.MlDsa65, Enumerable.Repeat((byte)9, 32).ToArray());
    static SuiteKey Hybrid(string name) => SuiteKey.Create("hybrid-ed25519-ml-dsa-65", Ed(name), Ml65());
    static SuiteKey PurePq() => SuiteKey.Create("ml-dsa-65", null, Ml65());
    static JD Args(string caseName) => D(L(Doc["cases"]).Select(D).First(c => (string)c["name"]! == caseName)["args"]);

    static string Refusal(Func<object?> f) => Assert.Throws<ArgumentException>(() => f()).Message;
    static string Produce(string op, JD args, JD? pq = null) => Refusal(() => ProducerVectors.Produce(op, args, Keys, pq));

    // ---- the producer dispatcher's argument refusals ----------------------------------------------------------------------------

    [Fact]
    public void EachArgumentReaderRefusesTheWrongType()
    {
        Assert.Equal("produce: contract_id must be a string", Produce("sign_contract_reset", J("""{"signer":"agent","contract_id":5,"seq":1}""")));
        Assert.Equal("produce: alg must be a string", Produce("suite_sign", J("""{"alg":5,"ed":"agent","message_utf8":"m"}""")));
        Assert.Equal("produce: state must be an object", Produce("fresh_at", J("""{"signer":"agent","scope":"s","state":5,"issued_at":1}""")));
        Assert.Equal("produce: prev must be an object",
            Produce("sign_step_receipt", J("""{"signer":"agent","workflow":{},"step":"s","outcome":"o","params_digest":"p","outputs":{},"issued_at":1,"prev":5}""")));
        Assert.Equal("produce: added_caveats must be an array", Produce("delegate", J("""{"parent":{"holder":"h"},"signer":"agent","added_caveats":5}""")));
        Assert.Equal("produce: nodes must be an array of objects", Produce("plan_commit", J("""{"nodes":[5]}""")));
        Assert.Equal("produce: labels must be an array of strings",
            Produce("sign_read_receipt", J("""{"signer":"rs","grant":{},"verb":"v","resource":"r","purpose":"p","fields":{},"labels":[5],"issued_at":1}""")));
        Assert.Equal("produce: body must be an object", Produce("sign_caution", J("""{"signer":"agent"}""")));
        Assert.Equal("produce: seed must be 32 bytes", Produce("ed25519_sign", J("""{"message_utf8":"m"}""")));
        Assert.Equal("produce: prepared must be canonical base64url", Produce("sign_prepared_share", J("""{"role":"r","signer":"agent","prepared":"a"}""")));
        Assert.Equal("produce: unknown artifact kind 'x'", Produce("sign_artifact_suite", J("""{"kind":"x","signer":"agent"}""")));
        Assert.Equal("produce: no post-quantum key 'nope'",
            Produce("suite_sign", J("""{"alg":"hybrid-ed25519-ml-dsa-65","ed":"agent","pq":"nope","message_utf8":"m"}"""), new JD()));
    }

    [Fact]
    public void ARuntimeFaultInAVectorIsRefusedAsMalformed()
    {
        var m = Produce("delegate", J("""{"parent":{"holder":"h","caveats":5},"to_holder":"subagent","signer":"agent","added_caveats":[]}"""));
        Assert.StartsWith("produce: malformed delegate vector: ", m);
        Assert.True(m.Length > "produce: malformed delegate vector: ".Length, m);
    }

    // the permissions refusal comes before every later argument is read (no aud here, and no now for compile_policy)
    [Fact]
    public void MissingPermissionsAreRefusedFirst()
    {
        Assert.Equal("compilePolicy: permissions must be an object", Produce("compile_policy", new JD()));
        Assert.Equal("compilePolicy: permissions must be an object",
            Produce("facade_act", J("""{"principal":"principal","holder":"agent","goal":"g","goal_salt":"s","now":1}""")));
    }

    [Fact]
    public void TheRecorderClockIsCheckedAndItsLastTickRepeats()
    {
        const string head = "\"mediator\":\"agent-harness\",\"kid\":\"k1\",\"key\":\"mediator\",\"session\":\"mmTWpUWNQx1UhvNzV3FyhtPdAzuxvKk1DgD1tT1g-DA\"";
        Assert.Equal("produce: clock must not be empty", Produce("prov_recorder", J("{" + head + ",\"clock\":[],\"steps\":[]}")));
        Assert.Equal("produce: clock must hold integers",
            Produce("prov_recorder", J("{" + head + ",\"clock\":[\"x\"],\"steps\":[{\"kind\":\"principal\",\"text\":\"t\"}]}")));
        Assert.Equal("produce: no recorder steps", Produce("prov_recorder", J("{" + head + ",\"clock\":[5],\"steps\":[]}")));
        var r = D(ProducerVectors.Produce("prov_recorder",
            J("{" + head + ",\"clock\":[7],\"steps\":[{\"kind\":\"principal\",\"text\":\"a\"},{\"kind\":\"principal\",\"text\":\"b\"}]}"), Keys));
        Assert.Single(L(r["receipts"]));
        Assert.NotNull(r["bundle"]);
    }

    // a guardian without an Ed25519 identity cannot sign a revocation epoch
    [Fact]
    public void APurePqGuardianIsRefusedAnEpoch()
    {
        var pqDoc = Load("producer-pq-vectors.json");
        var body = D(L(pqDoc["cases"]).Select(D).First(c => (string)c["op"]! == "sign_artifact_suite" && D(c["args"])["kind"] as string == "revocation_epoch")["args"])["body"];
        var args = new JD { ["kind"] = "revocation_epoch", ["alg"] = "ml-dsa-65", ["signer"] = null, ["pq"] = "principal/ml-dsa-65", ["body"] = body };
        Assert.Equal("SignEpoch: the guardian needs an Ed25519 identity",
            Refusal(() => ProducerVectors.Produce("sign_artifact_suite", args, D(pqDoc["ed_keys"]), D(pqDoc["pq_keys"]))));
    }

    // ---- refusals this SDK makes where the reference throws a bare runtime error or signs a body its verifier refuses ------------

    [Fact]
    public void AHeartbeatNeedsEveryMember()
    {
        var a = Args("lease-heartbeat");
        D(a["body"]).Remove("cap_id");
        Assert.Equal("signHeartbeat: cap_id is required", Produce("sign_heartbeat", a));
    }

    [Fact]
    public void AReadReceiptNeedsAnIntegerPreviousSeq()
    {
        var a = Args("read-receipt-first");
        a["prev"] = J("""{"seq":"x"}""");
        Assert.Equal("signReadReceipt: malformed previous receipt", Produce("sign_read_receipt", a));
    }

    [Fact]
    public void AMeshActionNeedsAChain()
    {
        Assert.Equal("signMeshAction: empty chain", Produce("sign_mesh_action", J("""{"signer":"agent","chain":[],"action":{}}""")));
    }

    [Fact]
    public void AShareNeedsAWellFormedSignerSet()
    {
        var a = Args("threshold-share-guardian");
        a["signer_set"] = new JL { "x" };
        Assert.Equal("shareMessage: malformed signer set", Produce("sign_threshold_share", a));
    }

    // the signed schema must pass the verifier's shape check: a kid it refuses is refused before the document leaves the signer
    [Fact]
    public void ASchemaKidTheVerifierRefusesIsRefused()
    {
        foreach (var kid in new[] { "", new string('k', 129) })
        {
            var a = Args("action-schema");
            a["kid"] = kid;
            Assert.Equal("signActionSchema: sig.kid must be a non-empty string", Produce("sign_action_schema", a));
        }
        var ok = Args("action-schema");
        ok["kid"] = new string('k', 128);
        Assert.Equal(new string('k', 128), D(D(ProducerVectors.Produce("sign_action_schema", ok, Keys))["sig"])["kid"]);
    }

    [Fact]
    public void MeshEvidenceNeedsAHeadAndItsRevocationBracketing()
    {
        var chain = new List<JD> { J("""{"id":"c0"}""") };
        var action = J("""{"verb":"read"}""");
        string Bad(string hop) => Refusal(() => Signers.AssembleMeshProof(chain, new[] { J(hop) }, action, Ed("agent")));
        Assert.Equal("assembleMeshProof: hop evidence needs a cosigned head", Bad("""{"domain":"d","revocation":{"cap":{"size":1},"issuer_key":{"size":1}}}"""));
        Assert.Equal("assembleMeshProof: hop evidence needs its revocation bracketing", Bad("""{"domain":"d","head":{"head":1,"sig":"s","cosigs":[]}}"""));
        Assert.Equal("assembleMeshProof: malformed revocation evidence",
            Bad("""{"domain":"d","head":{"head":1,"sig":"s","cosigs":[]},"revocation":{"cap":5,"issuer_key":{"size":1}}}"""));
    }

    [Fact]
    public void AMeshHeadWithoutCosignaturesCarriesAnEmptyList()
    {
        var p = Signers.AssembleMeshProof(new List<JD> { J("""{"id":"c0"}""") },
            new[] { J("""{"domain":"d","head":{"head":1,"sig":"s"},"inclusion":{},"revocation":{"cap":{"size":1},"issuer_key":{"size":1}}}""") }, J("{}"), Ed("agent"));
        Assert.Equal("""[{"cosigs":[],"head":1,"sig":"s"}]""", Pca.Canonicalize(p["heads"]));
    }

    [Fact]
    public void ACoordinatesValueThatIsNotAnObjectIsRefused()
    {
        Assert.Equal("not an object", Signers.IntentRequiredShapeError("x"));
        Assert.Equal("coords must be an object of 1..64 dimensions", Signers.CellCoordsError(new JD()));
        Assert.Equal("coords must be an object of 1..64 dimensions", Signers.CellCoordsError(new JL()));
    }

    // ---- threshold shares under a suite ----------------------------------------------------------------------------------------

    static JL Set => J("""{"s":[{"publicKey":"ru3oBFp5YsBfzclgdHTDSKKycXeABcfHPA2UibxZLyA","role":"guardian"}]}""")["s"] as JL ?? new JL();

    [Fact]
    public void OnlyARegisteredNonEd25519SuiteTagsAShare()
    {
        var m = Encoding.UTF8.GetBytes("m");
        var plain = Signers.ShareMessage("guardian", m, Set, 2);
        Assert.Equal(plain, Signers.ShareMessage("guardian", m, Set, 2, "ed25519"));
        Assert.Equal(plain, Signers.ShareMessage("guardian", m, Set, 2, "rot13"));
        foreach (var alg in new[] { "ml-dsa-65", "fn-dsa-512" })
            Assert.Equal(plain.Concat(Encoding.UTF8.GetBytes("\0atlas-pca/share-suite/v1\0" + alg)).ToArray(), Signers.ShareMessage("guardian", m, Set, 2, alg));
        Assert.Equal(2, plain[^1]);
        Assert.Equal("shareMessage: t must be 1, 2 or 3", Refusal(() => Signers.ShareMessage("guardian", m, Set, 0)));
    }

    [Fact]
    public void AHybridShareCarriesItsAlgAndPqSignature()
    {
        var prepared = Encoding.UTF8.GetBytes("prepared share");
        var s = Signers.SignPreparedShare("guardian", Hybrid("guardian"), prepared);
        Assert.Equal(new[] { "alg", "pq_sig", "publicKey", "role", "sig" }, s.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal("hybrid-ed25519-ml-dsa-65", s["alg"]);
        Assert.Equal(Ed("guardian").Id, s["publicKey"]);
        Assert.Equal(Pca.B64u(Ed("guardian").Sign(prepared)), s["sig"]);
        Assert.False(string.IsNullOrEmpty(s["pq_sig"] as string));
        // a pure ML-DSA share names the identity, signs with the PQ key and carries no pq_sig
        var pure = Signers.SignPreparedShare("guardian", SuiteKey.Create("ml-dsa-65", Ed("guardian"), Ml65()), prepared);
        Assert.Equal(new[] { "alg", "publicKey", "role", "sig" }, pure.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal("ml-dsa-65", pure["alg"]);
        // an ed25519 share carries neither
        Assert.Equal(new[] { "publicKey", "role", "sig" }, Signers.SignPreparedShare("guardian", SuiteKey.Ed25519(Ed("guardian")), prepared).Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal("signPreparedShare: a share needs the role's Ed25519 identity", Refusal(() => Signers.SignPreparedShare("guardian", PurePq(), prepared)));
    }

    // ---- session root, action schema and key entry under a suite -----------------------------------------------------------------

    static JD RootBody => D(Args("session-root")["body"]);

    [Fact]
    public void AHybridSessionRootBindsItsSuite()
    {
        var r = Signers.SignSessionRoot(RootBody, Hybrid("principal"));
        Assert.Equal("hybrid-ed25519-ml-dsa-65", r["alg"]);
        Assert.Equal(Ml65().PkB64u, r["pq_pk"]);
        Assert.False(string.IsNullOrEmpty(r["pq_sig"] as string));
        Assert.Null(IntentSession.RootShapeError(r));
        Assert.Equal("signSessionRoot: the signer needs an Ed25519 identity", Refusal(() => Signers.SignSessionRoot(RootBody, PurePq())));
    }

    // the signer's suite is part of the shape check before signing: a suite the registry no longer offers is refused
    [Fact]
    public void ASessionRootUnderASuiteTheRegistryDropsIsRefused()
    {
        var key = Hybrid("principal");
        Pq.SuitesHook = s => s.Remove("hybrid-ed25519-ml-dsa-65");
        try
        {
            Assert.Equal("signSessionRoot: alg: unsupported_suite: 'hybrid-ed25519-ml-dsa-65'", Refusal(() => Signers.SignSessionRoot(RootBody, key)));
        }
        finally { Pq.SuitesHook = null; }
    }

    [Fact]
    public void AHybridSchemaCarriesItsPqValueAndKeyEntry()
    {
        var doc = D(Args("action-schema")["doc"]);
        var sig = D(Signers.SignActionSchema(doc, "site-k1", Hybrid("site"))["sig"]);
        Assert.Equal(new[] { "alg", "kid", "pq_value", "value" }, sig.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal("hybrid-ed25519-ml-dsa-65", sig["alg"]);
        Assert.False(string.IsNullOrEmpty(sig["pq_value"] as string));
        var k = Signers.ActionSchemaKeyOf("site-k1", Hybrid("site"));
        Assert.Equal(Pca.Canonicalize(new JD { ["kid"] = "site-k1", ["alg"] = "hybrid-ed25519-ml-dsa-65", ["pk"] = Ed("site").Id, ["pq_pk"] = Ml65().PkB64u }), Pca.Canonicalize(k));
        Assert.Equal("a site key needs an Ed25519 identity", Refusal(() => Signers.ActionSchemaKeyOf("site-k1", PurePq())));
    }

    // ---- PCActn signing and request headers ------------------------------------------------------------------------------------

    [Fact]
    public void AnEd25519PCActnDropsStaleSuiteFieldsAndKeepsEveryOtherMember()
    {
        var body = J("""{"x":1,"":2,"pq_sig":"old","alg":"ml-dsa-65","pq_pk":"old","sig":"old"}""");
        var key = SuiteKey.Ed25519(Ed("agent"));
        var p = Issue.SignPCActn(body, key);
        Assert.Equal(new[] { "", "sig", "x" }, p.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal(Pca.B64u(Ed("agent").Sign(Pca.ThresholdMessage(J("""{"x":1,"":2}""")))), p["sig"]);
    }

    [Fact]
    public void HeadersCarryOnlyTheArtifactsGiven()
    {
        var p = J("""{"a":1}""");
        static string Enc(object? v) => Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(v)));
        Assert.Equal(new[] { "PCA-Action" }, Issue.Headers(p).Keys);
        Assert.Equal(new[] { "PCA-Action" }, Issue.Headers(p, new List<JD>()).Keys);
        var d = J("""{"d":1}""");
        var n = J("""{"n":1}""");
        var e = J("""{"e":1}""");
        var h = Issue.Headers(p, new[] { d }, n, e);
        Assert.Equal(Issue.Header(p), h["PCA-Action"]);
        Assert.Equal(Enc(new JL { d }), h["PCA-Discharges"]);
        Assert.Equal(Enc(n), h["PCA-Narrow"]);
        Assert.Equal(Enc(e), h["PCA-Escalation-Answer"]);
        Assert.Equal(4, h.Count);
    }

    // canonical {"p":"x..."} is 8 + n bytes; 6144 bytes encode to exactly 8192 characters, 6145 to 8194
    [Fact]
    public void AProvenanceHeaderOfExactly8192CharactersIsSent()
    {
        var p = J("""{"a":1}""");
        var at = new JD { ["p"] = new string('x', 6136) };
        var h = Issue.Headers(p, provenance: at);
        Assert.Equal(Issue.ProvenanceHeaderMax, h["PCA-Provenance"].Length);
        Assert.False(Issue.Headers(p, provenance: new JD { ["p"] = new string('x', 6137) }).ContainsKey("PCA-Provenance"));
    }

    // ---- PQ key seeds ---------------------------------------------------------------------------------------------------------

    [Fact]
    public void ASeedForAPrimitiveThisSdkCannotSignIsRefused()
    {
        foreach (var p in new[] { Pq.Prim.None, Pq.Prim.Less })
            Assert.Equal($"cannot sign with {p} in this SDK", Assert.Throws<ArgumentException>(() => PqKey.FromSeed(p, new byte[32])).Message);
        Assert.Equal("a MlDsa65 seed is 32 bytes", Assert.Throws<ArgumentException>(() => PqKey.FromSeed(Pq.Prim.MlDsa65, new byte[31])).Message);
    }

    [Fact]
    public void TheSeedReplayHandsOutTheSeedOnceAndRefusesMore()
    {
        var r = new PqKey.SeedReplay(new byte[] { 1, 2, 3, 4 });
        var a = new byte[3];
        r.NextBytes(a);
        Assert.Equal(new byte[] { 1, 2, 3 }, a);
        var over = Assert.Throws<InvalidOperationException>(() => r.NextBytes(new byte[2]));
        Assert.Equal("PqKey.FromSeed: the key generator asked for more than the seed", over.Message);
        var last = new byte[1];
        r.NextBytes(last);
        Assert.Equal(new byte[] { 4 }, last);
    }
}
