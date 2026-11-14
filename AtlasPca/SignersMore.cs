// More producers, byte for byte the TypeScript reference's: threshold shares, PQ key bindings, caution claims, lease heartbeats,
// progress steps, read receipts, mesh actions and proofs, intent session roots and session grants, action schemas, intent-required
// bodies, label receipts, facts and offer sets. Each runs the reference's checks before signing and throws on a malformed input
// (a signer never emits an artifact a verifier would refuse). A suite this SDK cannot sign is refused with unsupported_suite.
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class Signers
{
    const string ShareDomainPrefix = "atlas-pca/share/";
    const string ShareSuiteTag = "\0atlas-pca/share-suite/v1\0";
    public const string PqBindingDomain = "atlas-pca/pq-binding/v2\0";
    public const string CautionDomain = "atlas-pca/caution/v1";
    public const string HeartbeatDomain = "atlas-pca/lease-hb/v2";
    public const string ProgressSigDomain = "atlas-pca/progress-step/v2";
    public const string MeshActionDomain = "atlas-pca/mesh-action/v1\0";
    public const string IntentRequiredDomain = "atlas-pca/intent-required/v1\0";
    public const int MaxCautionReasonLength = 64;

    static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
    static byte[] MsgOf(string domain, object? body) => Pca.Canon(new JD { ["d"] = domain, ["b"] = body });
    static bool NonEmpty(object? v) => v is string { Length: > 0 };

    // ---- threshold shares ---------------------------------------------------------------------------------------------------

    /// <summary>The bytes a role's threshold share signs: <c>"atlas-pca/share/&lt;role&gt;\0" || sha256(message) || signerSetHash(signerSet) || t</c>,
    /// plus the suite tag for a non-ed25519 suite. <paramref name="t"/> is 1, 2 or 3.</summary>
    public static byte[] ShareMessage(string role, byte[] message, JL signerSet, int t, string alg = "ed25519")
    {
        if (t is < 1 or > 3) throw new ArgumentException("shareMessage: t must be 1, 2 or 3");
        var ssh = Pca.B64uDecode(Pca.SignerSetHashB64u(Issue.NormL(signerSet))) ?? throw new ArgumentException("shareMessage: malformed signer set");
        // the reference tags only a registered non-ed25519 suite: an unknown name resolves to null and adds no tag
        var tag = alg == "ed25519" || !Pq.RegisteredSuites.Contains(alg) ? Array.Empty<byte>() : Utf8(ShareSuiteTag + alg);
        return Pca.Cat(Utf8(ShareDomainPrefix + role + "\0"), Pca.Sha(message), ssh, new[] { (byte)t }, tag);
    }

    /// <summary>A role's explicit threshold share over <paramref name="message"/> (a PCActn's threshold message), bound to the signer set and
    /// <paramref name="t"/> it is for, so it cannot be replayed into another set or threshold. Under a PQ suite the role's PQ key must be
    /// the <c>pq_pk</c> the signer set registers for the role.</summary>
    public static JD SignThresholdShare(string role, SuiteKey key, byte[] message, JL signerSet, int t) =>
        SignPreparedShare(role, key, ShareMessage(role, message, signerSet, t, key.Alg));

    /// <summary>Sign share bytes computed elsewhere (the <c>share_message</c> a step-up hands a principal device): <c>{role, publicKey, sig}</c>,
    /// plus <c>alg</c> (and <c>pq_sig</c> for a hybrid) under a PQ suite.</summary>
    public static JD SignPreparedShare(string role, SuiteKey key, byte[] prepared)
    {
        if (key.Ed == null) throw new ArgumentException("signPreparedShare: a share needs the role's Ed25519 identity");
        var (sig, pqSig) = key.Sign(prepared);
        var share = new JD { ["role"] = role, ["publicKey"] = key.Ed.Id, ["sig"] = sig };
        if (key.Alg != "ed25519")
        {
            share["alg"] = key.Alg;
            if (pqSig != null) share["pq_sig"] = pqSig;
        }
        return share;
    }

    // ---- PQ key binding -------------------------------------------------------------------------------------------------------

    /// <summary>An identity's signed statement that <paramref name="pqPk"/> is its PQ key as of <paramref name="epoch"/> (a positive integer
    /// raised on every rotation) for the audience <paramref name="aud"/>: <c>{ed, pq, epoch, aud, sig}</c>.</summary>
    public static JD SignPqBinding(EdKey ed, string pqPk, long epoch, string aud)
    {
        if (epoch < 1 || epoch > Pca.MaxSafeInt) throw new ArgumentException("signPqBinding: epoch must be a positive safe integer");
        if (string.IsNullOrEmpty(aud)) throw new ArgumentException("signPqBinding: aud (the instance/audience id) is required");
        var msg = Pca.Cat(Utf8(PqBindingDomain), Utf8($"{ed.Id}\0{pqPk}\0{epoch.ToString(CultureInfo.InvariantCulture)}\0{aud}"));
        return new JD { ["ed"] = ed.Id, ["pq"] = pqPk, ["epoch"] = epoch, ["aud"] = aud, ["sig"] = Pca.B64u(ed.Sign(msg)) };
    }

    // ---- caution claim, lease heartbeat, progress step ------------------------------------------------------------------------

    static Regex ReasonRe => Rx.Get(@"\A[A-Za-z0-9_.:-]+\z", RegexOptions.CultureInvariant);

    static string? CautionBodyError(JD b)
    {
        if (!NonEmpty(b.GetValueOrDefault("action_digest"))) return "action_digest required";
        if (!NonEmpty(b.GetValueOrDefault("holder"))) return "holder required";
        if (IntentJs.NumOf(b.GetValueOrDefault("caution")) is not double c || !double.IsFinite(c) || c < 0 || c > 1) return "caution must be a finite number in [0,1]";
        if (b.ContainsKey("reason") && !(b["reason"] is string r && r.Length <= MaxCautionReasonLength && ReasonRe.IsMatch(r))) return "invalid reason";
        return null;
    }

    /// <summary>A holder's signed caution claim <c>{action_digest, caution in [0,1], reason?, holder}</c>: bound to one action, it can only
    /// raise the server's risk. Other members of <paramref name="body"/> are dropped.</summary>
    public static JD SignCaution(JD body, EdKey holder)
    {
        var b = Issue.NormJ(body);
        if (CautionBodyError(b) is { } e) throw new ArgumentException("signCaution: " + e);
        var clean = new JD { ["action_digest"] = b["action_digest"], ["caution"] = b["caution"], ["holder"] = b["holder"] };
        if (b.ContainsKey("reason")) clean["reason"] = b["reason"];
        var sig = Pca.B64u(holder.Sign(MsgOf(CautionDomain, clean)));
        clean["sig"] = sig;
        return clean;
    }

    /// <summary>A lease holder's signed heartbeat <c>{cap_id, seq, at, holder, lease_issued_at}</c> (other members dropped).</summary>
    public static JD SignHeartbeat(JD body, EdKey holder)
    {
        var b = Issue.NormJ(body);
        var clean = new JD();
        foreach (var k in new[] { "cap_id", "seq", "at", "holder", "lease_issued_at" })
            clean[k] = b.TryGetValue(k, out var v) ? v : throw new ArgumentException($"signHeartbeat: {k} is required");
        clean["sig"] = Pca.B64u(holder.Sign(MsgOf(HeartbeatDomain, new JD(clean))));
        return clean;
    }

    /// <summary>The holder's signed progress step <c>{step, holder, sig}</c>: the signature binds the step to the holder, goal, action,
    /// before / after state, sequence, chain link and step digest.</summary>
    public static JD SignProgressStep(JD step, EdKey holder)
    {
        var s = Issue.NormJ(step);
        object? M(string k) => s.TryGetValue(k, out var v) ? v : throw new ArgumentException($"signProgressStep: step.{k} is required");
        var b = new JD
        {
            ["holder"] = holder.Id, ["goal_commitment"] = M("goal_commitment"), ["action_digest"] = M("action_digest"), ["before_digest"] = M("before_digest"),
            ["after_digest"] = M("after_digest"), ["seq"] = M("seq"), ["prev"] = M("prev"), ["step_digest"] = M("digest"),
        };
        return new JD { ["step"] = s, ["holder"] = holder.Id, ["sig"] = Pca.B64u(holder.Sign(MsgOf(ProgressSigDomain, b))) };
    }

    // ---- read receipt ---------------------------------------------------------------------------------------------------------

    /// <summary>The resource server's receipt of one redacted read under <paramref name="grant"/> (the read grant BODY): <paramref name="fields"/>
    /// and <paramref name="labels"/> are what <see cref="ReadSide.RedactRead"/> reported; <paramref name="prev"/> is the previous receipt of the
    /// chain (null: the first, seq 0).</summary>
    public static JD SignReadReceipt(EdKey rs, JD grant, string verb, string resource, string purpose, JD fields, IEnumerable<string> labels, long issuedAt, JD? prev)
    {
        object? seq = 0L, reference = null;
        if (prev != null)
        {
            var p = Issue.NormJ(prev);
            if (!IntentJs.IsSafeInteger(p.GetValueOrDefault("seq"))) throw new ArgumentException("signReadReceipt: malformed previous receipt");
            seq = IntentJs.Lng(p["seq"]) + 1;
            reference = ReadSide.ReadReceiptRef(p);
        }
        var b = Issue.NormJ(new JD
        {
            ["v"] = 1L, ["grant"] = ReadSide.ReadGrantDigest(Issue.NormJ(grant)), ["verb"] = verb, ["resource"] = resource, ["purpose"] = purpose, ["seq"] = seq,
            ["prev"] = reference, ["fields"] = fields, ["labels"] = labels.Select(l => (object?)l).ToList(), ["issued_at"] = issuedAt, ["signer"] = rs.Id,
        });
        b["sig"] = Issue.SignBody(rs, ReadSide.ReceiptDomain, b);
        return b;
    }

    // ---- mesh -------------------------------------------------------------------------------------------------------------------

    /// <summary>The leaf holder's signature over the action bound to the chain tip:
    /// Ed25519 over <c>"atlas-pca/mesh-action/v1\0" || canonical({action, tip: capHash(tip)})</c>.</summary>
    public static string SignMeshAction(IReadOnlyList<JD> chain, JD action, EdKey leaf)
    {
        if (chain.Count == 0) throw new ArgumentException("signMeshAction: empty chain");
        var tip = Pca.CapHash(Issue.NormJ(chain[^1]));
        return Pca.B64u(leaf.Sign(IntentJs.Message(MeshActionDomain, new JD { ["action"] = Issue.NormJ(action), ["tip"] = tip })));
    }

    /// <summary>The compact mesh proof: hops issued against the same head share one <c>heads</c> entry (their witness cosignatures merged),
    /// identical revocation bracketing leaves are carried once, and the leaf signs the action. <paramref name="hops"/> are the per-hop
    /// evidence <c>{domain, head: {head, sig, cosigs}, inclusion, revocation: {cap, issuer_key}, binding?}</c>.
    /// shortcut: entries are deduplicated by canonical JSON where the reference compares JSON.stringify text, so inputs that differ only
    /// in member order merge here and not there; evidence from one mesh domain never does.</summary>
    public static JD AssembleMeshProof(IReadOnlyList<JD> chain, IEnumerable<JD> hops, JD action, EdKey leaf, JL? pinProofs = null)
    {
        var heads = new JL();
        var headIdx = new Dictionary<string, int>();
        var leaves = new JL();
        var leafIdx = new Dictionary<string, int>();
        long LeafOf(object? l)
        {
            var k = Pca.Canonicalize(l);
            if (!leafIdx.TryGetValue(k, out var i)) { i = leaves.Count; leaves.Add(l); leafIdx[k] = i; }
            return i;
        }
        JD Compact(object? nv)
        {
            var n = nv as JD ?? throw new ArgumentException("assembleMeshProof: malformed revocation evidence");
            var o = new JD { ["size"] = n.GetValueOrDefault("size") };
            // a falsy side (null, false, 0, "") is left out, as the reference's `...(n.lo ? {lo} : {})` does
            foreach (var side in new[] { "lo", "hi" }) if (IntentRevocation.Truthy(n.GetValueOrDefault(side))) o[side] = LeafOf(n[side]);
            return o;
        }
        var outHops = new JL();
        foreach (var raw in hops)
        {
            var ev = Issue.NormJ(raw);
            if (ev.GetValueOrDefault("head") is not JD h) throw new ArgumentException("assembleMeshProof: hop evidence needs a cosigned head");
            var cosigs = h.GetValueOrDefault("cosigs") as JL ?? new JL();
            var key = h.GetValueOrDefault("sig") + "|" + Pca.Canonicalize(h.GetValueOrDefault("head"));
            if (!headIdx.TryGetValue(key, out var i))
            {
                i = heads.Count;
                heads.Add(new JD { ["head"] = h.GetValueOrDefault("head"), ["sig"] = h.GetValueOrDefault("sig"), ["cosigs"] = new JL(cosigs) });
                headIdx[key] = i;
            }
            else
            {
                var have = (JL)((JD)heads[i]!)["cosigs"]!;
                var seen = have.Select(c => (c as JD)?.GetValueOrDefault("witness")).ToList();
                foreach (var c in cosigs) if (c is JD cm && !seen.Contains(cm.GetValueOrDefault("witness"))) have.Add(c);
            }
            var rev = ev.GetValueOrDefault("revocation") as JD ?? throw new ArgumentException("assembleMeshProof: hop evidence needs its revocation bracketing");
            var o = new JD
            {
                ["domain"] = ev.GetValueOrDefault("domain"), ["head"] = (long)i, ["inclusion"] = ev.GetValueOrDefault("inclusion"),
                ["revocation"] = new JD { ["cap"] = Compact(rev.GetValueOrDefault("cap")), ["issuer_key"] = Compact(rev.GetValueOrDefault("issuer_key")) },
            };
            if (IntentRevocation.Truthy(ev.GetValueOrDefault("binding"))) o["binding"] = ev["binding"];
            outHops.Add(o);
        }
        var proof = new JD
        {
            ["chain"] = chain.Select(c => (object?)c).ToList(), ["heads"] = heads, ["rev_leaves"] = leaves, ["hops"] = outHops, ["action"] = action,
            ["action_sig"] = SignMeshAction(chain, action, leaf),
        };
        if (pinProofs is { Count: > 0 }) proof["pin_proofs"] = pinProofs;
        return Issue.NormJ(proof);
    }

    // ---- intent session root and session grants ----------------------------------------------------------------------------------

    static string[] SessionRootUnsignedKeys => new[]
        { "v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors", "question_uri", "revocation", "flows", "expires_at" };

    /// <summary>Sign the session root S as one of its principals (the signer's Ed25519 identity must be listed in <c>principals</c>). A
    /// non-ed25519 suite binds <c>alg</c> and <c>pq_pk</c> into the signed body.</summary>
    public static JD SignSessionRoot(JD body, SuiteKey principal)
    {
        if (principal.Ed == null) throw new ArgumentException("signSessionRoot: the signer needs an Ed25519 identity");
        var b = Issue.NormJ(body);
        foreach (var k in b.Keys) if (!SessionRootUnsignedKeys.Contains(k)) throw new ArgumentException($"signSessionRoot: session root: unknown member '{k}'");
        var base_ = new JD();
        foreach (var k in SessionRootUnsignedKeys) if (b.TryGetValue(k, out var v)) base_[k] = v;
        base_["signer"] = principal.Ed.Id;
        var probe = new JD(base_);
        if (principal.Alg != "ed25519") { probe["alg"] = principal.Alg; probe["pq_pk"] = principal.PqPk; }
        probe["sig"] = "";
        var bad = IntentSession.RootShapeError(probe);
        if (bad == "signer is not one of the session principals") throw new ArgumentException("signSessionRoot: the signer is not one of the session principals");
        if (bad != null) throw new ArgumentException("signSessionRoot: " + bad);
        return Issue.SignArtifact(IntentSession.IntentSessionSigDomain, base_, principal);
    }

    /// <summary>Mint a session grant: G_0 (<paramref name="seq"/> 0) or a delta grant D_k, a principal-signed root capability whose caveats are
    /// the envelope (goal <c>pca-intent:v2:&lt;session&gt;:&lt;map_digest&gt;</c>, or <c>v2c</c> over a committed map when
    /// <paramref name="mapForm"/> is <c>"commit"</c>) and the <c>intent_session</c> caveat. <paramref name="prev"/> is required exactly when
    /// seq &gt; 0. The result's goal salt goes in the PCActn's <c>intent.goal_salt</c>.</summary>
    public static MintedGrant MintSessionGrant(SuiteKey principal, string holder, string session, long seq, string root, string mapDigest, JL predicates,
        string? prev = null, string? mapForm = null, JL? caveats = null, JD? agentBinding = null, JD? riskPolicy = null, string? salt = null, string? holderPqPk = null)
    {
        var sc = new JD { ["type"] = IntentSession.IntentSessionCaveat, ["session"] = session, ["seq"] = seq, ["root"] = root };
        if (prev != null) sc["prev"] = prev;
        var scn = Issue.NormJ(sc);
        if (IntentSession.CaveatError(scn) is { } bad) throw new ArgumentException("mintSessionGrant: " + bad);
        if (!IntentJs.B32(mapDigest)) throw new ArgumentException("mintSessionGrant: mapDigest must be canonical base64url (32 bytes)");
        var s = salt ?? Issue.RandomB64u(16);
        var goal = mapForm == "commit" ? IntentSession.IntentGoalV2c(session, mapDigest) : IntentSession.IntentGoalV2(session, mapDigest);
        var commit = Issue.GoalCommit(goal, s);
        var env = Issue.NormJ(new JD
        {
            ["type"] = Issue.EnvelopeCaveat, ["goal_commit"] = commit, ["predicates"] = predicates, ["caveats"] = caveats ?? new JL(),
            ["agent_binding"] = agentBinding ?? new JD(), ["risk_policy"] = riskPolicy ?? Issue.DefaultRiskPolicy(),
        });
        return new MintedGrant(Issue.MintRoot(principal, holder, holderPqPk, new JL { env, scn }), commit, s);
    }

    // ---- site and oracle artifacts ---------------------------------------------------------------------------------------------------

    static JD SiteSig(SuiteKey site, string kid, byte[] msg)
    {
        var (sig, pqSig) = site.Sign(msg);
        var s = new JD { ["alg"] = site.Alg, ["kid"] = kid, ["value"] = sig };
        if (pqSig != null) s["pq_value"] = pqSig;
        return s;
    }

    /// <summary>Sign an action schema as the site: <paramref name="kid"/> names the discovery key entry. The signature covers
    /// <c>"atlas-pca/action-schema/v1\0" || canonical(doc)</c> and lands in <c>sig: {alg, kid, value, pq_value?}</c>.</summary>
    public static JD SignActionSchema(JD doc, string kid, SuiteKey site)
    {
        var d = Issue.NormJ(doc);
        if (ActionSchema.ShapeError(d, signed: false) is { } bad) throw new ArgumentException("signActionSchema: " + bad);
        var outp = new JD(d) { ["sig"] = SiteSig(site, kid, IntentJs.Message(ActionSchema.ActionSchemaDomain, d)) };
        // the signed document must pass the verifier's shape check too (a kid it would refuse is refused here)
        if (ActionSchema.ShapeError(outp) is { } after) throw new ArgumentException("signActionSchema: " + after);
        return outp;
    }

    /// <summary>The discovery key entry <c>{kid, alg, pk, pq_pk?}</c> a verifier pins for a site signer.</summary>
    public static JD ActionSchemaKeyOf(string kid, SuiteKey site)
    {
        var k = new JD { ["kid"] = kid, ["alg"] = site.Alg, ["pk"] = site.Ed?.Id ?? throw new ArgumentException("a site key needs an Ed25519 identity") };
        if (site.PqPk != null) k["pq_pk"] = site.PqPk;
        return k;
    }

    static string[] IntentRequiredKeys => new[]
        { "v", "kind", "session", "map_digest", "schema", "pcactn_digest", "action_digest", "cell", "reason", "question_id", "friction", "delivered_to", "expires_at", "sig" };
    static Regex QuestionIdRe => Rx.Get(@"\A[A-Za-z0-9_-]{1,64}\z", RegexOptions.CultureInvariant);

    /// <summary>The coordinates of a map cell: 1..64 dimensions, each an index range <c>[lo, hi]</c> (0 &lt;= lo &lt;= hi) or a set of 1..256
    /// distinct strings. Null when well formed.</summary>
    public static string? CellCoordsError(object? c)
    {
        if (c is not JD m || m.Count == 0 || m.Count > 64) return "coords must be an object of 1..64 dimensions";
        foreach (var (k, v) in m)
        {
            if (k.Length == 0 || k.Length > 256) return "a coordinate path must be 1..256 characters";
            if (v is JL r && r.Count == 2 && r.All(IntentJs.IsInt))
            {
                if (!(IntentJs.NumOf(r[0]) >= 0 && IntentJs.NumOf(r[0]) <= IntentJs.NumOf(r[1]))) return $"coords '{k}': need 0 <= lo <= hi";
            }
            else if (v is JL set && set.Count >= 1 && set.Count <= 256 && set.All(x => x is string))
            {
                if (set.Cast<string>().Distinct(StringComparer.Ordinal).Count() != set.Count) return $"coords '{k}': values must be distinct";
            }
            else return $"coords '{k}': an index range [lo, hi] or a value set";
        }
        return null;
    }

    /// <summary>The shape check of an UNSIGNED <c>pca-intent-required</c> v1 body (what the signer checks first). Null when well formed.</summary>
    public static string? IntentRequiredShapeError(object? bo)
    {
        if (bo is not JD b) return "not an object";
        foreach (var k in b.Keys) if (!IntentRequiredKeys.Contains(k)) return $"unknown member '{k}'";
        if (!OracleFacts.IsOne(b.GetValueOrDefault("v")) || b.GetValueOrDefault("kind") is not "pca-intent-required") return "not a pca-intent-required v1";
        foreach (var k in new[] { "session", "map_digest", "schema", "pcactn_digest", "action_digest" })
            if (!IntentJs.B32(b.GetValueOrDefault(k))) return $"{k} must be canonical base64url (32 bytes)";
        if (b.GetValueOrDefault("cell") is not JD cell || cell.Count != 2 || !cell.ContainsKey("coords") || cell.GetValueOrDefault("verb") is not string { Length: > 0 })
            return "cell must be {verb, coords}";
        if (CellCoordsError(cell["coords"]) is { } ce) return ce;
        if (b.GetValueOrDefault("reason") is not "uncertain") return "reason must be 'uncertain'";
        if (b.GetValueOrDefault("question_id") is not string q || !QuestionIdRe.IsMatch(q)) return "question_id must match [A-Za-z0-9_-]{1,64}";
        if (b.GetValueOrDefault("friction") is not ("tap" or "hold" or "typed" or "device")) return "unknown friction tier";
        if (b.GetValueOrDefault("delivered_to") is not ("wallet" or "agent")) return "delivered_to must be 'wallet' or 'agent'";
        if (!IntentJs.IsNonNeg(b.GetValueOrDefault("expires_at"))) return "expires_at must be a non-negative safe integer";
        if (b.ContainsKey("sig")) return "an unsigned body must not carry sig";
        return null;
    }

    /// <summary>The site's signed <c>pca-intent-required</c> v1 body: <c>sig = {alg, kid, value, pq_value?}</c> over
    /// <c>"atlas-pca/intent-required/v1\0" || canonical(body)</c>, pinned by the same discovery key entry as the action schema.</summary>
    public static JD SignIntentRequired(JD body, string kid, SuiteKey site)
    {
        var b = Issue.NormJ(body);
        if (IntentRequiredShapeError(b) is { } bad) throw new ArgumentException("signIntentRequired: " + bad);
        return new JD(b) { ["sig"] = SiteSig(site, kid, IntentJs.Message(IntentRequiredDomain, b)) };
    }

    static JD Kinded(string kind, JD body)
    {
        var full = new JD { ["v"] = 1L, ["kind"] = kind };
        foreach (var (k, v) in body) full[k] = v; // body members win, as in the reference's spread
        return full;
    }

    /// <summary>A site's signed label receipt: <c>{v: 1, kind: "pca-labels", ...body}</c> under the signer's suite.</summary>
    public static JD SignLabels(JD body, SuiteKey key) => Issue.SignArtifact(ParamProvenance.LabelsDomain, Kinded("pca-labels", body), key);

    /// <summary>An oracle's signed fact: <c>{v: 1, kind: "pca-fact", ...body}</c> under the signer's suite.</summary>
    public static JD SignFact(JD body, SuiteKey key) => Issue.SignArtifact(OracleFacts.FactDomain, Kinded("pca-fact", body), key);

    /// <summary>A site's signed offer set under the signer's suite.</summary>
    public static JD SignOfferSet(JD body, SuiteKey key) => Issue.SignArtifact(OracleFacts.OfferSetDomain, body, key);
}
