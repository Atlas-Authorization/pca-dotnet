using AtlasPca.IntentPkg;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Evidence;

/// <summary>A verifier for one artifact: <c>{ok: true}</c> or <c>{ok: false, reason}</c>. For artifacts with a core verifier it overrides the default.</summary>
public delegate Dictionary<string, object?> EvidencePort(object? artifact, Dictionary<string, object?> bundle);

/// <summary><c>verifyEvidenceBundle</c>: deterministic replay of a dispute evidence bundle. Every finding is recomputed from the signed artifacts; the output is a
/// findings report whose text comes from fixed templates, so two readers of the same bundle with the same trust inputs get byte-identical reports
/// (<c>report_digest</c>). Statuses: <c>pass</c>, <c>fail</c>, <c>unverified</c> (never reported as a pass). A <c>trust.verifiers.&lt;name&gt;</c> port overrides
/// the core default for the artifacts that have one.</summary>
public static class EvidenceReplay
{
    static readonly Dictionary<string, string> Templates = new()
    {
        ["shape"] = "The bundle is well formed (pca-intent-evidence v1, closed members)",
        ["principal.pinned"] = "Every session-root key that signs in this bundle is a principal key pinned by the reader (attribution)",
        ["trust.principals"] = "The pinned principal keys (trust.principals) are well formed",
        ["statement.commit"] = "The session root commits to the intent statement the bundle names",
        ["statement.opening"] = "The opened statement is signed by a principal and hashes to the committed ref",
        ["session_root.signature"] = "The session root is signed by one of its principal keys",
        ["schema.signature"] = "The action schema is signed by a site key",
        ["schema.digest"] = "The session root binds this action schema",
        ["schema.anchor"] = "The action schema is anchored in a transparency log",
        ["map.replay"] = "The task map replays to its committed digest",
        ["root_grant"] = "The root intent grant G_0 is principal-signed and bound to the session",
        ["delta.signature"] = "The delta grant is a root capability signed by a principal of the session",
        ["delta.chain"] = "The delta grant chains to the session (session, seq, prev, root)",
        ["delta.backed"] = "Every delta grant is backed by a principal \"yes\" answer",
        ["answer.signature"] = "The answer is signed by a principal of the session, for this session",
        ["answer.map"] = "The answer refers to a map version in the bundle",
        ["answer.tier"] = "The answer meets the site minimum friction tier for the verb",
        ["answer.typed"] = "The typed-tier value re-derives the signed typed digest",
        ["answer.device"] = "The device-tier WebAuthn assertion verifies with user verification",
        ["canaries.summary"] = "The canary summary equals the one recomputed from the signed canary answers",
        ["pcactn.verify"] = "The PCActn verifies (signature, chain, audience, validity at its issue time)",
        ["pcactn.root"] = "The PCActn's root capability is G_0 or a bundled delta grant",
        ["pcactn.session"] = "The PCActn's signed intent_session member matches the session, its root grant and the accumulator events",
        ["subject.present"] = "The subject PCActn is in the bundle",
        ["jit.consent"] = "The irreversible subject action carries a principal JIT consent bound to its exact action digest",
        ["accumulator.declared"] = "The accumulator is declared in the session root",
        ["accumulator.arithmetic"] = "The accumulator posts are the running values of the counted events",
        ["accumulator.cap"] = "Every accumulator post is within the admitting grant's cap",
        ["accumulator.receipts"] = "The sequencer reservation receipt verifies and is consistent",
        ["acc.keysets.equivocation"] = "No two different sequencer key sets share one root and version",
        ["acc.keysets"] = "The sequencer key set is signed by the session's pinned sequencer root and its version never rolls back",
        ["trust.acc"] = "The verifier freshness configuration (trust.acc) is well formed",
        ["effect.binding"] = "The effect record is bound to the PCActn's signed params",
        ["effect.charged"] = "The charged amount is within the confirmed value",
        ["effect.frame"] = "No monitored state outside the write set changed",
        ["effect.signature"] = "The effect record is signed by the site",
        ["verdict.signature"] = "The site verdict record verifies",
        ["fact.signature"] = "The oracle fact verifies under a pinned oracle key",
        ["classifier.signature"] = "The classifier verdict verifies under a pinned judge key",
        ["offer_set.signature"] = "The offer set is signed by a site key, for this session",
        ["labels.signature"] = "The label receipt is signed by a pinned site key, for this session",
        ["settlement.signature"] = "The settlement record verifies",
        ["revocation.history"] = "The bundled revocation epoch extends its predecessor (one append-only chain by the session revocation authority)",
        ["revocation.epoch"] = "A fresh revocation epoch shows the session, its maps and its deltas unrevoked at the action time",
        ["anchor.inclusion"] = "The anchored artifact is included under a guardian-signed head of the intent log",
    };

    static readonly Dictionary<string, string> StatusText = new() { ["pass"] = "verified", ["fail"] = "REFUTED", ["unverified"] = "not verified here" };

    static readonly string[] NotProven =
    {
        "That the principal understood the question: the bundle proves only that a deterministic card with the recorded digest was shown and answered at the recorded friction tier.",
        "That the site's signed schema describes what its endpoints really do (SCH).",
        "That the site's effect records and any oracle facts are true (EFF, ORC).",
        "Acceptance of this bundle by any card network, court or regulator.",
    };

    // ---- small JSON helpers ----

    static D? M(object? o) => o as D;
    static L Lst(object? o) => o as L ?? new L();
    static object? G(object? o, string k) => IntentJs.Get(o, k);
    static bool Has(object? o, string k) => o is D d && d.ContainsKey(k);
    static double? Nm(object? o) => IntentJs.NumOf(o);
    static bool IsNum(object? o) => Nm(o) is double d && double.IsFinite(d);
    static bool NumEq(object? a, object? b) => Nm(a) is double x && Nm(b) is double y && x == y;
    static long Lng(object? o) => (long)Nm(o)!.Value;
    static bool Str(object? o, string? v) => o is string s && s == v;
    static bool Eq(object? a, object? b) => a == null ? b == null : b != null && IntentJs.JsonEquals(a, b);
    static Num N(long v) => IntentJs.OfLong(v);
    static string Js(double d) => JsCanon.NumberString(d == 0 ? 0 : d);
    static int Cmp(string a, string b) => Math.Sign(string.CompareOrdinal(a, b));
    static string Id(object? o) => IntentRevocation.JsText(o, true);
    static string Join(IEnumerable<object?> xs, string sep) => string.Join(sep, xs.Select(x => x == null ? "" : IntentRevocation.JsText(x, true)));
    static bool Truthy(object? o) => o switch
    {
        null => false,
        bool b => b,
        string s => s.Length > 0,
        Num n => IntentJs.NumOf(n) is double d && d != 0 && !double.IsNaN(d),
        _ => true,
    };
    static double OrZero(object? o) => Nm(o) is double d && !double.IsNaN(d) ? d : 0;

    static D Vd(bool ok, string? reason)
    {
        var v = new D { ["ok"] = ok };
        if (!ok) v["reason"] = reason;
        return v;
    }
    static D Nul(string? e) => Vd(e == null, e);
    static bool Ok(D v) => v.GetValueOrDefault("ok") is true;
    static List<string> R(params string[] r) => r.ToList();

    // ---- findings ----

    sealed class Findings
    {
        public readonly List<D> List = new();

        public void Add(string code, string status, List<string>? refs = null, string? detail = null)
        {
            var text = Templates[code] + ": " + StatusText[status] + (!string.IsNullOrEmpty(detail) ? " (" + detail + ")" : "") + ".";
            List.Add(new D { ["code"] = code, ["status"] = status, ["text"] = text, ["refs"] = new L((refs ?? new List<string>()).Cast<object?>()) });
        }
        public void Add(string code, bool pass, List<string> refs) => Add(code, pass ? "pass" : "fail", refs);

        public void Verdict(string code, D v, List<string> refs)
        {
            if (Ok(v)) Add(code, "pass", refs);
            else Add(code, "fail", refs, v.GetValueOrDefault("reason") as string);
        }

        /// <summary>Run <paramref name="port"/> if supplied, else the core default; with neither (or a null core verdict) the artifact stays unverified.</summary>
        public void Check(string code, EvidencePort? port, Func<D?>? core, object? artifact, D bundle, List<string> refs, string what)
        {
            D? v;
            try { v = port != null ? port(artifact, bundle) : core?.Invoke(); }
            catch (Exception e) { v = Vd(false, "verifier threw: " + e.Message); }
            if (v == null) Add(code, "unverified", refs, "no verifier for " + what);
            else Verdict(code, v, refs);
        }
    }

    static bool Pass(Findings f, string code)
    {
        bool any = false;
        foreach (var x in f.List)
        {
            if (!Str(x["code"], code)) continue;
            if (Str(x["status"], "fail")) return false;
            if (Str(x["status"], "pass")) any = true;
        }
        return any;
    }

    // ---- entry ----

    static D EmptySummary() => new()
    {
        ["admitted_under"] = null,
        ["principal_keys"] = new L(),
        ["answers"] = new D { ["total"] = N(0), ["yes"] = N(0), ["no"] = N(0), ["partial"] = N(0), ["canaries"] = N(0) },
        ["refusals"] = new L(),
        ["consent"] = null,
        ["charged"] = null,
        ["canary_accuracy"] = new D { ["correct"] = N(0), ["asked"] = N(0) },
        ["attribution"] = new D { ["pinned"] = false, ["keys_to_check"] = new L() },
        ["proven"] = new L(),
        ["not_proven"] = new L(NotProven.Cast<object?>()),
    };

    static D Finish(Findings f, string? digest, D summary)
    {
        var findings = f.List.OrderBy(x => x, Comparer<D>.Create((a, b) =>
        {
            int c = Cmp((string)a["code"]!, (string)b["code"]!);
            if (c != 0) return c;
            c = Cmp(Join(Lst(a["refs"]), ","), Join(Lst(b["refs"]), ","));
            if (c != 0) return c;
            c = Cmp((string)a["status"]!, (string)b["status"]!);
            return c != 0 ? c : Cmp((string)a["text"]!, (string)b["text"]!);
        })).ToList();
        bool anyFail = false, anyUnverified = false, pinPass = false, pinOther = false;
        foreach (var x in findings)
        {
            var st = (string)x["status"]!;
            if (st == "fail") anyFail = true;
            if (st == "unverified") anyUnverified = true;
            if (Str(x["code"], "principal.pinned")) { if (st == "pass") pinPass = true; else pinOther = true; }
        }
        bool consistent = findings.Count > 0 && !anyFail;
        bool attributed = pinPass && !pinOther;
        bool ok = consistent && attributed;
        bool complete = !anyUnverified;
        var notProven = Lst(summary["not_proven"]);
        var toCheck = Lst(G(summary["attribution"], "keys_to_check"));
        if (consistent && !attributed && toCheck.Count > 0)
            notProven.Insert(0, "The bundle is internally consistent but NOT attributed to any known principal: verify these session-root keys out of band: " + Join(toCheck, ", ") + ".");
        var codes = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var x in findings) if (Str(x["status"], "unverified")) codes.Add((string)x["code"]!);
        if (codes.Count > 0) notProven.Add("Checked only through a supplied verifier, or not at all: " + string.Join(", ", codes) + ".");
        var body = new D
        {
            ["ok"] = ok, ["consistent"] = consistent, ["attributed"] = attributed, ["complete"] = complete, ["digest"] = digest,
            ["findings"] = new L(findings.Cast<object?>()), ["summary"] = summary,
        };
        var w = new D { ["d"] = EvidenceVerify.EvidenceReportDomain, ["r"] = body };
        var outD = new D(body) { ["report_digest"] = Pca.HashCanonical(w) };
        return outD;
    }

    /// <summary>Replays a bundle. Never throws: a malformed bundle is a report with a failed <c>shape</c> finding.</summary>
    public static D Verify(object? input, D? trustIn, IReadOnlyDictionary<string, EvidencePort>? ports)
    {
        var trust = trustIn ?? new D();
        var f = new Findings();
        var summary = EmptySummary();
        if (trust.ContainsKey("acc"))
        {
            var te = EvidenceVerify.AccTrustError(trust["acc"]);
            if (te != null) { f.Add("trust.acc", "fail", new List<string>(), te); return Finish(f, null, summary); }
        }
        if (trust.ContainsKey("principals"))
        {
            var pe = EvidenceVerify.PrincipalsTrustError(trust["principals"]);
            if (pe != null) { f.Add("trust.principals", "fail", new List<string>(), pe); return Finish(f, null, summary); }
        }
        var bad = EvidenceBundle.BundleShapeError(input);
        if (bad != null) { f.Add("shape", "fail", new List<string>(), bad); return Finish(f, null, summary); }
        D b;
        string digest;
        try
        {
            b = EvidenceBundle.NormalizeBundle(input);
            digest = EvidenceBundle.EvidenceDigest(b);
        }
        catch (Exception e)
        {
            f.Add("shape", "fail", new List<string>(), "not canonicalizable: " + e.Message);
            return Finish(f, null, summary);
        }
        f.Add("shape", "pass");
        try { Replay(b, digest, trust, ports ?? new Dictionary<string, EvidencePort>(), f, summary); }
        catch (Exception e) { f.Add("shape", "fail", new List<string>(), "replay aborted: " + e.Message); }
        return Finish(f, digest, summary);
    }

    // ---- the replay ----

    sealed record Grant(D Cap, int Seq);

    sealed class KeySetsAt
    {
        public L Sets = new();
        public double? MinV;
        public D? Tracked;
    }

    /// <summary>The Java EvidenceBridge receipt entry: a bare version floor, then the core receipt check (null ages take the core defaults).</summary>
    static bool VerifyReceipt(D r, D holder, L keySets, double now, double? maxReceiptAgeMs, double? maxKeySetAgeMs, D? tracked, double? minKeySetVersion)
    {
        var sets = new L(keySets);
        if (minKeySetVersion is double fl)
        {
            if (!(double.IsFinite(fl) && fl == Math.Round(fl) && fl >= 0 && fl <= IntentJs.MaxSafe && !IntentJs.IsNegZero(fl))) return false;
            sets.RemoveAll(k => Nm(G(k, "version")) is double v && v < fl);
        }
        return IntentAcc.VerifyReceiptAgainstHolder(r, holder, sets, now, maxReceiptAgeMs ?? IntentAcc.DefaultMaxReceiptAgeMs, maxKeySetAgeMs ?? IntentAcc.DefaultMaxKeySetAgeMs, tracked);
    }

    static void Replay(D b, string digest, D trust, IReadOnlyDictionary<string, EvidencePort> ports, Findings f, D summary)
    {
        EvidencePort? Port(string name) => ports.GetValueOrDefault(name);
        var S = M(b["session_root"])!;
        var subjectM = M(b["subject"])!;
        var session = (string)subjectM["session"]!;
        var subjectAud = (string)subjectM["aud"]!;
        var principals = new List<string>();
        foreach (var p in Lst(S["principals"])) principals.Add((string)G(p, "key")!);
        principals.Sort(StringComparer.Ordinal);
        summary["principal_keys"] = new L(principals.Cast<object?>());
        var sRef = trust.GetValueOrDefault("sessionRootDigest") as string ?? IntentSession.RootDigest(S);
        var pqPinsD = new D();
        var pqPinsS = new Dictionary<string, string>();
        if (trust.GetValueOrDefault("principals") is L tp)
            foreach (var p in tp)
                if (G(p, "pq_pk") is string pq) { pqPinsD[(string)G(p, "key")!] = pq; pqPinsS[(string)G(p, "key")!] = pq; }
        var siteKeys = trust.GetValueOrDefault("siteKeys") as L;
        var schemaM = M(b["schema"])!;
        var schemaDoc = M(schemaM["doc"])!;

        // -- session root
        if (!Str(S["session"], session)) f.Add("session_root.signature", "fail", R("session_root"), "session root is for another session");
        else f.Check("session_root.signature", Port("sessionRoot"), () => Nul(IntentSession.VerifyRoot(S, pqPinsD)), S, b, R("session_root"), "the session root");

        // -- statement
        var stmt = M(b["statement"])!;
        f.Add("statement.commit", Str(S["intent_ref"], stmt["commit"] as string), R("statement"));
        var hasOpening = stmt.ContainsKey("opening");
        var opening = stmt.GetValueOrDefault("opening");
        if (!hasOpening) f.Add("statement.opening", "unverified", R("statement"), "the statement was not opened (it stays a commitment)");
        else
        {
            var v = IntentStatement.VerifyIntent(opening);
            if (!Ok(v)) f.Add("statement.opening", "fail", R("statement"), v.GetValueOrDefault("reason") as string);
            else if (IntentStatement.IntentRef(opening) != (stmt["commit"] as string)) f.Add("statement.opening", "fail", R("statement"), "the opening does not hash to the commitment");
            else if (!(G(opening, "principal") is string opp && principals.Contains(opp))) f.Add("statement.opening", "fail", R("statement"), "signed by a key that is not a principal of the session");
            else f.Add("statement.opening", "pass", R("statement"));
        }

        // -- schema
        f.Check("schema.signature", Port("schema"), siteKeys != null ? () => Nul(ActionSchema.Verify(schemaDoc, siteKeys)) : null, schemaDoc, b, R("schema"), "the action schema (no site keys supplied)");
        var schemaDigest = ActionSchema.Digest(schemaDoc);
        f.Add("schema.digest", Str(G(S["schema"], "digest"), schemaDigest) && Str(G(S["schema"], "aud"), subjectAud), R("schema"));

        // -- maps
        var mapCommits = new HashSet<string>(StringComparer.Ordinal);
        foreach (var mo in Lst(b["maps"])) if (G(mo, "commit") is string mc) mapCommits.Add(mc);
        foreach (var mo in Lst(b["maps"]))
        {
            var rf = R("map:" + Id(G(mo, "seq")));
            if (!Truthy(G(mo, "map"))) { f.Add("map.replay", "unverified", rf, "committed map not revealed"); continue; }
            var r = IntentMapKit.VerifyIntentMap(G(mo, "map"));
            if (r.GetValueOrDefault("ok") is not true)
            {
                var pr = Lst(r.GetValueOrDefault("problems"));
                f.Add("map.replay", "fail", rf, Join(pr.Take(3), "; "));
            }
            else if (IntentMapKit.IntentMapDigest(G(mo, "map")) != (G(mo, "commit") as string)) f.Add("map.replay", "fail", rf, "the revealed map does not hash to its commit");
            else f.Add("map.replay", "pass", rf);
        }

        // -- grants: G_0 and the delta chain
        var grants = new Dictionary<string, Grant>();
        var g0 = M(b["root_grant"])!;
        {
            var cv = IntentSession.GrantSessionCaveat(g0);
            var (why, okc) = Pca.VerifyChain(new L { g0 }, g0["issuer"], true, null, pqPinsS, null);
            if (!okc) f.Add("root_grant", "fail", R("G_0"), why);
            else if (!(g0["issuer"] is string gi && principals.Contains(gi))) f.Add("root_grant", "fail", R("G_0"), "not signed by a principal of the session");
            else if (cv == null || IntentSession.CaveatError(cv) != null) f.Add("root_grant", "fail", R("G_0"), cv != null ? IntentSession.CaveatError(cv) : "no intent_session caveat");
            else if (!Str(cv["session"], session) || !NumEq(cv["seq"], N(0)) || !Str(cv["root"], sRef)) f.Add("root_grant", "fail", R("G_0"), "intent_session caveat does not bind seq 0 of this session root");
            else
            {
                f.Add("root_grant", "pass", R("G_0"));
                grants[(string)g0["id"]!] = new Grant(g0, 0);
            }
        }
        var prevId = (string?)g0["id"];
        var deltas = Lst(b["deltas"]);
        for (int i = 0; i < deltas.Count; i++)
        {
            var d = M(deltas[i])!;
            int want = i + 1;
            var rf = R("D_" + want);
            var (dwhy, dok) = Pca.VerifyChain(new L { d }, d["issuer"], true, null, pqPinsS, null);
            if (!dok || !(d["issuer"] is string di && principals.Contains(di)) || d.ContainsKey("parent"))
            {
                f.Add("delta.signature", "fail", rf, !dok ? dwhy : "not a principal-signed root capability");
                continue;
            }
            f.Add("delta.signature", "pass", rf);
            var cv = IntentSession.GrantSessionCaveat(d);
            int nCv = 0;
            foreach (var k in Lst(d.GetValueOrDefault("caveats"))) if (Str(G(k, "type"), "intent_session")) nCv++;
            string? why2 = null;
            if (cv == null || nCv != 1) why2 = "no single intent_session caveat";
            else if (IntentSession.CaveatError(cv) != null) why2 = IntentSession.CaveatError(cv);
            else if (!Str(cv["session"], session)) why2 = "bound to another session";
            else if (!Str(cv["root"], sRef)) why2 = "bound to another session root";
            else if (!NumEq(cv["seq"], N(want))) why2 = "seq " + Id(cv["seq"]) + " where " + want + " was expected (gap, duplicate or reorder)";
            else if (!Str(cv["prev"], prevId)) why2 = "prev does not name the previous grant";
            if (why2 != null) f.Add("delta.chain", "fail", rf, why2);
            else
            {
                f.Add("delta.chain", "pass", rf);
                grants[(string)d["id"]!] = new Grant(d, want);
            }
            prevId = (string?)d["id"];
        }

        // -- answers
        var verified = new List<D>();
        foreach (var ao in Lst(b["answers"]))
        {
            var a = M(ao)!;
            var rf = R("answer:" + Id(a["question_id"]));
            var v = AtlasPca.Wallet.WalletCore.VerifyIntentAnswer(a, principals);
            if (!Ok(v)) { f.Add("answer.signature", "fail", rf, v.GetValueOrDefault("reason") as string); continue; }
            if (!Str(a["session"], session)) { f.Add("answer.signature", "fail", rf, "answer for another session"); continue; }
            f.Add("answer.signature", "pass", rf);
            verified.Add(a);
            f.Add("answer.map", a["map_digest"] is string md && mapCommits.Contains(md), rf);
            var ux = M(a["ux"])!;
            if (Truthy(ux.GetValueOrDefault("canary")) || !NumEq(a["y"], N(1))) continue;
            var min = G(trust.GetValueOrDefault("minTier"), a["verb"] as string ?? "");
            if (min != null)
                f.Add("answer.tier", AtlasPca.Wallet.WalletCore.FrictionRank(ux["tier"]) >= AtlasPca.Wallet.WalletCore.FrictionRank(min) ? "pass" : "fail", rf, Id(ux["tier"]) + " vs minimum " + Id(min));
            if (Str(ux["tier"], "typed"))
            {
                var tv = G(trust.GetValueOrDefault("typedValues"), (string)a["question_id"]!);
                if (tv == null) f.Add("answer.typed", "unverified", rf, "the typed value is not known to this verifier");
                else f.Add("answer.typed", AtlasPca.Wallet.WalletCore.TypedDigest((string)a["question_id"]!, (string)tv) == (ux.GetValueOrDefault("typed_digest") as string), rf);
            }
            if (Str(ux["tier"], "device"))
            {
                var wa = ux.GetValueOrDefault("webauthn");
                var cred = wa is D ? G(trust.GetValueOrDefault("credentials"), (string)G(wa, "credential_id")!) : null;
                if (wa is not D || cred == null) f.Add("answer.device", "unverified", rf, "unknown authenticator");
                else
                {
                    var assertion = new D
                    {
                        ["authenticatorData"] = Pca.B64uDecode(G(wa, "authenticator_data")),
                        ["clientDataJSON"] = Pca.B64uDecode(G(wa, "client_data_json")),
                        ["signature"] = Pca.B64uDecode(G(wa, "signature")),
                        ["publicKey"] = G(cred, "publicKey"),
                    };
                    var expect = new D
                    {
                        ["expectedChallenge"] = AtlasPca.Wallet.WalletCore.DeviceChallenge(a["question_id"], ux["rendered_digest"], a["y"], ux.ContainsKey("action_digest") ? ux["action_digest"] : null),
                        ["rpId"] = G(cred, "rpId"),
                        ["origins"] = G(cred, "origins"),
                        ["requireUV"] = true,
                        ["storedSignCount"] = Has(cred, "signCount") && G(cred, "signCount") != null ? G(cred, "signCount") : N(0),
                    };
                    var r = AtlasPca.Webauthn.Webauthn.VerifyAssertion(assertion, expect);
                    var rok = r.GetValueOrDefault("ok") is true;
                    f.Add("answer.device", rok ? "pass" : "fail", rf, rok ? null : r.GetValueOrDefault("reason") as string);
                }
            }
        }
        var real = new List<D>();
        var canaries = new List<D>();
        foreach (var a in verified) (Truthy(G(a["ux"], "canary")) ? canaries : real).Add(a);
        long yes = 0, no = 0, partial = 0, yesAny = 0;
        var refusals = new L();
        foreach (var a in real)
        {
            if (NumEq(a["y"], N(1)) && !a.ContainsKey("partial")) yes++;
            if (NumEq(a["y"], N(0))) { no++; refusals.Add(a["question_id"]); }
            if (a.ContainsKey("partial")) partial++;
            if (NumEq(a["y"], N(1))) yesAny++;
        }
        var ans = M(summary["answers"])!;
        ans["total"] = N(real.Count);
        ans["yes"] = N(yes);
        ans["no"] = N(no);
        ans["partial"] = N(partial);
        ans["canaries"] = N(canaries.Count);
        refusals = new L(refusals.OrderBy(x => (string)x!, StringComparer.Ordinal));
        summary["refusals"] = refusals;
        f.Add("delta.backed", yesAny >= deltas.Count ? "pass" : "fail", new List<string>(), deltas.Count + " delta(s), " + yesAny + " principal yes answer(s)");

        // -- canaries
        {
            var labels = new Dictionary<string, object?>();
            foreach (var c0 in Lst(b["canary_labels"])) labels[(string)G(c0, "question_id")!] = G(c0, "label");
            long falseYes = 0, falseNo = 0, missing = 0;
            foreach (var a in canaries)
            {
                var qid = (string)a["question_id"]!;
                var label = G(trust.GetValueOrDefault("canaryLabels"), qid);
                if (label == null) label = labels.GetValueOrDefault(qid);
                if (label == null) missing++;
                else if (NumEq(label, N(0)) && NumEq(a["y"], N(1))) falseYes++;
                else if (NumEq(label, N(1)) && NumEq(a["y"], N(0))) falseNo++;
            }
            var ca = M(summary["canary_accuracy"])!;
            ca["correct"] = N(canaries.Count - missing - falseYes - falseNo);
            ca["asked"] = N(canaries.Count);
            var c = M(b["canaries"])!;
            if (missing > 0) f.Add("canaries.summary", "fail", new List<string>(), missing + " canary answer(s) without a known label");
            else if (!NumEq(c["asked"], N(canaries.Count)) || !NumEq(c["false_yes"], N(falseYes)) || !NumEq(c["false_no"], N(falseNo)))
                f.Add("canaries.summary", "fail", new List<string>(), "claimed " + Id(c["asked"]) + "/" + Id(c["false_yes"]) + "/" + Id(c["false_no"]) + ", recomputed " + canaries.Count + "/" + falseYes + "/" + falseNo);
            else f.Add("canaries.summary", "pass", new List<string>(), canaries.Count + " asked, " + falseYes + " false yes, " + falseNo + " false no");
        }

        // -- sequencer key sets (rule 15)
        var acc = M(b["accumulator"])!;
        var rootHolders = new Dictionary<string, D>();
        foreach (var ao in Lst(S["accumulators"]))
        {
            var h = G(ao, "holder");
            if (Str(G(h, "kind"), "sequenced")) rootHolders[(string)G(h, "root")!] = (D)h!;
        }
        var acceptedKeySets = new List<D>();
        var verifiedKeySets = new List<D>();
        var equivocatedSlots = new HashSet<string>(StringComparer.Ordinal);
        {
            var sets = new L(Lst(acc.GetValueOrDefault("sequencer_keys")))
                .OrderBy(x => x, Comparer<object?>.Create((x, y) =>
                {
                    int c = OrZero(G(x, "issued_at")).CompareTo(OrZero(G(y, "issued_at")));
                    if (c != 0) return c;
                    c = OrZero(G(x, "version")).CompareTo(OrZero(G(y, "version")));
                    return c != 0 ? c : Cmp(Pca.HashCanonical(x), Pca.HashCanonical(y));
                })).ToList();
            var tracked = new Dictionary<string, double>();
            var byVersion = new Dictionary<string, string[]>();
            for (int i = 0; i < sets.Count; i++)
            {
                var ko = sets[i];
                var rf = "keyset#" + i + ":" + (ko is D ? Id(G(ko, "version")) : "?");
                D? holder = ko is D && G(ko, "sequencer") is string sq ? rootHolders.GetValueOrDefault(sq) : null;
                if (holder == null) { f.Add("acc.keysets", "fail", R(rf), "not signed by a sequencer root the session root pins"); continue; }
                var root = (string)holder["root"]!;
                if (!IntentAcc.VerifySequencerKeySet(ko, root, holder.GetValueOrDefault("root_pq_pk"), holder.ContainsKey("root_pq_pk")))
                {
                    f.Add("acc.keysets", "fail", R(rf), "the key set does not verify under its pinned root");
                    continue;
                }
                var k = M(ko)!;
                double ver = Nm(k["version"])!.Value;
                double? prev = tracked.TryGetValue(root, out var pv) ? pv : null;
                if (prev != null && ver < prev) { f.Add("acc.keysets", "fail", R(rf), "version " + Id(k["version"]) + " rolls back the tracked version " + Js(prev.Value)); continue; }
                var slot = root + "#" + Id(k["version"]);
                var dg = IntentAcc.SequencerKeySetDigest(k);
                var seen = byVersion.GetValueOrDefault(slot);
                if (seen != null && seen[0] != dg)
                {
                    equivocatedSlots.Add(slot);
                    verifiedKeySets.Add(k);
                    f.Add("acc.keysets.equivocation", "fail", R(seen[1], rf), "two different key sets under version " + Id(k["version"]) + " of one sequencer root");
                    continue;
                }
                if (seen == null) byVersion[slot] = new[] { dg, rf };
                verifiedKeySets.Add(k);
                tracked[root] = Math.Max(prev ?? 0, ver);
                acceptedKeySets.Add(k);
                f.Add("acc.keysets", "pass", R(rf));
            }
            for (int i = acceptedKeySets.Count - 1; i >= 0; i--)
            {
                var k = acceptedKeySets[i];
                if (equivocatedSlots.Contains(k["sequencer"] + "#" + Id(k["version"]))) acceptedKeySets.RemoveAt(i);
            }
        }
        KeySetsAt KeySetsAtFn(string root, double t)
        {
            var r = new KeySetsAt();
            D? newest = null;
            foreach (var k in verifiedKeySets)
            {
                if (!Str(k["sequencer"], root) || !(Nm(k["issued_at"])!.Value <= t)) continue;
                if (newest == null || Nm(k["version"])!.Value > Nm(newest["version"])!.Value) newest = k;
            }
            bool poisoned = newest != null && equivocatedSlots.Contains(root + "#" + Id(newest["version"]));
            double floor = newest == null ? 0 : Nm(newest["version"])!.Value;
            foreach (var k in acceptedKeySets)
                if (Str(k["sequencer"], root) && Nm(k["issued_at"])!.Value <= t + IntentAcc.ReceiptSkewMs && Nm(k["version"])!.Value >= floor) r.Sets.Add(k);
            r.MinV = newest == null ? null : Nm(newest["version"]);
            if (newest != null && !poisoned) r.Tracked = new D { ["version"] = newest["version"], ["digest"] = IntentAcc.SequencerKeySetDigest(newest) };
            return r;
        }

        // -- PCActns
        var byDigest = new Dictionary<string, D>();
        var rootSeq = new Dictionary<string, int>();
        var effects = Lst(b["effects"]);
        D? EffectOf(string d)
        {
            foreach (var e in effects) if (Str(G(e, "pcactn_digest"), d)) return M(e);
            return null;
        }
        static string? DigestOf(D? p)
        {
            try { return Pca.HashCanonical(p); } catch (Exception) { return null; }
        }
        var grantsBySeq = grants.Values.OrderBy(g => g.Seq).Select(g => g.Cap).ToList();
        var epochs = Lst(b["revocation_epochs"]);
        int EpochIdxAt(double t)
        {
            int idx = -1;
            for (int i = 0; i < epochs.Count; i++) if (Nm(G(G(epochs[i], "epoch"), "issued_at"))!.Value <= t) idx = i;
            return idx;
        }
        var pcactns = Lst(b["pcactns"]);
        var events = Lst(acc.GetValueOrDefault("events"));
        var history = new L();
        foreach (var evo in events)
        {
            var pd = (string)G(evo, "pcactn_digest")!;
            bool dup = false;
            foreach (var h in history) if (Str(G(h, "id"), pd)) { dup = true; break; }
            if (dup) continue;
            D? p = null;
            foreach (var x in pcactns) if (pd == DigestOf(M(x))) { p = M(x); break; }
            var eff = EffectOf(pd);
            var prm = eff?.GetValueOrDefault("params");
            if (p != null && prm != null)
            {
                history.Add(new D
                {
                    ["id"] = pd, ["verb"] = G(p["action"], "verb"), ["resource"] = G(p["action"], "resource"), ["params"] = prm, ["t"] = p["iat"],
                    ["status"] = Has(evo, "status") && G(evo, "status") != null ? G(evo, "status") : "committed",
                });
            }
        }
        var schemaVerbsOnly = new D { ["verbs"] = schemaDoc.GetValueOrDefault("verbs") };
        var receiptsAll = Lst(acc.GetValueOrDefault("receipts"));
        var trustAcc = trust.GetValueOrDefault("acc") as D;
        D? V2Context(D p, string d, int? seq)
        {
            var eff = EffectOf(d);
            var prm = eff?.GetValueOrDefault("params");
            if (prm is not D prmD || seq == null) return null;
            int idx = -1;
            for (int i = 0; i < history.Count; i++) if (Str(G(history[i], "id"), d)) { idx = i; break; }
            var before = new L();
            if (idx >= 0) before.AddRange(history.Take(idx));
            else foreach (var h in history) if (Nm(G(h, "t"))!.Value <= Nm(p["iat"])!.Value) before.Add(h);
            var accCtx = IntentHistory.AccContextFor(S, before, prmD, p["iat"], schemaVerbsOnly);
            int ri = EpochIdxAt(Nm(p["iat"])!.Value);
            var rev = ri >= 0 ? epochs[ri] : null;
            var revLast = ri > 0 ? epochs[ri - 1] : null;
            var ctx = new D { ["params"] = prm };
            ctx["schema"] = new D { ["docs"] = new L { schemaDoc }, ["keys"] = (object?)siteKeys ?? new L() };
            var sess = new D { ["root"] = S, ["grants"] = new L(grantsBySeq.Take(Math.Min(seq.Value, grantsBySeq.Count))), ["pq_pins"] = pqPinsD };
            if (rev != null) sess["revocation"] = rev;
            if (revLast != null) sess["revocation_last"] = revLast;
            ctx["session"] = sess;
            var accOut = new D(accCtx) { ["receipts"] = receiptsAll };
            var keys = new L();
            var versions = new D();
            foreach (var root in rootHolders.Keys)
            {
                var ks = KeySetsAtFn(root, Nm(p["iat"])!.Value);
                keys.AddRange(ks.Sets);
                if (ks.Tracked != null) versions[root] = ks.Tracked;
            }
            accOut["sequencer_keys"] = keys;
            accOut["keyset_versions"] = versions;
            ctx["acc"] = accOut;
            if (trustAcc != null) ctx["policy"] = new D { ["acc"] = trustAcc };
            return ctx;
        }
        var v2Checks = new HashSet<string> { "schema", "intent_session", "accumulators" };
        foreach (var po in pcactns)
        {
            var p = M(po)!;
            var d = DigestOf(p);
            if (d == null) { f.Add("pcactn.verify", "fail", R("pcactn:?"), "not canonicalizable"); continue; }
            byDigest[d] = p;
            var rf = R("pcactn:" + d);
            var capChain = p.GetValueOrDefault("cap_chain");
            var root = capChain is L cl && cl.Count > 0 ? cl[0] : null;
            if (!Truthy(root)) { f.Add("pcactn.verify", "fail", rf, "empty capability chain"); continue; }
            var g = G(root, "id") is string rid ? grants.GetValueOrDefault(rid) : null;
            bool sameRoot = g != null && Pca.HashCanonical(g.Cap) == Pca.HashCanonical(root);
            bool hasIs = p.ContainsKey("intent_session");
            var isD = hasIs ? M(p["intent_session"]) : null;
            var ctx = hasIs && sameRoot ? V2Context(p, d, g!.Seq) : null;
            var opts = new PcaCore.Options((D)root!)
            {
                PlanRoots = PlanRootPolicy.Skip, GrantFromArtifact = true, PqPins = pqPinsS, NowEpoch = Lng(p["iat"]),
            };
            opts.WithAudience(subjectAud);
            if (ctx != null) opts.IntentV2 = IntentV2Context.FromJson(ctx);
            var r = PcaCore.Verify(p, opts);
            var failed = r.Checks.Where(e => e.Value == PcaCore.Fail).Select(e => e.Key).ToList();
            failed.Sort(StringComparer.Ordinal);
            var v1f = failed.Where(k => !v2Checks.Contains(k)).ToList();
            var v2f = failed.Where(k => v2Checks.Contains(k)).ToList();
            f.Add("pcactn.verify", v1f.Count == 0 ? "pass" : "fail", rf, v1f.Count == 0 ? null : string.Join(", ", v1f) + ": " + (r.Reason ?? ""));
            if (sameRoot)
            {
                f.Add("pcactn.root", "pass", rf, g!.Seq == 0 ? "G_0" : "D_" + g.Seq);
                rootSeq[d] = g.Seq;
            }
            else f.Add("pcactn.root", "fail", rf, "rooted at a grant that is not G_0 or a verified delta of this session");
            if (hasIs)
            {
                string? why = null;
                if (!Str(G(isD, "session"), session)) why = "another session";
                else if (!Str(G(isD, "root"), sRef)) why = "another session root";
                else if (!Str(G(isD, "schema"), schemaDigest)) why = "another schema";
                else if (g != null && !NumEq(G(isD, "seq"), N(g.Seq))) why = "seq " + Id(G(isD, "seq")) + " but rooted at seq " + g.Seq;
                else
                {
                    foreach (var c in Lst(G(isD, "acc")))
                    {
                        object? found = null;
                        foreach (var e in events) if (Str(G(e, "pcactn_digest"), d) && Eq(G(e, "acc"), G(c, "id"))) { found = e; break; }
                        if (found == null || !NumEq(G(found, "post"), G(c, "post"))) why = "the signed claim " + Id(G(c, "id")) + ".post = " + Id(G(c, "post")) + " has no matching accumulator event";
                    }
                }
                if (why == null && v2f.Count > 0) why = "core v2 checks failed: " + string.Join(", ", v2f);
                if (why != null) f.Add("pcactn.session", "fail", rf, why);
                else if (ctx == null) f.Add("pcactn.session", "unverified", rf, "the core v2 checks need the plaintext params of the effect record");
                else f.Add("pcactn.session", "pass", rf);
            }
        }
        var subjectDigest = subjectM["pcactn_digest"] as string;
        var subject = subjectDigest != null ? byDigest.GetValueOrDefault(subjectDigest) : null;
        f.Add("subject.present", subject != null, R("pcactn:" + subjectM["pcactn_digest"]));
        int? sSeq = subjectDigest != null && rootSeq.TryGetValue(subjectDigest, out var ss) ? ss : null;
        summary["admitted_under"] = sSeq == null ? null : sSeq == 0 ? "G_0" : "D_" + sSeq;

        // -- effects
        foreach (var eo in effects)
        {
            var e = M(eo)!;
            var rf = R("effect:" + e["pcactn_digest"]);
            var p = e["pcactn_digest"] is string epd ? byDigest.GetValueOrDefault(epd) : null;
            if (p == null) { f.Add("effect.binding", "fail", rf, "no such PCActn in the bundle"); continue; }
            if (!e.ContainsKey("params")) f.Add("effect.binding", "unverified", rf, "no raw params to bind");
            else f.Add("effect.binding", Pca.ParamsDigest(e["params"]) == (G(p["action"], "params_digest") as string), rf);
            if (Truthy(e.GetValueOrDefault("charged")))
            {
                var ch = M(e["charged"])!;
                var chRef = (string)ch["ref"]!;
                var name = chRef.StartsWith("action.params.", StringComparison.Ordinal) ? chRef.Substring("action.params.".Length) : null;
                var bound = name != null && Truthy(e.GetValueOrDefault("params")) ? G(e["params"], name) : null;
                if (!IsNum(bound) || !IsNum(ch.GetValueOrDefault("amount"))) f.Add("effect.charged", "unverified", rf, "no numeric " + chRef + " to compare");
                else
                {
                    f.Add("effect.charged", Nm(ch["amount"])!.Value <= Nm(bound)!.Value ? "pass" : "fail", rf, Id(ch["amount"]) + " vs " + Id(bound));
                    if (Str(subjectM["pcactn_digest"], e["pcactn_digest"] as string)) summary["charged"] = new D { ["amount"] = ch["amount"], ["bound"] = bound };
                }
            }
            if (e.ContainsKey("frame_violations"))
            {
                var fv = Lst(e["frame_violations"]);
                var sorted = fv.Select(x => (string)x!).ToList();
                sorted.Sort(StringComparer.Ordinal);
                f.Add("effect.frame", fv.Count == 0 ? "pass" : "fail", rf, fv.Count == 0 ? null : string.Join(", ", sorted));
            }
            f.Check("effect.signature", Port("effect"), null, e, b, rf, "effect records (no core format yet)");
        }

        // -- JIT consent for an irreversible subject action
        if (subject != null && Str(G(subject["action"], "reversibility_class"), "irreversible"))
        {
            var rf = R("pcactn:" + subjectM["pcactn_digest"]);
            var ad = IntentJit.IntentActionDigest(subject["action"]);
            var need = trust.GetValueOrDefault("jitTier") ?? "typed";
            D? c = null;
            foreach (var a in real)
            {
                var ux = M(a["ux"])!;
                if (NumEq(a["y"], N(1)) && ux.GetValueOrDefault("consent_for_action") is true && ux.GetValueOrDefault("action_digest") as string == ad
                    && AtlasPca.Wallet.WalletCore.FrictionRank(ux["tier"]) >= AtlasPca.Wallet.WalletCore.FrictionRank(need)) { c = a; break; }
            }
            if (c != null)
            {
                f.Add("jit.consent", "pass", rf, "question " + Id(c["question_id"]) + ", " + Id(G(c["ux"], "tier")) + " tier");
                summary["consent"] = new D { ["question_id"] = c["question_id"], ["tier"] = G(c["ux"], "tier"), ["signer"] = c["signer"] };
            }
            else f.Add("jit.consent", "fail", rf, "no principal yes at " + Id(need) + " tier or above bound to this action digest");
        }

        // -- accumulators
        var decls = new Dictionary<string, D>();
        foreach (var ao in Lst(S["accumulators"])) decls[(string)G(ao, "id")!] = M(ao)!;
        long? ValueOf(D decl, string d)
        {
            var p = byDigest.GetValueOrDefault(d);
            var eff = EffectOf(d);
            var prm = eff?.GetValueOrDefault("params");
            if (p == null || prm is not D prmD) return null;
            var v = IntentAcc.AccValueOf(decl, (string)G(p["action"], "verb")!, prmD, schemaVerbsOnly);
            return v.Reason == null ? v.Val : null;
        }
        var running = new Dictionary<string, double>();
        for (int i = 0; i < events.Count; i++)
        {
            var ev = M(events[i])!;
            var rf = R("acc:" + Id(ev["acc"]) + "#" + i);
            var decl = ev["acc"] is string eacc ? decls.GetValueOrDefault(eacc) : null;
            if (decl == null) { f.Add("accumulator.declared", "fail", rf); continue; }
            var evDigest = ev["pcactn_digest"] as string ?? "";
            var p = byDigest.GetValueOrDefault(evDigest);
            bool counted = !Str(ev.GetValueOrDefault("status"), "released") && !Str(ev.GetValueOrDefault("status"), "reverted");
            double prev = running.GetValueOrDefault((string)ev["acc"]!, 0.0);
            double? expected = null;
            if (!counted) expected = prev;
            else if (Str(decl["agg"], "count")) expected = prev + 1;
            else if (Str(decl["agg"], "sum") || Str(decl["agg"], "max"))
            {
                var val = ValueOf(decl, evDigest);
                if (val != null) expected = Str(decl["agg"], "sum") ? prev + val.Value : Math.Max(prev, val.Value);
            }
            double post = Nm(ev["post"])!.Value;
            if (p == null) f.Add("accumulator.arithmetic", "fail", rf, "event names a PCActn that is not in the bundle");
            else if (expected == null) f.Add("accumulator.arithmetic", post >= prev ? "unverified" : "fail", rf, post >= prev ? "contribution not recomputable" : "post decreased");
            else f.Add("accumulator.arithmetic", post == expected ? "pass" : "fail", rf, post == expected ? null : "post " + Id(ev["post"]) + ", recomputed " + Js(expected.Value));
            running[(string)ev["acc"]!] = counted ? post : prev;
            if (!counted) continue;
            int? seq = p != null && rootSeq.TryGetValue(evDigest, out var rs) ? rs : null;
            if (Has(ev, "delta") && seq != null && !NumEq(ev["delta"], N(seq.Value))) { f.Add("accumulator.cap", "fail", rf, "the event names a different admitting grant from the PCActn root"); continue; }
            Grant? grant = null;
            foreach (var gg in grants.Values)
            {
                if (seq != null ? gg.Seq == seq : (Has(ev, "delta") && NumEq(ev["delta"], N(gg.Seq)))) { grant = gg; break; }
            }
            var caps = new List<double>();
            double? c1 = grant != null && p != null ? Nm(EvidenceVerify.CapOf(grant.Cap, (string)ev["acc"]!, (string)G(p["action"], "verb")!)) : null;
            if (c1 != null) caps.Add(c1.Value);
            if (IsNum(decl.GetValueOrDefault("domain_max"))) caps.Add(Nm(decl["domain_max"])!.Value);
            if (IsNum(decl.GetValueOrDefault("cap"))) caps.Add(Nm(decl["cap"])!.Value);
            if (caps.Count == 0) f.Add("accumulator.cap", "unverified", rf, "no cap stated for this accumulator");
            else
            {
                double cap = caps.Min();
                f.Add("accumulator.cap", post <= cap ? "pass" : "fail", rf, "post " + Id(ev["post"]) + ", cap " + Js(cap));
            }
        }
        var receipts = receiptsAll;
        if (Str(acc.GetValueOrDefault("holder"), "sequenced") && receipts.Count == 0) f.Add("accumulator.receipts", "fail", R("accumulator"), "a sequenced accumulator without receipts");
        for (int i = 0; i < receipts.Count; i++)
        {
            var r = M(receipts[i])!;
            D? Core()
            {
                var decl = r["acc"] is string racc ? decls.GetValueOrDefault(racc) : null;
                if (decl == null || !Str(G(decl["holder"], "kind"), "sequenced")) return Vd(false, "the receipt names an accumulator that is not sequenced in the session root");
                var holder = M(decl["holder"])!;
                if (!Str(r["session"], session) || !Str(r["aud"], subjectAud)) return Vd(false, "receipt for another session or audience");
                string? d = null;
                foreach (var e in byDigest)
                    if (IntentAcc.PcactnReservationDigest(e.Value) == (r["pcactn_digest"] as string)) { d = e.Key; break; }
                if (d == null) return Vd(false, "the receipt reserves for a PCActn that is not in the bundle");
                double admittedAt = Nm(byDigest[d]["iat"])!.Value;
                var ks = KeySetsAtFn((string)holder["root"]!, admittedAt);
                double? maxR = trustAcc != null && trustAcc.ContainsKey("max_receipt_age_s") ? Nm(trustAcc["max_receipt_age_s"]) * 1000 : null;
                double? maxK = trustAcc != null && trustAcc.ContainsKey("max_keyset_age_s") ? Nm(trustAcc["max_keyset_age_s"]) * 1000 : null;
                if (!VerifyReceipt(r, holder, ks.Sets, admittedAt, maxR, maxK, ks.Tracked, ks.Tracked == null ? ks.MinV : null))
                    return Vd(false, "not signed by a key the pinned sequencer root listed, or not fresh, at admission time");
                if (!(admittedAt <= Nm(r["expires_at"])!.Value)) return Vd(false, "the receipt had expired when the action was admitted");
                var val = ValueOf(decl, d);
                if (val == null) return null;
                if (!IntentAcc.ReceiptArithmeticOk(decl["agg"] as string, r, val.Value)) return Vd(false, "pre + delta does not give post for the reserved value");
                return Vd(true, null);
            }
            f.Check("accumulator.receipts", Port("receipt"), Core, r, b, R("receipt:" + Id(r["acc"]) + "#" + (r.ContainsKey("seq") ? Id(r["seq"]) : i.ToString())), "the reserved contribution (the effect params were withheld)");
        }

        // -- W-B artifacts
        var facts = Lst(b.GetValueOrDefault("facts"));
        for (int i = 0; i < facts.Count; i++)
        {
            var x = facts[i];
            var pk = x is D && G(x, "oracle") is string orc ? G(trust.GetValueOrDefault("oracleKeys"), orc) : null;
            Func<D?>? core = pk == null ? null : () =>
            {
                var w = OracleFacts.ValidateFactWire(x);
                if (w != null) return Vd(false, w);
                return IntentArtifacts.VerifyArtifactSig(OracleFacts.FactDomain, (D)x!, pk, null) ? Vd(true, null) : Vd(false, "bad oracle signature");
            };
            f.Check("fact.signature", Port("fact"), core, x, b, R("fact:" + i), "this fact (oracle key not pinned)");
        }
        var classifier = Lst(b.GetValueOrDefault("classifier"));
        for (int i = 0; i < classifier.Count; i++)
        {
            var x = classifier[i];
            var judge = x is D && G(x, "judge") is string jg ? jg : null;
            var judges = trust.GetValueOrDefault("judges") as L ?? new L();
            Func<D?>? core = judge == null || !judges.Any(j => Str(j, judge)) ? null : () =>
            {
                var w = IntentClassifier.ValidateVerdictWire(x);
                if (w != null) return Vd(false, w);
                if (!Str(G(x, "session"), session)) return Vd(false, "verdict for another session");
                return IntentArtifacts.VerifyArtifactSig(IntentClassifier.IntentClassifierDomain, (D)x!, judge, null) ? Vd(true, null) : Vd(false, "bad judge signature");
            };
            f.Check("classifier.signature", Port("classifier"), core, x, b, R("classifier:" + i), "this classifier verdict (judge not pinned)");
        }
        var offerSets = Lst(b.GetValueOrDefault("offer_sets"));
        for (int i = 0; i < offerSets.Count; i++)
        {
            var x = offerSets[i];
            object? key = null;
            if (siteKeys != null && x is D)
                foreach (var k in siteKeys) if (G(k, "kid") != null && Eq(G(k, "kid"), G(x, "kid")) && Str(G(k, "alg"), "ed25519")) { key = k; break; }
            var fkey = key;
            Func<D?>? core = key == null ? null : () =>
            {
                var w = OracleFacts.ValidateOfferSetWire(x);
                if (w != null) return Vd(false, w);
                if (!Str(G(x, "session"), session)) return Vd(false, "offer set for another session");
                return IntentArtifacts.VerifyArtifactSig(OracleFacts.OfferSetDomain, (D)x!, G(fkey, "pk"), null) ? Vd(true, null) : Vd(false, "bad site signature");
            };
            f.Check("offer_set.signature", Port("offerSet"), core, x, b, R("offer_set:" + i), "this offer set (site key not pinned)");
        }
        var labelKeys = new L();
        if (trust.GetValueOrDefault("labelKeys") is L tlk) labelKeys.AddRange(tlk);
        else if (siteKeys != null)
        {
            foreach (var k in siteKeys)
            {
                if (!Str(G(k, "alg"), "ed25519")) continue;
                labelKeys.Add(new D { ["site"] = schemaDoc.GetValueOrDefault("site"), ["kid"] = G(k, "kid"), ["pk"] = G(k, "pk") });
            }
        }
        var labelsL = Lst(b.GetValueOrDefault("labels"));
        for (int i = 0; i < labelsL.Count; i++)
        {
            var x = labelsL[i];
            Func<D?>? core = labelKeys.Count == 0 ? null : () =>
            {
                var e = ParamProvenance.VerifyLabels(x, labelKeys);
                if (e == null && !Str(G(x, "session"), session)) return Vd(false, "label receipt for another session");
                return Nul(e);
            };
            f.Check("labels.signature", Port("labels"), core, x, b, R("labels:" + i), "this label receipt (no site keys)");
        }

        // -- ported artifacts with no core format
        foreach (var v in Lst(b["verdicts"])) f.Check("verdict.signature", Port("verdict"), null, v, b, R("verdict:" + Id(G(v, "pcactn_digest"))), "site verdicts (no core format yet)");
        var settlements = Lst(b.GetValueOrDefault("settlements"));
        for (int i = 0; i < settlements.Count; i++) f.Check("settlement.signature", Port("settlement"), null, settlements[i], b, R("settlement:" + i), "settlement records (no core format yet)");

        // -- revocation
        if (epochs.Count == 0) f.Add("revocation.epoch", "unverified", new List<string>(), "no revocation epoch in the bundle");
        else if (!Truthy(S.GetValueOrDefault("revocation"))) f.Add("revocation.epoch", "fail", new List<string>(), "the session root names no revocation authority");
        else
        {
            var revO = S["revocation"];
            var authority = (string)G(revO, "key")!;
            double maxAgeMs = (Has(revO, "max_age_s") && G(revO, "max_age_s") != null ? Nm(G(revO, "max_age_s"))!.Value : 300) * 1000;
            Dictionary<string, string>? pin = null;
            if (G(revO, "pq_pk") is string rpq) pin = new Dictionary<string, string> { [authority] = rpq };
            bool historyOk = true;
            for (int i = 0; i < epochs.Count; i++)
            {
                var ev = epochs[i];
                var last = i > 0 ? epochs[i - 1] : null;
                var e = IntentRevocation.CheckSessionRevocation(ev, session, authority, new L(), Nm(G(G(ev, "epoch"), "issued_at"))!.Value, maxAgeMs, null, pin, last != null, last);
                if (e != null) historyOk = false;
                f.Verdict("revocation.history", Nul(e), R("epoch#" + i + ":" + Id(G(G(ev, "epoch"), "epoch"))));
            }
            if (subject == null) f.Add("revocation.epoch", "unverified", new List<string>(), "no subject action time");
            else
            {
                var ids = new L { IntentRevocation.SessionRevocationId(session) };
                foreach (var mo in Lst(b["maps"])) ids.Add(IntentRevocation.MapRevocationId((string)G(mo, "commit")!));
                foreach (var d in deltas) ids.Add(IntentRevocation.DeltaRevocationId((string)G(d, "id")!));
                int idx = EpochIdxAt(Nm(subject["iat"])!.Value);
                var ev = idx >= 0 ? epochs[idx] : null;
                if (ev == null) f.Add("revocation.epoch", "fail", new List<string>(), "every epoch was issued after the action");
                else if (!historyOk) f.Add("revocation.epoch", "fail", R("epoch:" + Id(G(G(ev, "epoch"), "epoch"))), "the bundled epochs are not one append-only chain");
                else
                {
                    var last = idx > 0 ? epochs[idx - 1] : null;
                    f.Verdict("revocation.epoch", Nul(IntentRevocation.CheckSessionRevocation(ev, session, authority, ids, Nm(subject["iat"])!.Value, maxAgeMs, null, pin, last != null, last)),
                        R("epoch:" + Id(G(G(ev, "epoch"), "epoch"))));
                }
            }
        }

        // -- anchors
        if (Truthy(schemaM.GetValueOrDefault("anchor"))) f.Add("schema.anchor", "unverified", R("schema"), "the anchor names a log position without an inclusion proof");
        var anchors = Lst(b["anchors"]);
        bool anyEvidenceAnchor = anchors.Any(a => Str(G(a, "kind"), "evidence"));
        if (!anyEvidenceAnchor) f.Add("anchor.inclusion", "unverified", R("anchor:evidence"), "the bundle is not anchored");
        foreach (var ao in anchors)
        {
            var kind = (string)G(ao, "kind")!;
            var dg = (string)G(ao, "digest")!;
            var rf = R("anchor:" + kind + ":" + Id(G(ao, "index")));
            bool anchorable = kind switch
            {
                "evidence" => dg == digest,
                "statement" => dg == (stmt["commit"] as string),
                "map" => mapCommits.Contains(dg),
                "schema" => dg == schemaDigest,
                "observation" => verified.Any(a => AtlasPca.Wallet.WalletCore.AnswerRef(a) == dg),
                _ => false,
            };
            if (!anchorable) { f.Add("anchor.inclusion", "fail", rf, "the anchor names an artifact that is not this one"); continue; }
            var g = trust.GetValueOrDefault("anchorGuardian");
            if (!Truthy(g)) { f.Add("anchor.inclusion", "unverified", rf, "no anchor-log guardian key supplied"); continue; }
            var h = G(ao, "signed_tree_head");
            var proof = G(ao, "proof");
            bool okA = Str(G(h, "principal"), EvidenceVerify.IntentAnchorLog)
                && Str(G(h, "instance_id"), G(g, "instance") as string)
                && Ledger.VerifyTreeHead(h, (string)G(g, "public")!, null)
                && NumEq(G(proof, "index"), G(ao, "index"))
                && NumEq(G(proof, "size"), G(h, "size"))
                && Ledger.VerifyLedgerInclusion((string)G(h, "root")!, proof, EvidenceVerify.AnchorCommit(kind, dg));
            f.Add("anchor.inclusion", okA, rf);
        }

        // -- attribution
        var signing = new HashSet<string>(StringComparer.Ordinal);
        void AddSigner(object? s) { if (s is string str) signing.Add(str); }
        AddSigner(S.GetValueOrDefault("signer"));
        AddSigner(g0["issuer"]);
        foreach (var d in deltas) AddSigner(G(d, "issuer"));
        foreach (var a in Lst(b["answers"])) AddSigner(G(a, "signer"));
        if (hasOpening) AddSigner(G(opening, "principal"));
        var keys2 = signing.ToList();
        keys2.Sort(StringComparer.Ordinal);
        M(summary["attribution"])!["keys_to_check"] = new L(keys2.Cast<object?>());
        if (!trust.ContainsKey("principals")) f.Add("principal.pinned", "unverified", keys2, "no pinned principal keys: the bundle names its own principals; verify these keys out of band");
        else
        {
            var pins = new Dictionary<string, object?>();
            foreach (var p in Lst(trust["principals"])) pins[(string)G(p, "key")!] = p;
            var unpinned = keys2.Where(k => !pins.ContainsKey(k)).ToList();
            var pqMismatch = new List<string>();
            foreach (var k in keys2)
            {
                var pin = pins.GetValueOrDefault(k);
                object? sp = null;
                foreach (var x in Lst(S["principals"])) if (Str(G(x, "key"), k)) { sp = x; break; }
                if (pin != null && !Eq(G(pin, "pq_pk"), G(sp, "pq_pk"))) pqMismatch.Add(k);
            }
            if (unpinned.Count > 0) f.Add("principal.pinned", "fail", unpinned, "signing keys that are not pinned principals");
            else if (pqMismatch.Count > 0) f.Add("principal.pinned", "fail", pqMismatch, "the session root binds a different PQ key than the pin");
            else
            {
                f.Add("principal.pinned", "pass", keys2);
                M(summary["attribution"])!["pinned"] = true;
            }
        }

        // -- plain-language facts (only what passed)
        var proven = new L();
        bool pinned = G(summary["attribution"], "pinned") is true;
        var adm = summary["admitted_under"];
        if (adm != null && Pass(f, "pcactn.verify")) proven.Add("The subject action was signed by the agent under " + adm + ", a grant signed by the session principal" + (pinned ? " (pinned)" : " (NOT pinned)") + ".");
        var consent = M(summary["consent"]);
        if (consent != null)
        {
            var sg = (string)consent["signer"]!;
            var who = pinned ? "Pinned principal key " + sg : "Session-root key " + sg + " (NOT pinned: not attributed to a known principal)";
            proven.Add(who + " signed a " + Id(consent["tier"]) + "-tier \"yes\" bound to this exact action (question " + Id(consent["question_id"]) + ").");
        }
        var chg = M(summary["charged"]);
        if (chg != null && Nm(chg["amount"])!.Value <= Nm(chg["bound"])!.Value) proven.Add("The charged amount " + Id(chg["amount"]) + " is within the confirmed value " + Id(chg["bound"]) + ".");
        if (refusals.Count > 0) proven.Add("The principal refused " + refusals.Count + " question(s): " + Join(refusals, ", ") + ".");
        long asked = Lng(G(summary["canary_accuracy"], "asked"));
        if (asked != 0) proven.Add("Canary accuracy " + Id(G(summary["canary_accuracy"], "correct")) + "/" + asked + ".");
        if (Pass(f, "accumulator.cap")) proven.Add("Every accumulator post is within the cap of the grant that admitted it.");
        if (Pass(f, "effect.frame")) proven.Add("The site reports no change to monitored state outside the write set.");
        summary["proven"] = proven;
    }
}
