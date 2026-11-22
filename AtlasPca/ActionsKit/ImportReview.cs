// The confirmation flow and signed review attestations. This is the ONE non-monotone step in the system: a def WITHOUT a valid attestation has the top of
// the registry as its effective traits, and a valid one sets them to exactly what the reviewer signed. It counts only when a key pinned with the reviewer
// role has signed this exact def digest. Any change to the def or to the trait registry the reviewer saw makes the attestation stale and the def reverts
// to unconfirmed. Defs, pins and verdicts are JSON trees.
using System.Text.RegularExpressions;
using static AtlasPca.ActionsKit.ImportCommon;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ImportReview
{
    static readonly Regex TraitIdRe = new("\\A(?:[a-z][a-z0-9_]{0,31}\\.[a-z][a-z0-9_]{0,63})\\z", RegexOptions.CultureInvariant);

    static D Fail(string reason, string detail) => ImportJx.Obj(("ok", false), ("reason", reason), ("detail", detail));

    static bool Strings(object? v) => v is L l && l.All(x => x is string);

    static List<string> SortUniq(object? xs) => xs is L l ? Ak.SortUniq(l.Select(x => (string)x!)) : new List<string>();

    /// <summary>Is this def's confirmation valid? True only if: state is confirmed; the attestation covers THIS def digest and an accepted registry digest;
    /// its final traits are the def's declared traits; the signer is pinned with the reviewer role and the timestamp is inside the key's validity; the
    /// signature verifies. Never throws. Returns {ok: true, kid} or {ok: false, reason, detail}.</summary>
    public static D VerifyAttestation(D def, D pins, Dictionary<string, D> registry)
    {
        try
        {
            var pe = Actions.ReviewerPinsError(pins);
            if (pe != null) return Fail("bad_pins", pe);
            var review = def.GetValueOrDefault("review");
            if (ImportJx.Get(review, "state") is not "confirmed") return Fail("not_confirmed", "review.state is not confirmed");
            if (!ImportJx.Has(review, "attestation")) return Fail("no_attestation", "a confirmed def carries an attestation");
            var a = ImportJx.Get(review, "attestation") is { } av ? av as D ?? new D() : null!; // a scalar has no members (the attestation is unsigned); null throws below, like the reference
            if (a.GetValueOrDefault("sig") is not string sigText) return Fail("no_signature", "the attestation is unsigned");
            if (a.GetValueOrDefault("facts_digest") is not string) return Fail("malformed", "the attestation facts_digest must be a string");
            // shape before meaning: a missing / null / "" final_traits must not read as "no traits" for a read def
            bool dismissedOk = a.GetValueOrDefault("dismissed") is L;
            if (dismissedOk) foreach (var dd in (L)a["dismissed"]!) if (dd is not D ddm || ddm.GetValueOrDefault("trait") is not string || ddm.GetValueOrDefault("reason") is not string) { dismissedOk = false; break; }
            if (!Strings(a.GetValueOrDefault("final_traits")) || !dismissedOk || !ImportJx.IsInt(a.GetValueOrDefault("ts")) || a.GetValueOrDefault("reviewer_kid") is not string kidText)
                return Fail("malformed", "the attestation final_traits, dismissed, ts or reviewer_kid is malformed");
            if (!JsXEq(Actions.DefDigest(def), a.GetValueOrDefault("def_digest"))) return Fail("digest_mismatch", "the def changed after it was reviewed");
            var accepted = new List<object?> { Actions.TraitsDigest(registry) };
            if (pins.GetValueOrDefault("traits_digests") is L td) accepted.AddRange(td);
            if (!accepted.Contains(a.GetValueOrDefault("traits_digest"))) return Fail("traits_digest_mismatch", "the trait registry changed since the review");
            if (!SortUniq(a["final_traits"]).SequenceEqual(SortUniq(def.GetValueOrDefault("traits")))) return Fail("final_traits_mismatch", "the attested final traits are not the def's declared traits");
            var fin = (L)a["final_traits"]!;
            foreach (var d in (L)a["dismissed"]!)
            {
                var dm = (D)d!;
                if (fin.Contains(dm["trait"]) || ActionConfirmation.BlankReason((string)dm["reason"]!)) return Fail("dismissed_conflict", "a dismissed trait is also final, or has no reason");
            }
            D? key = null;
            foreach (var k in (L)pins["keys"]!) if (kidText == (string?)((D)k!).GetValueOrDefault("kid")) { key = (D)k!; break; }
            if (key == null) return Fail("unknown_reviewer", "no pinned key '" + kidText + "'");
            if (!((L)key["roles"]!).Contains("reviewer")) return Fail("not_a_reviewer", "key '" + key["kid"] + "' does not hold the reviewer role");
            double ts = ImportJx.Dbl(a["ts"])!.Value;
            if ((key.ContainsKey("not_before") && ts < ImportJx.Dbl(key["not_before"])!.Value) || (key.ContainsKey("not_after") && ts > ImportJx.Dbl(key["not_after"])!.Value))
                return Fail("outside_validity", "the attestation time is outside the key validity");
            var body = new D(a);
            body.Remove("sig");
            return IntentJs.VerifyEd(key["pk"], ActionConfirmation.ReviewMessage(body), sigText)
                ? ImportJx.Obj(("ok", true), ("kid", key["kid"])) : Fail("bad_signature", "the attestation signature is invalid");
        }
        catch (Exception e) { return Fail("malformed", e.Message); }
    }

    static bool JsXEq(object? a, object? b) => AtlasPca.InteropJs.JsX.StrictEq(a, b);

    /// <summary>The state that counts: a confirmed def with an invalid attestation is stale (it behaves as unreviewed).</summary>
    public static object? ReviewStatus(D def, D pins, Dictionary<string, D> registry)
    {
        if (def.GetValueOrDefault("review") == null) throw new InvalidOperationException("Cannot read properties of undefined (reading 'state')");
        var st = ImportJx.Get(def["review"], "state");
        if (st is not "confirmed") return st;
        return VerifyAttestation(def, pins, registry)["ok"] is true ? "confirmed" : "stale";
    }

    /// <summary>Defs whose confirmation no longer holds go back to unreviewed (the attestation is dropped). Others are returned as they are.</summary>
    public static D RevertStale(D def, D pins, Dictionary<string, D> registry)
    {
        if (ReviewStatus(def, pins, registry) is not "stale") return def;
        var review = new D((D)def["review"]!);
        review.Remove("attestation");
        review["state"] = "unreviewed";
        var o = new D(def) { ["review"] = review };
        return o;
    }

    // ---- review view and confirm ----

    static readonly string[] Suspect = { "pca.money_moving", "pca.privilege_change", "pca.code_execution", "pca.destructive", "pca.external_communication" };
    static readonly string[] Next = { "pca.credential_access", "pca.data_export", "pca.regulated_data", "pca.public_exposure", "pca.infra_mutation", "pca.legal_binding", "pca.impersonation", "pca.persistence" };

    /// <summary>The profile the def would have once reviewed (its own facts and traits, without the review marker that every unreviewed def shares).</summary>
    static D Intrinsic(D def, Dictionary<string, D> registry) => (D)ActionEffective.EffectiveWith(def, registry, null)["hint"]!;

    /// <summary>Review queue priority: 0 = a core suspect trait, 1 = other risky, 2 = the rest. Lower first.</summary>
    public static int ReviewPriority(D def, Dictionary<string, D> registry)
    {
        var cl = new HashSet<object?>(((L)Intrinsic(def, registry)["closure"]!));
        foreach (var t in Suspect) if (cl.Contains(t)) return 0;
        foreach (var t in Next) if (cl.Contains(t)) return 1;
        return 2;
    }

    /// <summary>Defs in review order: suspect traits first, then by risk (highest first), then by verb. Deterministic.</summary>
    public static List<D> ReviewQueueOrder(IEnumerable<D> defs, Dictionary<string, D> registry) =>
        defs.Select(d => (Def: d, P: ReviewPriority(d, registry), R: ImportJx.Dbl(((D)Intrinsic(d, registry)["eff"]!)["risk"])!.Value))
            .OrderBy(x => x.P).ThenByDescending(x => x.R).ThenBy(x => ImportJx.JsStr(x.Def["verb"]), StringComparer.Ordinal).Select(x => x.Def).ToList();

    /// <summary>Traits implied by the def's own facts (effects, roles, tags, scope, reversibility).</summary>
    internal static List<string> ImpliedTraits(D def) => ActionEffective.ImpliedTraits(Actions.Normalize(def));

    /// <summary>The reviewer's view of a def: facts, implied and suggested traits, the effective profile, the policy card, what changed since previous.</summary>
    public static D PrepareReview(D def, Dictionary<string, D> registry, D? previous = null)
    {
        var eff = ActionEffective.EffectiveWith(def, registry, null);
        // the card shows what the reviewer would be signing (the hint), not the all-traits view that applies until they sign
        var shown = new D(eff);
        ImportJx.PutAll(shown, (D)eff["hint"]!);
        shown["confirmed"] = true;
        var sbo = ImportJx.Get(def.GetValueOrDefault("review"), "suggested_by");
        var added = ImportJx.Get(sbo, "added");
        var changes = new L();
        if (previous != null)
        {
            var a = Strip(previous); var b = Strip(def);
            var ks = new SortedSet<string>(a.Keys, StringComparer.Ordinal);
            foreach (var k in b.Keys) ks.Add(k);
            foreach (var k in ks) if (!SameJsonMember(a, b, k)) changes.Add(k);
        }
        return ImportJx.Obj(("verb", def.GetValueOrDefault("verb")), ("def_digest", Actions.DefDigest(def)), ("state", ImportJx.Get(def.GetValueOrDefault("review"), "state")),
            ("declared_traits", Ak.ToL(SortUniq(def.GetValueOrDefault("traits")))), ("implied_traits", Ak.ToL(ImpliedTraits(def))),
            ("suggested", added ?? ImportJx.Obj(("traits", new L()), ("roles", new D()), ("tags", new D()))),
            ("effective", eff), ("card", ActionDerive.CardOf(def, shown, registry)), ("changes", changes), ("priority", ImportJx.N(ReviewPriority(def, registry))));
    }

    /// <summary>JSON.stringify(a[k]) === JSON.stringify(b[k]) where an absent member is undefined.</summary>
    static bool SameJsonMember(D a, D b, string k)
    {
        bool pa = a.ContainsKey(k), pb = b.ContainsKey(k);
        if (!pa || !pb) return !pa && !pb;
        return AtlasPca.Js.JsJson.Stringify(a[k]) == AtlasPca.Js.JsJson.Stringify(b[k]);
    }

    static D Strip(D d)
    {
        var o = new D(d);
        foreach (var k in new[] { "review", "examples", "source", "since" }) o.Remove(k);
        return o;
    }

    /// <summary>Review one def: validates the decision, writes the final traits, signs an attestation over the resulting digest and returns the confirmed def.
    /// Throws ActionKitError (bad_confirm, undismissed_suggestion, not_reviewer) rather than guessing. pins: when not null, the reviewer must be pinned with
    /// the reviewer role under this key. finalTraits: the final DECLARED trait set. dismissed: [{trait, reason}] or null. ts: seconds, a non-negative safe integer.</summary>
    public static D ConfirmDef(D def, Dictionary<string, D> registry, string reviewerKid, byte[] reviewerSecret, D? pins, L finalTraits, L? dismissed, object? ts)
    {
        if (!ImportJx.IsInt(ts) || ImportJx.Dbl(ts)! < 0) throw new ActionKitError("bad_confirm", "ts must be a non-negative integer");
        var fin = SortUniq(finalTraits);
        if (fin.Count != finalTraits.Count) throw new ActionKitError("bad_confirm", "final traits must be distinct");
        foreach (var t in fin)
        {
            if (!TraitIdRe.IsMatch(t) || !registry.ContainsKey(t)) throw new ActionKitError("bad_confirm", "unknown trait '" + t + "'");
            if (t == "pca.unreviewed") throw new ActionKitError("bad_confirm", "'pca.unreviewed' is the review marker, not a final trait");
        }
        // copied: a batch shares one dismissal list across defs
        var dis = new L();
        if (dismissed != null) foreach (var d in dismissed) dis.Add(ImportJx.Obj(("trait", ImportJx.Get(d, "trait")), ("reason", ImportJx.Get(d, "reason"))));
        var dset = new List<object?>();
        foreach (var d in dis)
        {
            var reason = ImportJx.Get(d, "reason"); var trait = ImportJx.Get(d, "trait");
            if (reason is not string rs || ImportJx.JsTrim(rs).Length == 0 || rs.Length > 256) throw new ActionKitError("bad_confirm", "dismissed trait '" + ImportJx.JsStr(trait) + "' needs a reason (1..256 characters)");
            if (dset.Contains(trait)) throw new ActionKitError("bad_confirm", "trait '" + ImportJx.JsStr(trait) + "' is dismissed twice");
            dset.Add(trait);
            if (trait is string ts1 && fin.Contains(ts1)) throw new ActionKitError("bad_confirm", "trait '" + ImportJx.JsStr(trait) + "' is both final and dismissed");
        }
        // what the reviewer was shown: the importer's and the suggesters' traits, plus what the def already declares
        var sbAdded = ImportJx.Get(ImportJx.Get(def.GetValueOrDefault("review"), "suggested_by"), "added");
        var shownAll = new L();
        if (def.GetValueOrDefault("traits") is L dtl) shownAll.AddRange(dtl);
        if (ImportJx.Get(sbAdded, "traits") is L satl) shownAll.AddRange(satl);
        var shown = SortUniq(shownAll);
        var seed = new List<string>(fin);
        seed.AddRange(ImpliedTraits(def));
        var covered = new HashSet<string>(Actions.Closure(registry, SortUniq(new L(seed.Cast<object?>())).Cast<object?>()), StringComparer.Ordinal);
        foreach (var t in shown)
        {
            if (fin.Contains(t) || covered.Contains(t)) continue;
            if (!dset.Contains(t)) throw new ActionKitError("undismissed_suggestion", "trait '" + t + "' was suggested and is not in the final set: record it as dismissed with a reason");
        }
        foreach (var t in dset) if (t is not string tsx || !shown.Contains(tsx)) throw new ActionKitError("bad_confirm", "trait '" + ImportJx.JsStr(t) + "' was never suggested; nothing to dismiss");
        if (pins != null)
        {
            var pe = Actions.ReviewerPinsError(pins);
            if (pe != null) throw new ActionKitError("bad_confirm", pe);
            D? key = null;
            foreach (var k in (L)pins["keys"]!) if (reviewerKid == (string?)((D)k!).GetValueOrDefault("kid")) { key = (D)k!; break; }
            if (key == null || !((L)key["roles"]!).Contains("reviewer")) throw new ActionKitError("not_reviewer", "key '" + reviewerKid + "' is not pinned with the reviewer role");
            if (!JsXEq(EdKey.FromSeed(reviewerSecret).Id, key.GetValueOrDefault("pk"))) throw new ActionKitError("not_reviewer", "the secret does not belong to the pinned key '" + reviewerKid + "'");
        }
        var body = new D(def);
        if (fin.Count == 0) body.Remove("traits"); else body["traits"] = Ak.ToL(fin);
        var digest = Actions.DefDigest(body);
        // the facts of the verb this definition publishes: the verifier will recompute them from the schema and compare
        var verb = (D)ActionDerive.ToSchemaVerb(body, registry, null)["verb"]!;
        var att = ActionConfirmation.SignReview(ImportJx.Obj(("def_digest", digest), ("traits_digest", Actions.TraitsDigest(registry)), ("facts_digest", Actions.FactsDigest(verb)),
            ("final_traits", Ak.ToL(fin)), ("dismissed", dis), ("reviewer_kid", reviewerKid), ("ts", ts)), reviewerSecret);
        var rv = new D((D)def["review"]!) { ["state"] = "confirmed", ["attestation"] = att };
        var o = new D(body) { ["review"] = rv };
        var bad = Actions.ValidateDef(o);
        if (bad != null) throw new ActionKitError("bad_confirm", "the confirmed def is invalid: " + bad);
        return o;
    }
}
