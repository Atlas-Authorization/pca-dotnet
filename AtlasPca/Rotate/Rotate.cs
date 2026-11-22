// Key rotation and subtree revocation for PCA capability chains. Chains are re-issued with the real core builders (Issue.MintRoot /
// Issue.Delegate): every re-issued hop carries exactly the caveats of the hop it replaces, so a re-issue never widens authority.
// Each function returns the new chain together with a revocation record (a JSON tree) for the old key or subtree.
// Chains are JSON trees (a list of capability dictionaries); keys are Ed25519 keys (EdKey).
using System.Globalization;
using AtlasPca.Js;
using AtlasPca.Revoke;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Rotate;

/// <summary>A rotation's new chain and the revocation record of what it replaced.</summary>
public sealed record RotationResult(L Chain, D Revocation);

/// <summary>The compromised-key flow: one revocation record per capability of the compromised subtree (root to leaf) and the re-issued chain.</summary>
public sealed record CompromisedKeyResult(List<D> Revocations, L Reissued);

/// <summary>The part of a revocation registry that <see cref="RotateApi.ApplyRotation"/> needs.</summary>
public interface IRevocationSink
{
    /// <summary>input = {kind: "cap", value, reason?, revokedAt?}.</summary>
    Task Revoke(D input);
    Task<bool> Unrevoke(D key);
    /// <summary>The entry, or null.</summary>
    Task<D?> Lookup(string kind, string value);
}

/// <summary>Adapts a <see cref="RevocationRegistry"/> to the sink.</summary>
public sealed class RegistrySink(RevocationRegistry registry) : IRevocationSink
{
    public async Task Revoke(D input) => await registry.Revoke(input).ConfigureAwait(false);
    public Task<bool> Unrevoke(D key) => registry.Unrevoke(key);
    public Task<D?> Lookup(string kind, string value) => registry.Lookup(kind, value);
}

public static class RotateApi
{
    // a JavaScript property read: null / undefined throws (TypeError), a non-object has no members
    static object? Prop(object? o, string k)
    {
        if (o == null) throw new ArgumentException($"TypeError: cannot read '{k}' of {(o == null ? "null" : "value")}");
        return o is D d ? d.GetValueOrDefault(k) : null;
    }

    static bool Has(object? o, string k) => o is D d && d.ContainsKey(k);

    static void Put(D rec, string key, object? src, string srcKey)
    {
        if (Has(src, srcKey)) rec[key] = ((D)src!)[srcKey];
    }

    static Num NumOf(double d) => new(JsJson.NumberToString(d));

    static void CheckNow(object? now, string ctx)
    {
        if (now != null && !(now is Num n && double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && double.IsFinite(d)))
            throw new ArgumentException($"{ctx}: now must be a finite number");
    }

    static object RevokedAt(object? now) => now ?? NumOf(AtlasPca.ReplayClock.NowMs());

    static L RequireNonEmpty(object? chain, string ctx) => chain is L l && l.Count > 0 ? l : throw new ArgumentException($"{ctx}: empty chain");

    static EdKey Need(EdKey? k) => k ?? throw new ArgumentException("TypeError: expected a secret key");

    /// <summary>The caveats a child appended beyond its parent (caveats are append-only).</summary>
    static L AppendedCaveats(object? parent, object? child)
    {
        var cc = Prop(child, "caveats");
        var pc = Prop(parent, "caveats");
        if (cc is not L c || pc is not L p) throw new ArgumentException("malformed capability: caveats must be arrays");
        if (c.Count < p.Count) throw new ArgumentException("malformed chain: a child carries fewer caveats than its parent (not an attenuation)");
        return c.GetRange(p.Count, c.Count - p.Count);
    }

    static D Cap(object? hop) => hop as D ?? throw new ArgumentException("malformed capability");

    // ---- agent (leaf holder) key rotation ----

    /// <summary>Rotate the AGENT (leaf holder) key: the leaf's issuer (the parent's holder) re-signs the leaf, re-bound to <paramref name="newKey"/> with the leaf's exact caveats. Throws when <paramref name="oldHolder"/> is not the leaf's issuer. <paramref name="now"/>: a JSON number or null.</summary>
    public static RotationResult RotateAgentKey(object? chain, EdKey? oldHolder, EdKey? newKey, string? reason = null, object? now = null)
    {
        var ch = RequireNonEmpty(chain, "rotateAgentKey");
        if (ch.Count < 2) throw new ArgumentException("rotateAgentKey: a root-only chain has no leaf delegation to re-issue; use rotatePrincipalKey");
        var parent = ch[^2];
        var leaf = ch[^1];
        var signerPub = Need(oldHolder).Id;
        if (signerPub != Prop(leaf, "issuer") as string) throw new ArgumentException($"rotateAgentKey: oldHolderSecret (pub {signerPub}) is not the leaf's issuer {JsJson.ToJsString(Prop(leaf, "issuer"))}; the leaf is re-signed by its parent holder (the leaf issuer)");
        var newHolder = Need(newKey).Id;
        if (newHolder == Prop(leaf, "holder") as string) throw new ArgumentException("rotateAgentKey: newKeyPair is the key being rotated out");
        CheckNow(now, "rotateAgentKey");
        var newLeaf = Issue.Delegate(Cap(parent), newHolder, AppendedCaveats(parent, leaf), SuiteKey.Ed25519(oldHolder!));
        var newChain = ch.GetRange(0, ch.Count - 1);
        newChain.Add(newLeaf);
        var rec = new D();
        Put(rec, "capId", leaf, "id");
        Put(rec, "holder", leaf, "holder");
        Put(rec, "issuer", leaf, "issuer");
        rec["capIds"] = new L { Prop(leaf, "id") };
        rec["reason"] = reason ?? "agent key rotated";
        rec["revokedAt"] = RevokedAt(now);
        return new RotationResult(newChain, rec);
    }

    // ---- principal (root) key rotation / re-root ----

    /// <summary>Rotate the PRINCIPAL (root) key by re-rooting: mint a fresh root under <paramref name="newPrincipal"/> for the same holder and caveats, then re-issue every downstream hop onto it. <paramref name="holderSecrets"/> are the issuer secrets of the non-root hops, in chain order. Pass the full chain, or for a root-only chain just <paramref name="oldRoot"/> (ignored when a chain is given).</summary>
    public static RotationResult RotatePrincipalKey(object? chain, object? oldRoot, EdKey? oldPrincipal, EdKey? newPrincipal, IReadOnlyList<EdKey?>? holderSecrets = null, string? reason = null, object? now = null)
    {
        var chainV = chain ?? (IsTruthy(oldRoot) ? new L { oldRoot } : new L());
        var ch = RequireNonEmpty(chainV, "rotatePrincipalKey");
        var root = ch[0];
        if (Prop(root, "parent") != null || Has(root, "parent")) throw new ArgumentException("rotatePrincipalKey: chain[0] is not a root (it has a parent)");
        var oldPub = Need(oldPrincipal).Id;
        if (oldPub != Prop(root, "issuer") as string) throw new ArgumentException($"rotatePrincipalKey: oldPrincipalSecret (pub {oldPub}) is not the root's issuer {JsJson.ToJsString(Prop(root, "issuer"))}");
        var secrets = holderSecrets ?? Array.Empty<EdKey?>();
        if (secrets.Count != ch.Count - 1) throw new ArgumentException($"rotatePrincipalKey: expected {ch.Count - 1} holderSecrets (one per non-root hop), got {secrets.Count}");
        var newPub = Need(newPrincipal).Id;
        if (newPub == Prop(root, "issuer") as string) throw new ArgumentException("rotatePrincipalKey: newPrincipalKeyPair is the key being rotated out");
        CheckNow(now, "rotatePrincipalKey");
        if (Prop(root, "holder") is not string rootHolder || Prop(root, "caveats") is not L rootCaveats) throw new ArgumentException("malformed root capability");
        var newRoot = Issue.MintRoot(SuiteKey.Ed25519(newPrincipal!), rootHolder, null, rootCaveats);
        var newChain = new L { newRoot };
        for (var i = 1; i < ch.Count; i++)
        {
            var oldParent = ch[i - 1];
            var oldChild = ch[i];
            var signer = secrets[i - 1];
            var signerPub = Need(signer).Id;
            if (signerPub != Prop(oldChild, "issuer") as string) throw new ArgumentException($"rotatePrincipalKey: holderSecret for hop {i} (pub {signerPub}) is not that hop's issuer {JsJson.ToJsString(Prop(oldChild, "issuer"))}");
            if (!Has(oldChild, "holder")) throw new InvalidOperationException("canonicalize: unsupported type undefined"); // the re-signed hop would carry an undefined holder
            newChain.Add(Issue.Delegate(Cap(newChain[i - 1]), (string)Prop(oldChild, "holder")!, AppendedCaveats(oldParent, oldChild), SuiteKey.Ed25519(signer!)));
        }
        var rec = new D();
        Put(rec, "capId", root, "id");
        Put(rec, "issuer", root, "issuer");
        Put(rec, "holder", root, "holder");
        Put(rec, "subtreeRoot", root, "id");
        rec["capIds"] = ch.Select(c => Prop(c, "id")).ToList();
        rec["reason"] = reason ?? "principal key rotated (re-root)";
        rec["revokedAt"] = RevokedAt(now);
        return new RotationResult(newChain, rec);
    }

    static bool IsTruthy(object? v) => v switch { null => false, bool b => b, string s => s.Length > 0, Num n => double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && d != 0 && !double.IsNaN(d), _ => true };

    // ---- compromised-subtree revoke + re-issue ----

    static int IndexOfHolder(L chain, object? holder)
    {
        for (var i = 0; i < chain.Count; i++)
            if (holder is string h && Prop(chain[i], "holder") is string x && x == h) return i;
            else if (chain[i] == null) throw new ArgumentException("TypeError: cannot read 'holder' of null");
        return -1;
    }

    /// <summary>Treat <paramref name="compromisedHolder"/> as compromised: revoke the hop it first holds and every descendant, and re-issue from the nearest safe ancestor straight to <paramref name="newKey"/>, carrying the deepest leaf's caveats. <paramref name="ancestorSecret"/> must be the safe ancestor's holder key.</summary>
    public static RotationResult RevokeAndReissueSubtree(object? chain, object? compromisedHolder, EdKey? newKey, EdKey? ancestorSecret, string? reason = null, object? now = null)
    {
        var ch = RequireNonEmpty(chain, "revokeAndReissueSubtree");
        var idx = IndexOfHolder(ch, compromisedHolder);
        if (idx < 0) throw new ArgumentException($"revokeAndReissueSubtree: holder {JsJson.ToJsString(compromisedHolder)} is not in the chain");
        if (idx == 0) throw new ArgumentException("revokeAndReissueSubtree: the compromised holder is the root holder (no safe delegation ancestor); rotate the root with rotatePrincipalKey");
        var ancestor = ch[idx - 1];
        var subtreeRoot = ch[idx];
        var leaf = ch[^1];
        var ancestorPub = Need(ancestorSecret).Id;
        if (ancestorPub != Prop(ancestor, "holder") as string) throw new ArgumentException($"revokeAndReissueSubtree: ancestorSecret (pub {ancestorPub}) is not the safe ancestor's holder {JsJson.ToJsString(Prop(ancestor, "holder"))}");
        var newHolder = Need(newKey).Id;
        if (ch.Skip(idx).Any(c => Prop(c, "holder") is string h && h == newHolder)) throw new ArgumentException("revokeAndReissueSubtree: newKeyPair is a key held inside the compromised subtree");
        CheckNow(now, "revokeAndReissueSubtree");
        var newHop = Issue.Delegate(Cap(ancestor), newHolder, AppendedCaveats(ancestor, leaf), SuiteKey.Ed25519(ancestorSecret!));
        var reissued = ch.GetRange(0, idx);
        reissued.Add(newHop);
        var rec = new D();
        Put(rec, "capId", subtreeRoot, "id");
        rec["holder"] = compromisedHolder;
        Put(rec, "issuer", subtreeRoot, "issuer");
        Put(rec, "subtreeRoot", subtreeRoot, "id");
        rec["capIds"] = ch.Skip(idx).Select(c => Prop(c, "id")).ToList();
        rec["reason"] = reason ?? "delegation subtree compromised";
        rec["revokedAt"] = RevokedAt(now);
        return new RotationResult(reissued, rec);
    }

    /// <summary>End-to-end compromised-key handling: one revocation record per capability in the compromised subtree (root to leaf) plus the re-issued chain.</summary>
    public static CompromisedKeyResult CompromisedKeyFlow(object? chain, object? compromisedHolder, EdKey? newKey, EdKey? ancestorSecret, string? reason = null, object? now = null)
    {
        var ch = RequireNonEmpty(chain, "compromisedKeyFlow");
        var idx = IndexOfHolder(ch, compromisedHolder);
        if (idx < 0) throw new ArgumentException($"compromisedKeyFlow: holder {JsJson.ToJsString(compromisedHolder)} is not in the chain");
        var reissued = RevokeAndReissueSubtree(ch, compromisedHolder, newKey, ancestorSecret, reason, now).Chain;
        var subtreeRoot = ch[idx];
        var revokedAt = RevokedAt(now);
        var why = reason ?? "delegation subtree compromised";
        var revocations = new List<D>();
        foreach (var c in ch.Skip(idx))
        {
            var r = new D();
            Put(r, "capId", c, "id");
            Put(r, "holder", c, "holder");
            Put(r, "issuer", c, "issuer");
            Put(r, "subtreeRoot", subtreeRoot, "id");
            r["capIds"] = new L { Prop(c, "id") };
            r["reason"] = why;
            r["revokedAt"] = revokedAt;
            revocations.Add(r);
        }
        return new CompromisedKeyResult(revocations, reissued);
    }

    // ---- atomic rotate-and-revoke ----

    /// <summary>Revoke what a rotation replaced, all or nothing: every capability id the record(s) cover is revoked in <paramref name="sink"/>; if any revoke throws, the ones this call added are removed again and the error is rethrown. Refuses, before touching the sink, a record that names no capability id and a re-issued chain sharing an id with what is being revoked. Returns the ids revoked.</summary>
    public static async Task<List<string>> ApplyRotation(IRevocationSink sink, object? records, object? reissued = null)
    {
        var list = records is L l ? l : new L { records };
        var todo = new List<(string Id, object? Rec)>();
        var seen = new HashSet<string>();
        foreach (var r in list)
        {
            if (r == null) throw new ArgumentException("TypeError: cannot read 'capIds' of null");
            var capIds = Prop(r, "capIds");
            IEnumerable<object?> ids;
            if (capIds != null)
            {
                if (capIds is L cl) ids = cl;
                else if (capIds is string cs) ids = cs.Select(ch => (object?)ch.ToString());
                else throw new ArgumentException("TypeError: capIds is not iterable");
            }
            else ids = !Has(r, "capId") ? new L() : new L { Prop(r, "capId") };
            foreach (var id in ids)
            {
                if (id is not string s || s.Length == 0) throw new ArgumentException("applyRotation: a record names an invalid capability id");
                if (seen.Add(s)) todo.Add((s, r));
            }
        }
        if (todo.Count == 0) throw new ArgumentException("applyRotation: the record names no capability to revoke");
        var kept = new HashSet<object?>();
        if (reissued != null)
        {
            if (reissued is not L rl) throw new ArgumentException("TypeError: reissued.map is not a function");
            foreach (var c in rl) kept.Add(Prop(c, "id"));
        }
        foreach (var (id, _) in todo)
            if (kept.Contains(id)) throw new ArgumentException("applyRotation: the re-issued chain contains a capability that is being revoked");
        var added = new List<string>();
        try
        {
            foreach (var (id, r) in todo)
            {
                if (await sink.Lookup("cap", id).ConfigureAwait(false) == null) added.Add(id);
                await sink.Revoke(new D { ["kind"] = "cap", ["value"] = id, ["reason"] = Prop(r, "reason"), ["revokedAt"] = Prop(r, "revokedAt") }).ConfigureAwait(false);
            }
        }
        catch (Exception)
        {
            foreach (var id in added)
            {
                try { await sink.Unrevoke(new D { ["kind"] = "cap", ["value"] = id }).ConfigureAwait(false); }
                catch (Exception) { /* best effort: the original failure is the one to report */ }
            }
            throw;
        }
        return todo.Select(t => t.Id).ToList();
    }
}
