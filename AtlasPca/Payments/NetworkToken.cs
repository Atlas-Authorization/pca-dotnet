// Agent payment network tokens (packages/pca-payments network-token.ts): a PCA grant holder bound to an OPAQUE network-token reference (never a PAN),
// the controls derived from the rail limits, the settlement metadata that joins a card-network record to the PCA ledger entry, and the charge that carries
// the PCActn digest. Heuristic-free: every check is exact and any malformed input is a refusal. The partner adapters make no network call and are not ported.
using System.Text;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Payments;

public static partial class NetworkTokens
{
    public const string BindingKind = "pca.network_token_binding";
    static readonly Regex RefRe = new(@"\A[A-Za-z0-9_.:-]{8,128}\z", RegexOptions.CultureInvariant);

    static bool Luhn(string d)
    {
        int sum = 0; bool dbl = false;
        for (int i = d.Length - 1; i >= 0; i--)
        {
            int n = d[i] - '0';
            if (dbl) { n *= 2; if (n > 9) n -= 9; }
            sum += n; dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    /// <summary>True when a maximal digit run (whitespace and hyphens removed) is 13..19 long and Luhn-valid. Whole runs only: no sliding windows.</summary>
    public static bool LooksLikePan(string s)
    {
        var sb = new StringBuilder();
        foreach (var c in s) if (!Js.IsWs(c) && c != '-') sb.Append(c);
        var t = sb.ToString();
        int i = 0;
        while (i < t.Length)
        {
            if (t[i] is < '0' or > '9') { i++; continue; }
            int j = i;
            while (j < t.Length && t[j] is >= '0' and <= '9') j++;
            if (j - i >= 13 && j - i <= 19 && Luhn(t[i..j])) return true;
            i = j;
        }
        return false;
    }

    /// <summary>Null when <paramref name="r"/> is an opaque handle (8..128 chars of <c>[A-Za-z0-9_.:-]</c>, not PAN-shaped), else the reason.</summary>
    public static string? TokenRefError(object? r)
    {
        if (r is not string s || !RefRe.IsMatch(s)) return "token_ref_malformed";
        return LooksLikePan(s) ? "token_ref_looks_like_pan" : null;
    }

    static string Need(object? o, string k) => Js.Has(o, k) ? Pca.HashCanonical(Js.Prop(o, k)) : throw new InvalidOperationException("canonicalize: unsupported type undefined");

    /// <summary>The body the holder signs a digest of: <c>{kind, v: 1, provider, token_ref, grant_digest, issuer_nonce, holder}</c> (an absent member cannot be canonicalized: throws).</summary>
    static JD BodyOf(object? b)
    {
        foreach (var k in new[] { "provider", "token_ref", "grant_digest", "issuer_nonce", "holder" })
            if (!Js.Has(b, k)) throw new InvalidOperationException("canonicalize: unsupported type undefined");
        return new JD
        {
            ["kind"] = BindingKind, ["v"] = new Num("1"), ["provider"] = Js.Prop(b, "provider"), ["token_ref"] = Js.Prop(b, "token_ref"),
            ["grant_digest"] = Js.Prop(b, "grant_digest"), ["issuer_nonce"] = Js.Prop(b, "issuer_nonce"), ["holder"] = Js.Prop(b, "holder"),
        };
    }

    /// <summary>The exact bytes the holder signs: the UTF-8 of the canonical-JSON digest of the body (domain-separated by <c>kind</c>).</summary>
    public static byte[] BindingMessage(object? b) => Encoding.UTF8.GetBytes(Pca.HashCanonical(BodyOf(b)));

    /// <summary>Bind a network-token reference to a grant holder. <paramref name="o"/>: <c>{provider, tokenRef, grant, issuerNonce, holderSecret (32-byte seed), holderPublic (bytes)}</c>.</summary>
    public static JD BindNetworkToken(object? o)
    {
        var e = TokenRefError(Js.Prop(o, "tokenRef"));
        if (e != null) throw new ArgumentException("bindNetworkToken: " + e);
        var nonce = Js.Prop(o, "issuerNonce");
        if (Js.Length(nonce, Js.Has(o, "issuerNonce")) is double len ? len < 16 : false) throw new ArgumentException("bindNetworkToken: issuer nonce must be at least 16 chars");
        if (Js.Prop(o, "holderSecret") is not byte[] seed || Js.Prop(o, "holderPublic") is not byte[] pub) throw new ArgumentException("bindNetworkToken: holderSecret and holderPublic are required");
        var core = new JD
        {
            ["provider"] = Js.Prop(o, "provider"), ["token_ref"] = Js.Prop(o, "tokenRef"), ["grant_digest"] = Need(o, "grant"), ["issuer_nonce"] = nonce, ["holder"] = Pca.B64u(pub),
        };
        using var key = EdKey.FromSeed(seed);
        var res = new JD { ["kind"] = BindingKind };
        foreach (var kv in core) res[kv.Key] = kv.Value;
        res["binding_proof"] = Pca.B64u(key.Sign(BindingMessage(core)));
        return res;
    }

    /// <summary>Null when the binding is valid, else the reason. Total. <paramref name="expect"/>: <c>{grant, holder, issuerNonce, provider?}</c>.</summary>
    public static string? VerifyNetworkTokenBinding(object? b, object? expect)
    {
        try
        {
            if (!(b is JD x) || Js.Prop(x, "kind") is not BindingKind) return "binding_malformed";
            var e = TokenRefError(Js.Prop(x, "token_ref"));
            if (e != null) return e;
            if (Js.Prop(x, "provider") is not string p || p.Length == 0 || (Js.Has(expect, "provider") && !(Js.Prop(expect, "provider") is string ep && ep == p))) return "provider_mismatch";
            var expectedGrant = Need(expect, "grant"); // hashCanonical(expect.grant) is evaluated whatever x carries
            if (!(Js.Prop(x, "grant_digest") is string gd && gd == expectedGrant)) return "grant_digest_mismatch";
            if (!(Js.Prop(x, "holder") is string h && Js.Prop(expect, "holder") is string eh && h == eh)) return "holder_mismatch";
            if (!(Js.Prop(x, "issuer_nonce") is string n && Js.Prop(expect, "issuerNonce") is string en && n == en)) return "issuer_nonce_mismatch";
            var pub = Pca.B64uDecode(h) ?? throw new FormatException("decodeKey");
            var sig = Pca.B64uDecode(Js.Prop(x, "binding_proof")) ?? throw new FormatException("decodeKey");
            var msg = BindingMessage(x);
            return pub.Length == 32 && sig.Length == 64 && Pca.VerifyEd25519Strict(pub, msg, sig) ? null : "binding_proof_invalid";
        }
        catch (Exception) { return "binding_malformed"; }
    }

    /// <summary>The network-side controls: an upper-bounded copy of the rail limits plus <c>metadata: {grant_digest}</c>.</summary>
    public static JD ControlsFromLimits(object? limits, object? grant)
    {
        var o = new JD
        {
            ["currency"] = Js.Prop(limits, "currency"), ["perAuthorizationMax"] = Js.Prop(limits, "perAuthorizationMax"), ["totalMax"] = Js.Prop(limits, "totalMax"),
            ["categories"] = Js.SpreadList(Js.Prop(limits, "categories")), ["merchants"] = Js.SpreadList(Js.Prop(limits, "merchants")),
        };
        if (Js.Has(limits, "expiresAt")) o["expiresAt"] = Js.Prop(limits, "expiresAt");
        o["metadata"] = new JD { ["grant_digest"] = Pca.HashCanonical(grant) };
        return o;
    }

    /// <summary>The metadata a charge carries (fixed keys; values are digests: no PII, no PAN).</summary>
    public static JD SettlementMetadata(object? b, object? pcactnDigest) =>
        new() { ["pca_grant"] = Js.Prop(b, "grant_digest"), ["pca_pcactn"] = pcactnDigest, ["pca_token_ref"] = Js.Prop(b, "token_ref") };

    /// <summary>A network settlement record joins the ledger entry only if all three echoed values match exactly: <c>{ok: true}</c> or <c>{ok: false, reasons}</c>.
    /// <paramref name="expected"/>: <c>{grantDigest, pcactnDigest, tokenRef}</c>; <paramref name="record"/>: <c>{metadata?}</c>.</summary>
    public static JD ReconcileNetworkSettlement(object? expected, object? record)
    {
        var m = Js.Prop(record, "metadata");
        if (m == null) m = new JD();
        var reasons = new JL();
        var echoed = Js.Prop(m, "pca_pcactn");
        // a settlement without the PCActn digest never joins, even if the expectation is empty too
        if (echoed is not string es || es.Length == 0 || (Js.Length(Js.Prop(expected, "pcactnDigest"), Js.Has(expected, "pcactnDigest")) is double l && l == 0)) reasons.Add("pcactn_digest_missing");
        if (!Rails.StrictEq(m, "pca_grant", expected, "grantDigest")) reasons.Add("grant_digest_mismatch");
        if (!Rails.StrictEq(m, "pca_pcactn", expected, "pcactnDigest")) reasons.Add("pcactn_digest_mismatch");
        if (!Rails.StrictEq(m, "pca_token_ref", expected, "tokenRef")) reasons.Add("token_ref_mismatch");
        return reasons.Count == 0 ? new JD { ["ok"] = true } : new JD { ["ok"] = false, ["reasons"] = reasons };
    }

    /// <summary>The one way to start a network-token charge: builds the signed PCActn of the charge and returns the metadata for the network request, derived from THAT
    /// PCActn's digest. Returns <c>{pcactn, node, metadata, pcactnDigest}</c>.</summary>
    public static JD ChargeWithNetworkToken(object? binding, object? mandate, object? charge, object? opts)
    {
        if (TokenRefError(Js.Prop(binding, "token_ref")) != null) throw new ArgumentException("chargeWithNetworkToken: bad binding");
        if (!(Js.Prop(binding, "grant_digest") is string gd && gd == Pca.HashCanonical(Js.Prop(mandate, "grant")))) throw new ArgumentException("chargeWithNetworkToken: binding is for another grant");
        var r = Payments.ChargeToPCActn(mandate, charge, opts);
        var digest = Pca.HashCanonical(r["pcactn"]);
        return new JD { ["pcactn"] = r["pcactn"], ["node"] = r["node"], ["metadata"] = SettlementMetadata(binding, digest), ["pcactnDigest"] = digest };
    }
}
