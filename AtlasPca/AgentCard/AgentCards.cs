using System.Globalization;
using System.Text.RegularExpressions;
using AtlasPca.A2aPkg;
using AtlasPca.InteropJs;
using J = AtlasPca.Jose.Jose;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.AgentCard;

/// <summary>Signed Agent Card plus AgentFacts attestor for PCA. The card signing surface is the A2A one (<see cref="A2aPca"/>: same canonical bytes,
/// same detached JWS, same <c>pca_passport</c> commitment), so a card issued here verifies there and the reverse. This class adds the card builder, the
/// AgentFacts document (self-asserted claims split from third-party attestations, each a detached JWS over a canonical statement), the well-known hosting
/// handlers and the registry entry. Values are parsed JSON (D, L, string, bool, Num, null); keys are JWK maps. Everything fails closed.
/// Shortcuts: attestation windows parse ISO 8601 only (a string the reference engine would accept through its legacy date fallback is refused here), a
/// date-time with no offset is read in the machine's zone as the reference engine reads it in its own, and <see cref="ToRegistryEntry"/> derives the card
/// URL for http(s) / ws(s) / ftp service URLs without credentials only.</summary>
public static class AgentCards
{
    public const string DefaultAlg = "EdDSA";
    public const string PcaAttestorId = "did:atlas:pca-attestor";
    public const string WellKnownAgentCardPath = "/.well-known/agent-card.json";
    public const string WellKnownAgentFactsPath = "/.well-known/agent-facts.json";
    const string StatementDomain = "atlas-pca/agentfacts/attestation/v1";

    /// <summary>The <c>@context</c> of a PCA AgentFacts document (a PCA profile, not NANDA-conformant).</summary>
    public static IReadOnlyList<string> AgentFactsContext => new[] { "https://www.w3.org/ns/did/v1", "https://nanda.ai/agentfacts/v1" };

    /// <summary>RFC 8785 canonical bytes (see <see cref="A2aCard.JcsBytes"/>).</summary>
    public static byte[] JcsBytes(object? value) => A2aCard.JcsBytes(value);

    /// <summary>The A2A 1.0 <c>AgentCard</c> problems (see <see cref="A2aCard.ValidateAgentCard1"/>).</summary>
    public static List<string> ValidateAgentCard1(object? card) => A2aCard.ValidateAgentCard1(card);

    static object? Undef => JsX.Undef;

    // ---- 1. signed Agent Card ----

    static D PassportRefFrom(object? p, object? uri)
    {
        if (p is L) return ReferenceEquals(uri, Undef) ? new D() : new D { ["uri"] = uri };
        if (p is not D m) throw JsX.TypeError("cannot use 'in' operator on a non-object");
        var o = new D();
        if (m.ContainsKey("id")) o["id"] = m["id"];
        if (m.ContainsKey("model_id")) { if (!ReferenceEquals(uri, Undef)) o["uri"] = uri; }
        else if (m.ContainsKey("uri")) o["uri"] = m["uri"];
        else if (!ReferenceEquals(uri, Undef)) o["uri"] = uri;
        return o;
    }

    /// <summary>Build an (unsigned) Agent Card from a PCA passport (an AgentPassport, or a bare <c>{id, uri?}</c>). <paramref name="opts"/>: <c>name</c>, <c>skills</c>,
    /// <c>url</c>, <c>description</c>, <c>version</c>, <c>passportUri</c>, <c>pcaProofRef</c>.</summary>
    public static D BuildAgentCard(object? passport, D opts)
    {
        var card = new D();
        if (opts.ContainsKey("name")) card["name"] = opts["name"];
        foreach (var k in new[] { "description", "url", "version", "skills" }) if (opts.ContainsKey(k)) card[k] = opts[k];
        card["pcaPassport"] = PassportRefFrom(passport, opts.TryGetValue("passportUri", out var pu) ? pu : Undef);
        if (opts.ContainsKey("pcaProofRef")) card["pcaProof"] = opts["pcaProofRef"];
        return card;
    }

    /// <summary>Sign an Agent Card (wire-identical to <see cref="A2aPca.IssueSignedAgentCard"/>).</summary>
    public static D IssueSignedAgentCard(object? card, object? signingKey, A2aPca.IssueOptions? opts = null) => A2aPca.IssueSignedAgentCard(card, signingKey, opts);

    /// <summary>Validate an Agent Card against its signatures (fail-closed): <c>{ok, reason?, passportRef?, passport?, pcaProof?}</c>. The wording after the first colon of a
    /// library failure is this port's own.</summary>
    public static D VerifyAgentCard(object? card, A2aPca.VerifyCardOptions opts) => A2aPca.VerifyCard(card, opts, true);

    // ---- 2. AgentFacts ----

    static byte[] StatementBytes(object? issuer, object? subject, object? attests, object? validFrom, object? validUntil) =>
        Pca.Canon(new D { ["d"] = StatementDomain, ["issuer"] = issuer, ["subject"] = subject, ["attests"] = attests, ["validFrom"] = validFrom, ["validUntil"] = validUntil });

    static D SignAttestation(object? issuer, object? subject, object? attests, object? validFrom, object? validUntil, object? keyO, object? alg, object? kid)
    {
        if (ReferenceEquals(subject, Undef) || ReferenceEquals(attests, Undef)) throw new ArgumentException("canonicalize: unsupported type undefined");
        var payload = StatementBytes(issuer, subject, attests, validFrom, ReferenceEquals(validUntil, Undef) ? null : validUntil);
        if (keyO is not D jwk) throw new ArgumentException("signDetached: the signing key must be a JWK");
        var sig = A2aJws.SignDetached(payload, jwk, alg as string ?? DefaultAlg, kid as string, false, new D { ["attestor"] = issuer });
        var o = new D { ["issuer"] = issuer, ["subject"] = subject, ["attests"] = attests, ["validFrom"] = validFrom };
        if (!ReferenceEquals(validUntil, Undef)) o["validUntil"] = validUntil;
        o["signature"] = sig;
        return o;
    }

    static object? ValidFromOf(D opts) =>
        opts.GetValueOrDefault("validFrom") ?? JsX.ToIsoString(opts.GetValueOrDefault("now") ?? (object)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

    static object? Member(D opts, string k) => opts.TryGetValue(k, out var v) ? v : Undef;

    /// <summary>Issue an AgentFacts document for a passport with PCA as the third-party attestor. <paramref name="opts"/>: <c>attestorKey</c> (a private JWK), <c>attests</c>,
    /// <c>selfAsserted</c>, <c>attestorId</c>, <c>agentId</c>, <c>alg</c>, <c>kid</c>, <c>validFrom</c>, <c>validUntil</c>, <c>now</c>, <c>context</c>. The self-asserted claims
    /// are echoed verbatim and never signed.</summary>
    public static D IssueAgentFacts(object? passport, D opts)
    {
        var agentId = opts.GetValueOrDefault("agentId") ?? JsX.At(passport, "id");
        var validFrom = ValidFromOf(opts);
        var issuer = opts.GetValueOrDefault("attestorId") ?? PcaAttestorId;
        var att = SignAttestation(issuer, agentId, Member(opts, "attests"), validFrom, Member(opts, "validUntil"), opts.GetValueOrDefault("attestorKey"), opts.GetValueOrDefault("alg"), opts.GetValueOrDefault("kid"));
        return new D
        {
            ["@context"] = opts.GetValueOrDefault("context") ?? AgentFactsContext.Cast<object?>().ToList(),
            ["id"] = agentId,
            ["type"] = "AgentFacts",
            ["selfAsserted"] = opts.GetValueOrDefault("selfAsserted") ?? new D(),
            ["attestations"] = new L { att },
        };
    }

    /// <summary>Append another third-party attestation to an AgentFacts document (a copy; the input is not mutated). <paramref name="opts"/> as <see cref="IssueAgentFacts"/>.</summary>
    public static D AddAttestation(object? facts, D opts)
    {
        var validFrom = ValidFromOf(opts);
        var issuer = opts.GetValueOrDefault("attestorId") ?? PcaAttestorId;
        var subject = JsX.At(facts, "id");
        var att = SignAttestation(issuer, subject, Member(opts, "attests"), validFrom, Member(opts, "validUntil"), opts.GetValueOrDefault("attestorKey"), opts.GetValueOrDefault("alg"), opts.GetValueOrDefault("kid"));
        var o = JsX.Spread(facts);
        var l = A2aPca.SpreadList(JsX.At(facts, "attestations"));
        l.Add(att);
        o["attestations"] = l;
        return o;
    }

    static D Check(object? issuer, bool ok, string? reason)
    {
        var c = new D { ["issuer"] = issuer, ["ok"] = ok };
        if (reason != null) c["reason"] = reason;
        return c;
    }

    static object IssuerOf(object? a) => a is D d && d.GetValueOrDefault("issuer") is string s ? s : "<unknown>";

    static Regex IsoRe => Rx.Get(@"^([+-][0-9]{6}|[0-9]{4})(?:-([0-9]{2})(?:-([0-9]{2}))?)?(?:T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]+))?)?(Z|[+-][0-9]{2}:[0-9]{2})?)?\z", RegexOptions.CultureInvariant);

    static long DaysFromCivil(long y, int m, int d)
    {
        if (m <= 2) y--;
        long era = (y >= 0 ? y : y - 399) / 400;
        long yoe = y - era * 400;
        long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
        long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * 146_097 + doe - 719_468;
    }

    /// <summary><c>Date.parse</c>: epoch ms, or NaN. ISO 8601 only (see the class note).</summary>
    internal static double ParseDate(object? sO)
    {
        if (sO is not string s) return double.NaN;
        var m = IsoRe.Match(s);
        if (!m.Success) return double.NaN;
        try
        {
            var ys = m.Groups[1].Value;
            if (ys == "-000000") return double.NaN;
            long y = long.Parse(ys.StartsWith('+') ? ys[1..] : ys, CultureInfo.InvariantCulture);
            int mo = m.Groups[2].Success ? int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture) : 1;
            int d = m.Groups[3].Success ? int.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture) : 1;
            bool timed = m.Groups[4].Success;
            int hh = timed ? int.Parse(m.Groups[4].Value, CultureInfo.InvariantCulture) : 0;
            int mi = timed ? int.Parse(m.Groups[5].Value, CultureInfo.InvariantCulture) : 0;
            int ss = m.Groups[6].Success ? int.Parse(m.Groups[6].Value, CultureInfo.InvariantCulture) : 0;
            int ms = m.Groups[7].Success ? int.Parse((m.Groups[7].Value + "00")[..3], CultureInfo.InvariantCulture) : 0;
            if (mo < 1 || mo > 12 || d < 1 || d > 31 || mi > 59 || ss > 59 || hh > 24 || (hh == 24 && (mi != 0 || ss != 0 || ms != 0))) return double.NaN;
            // a day past the month's end rolls into the next month, as the reference engine reads it (2026-02-30 is March 2)
            long baseMs = (DaysFromCivil(y, mo, 1) + (d - 1)) * 86_400_000L + ((hh * 60L + mi) * 60 + ss) * 1000 + ms;
            double v;
            var z = m.Groups[8].Success ? m.Groups[8].Value : null;
            if (z == "Z" || (z == null && !timed)) v = baseMs; // date-only forms are UTC
            else if (z != null)
            {
                int sign = z[0] == '-' ? -1 : 1;
                int oh = int.Parse(z.Substring(1, 2), CultureInfo.InvariantCulture), om = int.Parse(z.Substring(4, 2), CultureInfo.InvariantCulture);
                if (oh > 23 || om > 59) return double.NaN;
                v = baseMs - sign * (oh * 3600L + om * 60) * 1000.0;
            }
            else v = baseMs - TimeZoneInfo.Local.GetUtcOffset(DateTimeOffset.FromUnixTimeMilliseconds(baseMs)).TotalMilliseconds; // date-time with no offset: local time
            return Math.Abs(v) > 8.64e15 ? double.NaN : v;
        }
        catch (Exception) { return double.NaN; }
    }

    static D VerifyOne(object? a, object? docId, double now, A2aJws.Resolver? resolver)
    {
        var issuer = IssuerOf(a);
        if (!JsX.Truthy(a) || JsX.At(a, "subject") is not string subject || JsX.At(a, "attests") is not D || JsX.At(a, "validFrom") is not string)
            return Check(issuer, false, "attestation is malformed");
        if (!(docId is string ds && ds == subject)) return Check(issuer, false, $"attestation subject '{subject}' does not match agent id '{JsX.Str(docId)}'");
        var from = ParseDate(JsX.At(a, "validFrom"));
        if (double.IsNaN(from)) return Check(issuer, false, "attestation validFrom is not a valid date");
        if (!(double.IsFinite(now) && now >= from)) return Check(issuer, false, "attestation is not yet valid");
        var ad = (D)a!;
        if (ad.ContainsKey("validUntil"))
        {
            var until = ParseDate(ad["validUntil"]);
            if (double.IsNaN(until)) return Check(issuer, false, "attestation validUntil is not a valid date");
            if (!(now <= until)) return Check(issuer, false, "attestation has expired");
        }
        if (resolver == null) return Check(issuer, false, "no verification key or JWKS supplied");
        // the statement bytes are computed outside the verify guard in the reference: no canonical form is an error, not a refusal
        var payload = StatementBytes(Member(ad, "issuer"), subject, ad["attests"], ad["validFrom"], ad.GetValueOrDefault("validUntil"));
        if (ad.GetValueOrDefault("signature") == null) throw JsX.TypeError("cannot read properties of undefined (reading 'protected')");
        var r = A2aJws.VerifyDetached(payload, ad["signature"], resolver);
        if (!r.Ok) return Check(issuer, false, "signature did not verify: " + r.Reason);
        var ok = Check(issuer, true, null);
        ok["attests"] = ad["attests"];
        return ok;
    }

    /// <summary>Verify an AgentFacts document, fail-closed: a wrong subject, a closed or malformed validity window, or a signature that does not verify refuses that attestation,
    /// and any refused attestation refuses the document. <paramref name="opts"/>: <c>jwks</c> / <c>key</c> / <c>alg</c> / <c>now</c>. The result marks which claims are third-party
    /// attested and which merely self-asserted: <c>{ok, reason?, agentId, attestations[], attested, selfAsserted, claims}</c>.</summary>
    public static D VerifyAgentFacts(object? facts, D opts)
    {
        var saO = JsX.At(facts, "selfAsserted");
        var selfAsserted = saO as D ?? new D();
        var nowO = opts.GetValueOrDefault("now");
        double now = nowO != null ? IntentJs.NumOf(nowO) ?? double.NaN : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var listO = JsX.At(facts, "attestations");
        var id = JsX.At(facts, "id");
        if (listO is not L list) return Result(false, "agent facts has no attestations array", id, new L(), new D(), selfAsserted, new D());
        A2aJws.Resolver? resolver = null;
        if (list.Count > 0)
        {
            var (res, error) = A2aJws.ResolveVerifyKey(opts.GetValueOrDefault("jwks"), opts.ContainsKey("key"), opts.GetValueOrDefault("key"), opts.GetValueOrDefault("alg") as string);
            if (error != null)
            {
                var missing = new L();
                foreach (var a in list) missing.Add(Check(IssuerOf(a), false, "no verification key or JWKS supplied"));
                return Result(false, error, id, missing, new D(), selfAsserted, new D());
            }
            resolver = res;
        }
        var checks = new L();
        var attested = new D();
        bool allOk = true;
        foreach (var a in list)
        {
            var c = VerifyOne(a, id, now, resolver);
            checks.Add(c);
            if (c["ok"] is not true) { allOk = false; continue; }
            if (c.GetValueOrDefault("attests") is D at) foreach (var (k, v) in at) attested[k] = v;
        }
        var claims = new D();
        foreach (var k in selfAsserted.Keys) claims[k] = "self-asserted";
        foreach (var k in attested.Keys) claims[k] = "attested"; // attested wins on overlap
        return Result(allOk, allOk ? null : "one or more attestations did not verify", id, checks, attested, selfAsserted, claims);
    }

    static D Result(bool ok, string? reason, object? id, L checks, D attested, D self, D claims)
    {
        var o = new D { ["ok"] = ok };
        if (reason != null) o["reason"] = reason;
        if (!ReferenceEquals(id, Undef)) o["agentId"] = id;
        o["attestations"] = checks;
        o["attested"] = attested;
        o["selfAsserted"] = self;
        o["claims"] = claims;
        return o;
    }

    // ---- 3. well-known hosting ----

    /// <summary>A path handler: a request path in, the response <c>{status, headers, body}</c> out, or null when the path is not this handler's.</summary>
    public delegate D? PathHandler(string path);

    static D JsonResponse(object? value) => new()
    {
        ["status"] = new Num("200"),
        ["headers"] = new D { ["content-type"] = "application/json", ["cache-control"] = "no-store" },
        ["body"] = J.Stringify(value),
    };

    static string NormalizePath(string path)
    {
        int q = path.IndexOf('?');
        var noQuery = q == -1 ? path : path[..q];
        return noQuery.Length > 1 && noQuery.EndsWith('/') ? noQuery[..^1] : noQuery;
    }

    /// <summary>Serve a signed Agent Card at <paramref name="path"/> (null: <see cref="WellKnownAgentCardPath"/>); the handler returns null for any other path.</summary>
    public static PathHandler AgentCardHandler(object? card, string? path = null)
    {
        var target = NormalizePath(path ?? WellKnownAgentCardPath);
        var response = JsonResponse(card);
        return reqPath => NormalizePath(reqPath) == target ? response : null;
    }

    /// <summary>Serve an AgentFacts document at <paramref name="path"/> (null: <see cref="WellKnownAgentFactsPath"/>); the handler returns null for any other path.</summary>
    public static PathHandler AgentFactsHandler(object? facts, string? path = null)
    {
        var target = NormalizePath(path ?? WellKnownAgentFactsPath);
        var response = JsonResponse(facts);
        return reqPath => NormalizePath(reqPath) == target ? response : null;
    }

    // ---- 4. registry entry ----

    static string? WellKnownUrlFrom(object? serviceUrl, string path)
    {
        if (serviceUrl is not string s) return null;
        var u = AtlasPca.Jose.WhatwgUrl.TryParse(s);
        if (u == null || !(u.Protocol is "http:" or "https:" or "ws:" or "wss:" or "ftp:")) return null;
        return u.Protocol + "//" + u.Host + path;
    }

    /// <summary>Shape a registry entry from a signed card and an AgentFacts document (purely structural: it does NOT re-verify). Derives which advertised claim names a third party
    /// attests and which are only self-asserted.</summary>
    public static D ToRegistryEntry(object? card, object? facts)
    {
        var attestedSet = new List<string>();
        var atts = JsX.At(facts, "attestations");
        if (atts != null && !ReferenceEquals(atts, Undef))
        {
            if (atts is not L && atts is not string) throw JsX.TypeError("not iterable");
            if (atts is L al)
                foreach (var a in al)
                    if (JsX.Truthy(a) && JsX.At(a, "attests") is D at) foreach (var k in at.Keys) if (!attestedSet.Contains(k)) attestedSet.Add(k);
        }
        var selfOnly = new L();
        if (JsX.At(facts, "selfAsserted") is D sa) foreach (var k in sa.Keys) if (!attestedSet.Contains(k)) selfOnly.Add(k);
        var cardUrl = WellKnownUrlFrom(JsX.JsonOf(JsX.At(card, "url")), WellKnownAgentCardPath);
        var o = new D();
        var id = JsX.At(facts, "id");
        if (!ReferenceEquals(id, Undef)) o["id"] = id;
        var name = JsX.At(card, "name");
        if (!ReferenceEquals(name, Undef)) o["name"] = name;
        foreach (var k in new[] { "url", "version", "skills" }) { var v = JsX.At(card, k); if (!ReferenceEquals(v, Undef)) o[k] = v; }
        if (JsX.Truthy(JsX.At(card, "pcaPassport"))) o["passport"] = JsX.At(card, "pcaPassport");
        if (JsX.Truthy(JsX.At(card, "pcaProof"))) o["pcaProof"] = JsX.At(card, "pcaProof");
        o["card"] = card;
        if (cardUrl != null) o["agentCardUrl"] = cardUrl;
        o["facts"] = facts;
        o["attestedClaims"] = attestedSet.Cast<object?>().ToList();
        o["selfAssertedClaims"] = selfOnly;
        return o;
    }
}
