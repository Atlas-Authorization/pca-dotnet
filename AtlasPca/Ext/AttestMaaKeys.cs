// Trust in the Azure MAA token-signing keys (attest-maa-keys.ts + attest-maa-pins.ts): the guarded certificate-set fetch over an INJECTED transport (https origin only, size limits, no redirect), the JWKS
// evaluation (a self-signed certificate whose single CN is the issuer URL, or an x5c chain to a pinned root and intermediate), the rotation-safe trust store (memory or durable key/value) with re-pin under a
// release-signed manifest, multi-vantage corroboration (k of n vantages must agree on the key set) and the built-in release-signed pins. Values are the JSON tree; every refusal is a code, never a pass.
using System.Formats.Asn1;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The answer of an injected certs transport: <c>Ok</c> (2xx), <c>Status</c>, <c>Url</c> (the final URL; null: as requested), <c>ContentLength</c> (the declared header; null: none) and the <c>Body</c>.</summary>
public sealed record MaaFetchResponse(bool Ok, int Status, string? Url, string? ContentLength, byte[] Body);

/// <summary>An injected certs transport: the GET of <c>url</c> (the library requires no redirect following, a 10 s timeout is the transport's business).</summary>
public delegate MaaFetchResponse MaaFetch(string url);

/// <summary>Persistence of the last accepted key state per issuer.</summary>
public interface IMaaKeyStateStore
{
    object? Get(string issuer);
    void Set(string issuer, object? state);
}

/// <summary>The in-memory state store (a deep copy is kept).</summary>
public sealed class MemoryMaaKeyStateStore : IMaaKeyStateStore
{
    readonly Dictionary<string, object?> _m = new(StringComparer.Ordinal);
    public object? Get(string issuer) => _m.GetValueOrDefault(issuer);
    public void Set(string issuer, object? state) => _m[issuer] = IntentJs.Normalize(state);
    public Dictionary<string, object?> Snapshot() => new(_m);
}

/// <summary>The durable state store over a key/value store (key <c>maa-keys/&lt;issuer&gt;</c>); an older state never replaces a newer one.</summary>
public sealed class DurableMaaKeyStateStore(IDurableKv kv) : IMaaKeyStateStore
{
    static string K(string issuer) => "maa-keys/" + issuer;

    public object? Get(string issuer) { var v = kv.GetValue(K(issuer)); return ReferenceEquals(v, DurableState.Undefined) ? null : v; }

    public void Set(string issuer, object? state) =>
        kv.UpdateValue(K(issuer), prev =>
        {
            var p = ReferenceEquals(prev, DurableState.Undefined) || prev == null ? null : AttestMaaKeys.ParseState(prev, issuer);
            // a state without a numeric fetchedAtMs compares false (undefined), so it replaces whatever is stored
            var at = state is D sd && IntentJs.NumOf(sd.GetValueOrDefault("fetchedAtMs")) is double f ? f : double.NaN;
            return p != null && AttestMaaKeys.N(p["fetchedAtMs"]) > at ? DurableState.Undefined : state;
        });
}

/// <summary>The trust store of one policy: <c>GetTrustAnchors</c> answers the pinned signing-key SPKIs of an issuer, fetching and rotating under the policy.</summary>
public sealed class MaaKeyTrust
{
    readonly D _policy;
    readonly IMaaKeyStateStore _store;
    readonly MaaFetch _fetch;
    readonly HashSet<string> _trusted;
    readonly double _ttl, _maxStale, _maxNew, _maxInitial, _skew;
    readonly bool _requireOverlap;

    internal MaaKeyTrust(D policy, IMaaKeyStateStore store, MaaFetch fetch)
    {
        _policy = policy;
        _store = store;
        _fetch = fetch;
        _trusted = ((L)policy["trustedIssuers"]!).Cast<string>().ToHashSet(StringComparer.Ordinal);
        double Num(string k, double d) => policy.GetValueOrDefault(k) is { } v ? AttestMaaKeys.N(v) : d;
        _ttl = Num("ttlMs", AttestMaaKeys.Hour);
        _maxStale = Num("maxStaleMs", AttestMaaKeys.Day);
        _maxNew = Num("maxNewKeysPerFetch", 2);
        _maxInitial = Num("maxInitialKeys", 8);
        _skew = Num("clockSkewMs", 60_000);
        _requireOverlap = policy.GetValueOrDefault("requireOverlap") is not { } ro || Truthy(ro);
        // an infinite or NaN window would admit every expired key or stale cache; a count or max-stale may be +Infinity (no cap) but never NaN
        if (!double.IsFinite(_ttl) || !double.IsFinite(_skew) || double.IsNaN(_maxStale) || double.IsNaN(_maxNew) || double.IsNaN(_maxInitial)) throw new ArgumentException("createMaaKeyTrust: ttlMs and clockSkewMs must be finite; maxStaleMs and the key-count limits must not be NaN");
    }

    static bool Truthy(object? x) => IntentRevocation.Truthy(x);

    static D Fail(string code, string reason) => new() { ["ok"] = false, ["code"] = code, ["reason"] = reason };

    L Live(L anchors, double nowMs) => anchors.Cast<D>().Where(r => nowMs - _skew <= AttestMaaKeys.N(r["notAfterMs"]) && nowMs + _skew >= AttestMaaKeys.N(r["notBeforeMs"])).Cast<object?>().ToList();

    static D Build(string source, L anchors, List<string> newKeys, List<string> removedKeys, L rejected)
    {
        var spkis = anchors.Cast<D>().Select(a => (string)a["spki"]!).Distinct(StringComparer.Ordinal).OrderBy(s => s, StringComparer.Ordinal).ToList();
        if (spkis.Count == 0) return Fail("no-valid-keys", "no unexpired, un-revoked signing keys remain");
        return new D
        {
            ["ok"] = true, ["trustAnchors"] = new D { ["rootSpkiSha256"] = spkis.Cast<object?>().ToList() }, ["source"] = source, ["anchors"] = anchors,
            ["newKeys"] = newKeys.Cast<object?>().ToList(), ["removedKeys"] = removedKeys.Cast<object?>().ToList(), ["rejected"] = rejected,
        };
    }

    /// <summary>The trust anchors of <paramref name="issuer"/> at <paramref name="nowMs"/>: <c>{ok: true, trustAnchors: {rootSpkiSha256}, source, anchors, newKeys, removedKeys, rejected}</c> or <c>{ok: false, code, reason}</c>
    /// (untrusted-issuer, corrupt-state, clock-regression, fetch-failed, stale-exceeded, no-valid-keys, no-baseline, too-many-new-keys, no-overlap, repin-invalid, builtin-pins-invalid). <paramref name="repin"/>
    /// <c>{manifest, verify}</c>: a release-signed allowlist manifest that approves signing keys and revokes others.</summary>
    public D GetTrustAnchors(string issuer, object? nowMsO, D? repin = null)
    {
        try
        {
            if (!_trusted.Contains(issuer)) return Fail("untrusted-issuer", "issuer is not in policy.trustedIssuers");
            if (!IntentJs.IsSafeInteger(nowMsO)) return Fail("clock-regression", "nowMs must be an integer");
            double nowMs = AttestMaaKeys.N(nowMsO);
            var approved = new HashSet<string>(StringComparer.Ordinal);
            var denied = new HashSet<string>(StringComparer.Ordinal);
            if (repin != null)
            {
                var vopts = new D((D)repin["verify"]!) { ["nowMs"] = nowMsO };
                var v = AttestAllowlist.VerifyAllowlistManifest(repin["manifest"], vopts);
                if (v["ok"] is not true) return Fail("repin-invalid", $"{v["code"]}: {v["reason"]}");
                var p = AttestAllowlist.ProjectAllowlist(v, nowMsO);
                if (((D)p["maaSigningSpkis"]!).GetValueOrDefault(issuer) is L ap) foreach (var s in ap) approved.Add((string)s!);
                foreach (var r in ((L)p["revoked"]!).Cast<D>()) if (Equals(r["kind"], "maa-signing-spki") && Equals(r["label"], issuer)) denied.Add((string)r["value"]!);
            }
            var effPolicy = _policy;
            var builtinBaseline = new List<string>();
            string? builtinReason = null;
            var bp = _policy.GetValueOrDefault("builtinPins");
            if (!(bp is false))
            {
                var bopts = new D { ["nowMs"] = nowMsO };
                if (bp is D) bopts["source"] = bp;
                var b = AttestMaaKeys.LoadBuiltinMaaPins(bopts);
                if (b["ok"] is true)
                {
                    if (((D)b["maaSigningSpkis"]!).GetValueOrDefault(issuer) is L bl) builtinBaseline = bl.Cast<string>().ToList();
                    if (((D)b["revokedSigningSpkis"]!).GetValueOrDefault(issuer) is L rl) foreach (var r in rl) denied.Add((string)r!);
                    effPolicy = new D(_policy);
                    if (!_policy.ContainsKey("chainRootSpkiSha256") || _policy["chainRootSpkiSha256"] == null) effPolicy["chainRootSpkiSha256"] = b["maaChainRootSpkis"];
                    if (!_policy.ContainsKey("chainIntermediateSpkiSha256") || _policy["chainIntermediateSpkiSha256"] == null) effPolicy["chainIntermediateSpkiSha256"] = b["maaChainIntermediateSpkis"];
                    if (!_policy.ContainsKey("chainLeafCn") || _policy["chainLeafCn"] == null) effPolicy["chainLeafCn"] = AttestMaaKeys.BuiltinChainLeafCn.Cast<object?>().ToList();
                    if (builtinBaseline.Count > 0) builtinBaseline = [.. builtinBaseline, .. ((L)b["maaChainIntermediateSpkis"]!).Cast<string>()];
                }
                else builtinReason = (string)b["reason"]!;
            }
            L Allow(L a) => a.Cast<D>().Where(r => !denied.Contains((string)r["spki"]!)).Cast<object?>().ToList();
            var rawState = _store.Get(issuer);
            D? state = null;
            if (rawState != null)
            {
                state = AttestMaaKeys.ParseState(rawState, issuer);
                if (state == null) return Fail("corrupt-state", "persisted MAA key state failed validation");
                if (nowMs < AttestMaaKeys.N(state["fetchedAtMs"]) - _skew) return Fail("clock-regression", "clock is behind the last persisted fetch time");
            }
            if (state != null && nowMs - AttestMaaKeys.N(state["fetchedAtMs"]) < _ttl && nowMs >= AttestMaaKeys.N(state["fetchedAtMs"]))
            {
                var a = Allow(Live((L)state["anchors"]!, nowMs));
                if (a.Count > 0) return Build("cache", a, [], [], []);
            }
            D jwks;
            try
            {
                jwks = AttestMaaKeys.FetchMaaCerts(issuer, _fetch, _policy.GetValueOrDefault("fetchTimeoutMs"), _policy.GetValueOrDefault("maxBodyBytes"));
            }
            catch (Exception e)
            {
                var why = string.IsNullOrEmpty(e.Message) ? "fetch error" : e.Message;
                if (state == null) return Fail("fetch-failed", $"{why}; no cached key set");
                if (nowMs - AttestMaaKeys.N(state["fetchedAtMs"]) > _maxStale) return Fail("stale-exceeded", $"{why}; cached set is older than maxStaleMs");
                var a = Allow(Live((L)state["anchors"]!, nowMs));
                if (a.Count == 0) return Fail("stale-exceeded", $"{why}; every cached key has expired or been revoked");
                return Build("stale-cache", a, [], [], []);
            }
            var ev = AttestMaaKeys.EvaluateMaaJwks(jwks, issuer, effPolicy, nowMsO);
            var accepted = ((L)ev["accepted"]!).Cast<D>().Where(r => !denied.Contains((string)r["spki"]!)).ToList();
            var evRejected = (L)ev["rejected"]!;
            if (accepted.Count == 0)
                return Fail("no-valid-keys", $"no JWKS key passed validation ({(evRejected.Count == 0 ? "empty JWKS" : string.Join("; ", evRejected.Cast<D>().Select(r => $"{r["kid"]}: {r["reason"]}")))})");
            var prevAnchors = state != null ? Live((L)state["anchors"]!, nowMs) : new L();
            var baseline = new List<string>();
            void AddBase(string s) { if (!baseline.Contains(s)) baseline.Add(s); }
            foreach (var a in prevAnchors.Cast<D>()) AddBase((string)a["spki"]!);
            if (state == null)
            {
                if (_policy.GetValueOrDefault("initialPins") is D ip && ip.GetValueOrDefault(issuer) is L pl) foreach (var p in pl) AddBase(((string)p!).ToLowerInvariant());
                foreach (var p in builtinBaseline) AddBase(p);
            }
            foreach (var p in builtinBaseline) approved.Add(p);
            var acceptedSet = accepted.Select(a => (string)a["spki"]!).Distinct(StringComparer.Ordinal).ToList();
            var approvedHere = acceptedSet.Where(approved.Contains).ToList();
            var unapprovedNew = acceptedSet.Where(s => !baseline.Contains(s) && !approved.Contains(s)).ToList();
            if (baseline.Count == 0)
            {
                if (approvedHere.Count == 0 && !Truthy(_policy.GetValueOrDefault("allowTrustOnFirstUse")))
                {
                    if (builtinReason != null) return Fail("builtin-pins-invalid", $"built-in pins unusable ({builtinReason}); no persisted state, no initialPins, no signed re-pin; refusing trust-on-first-use");
                    return Fail("no-baseline", "no persisted state, no built-in pin for this issuer, no initialPins and no signed re-pin: refusing trust-on-first-use");
                }
                if (acceptedSet.Count > _maxInitial && approvedHere.Count < acceptedSet.Count) return Fail("too-many-new-keys", $"initial set of {acceptedSet.Count} keys exceeds maxInitialKeys");
            }
            else
            {
                if (unapprovedNew.Count > _maxNew) return Fail("too-many-new-keys", $"{unapprovedNew.Count} new keys exceed maxNewKeysPerFetch={JsJson.NumberToString(_maxNew)}");
                bool overlap = acceptedSet.Any(baseline.Contains) || approvedHere.Count > 0;
                if (_requireOverlap && !overlap) return Fail("no-overlap", "the new key set shares no key with the previous set and is not covered by a signed re-pin");
            }
            var firstSeen = new Dictionary<string, object?>(StringComparer.Ordinal);
            if (state != null) foreach (var a in ((L)state["anchors"]!).Cast<D>()) firstSeen[(string)a["spki"]!] = a["firstSeenMs"];
            var records = new L();
            foreach (var a in accepted)
                records.Add(new D { ["spki"] = a["spki"], ["kind"] = a["kind"], ["notBeforeMs"] = a["notBeforeMs"], ["notAfterMs"] = a["notAfterMs"], ["firstSeenMs"] = firstSeen.TryGetValue((string)a["spki"]!, out var fs) ? fs : nowMsO });
            var fetchedAt = state != null ? Math.Max(AttestMaaKeys.N(state["fetchedAtMs"]), nowMs) : nowMs;
            _store.Set(issuer, new D { ["v"] = IntentJs.OfLong(1), ["issuer"] = issuer, ["fetchedAtMs"] = AttestMaaKeys.Ms(fetchedAt), ["anchors"] = records });
            var newKeys = records.Cast<D>().Where(r => !baseline.Contains((string)r["spki"]!)).Select(r => (string)r["spki"]!).ToList();
            var removed = baseline.Where(s => !acceptedSet.Contains(s)).ToList();
            return Build("fetched", records, newKeys, removed, evRejected);
        }
        catch (Exception e) { return Fail("fetch-failed", string.IsNullOrEmpty(e.Message) ? "unexpected error" : e.Message); }
    }
}

public static class AttestMaaKeys
{
    internal const double Hour = 3_600_000, Day = 24 * Hour;
    const int MaxJwksKeys = 32, MaxX5c = 8, MaxX5cB64 = 131_072;
    public static readonly IReadOnlyList<string> BuiltinChainLeafCn = ["Microsoft Azure Attestation 2020"];

    static readonly Regex IssuerUrl = new(@"\Ahttps://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?\z", RegexOptions.CultureInvariant);
    static readonly Regex Hex64 = new(@"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
    static readonly string[] EcCurves = ["prime256v1", "secp384r1", "secp521r1"];

    internal static double N(object? x) => IntentJs.NumOf(x)!.Value;
    internal static Num Ms(double d) => IntentJs.OfLong((long)d);

    /// <summary>The published constants of the module.</summary>
    public static D Constants() => new()
    {
        ["BUILTIN_CHAIN_LEAF_CN"] = BuiltinChainLeafCn.Cast<object?>().ToList(), ["BUILTIN_MAA_PINS_ISSUER_ID"] = AttestMaaPinsData.IssuerId,
        ["BUILTIN_MAA_PINS_ISSUER_KEYS"] = BuiltinIssuerKeys(),
    };

    /// <summary>The issuer keys the built-in pins verify under: <c>{issuerId: {alg, keys}}</c>.</summary>
    public static D BuiltinIssuerKeys() => new() { [AttestMaaPinsData.IssuerId] = Pca.ParseJson(AttestMaaPinsData.IssuerKeyJson) };

    public static MemoryMaaKeyStateStore CreateMemoryMaaKeyStateStore() => new();
    public static IMaaKeyStateStore DurableMaaKeyStateStore(IDurableKv kv) => new DurableMaaKeyStateStore(kv);

    // ---- the guarded fetch ----

    /// <summary>GET <c>&lt;issuer&gt;/certs</c> over the injected transport and parse the JWKS: the issuer must be an https origin; a non-2xx answer, a redirect (a final URL that differs), a declared or actual size over
    /// <paramref name="maxBytes"/> (default 1 MiB), a body that is not UTF-8 JSON, more than 32 keys or a key without a well-formed x5c (1..8 base64 strings of 1..131072 characters) is refused.
    /// Returns <c>{keys: [{kid?, kty?, alg?, x5c}]}</c>.</summary>
    public static D FetchMaaCerts(string issuer, MaaFetch? fetch, object? timeoutMs = null, object? maxBytes = null)
    {
        if (fetch == null) throw new ArgumentException("fetchMaaCerts: a fetch implementation must be injected");
        if (!IssuerUrl.IsMatch(issuer)) throw new ArgumentException("fetchMaaCerts: issuer must be an https origin URL (no path, no trailing slash)");
        double max = maxBytes != null ? N(maxBytes) : 1_048_576;
        var url = issuer + "/certs";
        var res = fetch(url);
        if (!res.Ok) throw new InvalidOperationException($"MAA certs fetch failed: HTTP {res.Status}");
        if (res.Url is { Length: > 0 } u && u != url) throw new InvalidOperationException("MAA certs fetch: response URL differs from the request (redirect)");
        double declared = res.ContentLength == null ? 0 : JsJson.ToJsNumber(res.ContentLength);
        if (double.IsFinite(declared) && declared > max) throw new InvalidOperationException("MAA certs response exceeds the size limit");
        if (res.Body.Length > max) throw new InvalidOperationException("MAA certs response exceeds the size limit");
        object? parsed;
        try
        {
            var text = new UTF8Encoding(false, true).GetString(res.Body);
            parsed = Pca.ParseJson(text.Length > 0 && text[0] == '\uFEFF' ? text[1..] : text); // a UTF-8 decoder drops one leading byte order mark
        }
        catch (Exception) { throw new InvalidOperationException("MAA certs response is not valid UTF-8 JSON"); }
        return ParseJwks(parsed);
    }

    static D ParseJwks(object? x)
    {
        if (x is not D d || d.GetValueOrDefault("keys") is not L raw) throw new InvalidOperationException("MAA certs: response has no keys array");
        if (raw.Count > MaxJwksKeys) throw new InvalidOperationException("MAA certs: too many keys");
        var keys = new L();
        foreach (var k in raw)
        {
            if (k is not (D or L)) throw new InvalidOperationException("MAA certs: malformed key entry");
            var r = k as D ?? new D();
            if (r.GetValueOrDefault("x5c") is not L x5c || x5c.Count == 0 || x5c.Count > MaxX5c || x5c.Any(c => c is not string { Length: > 0 and <= MaxX5cB64 }))
                throw new InvalidOperationException("MAA certs: key without a well-formed x5c");
            var o = new D();
            foreach (var f in new[] { "kid", "kty", "alg" }) if (r.GetValueOrDefault(f) is string s) o[f] = s;
            o["x5c"] = x5c;
            keys.Add(o);
        }
        return new D { ["keys"] = keys };
    }

    // ---- certificate helpers ----

    static AttCert ParseCert(object? b64)
    {
        if (b64 is not string s) throw new InvalidOperationException("The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object.");
        return AttestCerts.ParseDer(AttestUtil.NodeB64(s));
    }

    static string SpkiOf(AttCert c) => AttestUtil.Hex(AttestUtil.Sha256(c.RawSpki));

    /// <summary>The attributes of a DER Name as (oid, text) in encounter order (text null for a type this reader does not decode).</summary>
    static List<(string Oid, string? Text)> NameAttrs(byte[] name)
    {
        var o = new List<(string, string?)>();
        var seq = AttestCerts.ReadElem(name, 0, name.Length, 0x30);
        foreach (var rdn in AttestCerts.Kids(name, seq))
            foreach (var ava in AttestCerts.Kids(name, rdn))
            {
                var kv = AttestCerts.Kids(name, ava);
                if (kv.Count != 2) continue;
                string? text = kv[1].Tag switch
                {
                    0x0c => Encoding.UTF8.GetString(name, kv[1].Start, kv[1].End - kv[1].Start),
                    0x13 or 0x16 or 0x14 => Encoding.Latin1.GetString(name, kv[1].Start, kv[1].End - kv[1].Start),
                    0x1e => Encoding.BigEndianUnicode.GetString(name, kv[1].Start, kv[1].End - kv[1].Start),
                    _ => null,
                };
                o.Add((AttestCerts.Dotted(name, kv[0]), text));
            }
        return o;
    }

    const string OidCn = "2.5.4.3";

    static string? SoleCn(byte[] name) => NameAttrs(name) is [(OidCn, { } t)] ? t : null;
    static string? LeafCn(byte[] name) => NameAttrs(name).FirstOrDefault(a => a.Oid == OidCn && a.Text != null).Text;

    static int RsaModulusBits(byte[] spki)
    {
        try
        {
            var r = new AsnReader(spki, AsnEncodingRules.DER).ReadSequence();
            r.ReadSequence();
            var bits = r.ReadBitString(out _);
            var s = new AsnReader(bits, AsnEncodingRules.DER).ReadSequence();
            var n = s.ReadIntegerBytes().ToArray();
            int i = 0;
            while (i < n.Length - 1 && n[i] == 0) i++;
            return n.Length == 0 ? 0 : (n.Length - i) * 8 - System.Numerics.BitOperations.LeadingZeroCount((uint)n[i]) + 24;
        }
        catch (Exception) { return 0; }
    }

    static string? KeyStrengthError(AttCert c)
    {
        var k = AttestCerts.KeyOf(c);
        if (k.Type == "rsa")
        {
            int bits = RsaModulusBits(c.RawSpki);
            if (!(bits >= 2048 && bits <= 8192)) return $"RSA key size {bits} outside 2048..8192";
            return k.Rsa != null ? null : "RSA public exponent must be odd, at least 3 and at most 32 bits";
        }
        if (k.Type == "ec") return EcCurves.Contains(k.Curve) ? null : $"EC curve '{k.Curve}' not allowed";
        return $"key type '{k.Type}' not allowed";
    }

    static bool SafeVerify(AttCert c, AttCert key)
    {
        try { return AttestCerts.SigOkBy(c, key); }
        catch (Exception) { return false; }
    }

    // ---- JWKS evaluation ----

    /// <summary>Evaluate a JWKS for <paramref name="issuer"/> at <paramref name="nowMsO"/>: <c>{accepted: [{spki, kind, notBeforeMs, notAfterMs}], rejected: [{kid, reason}]}</c>. A single-certificate key is a self-signed
    /// certificate whose only subject attribute is a CN equal to the issuer URL; a chained key needs <c>policy.chainRootSpkiSha256</c> (a pinned root), optionally pinned intermediates
    /// (<c>chainIntermediateSpkiSha256</c>) and leaf CNs (<c>chainLeafCn</c>), and passes the strict chain profile. Policy members: <c>clockSkewMs</c> (60 s), <c>maxKeyAgeMs</c> (400 days).</summary>
    public static D EvaluateMaaJwks(object? jwks, string issuer, D policy, object? nowMsO)
    {
        double now = N(nowMsO);
        double skew = policy.GetValueOrDefault("clockSkewMs") is { } cs ? N(cs) : 60_000;
        double maxAge = policy.GetValueOrDefault("maxKeyAgeMs") is { } ma ? N(ma) : 400 * Day;
        var roots = (policy.GetValueOrDefault("chainRootSpkiSha256") as L ?? new L()).Select(s => ((string)s!).ToLowerInvariant()).ToHashSet(StringComparer.Ordinal);
        var inters = (policy.GetValueOrDefault("chainIntermediateSpkiSha256") as L ?? new L()).Select(s => ((string)s!).ToLowerInvariant()).ToHashSet(StringComparer.Ordinal);
        var accepted = new List<D>();
        var rejected = new L();
        var keys = jwks is D jd && jd.GetValueOrDefault("keys") is L kl ? kl : new L();
        void Accept(D rec)
        {
            int ix = accepted.FindIndex(a => Equals(a["spki"], rec["spki"]));
            if (ix >= 0) accepted[ix] = rec; else accepted.Add(rec);
        }
        for (int i = 0; i < keys.Count; i++)
        {
            if (keys[i] is not D key) throw new InvalidOperationException("Cannot read properties of " + (keys[i] == null ? "null" : "a non-object") + " (reading 'kid')");
            var kid = key.GetValueOrDefault("kid") is string ks ? ks : "#" + i;
            void No(string reason) => rejected.Add(new D { ["kid"] = kid, ["reason"] = reason });
            try
            {
                if (!double.IsFinite(now) || !double.IsFinite(skew)) throw new InvalidOperationException("clock and skew must be finite");
                if (key.GetValueOrDefault("x5c") is not L x5c || x5c.Count == 0) { No("no x5c"); continue; }
                var certs = x5c.Select(ParseCert).ToList();
                var leaf = certs[0];
                for (int j = 0; j < certs.Count; j++)
                {
                    var (vf, vt) = AttestDer.DerValidity(certs[j].Raw);
                    if (!vf.Ok || !vt.Ok) throw new InvalidOperationException($"cert {j}: unparsable validity");
                    if (now + skew < vf.Ms) throw new InvalidOperationException($"cert {j}: not yet valid");
                    if (now - skew > vt.Ms) throw new InvalidOperationException($"cert {j}: expired");
                }
                var (lvf, lvt) = AttestDer.DerValidity(leaf.Raw);
                var strength = KeyStrengthError(leaf);
                if (strength != null) throw new InvalidOperationException(strength);
                if (certs.Count == 1)
                {
                    if (!(now - lvf.Ms <= maxAge)) throw new InvalidOperationException("key older than maxKeyAgeMs");
                    var cn = SoleCn(leaf.RawSubject) ?? throw new InvalidOperationException("subject is not a single CN");
                    if (cn.Contains('*')) throw new InvalidOperationException("wildcard CN rejected");
                    if (cn != issuer) throw new InvalidOperationException("subject CN does not equal the issuer URL");
                    if (!leaf.SelfIssued || !SafeVerify(leaf, leaf)) throw new InvalidOperationException("not a genuine self-signed cert");
                    var spki = SpkiOf(leaf);
                    Accept(new D { ["spki"] = spki, ["kind"] = "self-signed", ["notBeforeMs"] = Ms(lvf.Ms), ["notAfterMs"] = Ms(lvt.Ms) });
                    continue;
                }
                if (roots.Count == 0) throw new InvalidOperationException("chained key ignored (no chainRootSpkiSha256 configured)");
                for (int j = 0; j < certs.Count - 1; j++)
                    if (!SafeVerify(certs[j], certs[j + 1])) throw new InvalidOperationException($"chain link {j} is not signed by the next cert");
                var profile = AttestDer.StrictChainError(certs.Select(c => c.Raw).ToList());
                if (profile != null) throw new InvalidOperationException("chain profile: " + profile);
                var top = certs[^1];
                if (!top.SelfIssued || !SafeVerify(top, top)) throw new InvalidOperationException("chain does not end in a self-signed root");
                var rootSpki = SpkiOf(top);
                if (!roots.Contains(rootSpki)) throw new InvalidOperationException("chain root is not pinned");
                if (policy.GetValueOrDefault("chainLeafCn") is L allowed && !allowed.Any(a => Equals(a, LeafCn(leaf.RawSubject) ?? "\u0000"))) throw new InvalidOperationException("chained leaf CN not allowed");
                var (tvf, tvt) = AttestDer.DerValidity(top.Raw);
                string anchorSpki = rootSpki, anchorKind = "chained-root";
                double anchorFrom = tvf.Ms, anchorTo = tvt.Ms;
                if (inters.Count > 0)
                {
                    var mid = certs.Skip(1).SkipLast(1).FirstOrDefault(c => inters.Contains(SpkiOf(c))) ?? throw new InvalidOperationException("chain does not pass through a pinned intermediate");
                    var (mvf, mvt) = AttestDer.DerValidity(mid.Raw);
                    anchorSpki = SpkiOf(mid);
                    anchorKind = "chained-intermediate";
                    anchorFrom = mvf.Ms;
                    anchorTo = mvt.Ms;
                }
                var prev = accepted.FirstOrDefault(a => Equals(a["spki"], anchorSpki));
                Accept(new D
                {
                    ["spki"] = anchorSpki, ["kind"] = anchorKind, ["notBeforeMs"] = Ms(prev != null ? Math.Min(N(prev["notBeforeMs"]), anchorFrom) : anchorFrom),
                    ["notAfterMs"] = Ms(Math.Min(anchorTo, Math.Max(prev != null ? N(prev["notAfterMs"]) : 0, lvt.Ms))),
                });
            }
            catch (Exception e) { No(string.IsNullOrEmpty(e.Message) ? "invalid key" : e.Message); }
        }
        return new D { ["accepted"] = accepted.Cast<object?>().ToList(), ["rejected"] = rejected };
    }

    // ---- the trust store ----

    internal static D? ParseState(object? x, string issuer)
    {
        if (x is not D s || IntentJs.NumOf(s.GetValueOrDefault("v")) != 1 || !Equals(s.GetValueOrDefault("issuer"), issuer)) return null;
        bool Int(object? n) => IntentJs.IsSafeInteger(n) && !IntentJs.IsNegZero(IntentJs.NumOf(n)!.Value);
        if (!Int(s.GetValueOrDefault("fetchedAtMs")) || s.GetValueOrDefault("anchors") is not L anchors) return null;
        var outp = new L();
        foreach (var ao in anchors)
        {
            if (ao is not D a) return null;
            if (a.GetValueOrDefault("spki") is not string spki || !Hex64.IsMatch(spki)) return null;
            if (a.GetValueOrDefault("kind") is not ("self-signed" or "chained-root" or "chained-intermediate")) return null;
            if (!Int(a.GetValueOrDefault("notBeforeMs")) || !Int(a.GetValueOrDefault("notAfterMs")) || !Int(a.GetValueOrDefault("firstSeenMs"))) return null;
            outp.Add(new D { ["spki"] = spki, ["kind"] = a["kind"], ["notBeforeMs"] = a["notBeforeMs"], ["notAfterMs"] = a["notAfterMs"], ["firstSeenMs"] = a["firstSeenMs"] });
        }
        return new D { ["v"] = IntentJs.OfLong(1), ["issuer"] = issuer, ["fetchedAtMs"] = s["fetchedAtMs"], ["anchors"] = outp };
    }

    /// <summary>The key trust of a policy (<c>trustedIssuers</c>: a non-empty list of https origin URLs, ttlMs, maxStaleMs, maxNewKeysPerFetch, maxInitialKeys, requireOverlap, allowTrustOnFirstUse, initialPins,
    /// chain pins, builtinPins (false: off; an object: a source), clockSkewMs, fetchTimeoutMs, maxBodyBytes). Throws on a missing transport or a bad issuer list.</summary>
    public static MaaKeyTrust CreateMaaKeyTrust(D policy, IMaaKeyStateStore store, MaaFetch? fetch)
    {
        if (fetch == null) throw new ArgumentException("createMaaKeyTrust: fetch must be injected");
        if (policy.GetValueOrDefault("trustedIssuers") is not L ti || ti.Count == 0 || ti.Any(i => i is not string s || !IssuerUrl.IsMatch(s)))
            throw new ArgumentException("createMaaKeyTrust: policy.trustedIssuers must be a non-empty list of https origin URLs");
        return new MaaKeyTrust(new D(policy), store, fetch);
    }

    // ---- corroboration ----

    /// <summary>k of n vantages must observe the same valid key set for <c>opts.issuer</c>: <c>{ok: true, issuer, spkis, vantages, k}</c> or <c>{ok: false, code, reason}</c> (malformed, insufficient-vantages,
    /// vantage-disagreement, no-valid-keys). Observations are <c>{vantage, issuer, jwks}</c>; <c>opts</c> <c>{issuer, nowMs, policy?}</c>.</summary>
    public static D CorroborateMaaKeySets(object? sets, object? kO, D opts)
    {
        static D Bad(string code, string reason) => new() { ["ok"] = false, ["code"] = code, ["reason"] = reason };
        try
        {
            if (!IntentJs.IsSafeInteger(kO) || N(kO) < 2) return Bad("malformed", "k must be an integer >= 2");
            double k = N(kO);
            var issuer = opts.GetValueOrDefault("issuer");
            if (!(issuer is string iss && IssuerUrl.IsMatch(iss)) || !IntentJs.IsSafeInteger(opts.GetValueOrDefault("nowMs"))) return Bad("malformed", "issuer/nowMs invalid");
            if (sets is not L list) return Bad("malformed", "sets must be an array");
            var policy = new D { ["trustedIssuers"] = new L { iss } };
            if (opts.GetValueOrDefault("policy") is D extra) foreach (var e in extra) policy[e.Key] = e.Value;
            var order = new List<string>();
            var byVantage = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var oo in list)
            {
                var o = oo as D;
                if (o?.GetValueOrDefault("vantage") is not string { Length: > 0 and <= 100 } vantage) return Bad("malformed", "vantage label must be a non-empty string");
                if (!Equals(o.GetValueOrDefault("issuer"), iss)) return Bad("malformed", $"observation from '{vantage}' is for a different issuer");
                var ev = EvaluateMaaJwks(o.GetValueOrDefault("jwks"), iss, policy, opts["nowMs"]);
                var acc = (L)ev["accepted"]!;
                if (acc.Count == 0)
                {
                    var rej = (L)ev["rejected"]!;
                    return Bad("no-valid-keys", $"vantage '{vantage}' observed no valid key ({(rej.Count == 0 ? "empty" : string.Join("; ", rej.Cast<D>().Select(r => (string)r["reason"]!)))})");
                }
                var fp = string.Join(",", acc.Cast<D>().Select(a => (string)a["spki"]!).OrderBy(s => s, StringComparer.Ordinal));
                if (byVantage.TryGetValue(vantage, out var prior) && prior != fp) return Bad("vantage-disagreement", $"vantage '{vantage}' supplied two different key sets");
                if (!byVantage.ContainsKey(vantage)) order.Add(vantage);
                byVantage[vantage] = fp;
            }
            if (byVantage.Count < k) return Bad("insufficient-vantages", $"{byVantage.Count} distinct vantage(s) < k={JsJson.NumberToString(k)}");
            var distinct = byVantage.Values.Distinct(StringComparer.Ordinal).ToList();
            if (distinct.Count != 1)
                return Bad("vantage-disagreement", "vantages disagree: " + string.Join(" | ", order.Select(v => $"{v}={string.Join("+", byVantage[v].Split(',').Select(x => x.Length > 8 ? x[..8] : x))}")));
            return new D
            {
                ["ok"] = true, ["issuer"] = iss, ["spkis"] = distinct[0].Split(',').Cast<object?>().ToList(), ["vantages"] = order.OrderBy(v => v, StringComparer.Ordinal).Cast<object?>().ToList(), ["k"] = kO,
            };
        }
        catch (Exception e) { return Bad("malformed", string.IsNullOrEmpty(e.Message) ? "corroboration error" : e.Message); }
    }

    // ---- the built-in pins ----

    static D PinFail(string reason) => new() { ["ok"] = false, ["reason"] = reason };

    /// <summary>The release-signed built-in pins at <c>opts.nowMs</c> (<c>opts.source</c> {manifest, issuerKeys, minVersion?}: absent = the shipped pins): <c>{ok: true, version, digest, expiresAt, maaSigningSpkis,
    /// revokedSigningSpkis, maaChainRootSpkis, maaChainIntermediateSpkis, vantages, method}</c> or <c>{ok: false, reason}</c>. The manifest must verify under the release key, be valid, record at least 3 corroborating
    /// vantages and pin the Microsoft chain root and intermediate.</summary>
    public static D LoadBuiltinMaaPins(D opts)
    {
        try
        {
            if (!IntentJs.IsSafeInteger(opts.GetValueOrDefault("nowMs"))) return PinFail("nowMs must be an integer");
            double now = N(opts["nowMs"]);
            var src = opts.GetValueOrDefault("source") as D ?? new D
            {
                ["manifest"] = Pca.ParseJson(AttestMaaPinsData.ManifestJson), ["issuerKeys"] = BuiltinIssuerKeys(), ["minVersion"] = IntentJs.OfLong(AttestMaaPinsData.MinVersion),
            };
            var manifest = src.GetValueOrDefault("manifest");
            var nb = manifest is D md && md.GetValueOrDefault("body") is D bd ? bd.GetValueOrDefault("notBefore") : null;
            var v0 = AttestAllowlist.VerifyAllowlistManifest(manifest, new D
            {
                ["issuerKeys"] = src.GetValueOrDefault("issuerKeys"), ["nowMs"] = nb ?? opts["nowMs"], ["minVersion"] = src.GetValueOrDefault("minVersion") ?? IntentJs.OfLong(1), ["maxLifetimeMs"] = IntentJs.OfLong(400L * 24 * 3_600_000),
            });
            if (v0["ok"] is not true) return PinFail($"{v0["code"]}: {v0["reason"]}");
            var body = (D)v0["body"]!;
            var p = AttestAllowlist.ProjectAllowlist(v0, body["notBefore"]);
            var corr = (L)p["corroboration"]!;
            if (corr.Count != 1) return PinFail("manifest must carry exactly one attest-corroboration entry");
            var label = (string)((D)corr[0]!)["label"]!;
            var m = Regex.Match(label, @"^vantages=([0-9]+);method=(.*)$", RegexOptions.CultureInvariant);
            double vantages = m.Success ? double.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture) : 0;
            if (!m.Success || vantages < 3) return PinFail($"corroboration records {JsJson.NumberToString(vantages)} vantages < required 3");
            if (((D)p["maaSigningSpkis"]!).Count == 0) return PinFail("manifest pins no MAA signing key");
            if (((L)p["maaChainRootSpkis"]!).Count == 0 || ((L)p["maaChainIntermediateSpkis"]!).Count == 0) return PinFail("manifest lacks the Microsoft chain root / intermediate pins");
            var revoked = new D();
            foreach (var r in ((L)p["revoked"]!).Cast<D>())
                if (Equals(r["kind"], "maa-signing-spki"))
                {
                    var lab = (string)r["label"]!;
                    if (!revoked.TryGetValue(lab, out var l)) revoked[lab] = l = new L();
                    ((L)l!).Add(r["value"]);
                }
            if (now < N(body["notBefore"])) return PinFail("built-in pins are not yet valid (clock behind the release)");
            if (now > N(body["expiresAt"])) return PinFail("built-in pins expired; update the package or pass explicit initialPins");
            return new D
            {
                ["ok"] = true, ["version"] = v0["version"], ["digest"] = v0["digest"], ["expiresAt"] = body["expiresAt"], ["maaSigningSpkis"] = p["maaSigningSpkis"], ["revokedSigningSpkis"] = revoked,
                ["maaChainRootSpkis"] = p["maaChainRootSpkis"], ["maaChainIntermediateSpkis"] = p["maaChainIntermediateSpkis"], ["vantages"] = Ms(vantages), ["method"] = m.Groups[2].Value,
            };
        }
        catch (Exception e) { return PinFail(string.IsNullOrEmpty(e.Message) ? "built-in pins error" : e.Message); }
    }
}
