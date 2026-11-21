// Signed, versioned, expiring measurement-allowlist manifests of the reference (attest-allowlist.ts, domain "pca-attest-allowlist/v1\n"): verify (issuer keys, suite, validity window, rollback
// floor), durable verify (a version high-water mark in a key/value store that only ever moves up), create, sign, revoke an entry, the projection to per-vendor policy fields (Azure MAA, Intel DCAP,
// SEV-SNP, GCP Confidential Space, NVIDIA CC) and the transparency anchor (attest-allowlist-anchor.ts): the commit, the operator's log of anchored manifests with its signed head, the evidence and
// the anchored verification. Manifests, bodies and entries are the JSON tree in the reference's member names; a verification answers {ok, ...} with a code and never throws.
using System.Text.RegularExpressions;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>An operator's append-only log of (issuer, version, digest) anchors with its latest signed tree head.</summary>
public sealed class AllowlistAnchorLog
{
    internal readonly TransparencyLedger Ledger_;
    internal readonly List<D> EntriesList = new();
    internal D? LatestHead;
    public string InstanceId { get; }
    public string Principal { get; }

    internal AllowlistAnchorLog(string instanceId, string principal)
    {
        InstanceId = instanceId;
        Principal = principal;
        Ledger_ = new TransparencyLedger(principal);
    }

    /// <summary>A copy of every anchored entry, in order.</summary>
    public List<D> Entries() => EntriesList.Select(e => new D(e)).ToList();

    /// <summary>The latest signed head, or null before the first anchor.</summary>
    public D? Latest() => LatestHead;
}

public static class AttestAllowlist
{
    public const string Domain = "pca-attest-allowlist/v1\n";
    public const string AnchorDomain = "pca-attest-allowlist-anchor/v1";
    public const int MaxFeed = 100_000;
    const double DefaultSkewMs = 60_000, DefaultMaxAgeMs = 86_400_000;
    const int MaxEntries = 10_000;

    public static readonly IReadOnlyList<string> Kinds = ["tdx-mrtd", "tdx-rtmr", "sev-snp-measurement", "gcp-image-digest", "nvidia-measurement", "nvidia-driver-version", "maa-signing-spki",
        "maa-chain-root-spki", "maa-chain-intermediate-spki", "attest-corroboration"];

    static Regex Re(string p) => new(@"\A(?:" + p + @")\z", RegexOptions.CultureInvariant);
    static readonly Regex Hex96 = Re("[0-9a-f]{96}"), Hex64 = Re("[0-9a-f]{64}"), ImageDigest = Re("sha256:[0-9a-f]{64}"), DriverVersion = Re(@"[0-9]{1,6}(\.[0-9]{1,6}){1,3}"),
        CorroborationLabel = Re(@"vantages=[1-9][0-9]{0,2};method=[\x20-\x7e]{1,150}"), IssuerUrl = Re("https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?"),
        B64u43 = Re("[A-Za-z0-9_-]{43}"), AnchorDigest = Re("[A-Za-z0-9_-]{43}");

    static readonly string[] BodyKeys = ["version", "issuedAt", "notBefore", "expiresAt", "entries"], EntryKeys = ["kind", "value", "label", "notAfter", "revoked"],
        ManifestKeys = ["body", "issuer", "alg", "sig", "pq_sig"];

    /// <summary>The published constants of the module.</summary>
    public static D Constants() => new() { ["ALLOWLIST_KINDS"] = Kinds.Cast<object?>().ToList(), ["DOMAIN"] = Domain };

    static bool SafeInt(object? x) => IntentJs.IsSafeInteger(x);
    static bool IsEpoch(object? x) => IntentJs.IsNonNeg(x);
    static bool IsFiniteNum(object? x) => IntentJs.NumOf(x) is double d && double.IsFinite(d);
    static double N(object? x) => IntentJs.NumOf(x)!.Value;
    static bool OnlyKeys(D r, string[] allowed) => r.Keys.All(k => allowed.Contains(k));
    static bool HasControlChar(string s) => s.Any(c => c <= 0x1f || c == 0x7f);

    static string? ValueError(string kind, string value, string label)
    {
        switch (kind)
        {
            case "tdx-mrtd": case "tdx-rtmr": case "sev-snp-measurement": case "nvidia-measurement":
                return Hex96.IsMatch(value) ? null : $"{kind} must be 96 lowercase hex chars";
            case "gcp-image-digest":
                return ImageDigest.IsMatch(value) ? null : "gcp-image-digest must be sha256:<64 lowercase hex>";
            case "nvidia-driver-version":
                return DriverVersion.IsMatch(value) && value.Length <= 16 ? null : "nvidia-driver-version must be a dotted version of at most 16 chars";
            case "maa-signing-spki":
                if (!Hex64.IsMatch(value)) return "maa-signing-spki must be 64 lowercase hex chars";
                return IssuerUrl.IsMatch(label) ? null : "maa-signing-spki label must be the https issuer URL (no path, no trailing slash)";
            case "maa-chain-root-spki": case "maa-chain-intermediate-spki":
                return Hex64.IsMatch(value) ? null : $"{kind} must be 64 lowercase hex chars";
        }
        if (!Hex64.IsMatch(value)) return "attest-corroboration must be a 64 lowercase hex evidence digest";
        return CorroborationLabel.IsMatch(label) ? null : "attest-corroboration label must be vantages=<n>;method=<text>";
    }

    static D ParseBody(object? x)
    {
        if (x is not D b || !OnlyKeys(b, BodyKeys)) throw new ArgumentException("body must be an object with exactly version/issuedAt/notBefore/expiresAt/entries");
        var version = b.GetValueOrDefault("version"); var issued = b.GetValueOrDefault("issuedAt"); var notBefore = b.GetValueOrDefault("notBefore"); var expires = b.GetValueOrDefault("expiresAt");
        var entries = b.GetValueOrDefault("entries");
        if (!SafeInt(version) || N(version) < 1) throw new ArgumentException("version must be a positive integer");
        if (!IsEpoch(issued) || !IsEpoch(notBefore) || !IsEpoch(expires)) throw new ArgumentException("issuedAt/notBefore/expiresAt must be integer epoch ms");
        if (!(N(notBefore) < N(expires))) throw new ArgumentException("notBefore must be before expiresAt");
        if (!(N(issued) <= N(expires))) throw new ArgumentException("issuedAt must not be after expiresAt");
        if (entries is not L el || el.Count > MaxEntries) throw new ArgumentException("entries must be an array (bounded)");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var outp = new L();
        for (int i = 0; i < el.Count; i++)
        {
            if (el[i] is not D e || !OnlyKeys(e, EntryKeys)) throw new ArgumentException($"entry {i}: unexpected shape");
            if (e.GetValueOrDefault("kind") is not string kind || !Kinds.Contains(kind)) throw new ArgumentException($"entry {i}: unknown kind");
            if (e.GetValueOrDefault("value") is not string value || e.GetValueOrDefault("label") is not string label) throw new ArgumentException($"entry {i}: value and label must be strings");
            if (label.Length < 1 || label.Length > 200 || HasControlChar(label)) throw new ArgumentException($"entry {i}: label must be 1..200 printable chars");
            if (ValueError(kind, value, label) is { } ve) throw new ArgumentException($"entry {i}: {ve}");
            if (e.TryGetValue("notAfter", out var na) && !IsEpoch(na)) throw new ArgumentException($"entry {i}: notAfter must be integer epoch ms");
            if (e.TryGetValue("revoked", out var rv) && rv is not true) throw new ArgumentException($"entry {i}: revoked, when present, must be true");
            var dup = kind + "\0" + (kind == "maa-signing-spki" ? label + "\0" : "") + value;
            if (!seen.Add(dup)) throw new ArgumentException($"entry {i}: duplicate {kind} value");
            var item = new D { ["kind"] = kind, ["value"] = value, ["label"] = label };
            if (e.ContainsKey("notAfter")) item["notAfter"] = e["notAfter"];
            if (e.GetValueOrDefault("revoked") is true) item["revoked"] = true;
            outp.Add(item);
        }
        return new D { ["version"] = version, ["issuedAt"] = issued, ["notBefore"] = notBefore, ["expiresAt"] = expires, ["entries"] = outp };
    }

    static byte[] SignedBytes(D body) => IntentJs.Message(Domain, body);

    static D Fail(string code, string reason) => new() { ["ok"] = false, ["code"] = code, ["reason"] = reason };

    static string? PqPkMember(Pq.Prim p) => p switch
    {
        Pq.Prim.MlDsa65 => "mlDsaPub", Pq.Prim.Slh128f => "slhDsaPub", Pq.Prim.MlDsa87 => "mlDsa87Pub", Pq.Prim.Slh256s => "slhDsa256sPub",
        Pq.Prim.FnDsa512 => "fnDsa512Pub", Pq.Prim.FnDsa1024 => "fnDsa1024Pub", Pq.Prim.Less => "lessCat1Pub", _ => null,
    };

    static bool SignatureOk(string alg, object? keysO, byte[] msg, string sig, object? pqSig)
    {
        var suite = Pq.Suites[alg];
        var keys = keysO as D ?? new D();
        string? pk = null;
        if (suite.NeedsPqPk)
        {
            pk = PqPkMember(suite.Pq) is { } m ? keys.GetValueOrDefault(m) as string : null;
            if (pk == null) return false;
        }
        return PqSuites.VerifyWithSuite(alg == "ed25519" ? null : alg, keys.GetValueOrDefault("edPub") as string, pk, msg, sig, pqSig);
    }

    /// <summary>Verify a signed manifest: <c>{ok: true, body, issuer, alg, version, digest}</c> or <c>{ok: false, code, reason}</c>. Options: <c>issuerKeys</c> ({issuer: {alg, keys, notAfter?}}), <c>nowMs</c>,
    /// <c>minVersion</c>?, <c>lastSeenVersion</c>?, <c>lastSeenDigest</c>?, <c>clockSkewMs</c>?, <c>maxLifetimeMs</c>?. Codes: malformed, unknown-issuer, issuer-expired, alg-mismatch, bad-signature, not-yet-valid, expired,
    /// rollback, below-min-version, conflict, lifetime-too-long. A post-quantum or hybrid suite verifies only under the key the issuer registered. Total.</summary>
    public static D VerifyAllowlistManifest(object? manifest, object? opts)
    {
        try
        {
            if (manifest is not D m || !OnlyKeys(m, ManifestKeys)) return Fail("malformed", "manifest has an unexpected shape");
            var o = opts as D ?? new D();
            if (!SafeInt(o.GetValueOrDefault("nowMs"))) return Fail("malformed", "nowMs must be an integer");
            var issuer = m.GetValueOrDefault("issuer"); var alg = m.GetValueOrDefault("alg"); var sig = m.GetValueOrDefault("sig");
            bool hasPqSig = m.ContainsKey("pq_sig");
            var pqSig = m.GetValueOrDefault("pq_sig");
            if (issuer is not string iss || iss.Length == 0 || iss.Length > 200) return Fail("malformed", "issuer must be a string");
            if (alg is not string a || IntentJs.SuiteOf(a, true) == null) return Fail("malformed", "unknown signature alg");
            if (sig is not string sg) return Fail("malformed", "sig must be a string");
            if (hasPqSig && pqSig is not string) return Fail("malformed", "pq_sig must be a string");
            if (!Pq.Suites[a].NeedsPqSig == hasPqSig) return Fail("malformed", "pq_sig presence does not match the suite");
            D body;
            try { body = ParseBody(m.GetValueOrDefault("body")); }
            catch (Exception e) { return Fail("malformed", string.IsNullOrEmpty(e.Message) ? "invalid body" : e.Message); }
            var issuerKeys = (D)o["issuerKeys"]!;
            if (!issuerKeys.ContainsKey(iss)) return Fail("unknown-issuer", $"issuer '{iss}' is not registered");
            var reg = (D)issuerKeys[iss]!;
            if (!Equals(reg.GetValueOrDefault("alg"), a)) return Fail("alg-mismatch", $"issuer is registered for '{JsJson.ToJsString(reg.GetValueOrDefault("alg"))}', manifest claims '{a}'");
            if (reg.GetValueOrDefault("notAfter") != null && !(double.IsFinite(N(o["nowMs"])) && N(o["nowMs"]) <= N(reg["notAfter"]))) return Fail("issuer-expired", "issuer key is past its notAfter");
            if (!SignatureOk(a, reg.GetValueOrDefault("keys"), SignedBytes(body), sg, hasPqSig ? pqSig : null)) return Fail("bad-signature", "signature does not verify under the registered issuer key");
            var skewO = o.GetValueOrDefault("clockSkewMs"); var lifeO = o.GetValueOrDefault("maxLifetimeMs"); var minV = o.GetValueOrDefault("minVersion"); var last = o.GetValueOrDefault("lastSeenVersion");
            if (o.ContainsKey("clockSkewMs") && !IsFiniteNum(skewO)) return Fail("malformed", "clockSkewMs must be a finite number");
            if (o.ContainsKey("maxLifetimeMs") && !IsFiniteNum(lifeO)) return Fail("malformed", "maxLifetimeMs must be a finite number");
            if (o.ContainsKey("minVersion") && !SafeInt(minV)) return Fail("malformed", "minVersion must be an integer");
            if (o.ContainsKey("lastSeenVersion") && !SafeInt(last)) return Fail("malformed", "lastSeenVersion must be an integer");
            double skew = skewO != null ? Math.Max(0, N(skewO)) : 0;
            double now = N(o["nowMs"]);
            if (!(double.IsFinite(now) && double.IsFinite(skew) && now + skew >= N(body["notBefore"]))) return Fail("not-yet-valid", "manifest is not yet valid");
            if (!(now - skew <= N(body["expiresAt"]))) return Fail("expired", "manifest has expired");
            if (o.ContainsKey("maxLifetimeMs") && N(body["expiresAt"]) - N(body["notBefore"]) > N(lifeO)) return Fail("lifetime-too-long", "manifest lifetime exceeds maxLifetimeMs");
            if (o.ContainsKey("minVersion") && N(body["version"]) < N(minV)) return Fail("below-min-version", $"version {JsJson.ToJsString(body["version"])} < minVersion {JsJson.ToJsString(minV)}");
            var digest = Pca.HashCanonical(body);
            if (o.ContainsKey("lastSeenVersion"))
            {
                if (N(body["version"]) < N(last)) return Fail("rollback", $"version {JsJson.ToJsString(body["version"])} is older than last seen {JsJson.ToJsString(last)}");
                if (N(body["version"]) == N(last) && o.ContainsKey("lastSeenDigest") && !Equals(o["lastSeenDigest"], digest)) return Fail("conflict", "same version as last seen but a different body");
            }
            return new D { ["ok"] = true, ["body"] = body, ["issuer"] = iss, ["alg"] = a, ["version"] = body["version"], ["digest"] = digest };
        }
        catch (Exception e) { return Fail("malformed", string.IsNullOrEmpty(e.Message) ? "verification error" : e.Message); }
    }

    static D? ParseHighWater(object? x)
    {
        if (x is not D d || !SafeInt(d.GetValueOrDefault("version")) || IntentJs.IsNegZero(N(d["version"]))) return null;
        if (d.GetValueOrDefault("digest") is not string dg || !B64u43.IsMatch(dg)) return null;
        return new D { ["version"] = d["version"], ["digest"] = dg };
    }

    /// <summary>Verify a manifest against the persisted high-water mark of its issuer (key <c>allowlist/&lt;issuer&gt;</c> = {version, digest}) and advance it. The mark only ever moves up: an older version
    /// is a rollback, the same version with another body a conflict, a corrupt persisted mark is refused.</summary>
    public static D VerifyAllowlistDurable(object? manifest, D opts, IDurableKv kv)
    {
        try
        {
            var issuer = manifest is D md ? md.GetValueOrDefault("issuer") : null;
            if (issuer is not string iss || iss.Length > 200) return Fail("malformed", "issuer must be a string");
            var key = "allowlist/" + iss;
            var raw = kv.GetValue(key);
            bool has = !ReferenceEquals(raw, DurableState.Undefined) && raw != null;
            var prior = has ? ParseHighWater(raw) : null;
            if (has && prior == null) return Fail("malformed", "persisted allowlist high-water mark is corrupt");
            var o = new D(opts);
            if (prior != null) { o["lastSeenVersion"] = prior["version"]; o["lastSeenDigest"] = prior["digest"]; }
            var v = VerifyAllowlistManifest(manifest, o);
            if (v["ok"] is not true) return v;
            bool ran = false; object? seenCur = null;
            var stored = kv.UpdateValue(key, cur =>
            {
                ran = true;
                seenCur = cur;
                bool curHas = !ReferenceEquals(cur, DurableState.Undefined) && cur != null;
                var c = curHas ? ParseHighWater(cur) : null;
                if (curHas && c == null) return DurableState.Undefined; // corrupt: left alone
                return c != null && N(c["version"]) >= N(v["version"]) ? DurableState.Undefined : new D { ["version"] = v["version"], ["digest"] = v["digest"] };
            });
            D? nowKv;
            if (!ran)
            {
                nowKv = ParseHighWater(stored);
                if (nowKv == null) return Fail("rollback", "a newer manifest was accepted concurrently");
            }
            else
            {
                bool curHas = !ReferenceEquals(seenCur, DurableState.Undefined) && seenCur != null;
                nowKv = curHas ? ParseHighWater(seenCur) : null;
                if (curHas && nowKv == null) return Fail("rollback", "a newer manifest was accepted concurrently"); // a corrupt mark is never overwritten
            }
            var after = nowKv != null && N(nowKv["version"]) >= N(v["version"]) ? nowKv : new D { ["version"] = v["version"], ["digest"] = v["digest"] };
            if (N(after["version"]) > N(v["version"])) return Fail("rollback", "a newer manifest was accepted concurrently");
            if (N(after["version"]) == N(v["version"]) && !Equals(after["digest"], v["digest"])) return Fail("conflict", "same version as the stored high-water mark but a different body");
            return v;
        }
        catch (Exception e) { return Fail("malformed", string.IsNullOrEmpty(e.Message) ? "durable verification error" : e.Message); }
    }

    /// <summary>Validate and normalise a manifest body. Throws on any violation.</summary>
    public static D CreateAllowlistManifest(object? body) => ParseBody(body);

    /// <summary>Sign a validated body: <c>{body, issuer, alg, sig, pq_sig?}</c>. <paramref name="keys"/> carries the Ed25519 secret and the PQ key of the suite's family.</summary>
    public static D SignAllowlistManifest(object? body, string issuer, string alg, SuiteSecretKeys keys)
    {
        var clean = ParseBody(body);
        if (IntentJs.SuiteOf(alg, true) == null) throw new ArgumentException($"unknown signature alg '{alg}'");
        var parts = PqSuites.SignWithSuite(alg == "ed25519" ? null : alg, keys, SignedBytes(clean));
        var o = new D { ["body"] = clean, ["issuer"] = issuer, ["alg"] = alg, ["sig"] = parts.Sig };
        if (parts.PqSig != null) o["pq_sig"] = parts.PqSig;
        return o;
    }

    /// <summary>The next manifest body (version + 1, the new times) with the matching entry marked revoked, or a new revoked entry when none matches.</summary>
    public static D RevokeAllowlistEntry(D prev, D rev, D times)
    {
        var entries = ((L)prev["entries"]!).Select(e => new D((D)e!)).ToList();
        var hit = entries.FirstOrDefault(e => Equals(e["kind"], rev["kind"]) && Equals(e["value"], rev["value"]) && (!Equals(rev["kind"], "maa-signing-spki") || Equals(e.GetValueOrDefault("label"), rev.GetValueOrDefault("label"))));
        if (hit != null) hit["revoked"] = true;
        else entries.Add(new D { ["kind"] = rev["kind"], ["value"] = rev["value"], ["label"] = rev.GetValueOrDefault("label") ?? "revoked", ["revoked"] = true });
        var next = new D { ["version"] = Facade.JsNumber(N(prev["version"]) + 1) };
        foreach (var e in times) next[e.Key] = e.Value;
        next["entries"] = entries.Cast<object?>().ToList();
        return ParseBody(next);
    }

    /// <summary>The 16-byte slot of an NVIDIA driver version string as 32 hex chars (ASCII, zero padded). Throws on a malformed version.</summary>
    public static string DriverVersionSlotHex(object? version)
    {
        if (version is not string v || !DriverVersion.IsMatch(v) || v.Length > 16) throw new ArgumentException("invalid driver version");
        return Convert.ToHexString(System.Text.Encoding.ASCII.GetBytes(v)).ToLowerInvariant().PadRight(32, '0');
    }

    /// <summary>The per-vendor lists of the entries that are live at <paramref name="nowMs"/> (not revoked, not denied by a revocation of the same kind and value, not past their own <c>notAfter</c>), plus the
    /// revoked and expired entries.</summary>
    public static D ProjectAllowlist(D verified, object? nowMs)
    {
        var body = (D)verified["body"]!;
        var tdxMrtds = new L(); var tdxRtmrs = new L(); var snp = new L(); var images = new L(); var nv = new L(); var drivers = new L(); var ccDrivers = new L();
        var maa = new D(); var roots = new L(); var inters = new L(); var corr = new L(); var revoked = new L(); var expired = new L();
        var denied = new HashSet<string>(StringComparer.Ordinal);
        var entries = ((L)body["entries"]!).Cast<D>().ToList();
        foreach (var e in entries)
            if (e.GetValueOrDefault("revoked") is true)
            {
                denied.Add(e["kind"] + "\0" + e["value"]);
                revoked.Add(new D { ["kind"] = e["kind"], ["value"] = e["value"], ["label"] = e["label"] });
            }
        foreach (var e in entries)
        {
            if (e.GetValueOrDefault("revoked") is true || denied.Contains(e["kind"] + "\0" + e["value"])) continue;
            if (e.GetValueOrDefault("notAfter") != null && !(double.IsFinite(N(nowMs)) && N(nowMs) <= N(e["notAfter"])))
            {
                expired.Add(new D { ["kind"] = e["kind"], ["value"] = e["value"], ["label"] = e["label"] });
                continue;
            }
            var v = e["value"]; var k = (string)e["kind"]!;
            switch (k)
            {
                case "tdx-mrtd": tdxMrtds.Add(v); break;
                case "tdx-rtmr": tdxRtmrs.Add(v); break;
                case "sev-snp-measurement": snp.Add(v); break;
                case "gcp-image-digest": images.Add(v); break;
                case "nvidia-measurement": nv.Add(v); break;
                case "nvidia-driver-version": drivers.Add(v); ccDrivers.Add(DriverVersionSlotHex(v)); break;
                case "maa-signing-spki":
                {
                    var lab = (string)e["label"]!;
                    if (!maa.TryGetValue(lab, out var list)) maa[lab] = list = new L();
                    ((L)list!).Add(v);
                    break;
                }
                case "maa-chain-root-spki": roots.Add(v); break;
                case "maa-chain-intermediate-spki": inters.Add(v); break;
                case "attest-corroboration": corr.Add(new D { ["value"] = v, ["label"] = e["label"] }); break;
            }
        }
        return new D
        {
            ["tdxMrtds"] = tdxMrtds, ["tdxRtmrs"] = tdxRtmrs, ["sevSnpMeasurements"] = snp, ["imageDigests"] = images, ["nvidiaMeasurements"] = nv, ["nvidiaDriverVersions"] = drivers,
            ["nvidiaCcDriverVersions"] = ccDrivers, ["maaSigningSpkis"] = maa, ["maaChainRootSpkis"] = roots, ["maaChainIntermediateSpkis"] = inters, ["corroboration"] = corr, ["revoked"] = revoked,
            ["expired"] = expired, ["version"] = body["version"], ["manifestExpiresAt"] = body["expiresAt"],
        };
    }

    static L Copy(object? l) => new((L)l!);
    static bool NonEmpty(object? l) => l is L { Count: > 0 };

    public static D AzureMaaPolicyFields(D p)
    {
        var o = new D();
        foreach (var k in new[] { "tdxMrtds", "sevSnpMeasurements", "tdxRtmrs" }) if (NonEmpty(p[k])) o[k] = Copy(p[k]);
        return o;
    }

    public static D IntelDcapPolicyFields(D p)
    {
        var o = new D { ["mrtds"] = Copy(p["tdxMrtds"]) };
        if (NonEmpty(p["tdxRtmrs"])) o["rtmrs"] = Copy(p["tdxRtmrs"]);
        return o;
    }

    public static D SevSnpPolicyFields(D p) => new() { ["measurements"] = Copy(p["sevSnpMeasurements"]) };
    public static D GcpCsPolicyFields(D p) => new() { ["imageDigests"] = Copy(p["imageDigests"]) };

    public static D NvidiaCcPolicyFields(D p)
    {
        var o = new D { ["measurements"] = Copy(p["nvidiaMeasurements"]) };
        if (NonEmpty(p["nvidiaCcDriverVersions"])) o["driverVersions"] = Copy(p["nvidiaCcDriverVersions"]);
        return o;
    }

    // ---- the transparency anchor ----

    static D Refusal(string code) => new() { ["ok"] = false, ["code"] = code };

    static bool IsEntry(object? e) =>
        e is D d && d.Count == 3 && d.GetValueOrDefault("issuer") is string { Length: > 0 and <= 200 } && SafeInt(d.GetValueOrDefault("version")) && N(d["version"]) >= 1
        && d.GetValueOrDefault("digest") is string dg && AnchorDigest.IsMatch(dg);

    /// <summary>The leaf the log stores for an entry: the strict hash of {domain, issuer, version, digest}.</summary>
    public static string AllowlistAnchorCommit(D e) => Pca.HashCanonical(new D { ["domain"] = AnchorDomain, ["issuer"] = e["issuer"], ["version"] = e["version"], ["digest"] = e["digest"] });

    /// <summary>The anchor entry <c>{issuer, version, digest}</c> of a verified manifest.</summary>
    public static D AnchorEntryOf(D verified) => new() { ["issuer"] = verified["issuer"], ["version"] = verified["version"], ["digest"] = verified["digest"] };

    static IReadOnlyDictionary<string, string>? PinsOf(object? v) => v is D d ? d.Where(e => e.Value is string).ToDictionary(e => e.Key, e => (string)e.Value!) : null;

    /// <summary>Check the log evidence <c>{head, entries, proof, consistency?}</c> of a manifest that has ALREADY been signature-verified (<paramref name="mine"/> = {issuer, version, digest}): the signed tree head
    /// under the pinned log key (<c>trust.logKey</c>, <c>instanceId</c>, <c>principal</c>, <c>witnesses</c>?, <c>pqPins</c>?), head freshness, the cached head (<c>cachedHead</c>: size, split view and RFC 9162 consistency),
    /// the RFC 6962 root over the supplied entries, the inclusion proof and the per-issuer version rules. Returns <c>{ok: true, issuer, version, digest, highestAnchoredVersion, head}</c> or <c>{ok: false, code}</c>
    /// (missing-proof, bad-head, stale-head, bad-cache, log-rollback, split-view, inconsistent-with-cache, feed-mismatch, bad-proof, not-anchored, anchored-rollback, log-conflict). Options: <c>trust</c>, <c>nowMs</c>,
    /// <c>maxHeadAgeMs</c>?, <c>clockSkewMs</c>?, <c>cachedHead</c>?. Total.</summary>
    public static D VerifyAllowlistAnchored(object? mineO, object? evidenceO, D opts)
    {
        try
        {
            if (evidenceO is not D evidence || evidence.GetValueOrDefault("proof") is not D proof || evidence.GetValueOrDefault("head") == null || evidence.GetValueOrDefault("entries") is not L entries) return Refusal("missing-proof");
            var trust = opts.GetValueOrDefault("trust") as D ?? new D();
            var nowMs = opts.GetValueOrDefault("nowMs");
            if (!SafeInt(nowMs)) return Refusal("bad-head");
            var key = trust.GetValueOrDefault("logKey") as string;
            var witnesses = trust.GetValueOrDefault("witnesses") as D;
            var pins = PinsOf(trust.GetValueOrDefault("pqPins"));
            var head = evidence["head"] as D;
            if (key == null || !Ledger.VerifyTreeHead(head, key, witnesses, pins) || !Equals(head!["instance_id"], trust.GetValueOrDefault("instanceId")) || !Equals(head["principal"], trust.GetValueOrDefault("principal"))
                || !SafeInt(head.GetValueOrDefault("timestamp")))
                return Refusal("bad-head");
            double now = N(nowMs);
            var clockSkew = opts.GetValueOrDefault("clockSkewMs");
            var maxAgeO = opts.GetValueOrDefault("maxHeadAgeMs");
            double skew = clockSkew == null ? DefaultSkewMs : Math.Max(0, N(clockSkew));
            double maxAge = maxAgeO == null ? DefaultMaxAgeMs : N(maxAgeO);
            if (!(double.IsFinite(now) && double.IsFinite(skew) && N(head["timestamp"]) <= now + skew) || !(double.IsFinite(now - N(head["timestamp"])) && now - N(head["timestamp"]) <= maxAge)) return Refusal("stale-head");
            var cached = opts.GetValueOrDefault("cachedHead") as D;
            if (cached != null)
            {
                if (!Ledger.VerifyTreeHead(cached, key, witnesses, pins) || !Equals(cached["instance_id"], trust.GetValueOrDefault("instanceId")) || !Equals(cached["principal"], trust.GetValueOrDefault("principal"))) return Refusal("bad-cache");
                if (N(head["size"]) < N(cached["size"])) return Refusal("log-rollback");
                if (N(head["size"]) == N(cached["size"]) && !Equals(head["root"], cached["root"])) return Refusal("split-view");
                if (N(head["size"]) > N(cached["size"]) && !Ledger.VerifyHeadConsistency(cached, head, evidence.GetValueOrDefault("consistency"), key, witnesses, pins)) return Refusal("inconsistent-with-cache");
            }
            if (entries.Count > MaxFeed || entries.Count != N(head["size"]) || !entries.All(IsEntry)) return Refusal("feed-mismatch");
            var root = Ledger.LedgerRootOf(entries.Select(e => AllowlistAnchorCommit((D)e!)));
            if (!Equals(root, head["root"])) return Refusal("feed-mismatch");
            var mine = mineO as D;
            var digests = new Dictionary<double, string>();
            double highest = 0;
            foreach (var eo in entries)
            {
                var e = (D)eo!;
                if (!Equals(e["issuer"], mine?.GetValueOrDefault("issuer"))) continue;
                double ver = N(e["version"]);
                if (digests.TryGetValue(ver, out var dg) && dg != (string)e["digest"]!) return Refusal("log-conflict");
                digests[ver] = (string)e["digest"]!;
                highest = Math.Max(highest, ver);
            }
            if (!IsEntry(mine) || !SafeInt(proof.GetValueOrDefault("size")) || N(proof["size"]) != N(head["size"]) || !Ledger.VerifyLedgerInclusion((string)head["root"]!, proof, AllowlistAnchorCommit(mine!))) return Refusal("bad-proof");
            if (N(mine!["version"]) < highest) return Refusal("anchored-rollback");
            if (!digests.TryGetValue(N(mine["version"]), out var mineDigest) || mineDigest != (string)mine["digest"]!) return Refusal("not-anchored");
            return new D { ["ok"] = true, ["issuer"] = mine["issuer"], ["version"] = mine["version"], ["digest"] = mine["digest"], ["highestAnchoredVersion"] = Facade.JsNumber(highest), ["head"] = head };
        }
        catch (Exception) { return Refusal("bad-head"); }
    }

    public static AllowlistAnchorLog CreateAllowlistAnchorLog(string instanceId, string principal) => new(instanceId, principal);

    static D SignHead(AllowlistAnchorLog log, byte[] guardianSecret, object? nowMs, SuiteKey? suite)
    {
        var h = log.Ledger_.Head();
        using var key = EdKey.FromSeed(guardianSecret);
        var sth = Ledger.SignTreeHead(key, new D
        {
            ["instance_id"] = log.InstanceId, ["principal"] = log.Principal, ["size"] = h["size"], ["root"] = h["root"], ["prev_root"] = log.LatestHead != null ? log.LatestHead["root"] : "", ["timestamp"] = nowMs,
        }, suite);
        log.LatestHead = sth;
        return sth;
    }

    /// <summary>The evidence for the entry at <paramref name="index"/>: the latest head, every entry, the inclusion proof and, for a cached head older than the latest, the consistency proof from it. Throws before the first head.</summary>
    public static D EvidenceFor(AllowlistAnchorLog log, long index, D? cached = null)
    {
        if (log.LatestHead == null) throw new InvalidOperationException("evidenceFor: log has no signed head");
        var o = new D { ["head"] = log.LatestHead, ["entries"] = log.Entries().Cast<object?>().ToList(), ["proof"] = log.Ledger_.InclusionProof(index) };
        if (cached != null && N(cached["size"]) > 0 && N(cached["size"]) < N(log.LatestHead["size"]))
            o["consistency"] = log.Ledger_.ConsistencyProof((long)N(cached["size"]), (long)N(log.LatestHead["size"]));
        return o;
    }

    /// <summary>Anchor a manifest's entry (an entry, or a verified-manifest result) and sign the new head; returns the evidence of the entry. The same version anchored again with the same digest is idempotent; another digest,
    /// or a lower version than anchored, throws.</summary>
    public static D AnchorAllowlistHead(AllowlistAnchorLog log, object? what, byte[] guardianSecret, object? nowMs, SuiteKey? suite = null)
    {
        var w = what as D ?? throw new ArgumentException("anchorAllowlistHead: malformed entry");
        var entry = w.ContainsKey("body") ? AnchorEntryOf(w) : new D(w);
        if (!IsEntry(entry)) throw new ArgumentException("anchorAllowlistHead: malformed entry");
        int same = log.EntriesList.FindIndex(e => Equals(e["issuer"], entry["issuer"]) && N(e["version"]) == N(entry["version"]));
        long index;
        if (same >= 0)
        {
            if (!Equals(log.EntriesList[same]["digest"], entry["digest"])) throw new InvalidOperationException("anchorAllowlistHead: this version is already anchored with a different digest");
            index = same;
        }
        else
        {
            double mx = log.EntriesList.Where(e => Equals(e["issuer"], entry["issuer"])).Select(e => N(e["version"])).DefaultIfEmpty(0).Max();
            if (N(entry["version"]) < mx) throw new InvalidOperationException($"anchorAllowlistHead: version {JsJson.ToJsString(entry["version"])} is lower than the anchored {JsJson.NumberToString(mx)}");
            index = log.Ledger_.AppendCommitment(AllowlistAnchorCommit(entry)).Index;
            log.EntriesList.Add(entry);
            SignHead(log, guardianSecret, nowMs, suite);
        }
        if (log.LatestHead == null) SignHead(log, guardianSecret, nowMs, suite);
        return EvidenceFor(log, index);
    }

    /// <summary>Re-sign the current head with a new timestamp (freshness for the verifiers). Throws before anything is anchored.</summary>
    public static D RefreshAnchorHead(AllowlistAnchorLog log, byte[] guardianSecret, object? nowMs, SuiteKey? suite = null)
    {
        if (log.Ledger_.Size == 0) throw new InvalidOperationException("refreshAnchorHead: nothing anchored yet");
        return SignHead(log, guardianSecret, nowMs, suite);
    }
}
