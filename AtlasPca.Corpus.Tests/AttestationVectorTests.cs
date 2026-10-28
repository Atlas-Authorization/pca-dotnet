using System.Text;
using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Replays packages/pca/conformance/attestation-evidence-vectors.json: every vendor verifier (AMD SEV-SNP, Intel TDX DCAP, Azure MAA, Google
// Confidential Space, NVIDIA GPU) answers exactly what the reference verifiers answered when the file was generated (reason text included; an
// OpenSSL / node:crypto message is compared by its stable prefix), and the strict X.509 readers answer every unit row. The file is produced
// by the TypeScript generator; a missing file FAILS the test (it is never skipped).
public class AttestationVectorTests
{
    const string File_ = "attestation-evidence-vectors.json";

    static D Doc() => Load(File_);

    /// <summary>Replaces every {"$blob": id} with the string stored under blobs[id].</summary>
    static object? Hydrate(object? x, D blobs)
    {
        switch (x)
        {
            case L l: return l.Select(e => Hydrate(e, blobs)).ToList();
            case D m:
                if (m.Count == 1 && m.TryGetValue("$blob", out var id) && id is string sid)
                    return blobs.TryGetValue(sid, out var v) ? v : throw new InvalidOperationException("unknown blob " + sid);
                return m.ToDictionary(kv => kv.Key, kv => Hydrate(kv.Value, blobs));
        }
        return x;
    }

    static string C(object? v) => JsCanon.Lenient(v) ?? throw new InvalidOperationException("not canonicalizable: " + v);

    static AttestationBinding? BindingOf(object? v) =>
        v is D m ? new AttestationBinding((string)(m.GetValueOrDefault("holderPub") ?? ""), (string)(m.GetValueOrDefault("grantRef") ?? ""), IntentJs.NumOf(m.GetValueOrDefault("epoch")) ?? 0, (string)(m.GetValueOrDefault("nonce") ?? "")) : null;

    static D RunRow(D row)
    {
        var vendor = (string)row["vendor"]!;
        IVendorVerifier ver;
        try { ver = AttestationVerifiers.FromConfig(vendor, row.GetValueOrDefault("config") as D); }
        catch (ArgumentException e) { return new D { ["construct_error"] = e.Message }; }
        return ver.Verify(row.GetValueOrDefault("evidence") as D, BindingOf(row.GetValueOrDefault("expected_binding")), N(row["now"])).Wire();
    }

    [Fact]
    public void EveryVendorReproducesTheReference()
    {
        var doc = Doc();
        var blobs = D(doc.GetValueOrDefault("blobs") ?? new D());
        var rows = L(doc["attestation_vectors"]);
        var schemaVendors = D(doc["verifier_config_schema"]).Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        Assert.Equal(AttestationVerifiers.Vendors.OrderBy(k => k, StringComparer.Ordinal).ToList(), schemaVendors);
        var seen = new HashSet<string>(); var perVendor = new Dictionary<string, int>();
        foreach (var r in rows)
        {
            var row = D(r);
            Assert.True(seen.Add((string)row["id"]!), "duplicate vector id " + row["id"]);
            perVendor[(string)row["vendor"]!] = perVendor.GetValueOrDefault((string)row["vendor"]!) + 1;
        }
        foreach (var v in AttestationVerifiers.Vendors) Assert.True(perVendor.GetValueOrDefault(v) > 0, "no vectors for " + v);
        Assert.True(rows.Count >= 750, $"only {rows.Count} attestation vectors");
        var bad = new List<string>();
        foreach (var r in rows)
        {
            var row = D(Hydrate(r, blobs));
            var got = new D(RunRow(row));
            var exp = new D(D(row["expect"]));
            if (exp.GetValueOrDefault("reason_match") as string == "prefix")
            {
                var prefix = exp.GetValueOrDefault("reason_prefix") as string ?? "";
                var reason = got.GetValueOrDefault("reason") as string ?? "";
                if (!reason.StartsWith(prefix, StringComparison.Ordinal)) { bad.Add($"{row["id"]}: reason '{reason}' does not start with '{prefix}'"); continue; }
                got.Remove("reason"); exp.Remove("reason");
            }
            exp.Remove("reason_match"); exp.Remove("reason_prefix");
            if (C(got) != C(exp)) bad.Add($"{row["id"]} ({row.GetValueOrDefault("intent")})\n    got  {C(got)}\n    want {C(exp)}");
        }
        Assert.True(bad.Count == 0, $"{bad.Count}/{rows.Count} vectors differ:\n  " + string.Join("\n  ", bad.Take(25)));
    }

    static byte[] B64(object? v) => Convert.FromBase64String((string)v!);

    static D Ok(object? v) => new() { ["ok"] = true, ["value"] = v };
    static D Err(Exception e) => new() { ["ok"] = false, ["error"] = e.Message };

    static L ExtList(ExtTable t) => new(t.Oids.Select(oid => (object?)new D { ["oid"] = oid, ["critical"] = t.Map[oid].Critical, ["value"] = AttestUtil.Hex(t.Map[oid].Value) }));
    static object? Instant(DerInstant i) => i.Ok ? new Num(i.Ms.ToString()) : null;

    static D RunX509(string fn, D input)
    {
        try
        {
            switch (fn)
            {
                case "read_cert_role_info":
                    {
                        var info = AttestDer.ReadCertRoleInfo(B64(input["cert"]));
                        var m = new D { ["hasBasicConstraints"] = info.HasBasicConstraints, ["ca"] = info.Ca, ["hasKeyUsage"] = info.HasKeyUsage, ["keyCertSign"] = info.KeyCertSign };
                        if (info.PathLen >= 0) m["pathLen"] = new Num(info.PathLen.ToString());
                        return Ok(m);
                    }
                case "parse_cert_extensions": return Ok(ExtList(AttestDer.ParseCertExtensions(B64(input["cert"]))));
                case "parse_tbs_extensions": return Ok(ExtList(AttestDer.ParseTbsExtensions(B64(input["tbs"]))));
                case "tbs_of_certificate": return Ok(Convert.ToBase64String(AttestDer.TbsOfCertificate(B64(input["cert"]))));
                case "unrecognised_critical_extension":
                    {
                        var rec = input.GetValueOrDefault("recognised") is L l ? l.Cast<string>().ToHashSet() : null;
                        return Ok(AttestDer.UnrecognisedCriticalExtension(B64(input["cert"]), rec));
                    }
                case "check_chain_roles": return Ok(AttestDer.CheckChainRoles(L(input["chain"]).Select(B64).ToList()));
                case "der_validity_ms":
                    {
                        var (vf, vt) = AttestDer.DerValidity(B64(input["cert"]));
                        return Ok(new D { ["from"] = Instant(vf), ["to"] = Instant(vt) });
                    }
                case "parse_der_time": return Ok(Instant(AttestDer.ParseDerTime((int)N(input["tag"]), (string)input["text"]!)));
            }
        }
        catch (AttestError e) { return Err(e); }
        throw new InvalidOperationException("unknown x509 function " + fn);
    }

    [Fact]
    public void StrictX509ReadersAnswerEveryUnitRow()
    {
        var doc = Doc();
        var blobs = D(doc.GetValueOrDefault("blobs") ?? new D());
        var rows = L(doc["x509_vectors"]);
        Assert.True(rows.Count >= 90, $"only {rows.Count} x509 vectors");
        var bad = new List<string>();
        foreach (var r in rows)
        {
            var row = D(Hydrate(r, blobs));
            var got = C(RunX509((string)row["fn"]!, D(row["input"])));
            var want = C(row["expect"]);
            if (got != want) bad.Add($"{row["id"]}: got {got} want {want}");
        }
        Assert.True(bad.Count == 0, $"{bad.Count} x509 rows differ:\n  " + string.Join("\n  ", bad.Take(25)));
    }
}
