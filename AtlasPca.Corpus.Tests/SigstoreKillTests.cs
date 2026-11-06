using System.Buffers.Binary;
using System.Collections;
using System.Formats.Asn1;
using System.Globalization;
using System.Numerics;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AtlasPca;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Sigstore.cs against its reference (packages/pca-attest-eat/src/sigstore.ts): exact refusal codes and details, every length
/// boundary. Helpers are private, so they are reached by reflection; the verifier runs on a PKI minted here (CA, leaf, TSA, ECDSA and
/// Ed25519 logs, CT log) so a case fails at exactly the check it targets.</summary>
public class SigstoreKillTests
{
    const long T0s = 1_700_000_000; // 2023-11-14T22:13:20Z
    const long T0 = T0s * 1000;
    const string Identity = "https://id.example/w";
    const string Issuer = "https://issuer.example";
    const string OidSct = "1.3.6.1.4.1.11129.2.4.2";
    const string OidSan = "2.5.29.17";
    const string OidEku = "2.5.29.37";
    const string OidCt = "1.2.840.113549.1.9.3";
    const string OidMd = "1.2.840.113549.1.9.4";
    const string OidTst = "1.2.840.113549.1.9.16.1.4";
    const string OidSd = "1.2.840.113549.1.7.2";
    const string OidSha256 = "2.16.840.1.101.3.4.2.1";
    const string TrustedRootType = "application/vnd.dev.sigstore.trustedroot+json;version=0.1";

    // ---- seams

    static object? Call(string name, params object?[] a)
    {
        var m = typeof(Sigstore).GetMethods(BindingFlags.NonPublic | BindingFlags.Static).Single(x =>
        {
            var p = x.GetParameters();
            return x.Name == name && p.Length == a.Length && p.Zip(a).All(e => e.Second == null || e.First.ParameterType.IsInstanceOfType(e.Second));
        });
        try { return m.Invoke(null, a); }
        catch (TargetInvocationException e)
        {
            ExceptionDispatchInfo.Capture(e.InnerException!).Throw();
            throw;
        }
    }

    /// <summary>The message of the verifier's own refusal: any other exception type (an index error past a removed check) fails.</summary>
    static string Bad(Action f)
    {
        try { f(); }
        catch (Exception e)
        {
            Assert.True(e.GetType().Name == "Bad", $"{e.GetType().Name}: {e.Message}");
            return e.Message;
        }
        throw new InvalidOperationException("did not throw");
    }

    static object? P(object o, string name) => o.GetType().GetProperty(name)!.GetValue(o);
    static object T(byte[] b, int off = 0, int limit = -1) => Call("T", b, off, limit)!;
    static object Pc(byte[] der) => Call("ParseCert", der)!;
    static bool Is(string name, params object?[] a) => (bool)Call(name, a)!;

    // ---- DER

    static byte[] B(params int[] x) => x.Select(i => (byte)i).ToArray();
    static byte[] U(string s) => Encoding.UTF8.GetBytes(s);
    static byte[] Cat(params byte[][] p)
    {
        var o = new byte[p.Sum(x => x.Length)];
        int i = 0;
        foreach (var x in p) { x.CopyTo(o, i); i += x.Length; }
        return o;
    }
    static byte[] E(int tag, params byte[][] c)
    {
        var b = Cat(c);
        int n = b.Length;
        byte[] h = n < 0x80 ? B(n) : n < 0x100 ? B(0x81, n) : n < 0x10000 ? B(0x82, n >> 8, n & 255) : B(0x83, n >> 16, (n >> 8) & 255, n & 255);
        return Cat(B(tag), h, b);
    }
    static byte[] O(string oid)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteObjectIdentifier(oid);
        return w.Encode();
    }
    static byte[] U16b(int n) => B(n >> 8, n & 255);
    static byte[] Be64(ulong v)
    {
        var o = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(o, v);
        return o;
    }
    static string B64(byte[] b) => Convert.ToBase64String(b);
    static DateTimeOffset S(long seconds) => DateTimeOffset.FromUnixTimeSeconds(seconds);

    static string J(object? o) => o switch
    {
        null => "null",
        string s => "\"" + s + "\"",
        long n => n.ToString(CultureInfo.InvariantCulture),
        D d => "{" + string.Join(",", d.Select(e => J(e.Key) + ":" + J(e.Value))) + "}",
        L l => "[" + string.Join(",", l.Select(x => J(x))) + "]",
        _ => throw new ArgumentException("no JSON form", nameof(o)),
    };

    // ---- the PKI (static fields initialise in this order)

    static readonly ECDsa CaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256), MidKey = ECDsa.Create(ECCurve.NamedCurves.nistP256),
        LeafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256), Leaf384Key = ECDsa.Create(ECCurve.NamedCurves.nistP384),
        TsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256), LogKey = ECDsa.Create(ECCurve.NamedCurves.nistP256), CtKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    static readonly RSA RsaKey = RSA.Create(2048);
    static readonly DateTimeOffset Nb = S(T0s - 100_000_000), Na = S(T0s + 100_000_000);
    static readonly X509Certificate2 CaCert = MakeCa(Nb, Na);
    static readonly X509Certificate2 TsaCert = MakeTsa();
    static readonly X509Certificate2 RsaCert = new CertificateRequest("CN=rsa", RsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(Nb, Na);
    static readonly Ed25519PrivateKeyParameters EdSk = new(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray(), 0);
    static readonly byte[] EdRaw = EdSk.GeneratePublicKey().GetEncoded();
    static readonly byte[] EdPrefix = B(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00);
    const string V2Name = "log.example";
    static readonly SigstorePinnedLog EdLog = new(EdId(V2Name, EdRaw), null, false, EdRaw, 0, long.MaxValue, V2Name);
    static readonly byte[] LogSpki = LogKey.ExportSubjectPublicKeyInfo();
    static readonly byte[] LogId = SHA256.HashData(LogSpki);
    static readonly SigstorePinnedLog EcLog = new(LogId, LogSpki, false, null, 0, long.MaxValue, null);
    static readonly SigstorePinnedLog CtLog = new(SHA256.HashData(CtKey.ExportSubjectPublicKeyInfo()), CtKey.ExportSubjectPublicKeyInfo(), false, null, 0, long.MaxValue, null);
    static readonly SigstorePinnedCa TsaCa = new(new[] { TsaCert }, 0, long.MaxValue);

    static readonly byte[] Ver = E(0xa0, E(2, B(2)));
    static readonly byte[] Ser = E(2, B(1));
    static readonly byte[] A256 = E(0x30, O("1.2.840.10045.4.3.2"));
    static readonly byte[] A384 = E(0x30, O("1.2.840.10045.4.3.3"));
    static readonly byte[] Nm = E(0x30, E(0x31, E(0x30, O("2.5.4.3"), E(0x0c, U("x")))));
    static readonly byte[] Utc = E(0x17, U("230101000000Z"));
    static readonly byte[] Val = E(0x30, Utc, E(0x17, U("350101000000Z")));
    static readonly byte[] Spk = LeafKey.ExportSubjectPublicKeyInfo();
    static readonly byte[] SigB = E(3, B(0, 1));
    static readonly byte[] Ex3 = E(0xa3, E(0x30, Ext("1.2.3", B(1))));

    static byte[] EdId(string name, byte[] raw) => SHA256.HashData(Cat(U(name + "\n"), B(1), raw));
    static byte[] Ext(string oid, byte[] value) => E(0x30, O(oid), E(4, value));
    static byte[] C(params byte[][] tbsKids) => E(0x30, E(0x30, tbsKids), A256, SigB);
    static byte[] EdSign(byte[] m)
    {
        var s = new Ed25519Signer();
        s.Init(true, EdSk);
        s.BlockUpdate(m, 0, m.Length);
        return s.GenerateSignature();
    }

    static X509Certificate2 MakeCa(DateTimeOffset nb, DateTimeOffset na)
    {
        var r = new CertificateRequest("CN=ca", CaKey, HashAlgorithmName.SHA256);
        r.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        r.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return r.CreateSelfSigned(nb, na);
    }

    static X509Certificate2 MakeTsa()
    {
        var r = new CertificateRequest("CN=tsa", TsaKey, HashAlgorithmName.SHA256);
        r.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.8") }, true));
        return r.CreateSelfSigned(Nb, Na);
    }

    static byte[] Leaf(Action<CertificateRequest>? edit = null, CertificateRequest? req = null, bool eku = true, bool iss = true, DateTimeOffset? nb = null, DateTimeOffset? na = null)
    {
        req ??= new CertificateRequest("CN=leaf", LeafKey, HashAlgorithmName.SHA256);
        var sb = new SubjectAlternativeNameBuilder();
        sb.AddUri(new Uri(Identity));
        req.CertificateExtensions.Add(sb.Build());
        if (eku) req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") }, false));
        if (iss) req.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.57264.1.8", E(0x0c, U(Issuer)), false));
        edit?.Invoke(req);
        return req.Create(CaCert.SubjectName, X509SignatureGenerator.CreateForECDsa(CaKey), nb ?? S(T0s - 3600), na ?? S(T0s + 3600), B(1)).RawData;
    }

    static X509Certificate2 Issued(string cn, ECDsa key, string issuerCn, ECDsa signer, bool ca)
    {
        var r = new CertificateRequest("CN=" + cn, key, HashAlgorithmName.SHA256);
        if (ca) r.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        return r.Create(new X500DistinguishedName("CN=" + issuerCn), X509SignatureGenerator.CreateForECDsa(signer), Nb, Na, B(2));
    }

    // ---- RFC 3161

    static string Gen(long ms) => DateTimeOffset.FromUnixTimeMilliseconds(ms).UtcDateTime.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + "Z";
    static byte[] Tst(byte[] data, string? gen = null, byte[]? imprint = null, string alg = OidSha256) =>
        E(0x30, E(2, B(1)), O("1.2.3"), E(0x30, E(0x30, O(alg)), E(4, imprint ?? SHA256.HashData(data))), E(2, B(1)), E(0x18, U(gen ?? Gen(T0))));
    static byte[] Encap(byte[] tst) => E(0x30, O(OidTst), E(0xa0, E(4, tst)));
    static byte[] Sd(params byte[][] kids) => E(0x30, O(OidSd), E(0xa0, E(0x30, kids)));
    static byte[] Attrs(byte[] tst) => E(0xa0, E(0x30, O(OidCt), E(0x31, O(OidTst))), E(0x30, O(OidMd), E(0x31, E(4, SHA256.HashData(tst)))));
    static byte[] Si(byte[] attrs, byte[] sigT) => E(0x30, E(2, B(1)), E(0x30), E(0x30, O(OidSha256)), attrs, A256, sigT);
    static byte[] Tok(byte[] tst, byte[] si) => Sd(E(2, B(3)), E(0x31), Encap(tst), E(0x31, si));
    static byte[] SignedToken(byte[] data, long ms)
    {
        var tst = Tst(data, Gen(ms));
        var attrs = Attrs(tst);
        var sig = TsaKey.SignData(Cat(B(0x31), attrs[1..]), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return Tok(tst, Si(attrs, E(4, sig)));
    }

    // ---- a whole bundle, signed end to end

    sealed class Fx
    {
        public string Kind = "dsse";
        public byte[] Payload = U(Statement());
        public byte[] LeafDer = Leaf();
        public ECDsa Signer = LeafKey;
        public HashAlgorithmName Hash = HashAlgorithmName.SHA256;
        public byte[]? SigOverride;
        public bool UseSet = true;
        public readonly List<long> TsaTimes = new();
        public Action<Fx, D>? BodyEdit;
        public long LogStart;
        public IReadOnlyList<SigstorePinnedCa>? Cas;
        public readonly List<SigstorePinnedLog> Ctlogs = new();
        public string SigB64 = "", PemB64 = "", LeafB64 = "", PayloadHex = "", PaeDigest = "";

        public D Body()
        {
            var ph = new D { ["algorithm"] = "sha256", ["value"] = PayloadHex };
            return Kind switch
            {
                "dsse" => new D
                {
                    ["kind"] = "dsse", ["apiVersion"] = "0.0.1",
                    ["spec"] = new D { ["payloadHash"] = ph, ["signatures"] = new L { new D { ["signature"] = SigB64, ["verifier"] = PemB64 } } },
                },
                "intoto" => new D
                {
                    ["kind"] = "intoto", ["apiVersion"] = "0.0.2",
                    ["spec"] = new D { ["content"] = new D { ["payloadHash"] = ph, ["envelope"] = new D { ["signatures"] = new L { new D { ["sig"] = B64(U(SigB64)), ["publicKey"] = PemB64 } } } } },
                },
                _ => new D
                {
                    ["kind"] = "hashedrekord", ["apiVersion"] = "0.0.2",
                    ["spec"] = new D
                    {
                        ["hashedRekordV002"] = new D
                        {
                            ["data"] = new D { ["algorithm"] = Hash == HashAlgorithmName.SHA384 ? "SHA2_384" : "SHA2_256", ["digest"] = PaeDigest },
                            ["signature"] = new D { ["content"] = SigB64, ["verifier"] = new D { ["x509Certificate"] = new D { ["rawBytes"] = LeafB64 } } },
                        },
                    },
                },
            };
        }

        public D Bundle()
        {
            var pae = Sigstore.DssePae(Sigstore.IntotoPayloadType, Payload);
            var sig = SigOverride ?? Signer.SignData(pae, Hash, DSASignatureFormat.Rfc3279DerSequence);
            SigB64 = B64(sig);
            LeafB64 = B64(LeafDer);
            PemB64 = B64(U("-----BEGIN CERTIFICATE-----\n" + LeafB64 + "\n-----END CERTIFICATE-----\n"));
            PayloadHex = Convert.ToHexString(SHA256.HashData(Payload)).ToLowerInvariant();
            PaeDigest = B64(Hash == HashAlgorithmName.SHA384 ? SHA384.HashData(pae) : SHA256.HashData(pae));
            var bodyObj = Body();
            BodyEdit?.Invoke(this, bodyObj);
            var body = U(J(bodyObj));
            var bodyB64 = B64(body);
            var v2 = Kind == "hashedrekord";
            var keyId = v2 ? EdLog.KeyId : LogId;
            var root = ProvenanceGate.Rfc9162LeafHash(body);
            var cpBody = V2Name + "\n1\n" + B64(root) + "\n";
            var cpSig = v2 ? EdSign(U(cpBody)) : LogKey.SignData(U(cpBody), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            var entry = new D
            {
                ["logId"] = new D { ["keyId"] = B64(keyId) },
                ["kindVersion"] = new D { ["kind"] = Kind, ["version"] = Kind == "dsse" ? "0.0.1" : "0.0.2" },
                ["logIndex"] = "7",
                ["canonicalizedBody"] = bodyB64,
                ["inclusionProof"] = new D
                {
                    ["logIndex"] = "0", ["rootHash"] = B64(root), ["treeSize"] = "1", ["hashes"] = new L(),
                    ["checkpoint"] = new D { ["envelope"] = cpBody + "\n— " + V2Name + " " + B64(Cat(keyId[..4], cpSig)) + "\n" },
                },
            };
            if (UseSet)
            {
                var msg = "{\"body\":\"" + bodyB64 + "\",\"integratedTime\":" + T0s + ",\"logID\":\"" + Convert.ToHexString(keyId).ToLowerInvariant() + "\",\"logIndex\":7}";
                entry["integratedTime"] = T0s.ToString(CultureInfo.InvariantCulture);
                entry["inclusionPromise"] = new D { ["signedEntryTimestamp"] = B64(LogKey.SignData(U(msg), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)) };
            }
            var vm = new D { ["certificate"] = new D { ["rawBytes"] = LeafB64 }, ["tlogEntries"] = new L { entry } };
            if (TsaTimes.Count > 0)
            {
                var list = new L();
                foreach (var t in TsaTimes) list.Add(new D { ["signedTimestamp"] = B64(SignedToken(sig, t)) });
                vm["timestampVerificationData"] = new D { ["rfc3161Timestamps"] = list };
            }
            return new D
            {
                ["mediaType"] = "application/vnd.dev.sigstore.bundle.v0.3+json",
                ["verificationMaterial"] = vm,
                ["dsseEnvelope"] = new D { ["payload"] = B64(Payload), ["payloadType"] = Sigstore.IntotoPayloadType, ["signatures"] = new L { new D { ["sig"] = SigB64 } } },
            };
        }

        public SigstorePinnedRoots Roots()
        {
            var log = Kind == "hashedrekord" ? EdLog : new SigstorePinnedLog(LogId, LogSpki, false, null, LogStart, long.MaxValue, null);
            return new SigstorePinnedRoots(new[] { log }, Ctlogs, Cas ?? new[] { new SigstorePinnedCa(new[] { CaCert }, 0, long.MaxValue) }, new[] { TsaCa });
        }
    }

    static string Statement(string? predicateType = "https://slsa.dev/provenance/v1", D? predicate = null)
    {
        var d = new D { ["_type"] = "https://in-toto.io/Statement/v1", ["subject"] = new L { new D { ["digest"] = new D { ["sha256"] = "aa" } } } };
        if (predicateType != null) d["predicateType"] = predicateType;
        d["predicate"] = predicate ?? new D
        {
            ["buildDefinition"] = new D { ["buildType"] = "b", ["externalParameters"] = new D() },
            ["runDetails"] = new D { ["builder"] = new D { ["id"] = "i" } },
        };
        return J(d);
    }

    static Fx V2()
    {
        var f = new Fx { Kind = "hashedrekord", UseSet = false };
        f.TsaTimes.Add(T0);
        return f;
    }

    static SigstoreCoreResult Run(Fx f, Action<D>? post = null)
    {
        var b = f.Bundle();
        post?.Invoke(b);
        return Sigstore.VerifySigstoreBundleCore(b, f.Roots());
    }

    static D Vm(D b) => (D)b["verificationMaterial"]!;
    static D Env(D b) => (D)b["dsseEnvelope"]!;
    static D Entry(D b) => (D)((L)Vm(b)["tlogEntries"]!)[0]!;
    static D Proof(D b) => (D)Entry(b)["inclusionProof"]!;
    static D Dig(D d, params string[] path)
    {
        foreach (var k in path) d = (D)d[k]!;
        return d;
    }
    static D First(D d, string key) => (D)((L)d[key]!)[0]!;

    static void Good(string name, SigstoreCoreResult r) => Assert.True(r.Ok, $"{name}: {r.Code}: {r.Detail}");
    static void No(string name, SigstoreCoreResult r, string code, string detail) =>
        Assert.True(!r.Ok && r.Code == code && r.Detail == detail, $"{name}: got ok={r.Ok} {r.Code}: {r.Detail}");

    // ---- L70-72 base64, L79-92 RFC 3339

    [Fact]
    public void Base64()
    {
        Assert.Equal(B(0x41), (byte[])Call("B64", "QQ==")!);
        Assert.Empty((byte[])Call("B64", "")!);
        foreach (var bad in new[] { "!!!!", "AAA", "A===" }) Assert.Equal("not base64", Bad(() => Call("B64", bad)));
        Assert.Equal("not base64", Bad(() => Call("B64", new object?[] { 5L })));
    }

    [Fact]
    public void Rfc3339AsTheReferenceReadsIt()
    {
        // Date.parse values, from node
        foreach (var (s, want) in new[]
        {
            ("2021-01-12T11:53:27Z", 1610452407000L), ("2021-01-12T11:53:27+01:00", 1610448807000L), ("2021-01-12T11:53:27-01:00", 1610456007000L),
            ("2021-01-12T11:53:27+01:59", 1610445267000L), ("2021-01-12T11:53:27.5Z", 1610452407500L), ("2021-01-12T11:53:27.9999Z", 1610452407999L),
            ("2021-01-12T11:53:27.123456789Z", 1610452407123L), ("0100-01-01T00:00:00Z", -59011459200000L),
        })
            Assert.Equal(want, (long)Call("Ms", s, "w")!);
        // refused by the reference too: an offset minute past 59 (NaN), years 0..99 (its Date.UTC round trip), a day that does not exist
        foreach (var s in new[] { "x", "2021-01-12", "2021-01-12T11:53:27+01:60", "2021-01-12T11:53:27+01:99", "0099-12-31T00:00:00Z", "0050-01-01T00:00:00Z", "2021-02-30T00:00:00Z" })
            Assert.Equal("w", Bad(() => Call("Ms", s, "w")));
    }

    [Fact]
    public void HashName() => Assert.Equal("unsupported hash", Bad(() => Call("Sha", "md5", Array.Empty<byte[]>())));

    // ---- L111-182 trusted root

    static D LogJ(string details, byte[] der, byte[] keyId, D? validFor = null, string? baseUrl = null)
    {
        var d = new D
        {
            ["publicKey"] = new D { ["rawBytes"] = B64(der), ["keyDetails"] = details, ["validFor"] = validFor ?? new D { ["start"] = "2021-01-12T11:53:27Z" } },
            ["logId"] = new D { ["keyId"] = B64(keyId) },
        };
        if (baseUrl != null) d["baseUrl"] = baseUrl;
        return d;
    }
    static D EcJ(D? validFor = null) => LogJ("PKIX_ECDSA_P256_SHA_256", LogSpki, LogId, validFor);
    static D CaJ() => new() { ["certChain"] = new D { ["certificates"] = new L { new D { ["rawBytes"] = B64(CaCert.RawData) } } }, ["validFor"] = new D { ["start"] = "2021-01-12T11:53:27Z" } };
    static D RootJ(L? tlogs = null, L? ctlogs = null, L? cas = null) => new()
    {
        ["mediaType"] = TrustedRootType, ["tlogs"] = tlogs ?? new L { EcJ() }, ["ctlogs"] = ctlogs ?? new L(), ["certificateAuthorities"] = cas ?? new L { CaJ() }, ["timestampAuthorities"] = new L(),
    };

    [Fact]
    public void TrustedRootRefusals()
    {
        var noKey = EcJ();
        noKey.Remove("publicKey");
        var noId = EcJ();
        noId.Remove("logId");
        var longDer = Cat(LogSpki, B(0));
        var rsaDer = RsaKey.ExportRSAPublicKey();
        var edDer = Cat(EdPrefix, EdRaw);
        var longEd = Cat(EdPrefix, EdRaw, B(0));
        var otherEd = Cat(B(0x31), EdPrefix[1..], EdRaw);
        (string Msg, D Root)[] rows =
        {
            ("not a trusted root v0.1", new D { ["mediaType"] = "x" }),
            ("log entry malformed", RootJ(new L { noKey })),
            ("log entry malformed", RootJ(new L { noId })),
            ("validFor.start missing", RootJ(new L { EcJ(new D()) })),
            ("validFor.start missing", RootJ(new L { EcJ(new D { ["start"] = "soon" }) })),
            ("validFor.end malformed", RootJ(new L { EcJ(new D { ["start"] = "2021-01-12T11:53:27Z", ["end"] = "later" }) })),
            ("log id is not the SHA-256 of its key", RootJ(new L { LogJ("PKIX_ECDSA_P256_SHA_256", LogSpki, new byte[32]) })),
            ("trailing key bytes", RootJ(new L { LogJ("PKIX_ECDSA_P256_SHA_256", longDer, SHA256.HashData(longDer)) })),
            ("log id is not the SHA-256 of its key", RootJ(ctlogs: new L { LogJ("PKCS1_RSA_PKCS1V5", rsaDer, new byte[32]) })),
            ("not an Ed25519 key", RootJ(new L { LogJ("PKIX_ED25519", longEd, EdId(V2Name, longEd[12..]), null, "https://" + V2Name) })),
            ("not an Ed25519 key", RootJ(new L { LogJ("PKIX_ED25519", otherEd, EdId(V2Name, EdRaw), null, "https://" + V2Name) })),
            ("log id is not the signed-note key hash of its key", RootJ(new L { LogJ("PKIX_ED25519", edDer, EdId("other.example", EdRaw), null, "https://" + V2Name) })),
            // no base URL: no name, whatever the id hashes
            ("log id is not the signed-note key hash of its key", RootJ(new L { LogJ("PKIX_ED25519", edDer, EdId("", EdRaw)) })),
            ("log id is not the signed-note key hash of its key", RootJ(new L { LogJ("PKIX_ED25519", edDer, EdId("Stryker was here!", EdRaw)) })),
            ("certificate authority entry malformed", RootJ(cas: new L { new D { ["certChain"] = new D { ["certificates"] = new L() } } })),
            ("a trusted root needs a transparency log and a CA", RootJ(new L())),
            ("a trusted root needs a transparency log and a CA", RootJ(cas: new L())),
        };
        foreach (var (msg, root) in rows)
            Assert.Equal("trusted root malformed: " + msg, Assert.Throws<ArgumentException>(() => Sigstore.ParseTrustedRoot(root)).Message);
    }

    [Fact]
    public void TrustedRootLogs()
    {
        var edDer = Cat(EdPrefix, EdRaw);
        var rsaSpki = RsaKey.ExportSubjectPublicKeyInfo();
        var r = Sigstore.ParseTrustedRoot(RootJ(
            new L { EcJ(new D { ["start"] = "2021-01-12T11:53:27.5-01:00", ["end"] = "2035-01-01T00:00:00Z" }), LogJ("PKIX_ED25519", edDer, EdId(V2Name, EdRaw), null, "https://" + V2Name + ":8443/x") },
            new L { LogJ("PKCS1_RSA_PKCS1V5", RsaKey.ExportRSAPublicKey(), SHA256.HashData(rsaSpki)) }));
        var ec = r.Tlogs[0];
        Assert.False(ec.Rsa);
        Assert.Equal(LogSpki, ec.Spki);
        Assert.Null(ec.V2Name);
        Assert.Equal(1610456007500L, ec.Start);
        Assert.Equal(S(2051222400).ToUnixTimeMilliseconds(), ec.End);
        var ed = r.Tlogs[1];
        Assert.False(ed.Rsa);
        Assert.Equal(EdRaw, ed.Ed25519Key);
        Assert.Equal(V2Name, ed.V2Name);
        Assert.Equal(long.MaxValue, ed.End);
        var rsa = r.Ctlogs[0];
        Assert.True(rsa.Rsa);
        Assert.Equal(rsaSpki, rsa.Spki);
    }

    // ---- L190-243 the TLV reader and writer

    [Fact]
    public void TlvReader()
    {
        (string Msg, byte[] Der)[] rows =
        {
            ("DER truncated", B(4)),
            ("DER multi-byte tag", B(0x1f, 0)),
            ("DER length", B(4, 0x80)),
            ("DER length", B(4, 0x85, 0, 0, 0, 0, 0, 0)),
            ("DER length", B(4, 0x82, 0)),
            ("DER overrun", B(4, 5)),
        };
        foreach (var (msg, der) in rows) Assert.Equal(msg, Bad(() => T(der)));
        Assert.Equal("DER truncated", Bad(() => T(B(4, 0), 0, 0))); // a zero limit is a limit
        var four = T(B(4, 0x84, 0, 0, 0, 1, 0xaa));
        Assert.Equal(6, P(four, "Body"));
        Assert.Equal(7, P(four, "End"));
        var exact = T(B(4, 0x81, 0));
        Assert.Equal(3, P(exact, "Body"));
        Assert.Equal(3, P(exact, "End"));
    }

    [Fact]
    public void OidTag()
    {
        var b = E(2, B(1));
        Assert.Equal("not an OID", Bad(() => Call("Oid", b, T(b))));
    }

    [Fact]
    public void DerWriter()
    {
        foreach (var (n, head) in new[]
        {
            (0x7f, B(4, 0x7f)), (0x80, B(4, 0x81, 0x80)), (0xff, B(4, 0x81, 0xff)), (0x100, B(4, 0x82, 1, 0)), (0x1234, B(4, 0x82, 0x12, 0x34)),
            (0xffff, B(4, 0x82, 0xff, 0xff)), (0x10000, B(4, 0x83, 1, 0, 0)), (0x012345, B(4, 0x83, 1, 0x23, 0x45)),
        })
        {
            var o = (byte[])Call("Enc", 4, new byte[n])!;
            Assert.Equal(head.Length + n, o.Length);
            Assert.Equal(head, o[..head.Length]);
        }
    }

    // ---- L254-337 the certificate shape

    [Fact]
    public void CertificateShapeRefusals()
    {
        byte[] Tb(byte[] issuer) => C(Ser, A256, issuer, Val, Nm, Spk, Ex3);
        byte[] Ka(byte[] alg) => C(Ser, alg, Nm, Val, Nm, Spk, Ex3);
        byte[] Ks(byte[] spki) => C(Ser, A256, Nm, Val, Nm, spki, Ex3);
        byte[] Kv(byte[] validity) => C(Ser, A256, Nm, validity, Nm, Spk, Ex3);
        byte[] Ke(params byte[][] exts) => C(Ser, A256, Nm, Val, Nm, Spk, E(0xa3, E(0x30, exts)));
        (string Msg, byte[] Der)[] rows =
        {
            ("version malformed", C(E(0xa0), Ser, A256, Nm, Val, Nm, Spk, Ex3)),
            ("version malformed", C(E(0xa0, Ser, Ser), Ser, A256, Nm, Val, Nm, Spk, Ex3)),
            ("version malformed", C(E(0xa0, E(4)), Ser, A256, Nm, Val, Nm, Spk, Ex3)),
            ("serial is not an INTEGER", C()),
            ("serial is not an INTEGER", C(Ver)),
            ("serial is not an INTEGER", C(A256, A256, Nm, Val, Nm, Spk, Ex3)),
            ("TBSCertificate truncated", C(Ser)),
            ("TBSCertificate truncated", C(Ser, A256)),
            ("validity malformed", C(Ser, A256, Nm)),
            ("validity malformed", C(Ser, A256, Nm, E(0x31, Utc, Utc), Nm, Spk, Ex3)),
            ("validity malformed", Kv(E(0x30, Utc))),
            ("validity malformed", Kv(E(0x30, Utc, Utc, Utc))),
            ("validity malformed", Kv(E(0x30, Utc, E(2, B(1))))),
            ("validity malformed", Kv(E(0x30, E(2, B(1)), Utc))),
            ("TBSCertificate truncated", C(Ser, A256, Nm, Val)),
            ("subjectPublicKeyInfo malformed", C(Ser, A256, Nm, Val, Nm)),
            ("subjectPublicKeyInfo malformed", Ks(E(0x31))),
            ("subjectPublicKeyInfo malformed", Ks(E(0x30, A256))),
            ("subjectPublicKeyInfo malformed", Ks(E(0x30, A256, SigB, SigB))),
            ("subjectPublicKeyInfo malformed", Ks(E(0x30, A256, E(4)))),
            ("AlgorithmIdentifier is not a SEQUENCE", Ks(E(0x30, Ser, SigB))),
            ("unexpected TBSCertificate member", C(Ser, A256, Nm, Val, Nm, Spk, E(4), Ex3)),
            ("AlgorithmIdentifier is not a SEQUENCE", Ka(Ser)),
            ("AlgorithmIdentifier malformed", Ka(E(0x30))),
            ("AlgorithmIdentifier malformed", Ka(E(0x30, O("1.2.3"), O("1.2.3"), O("1.2.3")))),
            ("not an OID", Ka(E(0x30, Ser))),
            ("Name is not a SEQUENCE", Tb(E(0x31))),
            ("RelativeDistinguishedName is not a SET", Tb(E(0x30, E(0x30)))),
            ("empty RelativeDistinguishedName", Tb(E(0x30, E(0x31)))),
            ("AttributeTypeAndValue is not a SEQUENCE", Tb(E(0x30, E(0x31, E(0x31))))),
            ("AttributeTypeAndValue malformed", Tb(E(0x30, E(0x31, E(0x30, O("2.5.4.3")))))),
            ("not an OID", Tb(E(0x30, E(0x31, E(0x30, Ser, E(0x0c)))))),
            ("AttributeValue is not a universal primitive", Tb(E(0x30, E(0x31, E(0x30, O("2.5.4.3"), E(0x30)))))),
            ("AttributeValue is not a universal primitive", Tb(E(0x30, E(0x31, E(0x30, O("2.5.4.3"), E(0x80)))))),
            ("certificate is not one SEQUENCE", E(0x31, E(0x30, Ser), A256, SigB)),
            ("certificate is not one SEQUENCE", Cat(C(Ser, A256, Nm, Val, Nm, Spk, Ex3), B(0))),
            ("certificate is not tbs, algorithm, signature", E(0x30, E(0x30, Ser, A256, Nm, Val, Nm, Spk, Ex3), A256)),
            ("certificate is not tbs, algorithm, signature", E(0x30, E(0x30, Ser, A256, Nm, Val, Nm, Spk, Ex3), A256, SigB, SigB)),
            ("no TBSCertificate", E(0x30, E(0x31), A256, SigB)),
            ("AlgorithmIdentifier is not a SEQUENCE", E(0x30, E(0x30, Ser, A256, Nm, Val, Nm, Spk, Ex3), Ser, SigB)),
            ("signatureValue is not a BIT STRING", E(0x30, E(0x30, Ser, A256, Nm, Val, Nm, Spk, Ex3), A256, E(4))),
            ("no extensions", C(Ser, A256, Nm, Val, Nm, Spk)),
            ("extensions malformed", C(Ser, A256, Nm, Val, Nm, Spk, E(0xa3))),
            ("extensions malformed", C(Ser, A256, Nm, Val, Nm, Spk, E(0xa3, E(4)))),
            ("extension is not a SEQUENCE", Ke(E(2, B(1)))),
            ("extension malformed", Ke(E(0x30, O("1.2.3")))),
            ("extension malformed", Ke(E(0x30, O("1.2.3"), E(1, B(0)), E(4), E(4)))),
            ("extension malformed", Ke(E(0x30, O("1.2.3"), E(2, B(0)), E(4)))),
            ("extension value is not an OCTET STRING", Ke(E(0x30, O("1.2.3"), E(2, B(0))))),
            ("duplicate extension 1.2.3", Ke(Ext("1.2.3", B(1)), Ext("1.2.3", B(2)))),
        };
        foreach (var (msg, der) in rows) Assert.Equal(msg, Bad(() => Pc(der)));
    }

    [Fact]
    public void CertificateShapeAccepted()
    {
        Assert.NotNull(Pc(C(Ver, Ser, A256, Nm, Val, Nm, Spk, Ex3)));
        Assert.NotNull(Pc(C(Ser, A256, Nm, Val, Nm, Spk, Ex3))); // a v1-shaped TBS has no [0]
        Assert.NotNull(Pc(C(Ser, A256, Nm, E(0x30, Utc, E(0x18, U("20350101000000Z"))), Nm, Spk, Ex3)));
        foreach (var tag in new[] { 0x81, 0x82, 0xa1, 0xa2 }) Assert.NotNull(Pc(C(Ser, A256, Nm, Val, Nm, Spk, E(tag), Ex3)));
    }

    // ---- L339-369 extension readers

    [Fact]
    public void Utf8IsStrict() => Assert.Equal("not UTF-8", Bad(() => Call("Utf8Strict", B(0xff))));

    static object PcExts(params byte[][] exts) => Pc(C(Ver, Ser, A256, Nm, Val, Nm, Spk, E(0xa3, E(0x30, exts))));

    [Fact]
    public void FulcioExtensions()
    {
        var pc = PcExts(Ext("1.3.6.1.4.1.57264.1.6", U("raw")), Ext("1.3.6.1.4.1.57264.1.8", E(4, U("x"))), Ext("1.3.6.1.4.1.57264.1.9", E(0x0c, U("der"))));
        Assert.Equal("raw", Call("FulcioExt", pc, 6));
        Assert.Equal("der", Call("FulcioExt", pc, 9));
        Assert.Null(Call("FulcioExt", pc, 12));
        Assert.Equal("extension .1.8 is not a DER UTF8String", Bad(() => Call("FulcioExt", pc, 8)));
    }

    [Fact]
    public void SanIdentity()
    {
        var uri = E(0x86, U("https://u"));
        Assert.Equal("https://u", Call("SanIdentity", PcExts(Ext(OidSan, E(0x30, uri)))));
        Assert.Equal("a@b", Call("SanIdentity", PcExts(Ext(OidSan, E(0x30, E(0x81, U("a@b")))))));
        Assert.Equal("no subjectAltName", Bad(() => Call("SanIdentity", PcExts(Ext("1.2.3", B(1))))));
        Assert.Equal("subjectAltName must hold exactly one name", Bad(() => Call("SanIdentity", PcExts(Ext(OidSan, E(0x30, uri, uri))))));
        Assert.Equal("subjectAltName must hold exactly one name", Bad(() => Call("SanIdentity", PcExts(Ext(OidSan, E(0x31, uri))))));
        Assert.Equal("subjectAltName must be a URI or an email", Bad(() => Call("SanIdentity", PcExts(Ext(OidSan, E(0x30, E(0x82, U("d"))))))));
    }

    // ---- L374-402 signature primitives (L400: the reference is OpenSSL Ed25519, see the report)

    [Fact]
    public void SigOk()
    {
        var m = U("m");
        var ec = LeafKey.SignData(m, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        var rsa = RsaKey.SignData(m, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(Is("SigOk", "sha256", Spk, m, ec));
        Assert.True(Is("SigOk", "sha256", RsaKey.ExportSubjectPublicKeyInfo(), m, rsa));
        Assert.False(Is("SigOk", "sha256", RsaKey.ExportSubjectPublicKeyInfo(), U("n"), rsa));
        Assert.False(Is("SigOk", "sha256", null, m, ec));
        Assert.False(Is("SigOk", "sha256", Cat(EdPrefix, EdRaw), m, new byte[64])); // a key type this helper does not take
        Assert.False(Is("SigOk", "sha256", B(1, 2, 3), m, ec)); // an SPKI that does not parse
        Assert.False(Is("SigOk", "md5", Spk, m, ec)); // a hash that does not exist
    }

    [Fact]
    public void Ed25519LogSignature()
    {
        var m = U("note");
        var sig = EdSign(m);
        Assert.True(Is("LogSigOk", EdLog, m, sig));
        Assert.False(Is("LogSigOk", EdLog, U("other"), sig));
        Assert.False(Is("LogSigOk", EdLog, m, sig[..63]));
        Assert.False(Is("LogSigOk", EdLog, null, sig)); // anything thrown is a refusal
        // S + L: RFC 8032 and OpenSSL refuse a scalar past the group order
        var order = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493", CultureInfo.InvariantCulture);
        var s = (new BigInteger(sig.AsSpan(32), isUnsigned: true) + order).ToByteArray(isUnsigned: true);
        Array.Resize(ref s, 32);
        Assert.False(Is("LogSigOk", EdLog, m, Cat(sig[..32], s)));
    }

    // ---- L413-445 certificate signatures and issuer links

    static byte[] Tbs(byte[] alg) => E(0x30, Ver, Ser, alg, Nm, Val, Nm, Spk, Ex3);
    static byte[] Signed(byte[] tbs, byte[] outer, byte[] sig, int tag = 3, int unused = 0) => E(0x30, tbs, outer, E(tag, B(unused), sig));
    static bool CertSig(byte[] der, X509Certificate2 up) => Is("CertSigOk", der, up);
    static byte[] EcSig(byte[] tbs, HashAlgorithmName h) => CaKey.SignData(tbs, h, DSASignatureFormat.Rfc3279DerSequence);

    [Fact]
    public void CertificateSignatureAlgorithms()
    {
        foreach (var (oid, h) in new[] { ("1.2.840.10045.4.3.2", HashAlgorithmName.SHA256), ("1.2.840.10045.4.3.3", HashAlgorithmName.SHA384), ("1.2.840.10045.4.3.4", HashAlgorithmName.SHA512) })
        {
            var a = E(0x30, O(oid));
            var tbs = Tbs(a);
            Assert.True(CertSig(Signed(tbs, a, EcSig(tbs, h)), CaCert), oid);
        }
        foreach (var (oid, h) in new[] { ("1.2.840.113549.1.1.11", HashAlgorithmName.SHA256), ("1.2.840.113549.1.1.12", HashAlgorithmName.SHA384), ("1.2.840.113549.1.1.13", HashAlgorithmName.SHA512) })
        {
            var a = E(0x30, O(oid));
            var tbs = Tbs(a);
            Assert.True(CertSig(Signed(tbs, a, RsaKey.SignData(tbs, h, RSASignaturePadding.Pkcs1)), RsaCert), oid);
        }
    }

    [Fact]
    public void CertificateSignatureRefusals()
    {
        var tbs = Tbs(A256);
        var sig = EcSig(tbs, HashAlgorithmName.SHA256);
        Assert.True(CertSig(Signed(tbs, A256, sig), CaCert));
        Assert.False(CertSig(Signed(tbs, A256, sig, tag: 4), CaCert)); // not a BIT STRING
        Assert.False(CertSig(Signed(tbs, A256, sig, unused: 1), CaCert)); // unused bits
        var unknown = E(0x30, O("1.2.3"));
        var tbsU = Tbs(unknown);
        Assert.False(CertSig(Signed(tbsU, unknown, EcSig(tbsU, HashAlgorithmName.SHA256)), CaCert));
        Assert.False(CertSig(E(0x30, tbs, A256), CaCert)); // no signature member
        Assert.False(CertSig(B(1), CaCert)); // not DER
    }

    [Fact]
    public void TheTbsAlgorithmMustBeTheOuterOne()
    {
        // OpenSSL X509_verify refuses this, for every certificate of a chain (the signature itself is good under the outer algorithm)
        var tbs = Tbs(A384);
        Assert.False(CertSig(Signed(tbs, A256, EcSig(tbs, HashAlgorithmName.SHA256)), CaCert));
        // the same through a chain: the name links, the validity covers T0, only the algorithms differ
        byte[] Link(byte[] alg)
        {
            var t = E(0x30, Ver, Ser, alg, CaCert.SubjectName.RawData, Val, Nm, Spk, Ex3);
            return Signed(t, A256, EcSig(t, HashAlgorithmName.SHA256));
        }
        Assert.True(Is("ChainOk", new[] { new X509Certificate2(Link(A256)), CaCert }, T0));
        Assert.False(Is("ChainOk", new[] { new X509Certificate2(Link(A384)), CaCert }, T0));
        var v1 = E(0x30, Ser, A256, Nm, Val, Nm, Spk, Ex3); // no version: the algorithm is the second member
        Assert.True(CertSig(Signed(v1, A256, EcSig(v1, HashAlgorithmName.SHA256)), CaCert));
        var v1Other = E(0x30, Ser, A384, Nm, Val, Nm, Spk, Ex3);
        Assert.False(CertSig(Signed(v1Other, A256, EcSig(v1Other, HashAlgorithmName.SHA256)), CaCert));
    }

    [Fact]
    public void SpkiIsTheOneTheCertificateCarries()
    {
        Assert.Equal(CaKey.ExportSubjectPublicKeyInfo(), (byte[])Call("SpkiOf", CaCert)!);
        var v1 = new X509Certificate2(Signed(E(0x30, Ser, A256, Nm, Val, Nm, Spk), A256, B(1)));
        Assert.Equal(Spk, (byte[])Call("SpkiOf", v1)!);
    }

    [Fact]
    public void Ed25519CertificateSignature()
    {
        var edAlg = E(0x30, O("1.3.101.112"));
        X509Certificate2 Up(byte[] spki)
        {
            var t = E(0x30, Ver, Ser, edAlg, Nm, Val, Nm, spki);
            return new X509Certificate2(Signed(t, edAlg, EdSign(t)));
        }
        var edUp = Up(Cat(EdPrefix, EdRaw));
        // the same 32 bytes under another algorithm (X25519): not an Ed25519 key, though the bytes would verify
        var xUp = Up(E(0x30, E(0x30, O("1.3.101.110")), E(3, B(0), EdRaw)));
        var tbs = Tbs(edAlg);
        var sig = EdSign(tbs);
        Assert.True(CertSig(Signed(tbs, edAlg, sig), edUp));
        Assert.False(CertSig(Signed(tbs, edAlg, sig), xUp));
        Assert.False(CertSig(Signed(tbs, edAlg, sig[..63]), edUp));
        Assert.False(CertSig(Signed(tbs, edAlg, Cat(sig, B(0))), edUp));
        var flipped = (byte[])sig.Clone();
        flipped[10] ^= 1;
        Assert.False(CertSig(Signed(tbs, edAlg, flipped), edUp));
    }

    [Fact]
    public void IssuerLinks()
    {
        var mid = Issued("mid", MidKey, "ca", CaKey, ca: true);
        var midNotCa = Issued("mid", MidKey, "ca", CaKey, ca: false);
        var low = Issued("low", LeafKey, "mid", MidKey, ca: false);
        Assert.True(Is("NamedBy", low.RawData, mid)); // an issuer without keyUsage may sign
        Assert.True(Is("ChainOk", new[] { low, mid, CaCert }, T0));
        Assert.False(Is("ChainOk", new[] { low, midNotCa, CaCert }, T0)); // an intermediate must be a CA
    }

    [Fact]
    public void TheIssuerLinkIsCheckIssuedOverTheOriginalBytes()
    {
        var r = new CertificateRequest("CN=ca", CaKey, HashAlgorithmName.SHA256);
        r.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(r.PublicKey, false));
        var up = r.CreateSelfSigned(Nb, Na);
        byte[] With(string oid, byte[] value) => Leaf(q => q.CertificateExtensions.Add(new X509Extension(oid, value, false)));
        Assert.True(Is("NamedBy", Leaf(), up));
        Assert.False(Is("NamedBy", With("2.5.29.35", B(1, 2)), up)); // a malformed AKID
        Assert.False(Is("NamedBy", With("2.5.29.35", E(0x30, E(0x82, B(0x7e)))), up)); // the AKID serial of another issuer
        Assert.False(Is("NamedBy", With("2.5.29.35", E(0x30, E(0xa1, E(0xa4, E(0x30))))), up)); // the AKID directory name of another issuer
        Assert.False(Is("NamedBy", With("2.5.29.30", B(1, 2)), up)); // malformed nameConstraints
        Assert.False(Is("NamedBy", With("2.5.29.31", B(1, 2)), up)); // malformed CRL distribution points
        Assert.False(Is("NamedBy", new byte[] { 0x30 }, up)); // not a certificate: refused, not thrown
    }

    // ---- L447-479 the leaf as the platform loader sees it

    static readonly byte[] StandInValue = E(0x30, E(0x86, U("https://x")));

    static List<(string Oid, byte[] Value)> ExtsOf(object pc) =>
        ((IEnumerable)P(pc, "Exts")!).Cast<object>().Select(e => ((string)P(e, "OidText")!, (byte[])P(e, "Value")!)).ToList();

    [Fact]
    public void StandInSan()
    {
        var field = typeof(Sigstore).GetField("StandInSan", BindingFlags.NonPublic | BindingFlags.Static)!;
        Assert.Equal(E(0x30, O(OidSan), E(1, B(0xff)), E(4, StandInValue)), (byte[])field.GetValue(null)!);
    }

    [Fact]
    public void LeafX509ReplacesTheSanInPlace()
    {
        var orig = E(0x30, E(0x86, U("https://orig")));
        var eku = E(0x30, O("1.3.6.1.5.5.7.3.3"));
        var withSan = (X509Certificate2)Call("LeafX509", PcExts(Ext(OidSan, orig), Ext(OidEku, eku)))!;
        var got = ExtsOf(Pc(withSan.RawData));
        Assert.Equal(new[] { OidSan, OidEku }, got.Select(e => e.Oid).ToArray());
        Assert.Equal(StandInValue, got[0].Value);
        Assert.Equal(eku, got[1].Value);

        var noSan = (X509Certificate2)Call("LeafX509", PcExts(Ext(OidEku, eku)))!;
        var got2 = ExtsOf(Pc(noSan.RawData));
        Assert.Equal(new[] { OidEku, OidSan }, got2.Select(e => e.Oid).ToArray());
        Assert.Equal(StandInValue, got2[1].Value);
    }

    // ---- L520-570 SCT

    [Fact]
    public void U16() => Assert.Equal(0x0102, Call("U16", B(9, 1, 2), 1));

    static byte[] Sct(byte[] logId, ulong ts, byte[] ext, byte[] sig, int hash = 4, int sigAlg = 3, int? extLen = null, int? sigLen = null) =>
        Cat(B(0), logId, Be64(ts), U16b(extLen ?? ext.Length), ext, B(hash, sigAlg), U16b(sigLen ?? sig.Length), sig);
    static byte[] RawList(byte[] body) => Cat(U16b(body.Length), body);
    static byte[] SctList(params byte[][] items) => RawList(Cat(items.Select(i => Cat(U16b(i.Length), i)).ToArray()));
    static byte[] SctTbs(params byte[][] exts) => E(0x30, Ver, Ser, A256, Nm, Val, Nm, Spk, E(0xa3, E(0x30, exts)));
    static string? RunSct(byte[] list, SigstorePinnedLog? log = null) =>
        (string?)Call("VerifySct", PcExts(Ext(OidSct, E(4, list))), CaCert, new SigstorePinnedRoots(new[] { EcLog }, new[] { log ?? CtLog }, Array.Empty<SigstorePinnedCa>(), Array.Empty<SigstorePinnedCa>()));

    [Fact]
    public void SctRefusals()
    {
        var none = new byte[32];
        var pin = CtLog.KeyId;
        var nothing = Array.Empty<byte>();
        var roots = new SigstorePinnedRoots(new[] { EcLog }, new[] { CtLog }, Array.Empty<SigstorePinnedCa>(), Array.Empty<SigstorePinnedCa>());
        Assert.Equal("no embedded SCT", Call("VerifySct", PcExts(Ext("1.2.3", B(1))), CaCert, roots));
        Assert.Equal("SCT list is not an OCTET STRING", Call("VerifySct", PcExts(Ext(OidSct, E(2, B(1)))), CaCert, roots));
        (string Want, byte[] List)[] rows =
        {
            ("SCT list length", B(0)),
            ("SCT list length", B(0, 5)),
            ("no SCT from a pinned CT log", B(0, 0)),
            ("SCT truncated", RawList(B(0))), // a list ending inside a length
            ("SCT truncated", RawList(Cat(B(0, 100), new byte[10]))), // past the list, n >= 47
            ("SCT truncated", RawList(Cat(B(0, 47), new byte[46]))), // one byte past the list
            ("SCT truncated", RawList(Cat(B(0, 10), new byte[10]))), // inside the list, too short
            ("no SCT from a pinned CT log", SctList(Sct(none, 1, nothing, nothing))), // exactly 47 bytes, another log
            ("SCT truncated", SctList(Sct(none, 1, nothing, nothing, extLen: 5))), // the extensions pass the end
            ("SCT truncated", SctList(Sct(none, 1, nothing, nothing, extLen: 4))), // the extensions reach the end
            ("SCT truncated", SctList(Sct(none, 1, nothing, nothing, extLen: 1))), // no room for the signature header
            ("SCT malformed", SctList(Sct(none, 1, nothing, nothing, sigLen: 1))),
            ("SCT is not SHA-256 with ECDSA or RSA", SctList(Sct(pin, 1, nothing, nothing, hash: 2))),
            ("SCT is not SHA-256 with ECDSA or RSA", SctList(Sct(pin, 1, nothing, nothing, sigAlg: 2))),
            ("SCT timestamp out of range", SctList(Sct(pin, 9007199254740992, nothing, nothing))),
            ("SCT timestamp out of range", SctList(Sct(pin, 1UL << 63, nothing, nothing))),
            ("SCT signature invalid", SctList(Sct(pin, 1, nothing, B(1)))),
        };
        foreach (var (want, list) in rows) Assert.Equal(want, RunSct(list));
        // zero is a good timestamp: what refuses it here is the log's validity
        Assert.Equal("SCT log key not valid at its timestamp", RunSct(SctList(Sct(pin, 0, nothing, nothing)), CtLog with { Start = 1000 }));
        Assert.Equal("SCT log key not valid at its timestamp", RunSct(SctList(Sct(pin, 2000, nothing, nothing)), CtLog with { End = 1000 }));
    }

    static byte[] SctSignature(byte[] tbs, ulong ts, byte[] ext)
    {
        var signed = Cat(B(0, 0), Be64(ts), B(0, 1), SHA256.HashData(CaKey.ExportSubjectPublicKeyInfo()), B(tbs.Length >> 16, (tbs.Length >> 8) & 255, tbs.Length & 255), tbs, U16b(ext.Length), ext);
        return CtKey.SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }

    [Fact]
    public void SctSignedBytesCarryEveryLengthByte()
    {
        var roots = new SigstorePinnedRoots(new[] { EcLog }, new[] { CtLog }, Array.Empty<SigstorePinnedCa>(), Array.Empty<SigstorePinnedCa>());
        // a TBS past 64 KiB (the top length byte), an SCT extension past 255 bytes (the high length byte)
        foreach (var (tbsPad, extLen) in new[] { (1, 0), (70000, 0), (1, 300) })
        {
            var kept = Ext("1.2.3.4", new byte[tbsPad]);
            var ext = new byte[extLen];
            var sig = SctSignature(SctTbs(kept), 1234, ext);
            var der = E(0x30, SctTbs(kept, Ext(OidSct, E(4, SctList(Sct(CtLog.KeyId, 1234, ext, sig))))), A256, SigB);
            Assert.Null(Call("VerifySct", Pc(der), CaCert, roots));
        }
    }

    // ---- L574-585 digest and genTime

    [Fact]
    public void DigestAndGenTime()
    {
        var unknown = E(0x30, O("1.2.3"));
        Assert.Equal("unsupported digest algorithm", Bad(() => Call("DigestOf", unknown, T(unknown))));
        object? G(int tag, string s)
        {
            var b = E(tag, U(s));
            return Call("GeneralizedTime", b, T(b));
        }
        Assert.Equal(1672531200000L, G(0x18, "20230101000000Z"));
        Assert.Equal(1672531200500L, G(0x18, "20230101000000.5Z"));
        Assert.Equal(1672531200123L, G(0x18, "20230101000000.1239Z"));
        Assert.Equal("genTime is not a GeneralizedTime", Bad(() => G(0x17, "20230101000000Z")));
        Assert.Equal("genTime malformed", Bad(() => G(0x18, "2023")));
        // the reference's Date.UTC reads years 0..99 as 19xx and its round trip refuses them
        Assert.Equal("genTime is not a real date", Bad(() => G(0x18, "00500101000000Z")));
        Assert.Equal(-59011459200000L, G(0x18, "01000101000000Z"));
        Assert.ThrowsAny<ArgumentException>(() => G(0x18, "20230230000000Z"));
    }

    // ---- L592-652 RFC 3161

    [Fact]
    public void Rfc3161Refusals()
    {
        var data = U("dsse-sig");
        var tsas = new[] { TsaCa };
        var tst = Tst(data);
        var attrs = Attrs(tst);
        var sigT = E(4, B(1));
        var v = E(2, B(3));
        var da = E(0x31);
        var enc = Encap(tst);
        var si = Si(attrs, sigT);
        var ctOnly = E(0xa0, E(0x30, O(OidCt), E(0x31, O(OidTst))));
        var mdOnly = E(0xa0, E(0x30, O(OidMd), E(0x31, E(4, SHA256.HashData(tst)))));
        (string Msg, byte[] Token)[] rows =
        {
            ("timestamp is not one SEQUENCE", E(0x31)),
            ("timestamp is not one SEQUENCE", Cat(E(0x30), B(0))),
            ("not CMS SignedData", E(0x30)),
            ("not CMS SignedData", E(0x30, E(0x30))), // an empty first member is no status
            ("timestamp status is not granted", E(0x30, E(0x30, E(2, B(2))), Tok(tst, si))),
            ("no timeStampToken", E(0x30, E(0x30, E(2, B(0))))),
            ("not CMS SignedData", E(0x30, O(OidSd))),
            ("not CMS SignedData", E(0x30, O("1.2.3"), E(0xa0))),
            ("not CMS SignedData", E(0x30, O(OidSd), E(0x30))),
            ("no encapsulated content", Sd(v, da)),
            ("no encapsulated content", Sd(v, da, E(4))),
            ("content is not TSTInfo", Sd(v, da, E(0x30, O(OidTst)), E(0x31, si))),
            ("content is not TSTInfo", Sd(v, da, E(0x30, O("1.2.3"), E(0xa0, E(4, tst))), E(0x31, si))),
            ("TSTInfo is not an OCTET STRING", Sd(v, da, E(0x30, O(OidTst), E(0xa0, E(0x31))), E(0x31, si))),
            ("unsupported digest algorithm", Tok(Tst(data, alg: "1.2.3"), si)),
            ("messageImprint is not the hash of the signature", Tok(Tst(data, imprint: new byte[32]), si)),
            ("genTime malformed", Tok(Tst(data, gen: "x"), si)),
            ("no signerInfos", Sd(v, da, enc, E(0x30))),
            ("exactly one SignerInfo is required", Sd(v, da, enc, E(0x31))),
            ("exactly one SignerInfo is required", Sd(v, da, enc, E(0x31, si, si))),
            ("signed attributes are required", Tok(tst, Si(E(0x31), sigT))),
            ("an attribute must have one value", Tok(tst, Si(E(0xa0, E(0x30, O(OidCt), E(0x31))), sigT))),
            ("signed attributes do not commit to the TSTInfo", Tok(tst, Si(E(0xa0), sigT))),
            ("signed attributes do not commit to the TSTInfo", Tok(tst, Si(ctOnly, sigT))),
            ("signed attributes do not commit to the TSTInfo", Tok(tst, Si(mdOnly, sigT))),
            ("signature is not an OCTET STRING", Tok(tst, Si(attrs, E(3, B(0, 1))))),
            ("no pinned timestamp authority signed it (valid at its time)", Tok(tst, si)),
        };
        foreach (var (msg, token) in rows) Assert.Equal(msg, Bad(() => Sigstore.VerifyRfc3161(token, data, tsas)));
        Assert.Equal("no pinned timestamp authority signed it (valid at its time)", Bad(() => Sigstore.VerifyRfc3161(SignedToken(data, T0), data, Array.Empty<SigstorePinnedCa>())));
    }

    [Fact]
    public void Rfc3161Accepted()
    {
        var data = U("dsse-sig");
        var tsas = new[] { TsaCa };
        var token = SignedToken(data, T0);
        Assert.Equal(T0, Sigstore.VerifyRfc3161(token, data, tsas));
        foreach (var status in new[] { 0, 1 }) Assert.Equal(T0, Sigstore.VerifyRfc3161(E(0x30, E(0x30, E(2, B(status))), token), data, tsas));
    }

    // ---- L656-689 checkpoint and integers

    static string CpLine(string body) => "— l " + B64(Cat(LogId[..4], LogKey.SignData(U(body), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)));
    static string? Cp(string text, byte[] root) => (string?)Call("VerifyCheckpoint", text, EcLog, 1L, root);

    [Fact]
    public void Checkpoint()
    {
        var root = new byte[32];
        var r = B64(root);
        var body = "o\n1\n" + r + "\n";
        (string Want, string Text)[] rows =
        {
            ("checkpoint has no signature block", body),
            ("checkpoint body too short or without an origin", "\n\nx"), // a blank line at the very start
            ("checkpoint body too short or without an origin", "o\n1\n\n"),
            ("checkpoint body too short or without an origin", "\n1\n" + r + "\n\nx"),
            ("checkpoint size differs from the proof", "o\n2\n" + r + "\n\nx"),
            ("checkpoint root differs from the proof", "o\n1\n" + B64(new byte[31]) + "\n\nx"),
            ("no checkpoint signature by the pinned log key", body + "\nnot a signature line\n"),
            ("no checkpoint signature by the pinned log key", body + "\n— l " + B64(new byte[70]) + "\n"),
        };
        foreach (var (want, text) in rows) Assert.Equal(want, Cp(text, root));
        Assert.Null(Cp(body + "\n" + CpLine(body) + "\n", root));
        Assert.Null(Cp(body + "\n" + CpLine(body) + "\n\n", root)); // the FIRST blank line ends the body
    }

    [Fact]
    public void DecimalIntegers()
    {
        Assert.Equal(9007199254740991L, Call("DecInt", "9007199254740991"));
        Assert.Equal("integer out of range", Bad(() => Call("DecInt", "9007199254740992")));
        Assert.Equal("not a decimal integer string", Bad(() => Call("DecInt", "01")));
        Assert.Equal("not a decimal integer string", Bad(() => Call("DecInt", new object?[] { 5L })));
    }

    // ---- L715-904 the verifier, end to end

    [Fact]
    public void WholeBundlesVerify()
    {
        var r = Run(new Fx());
        Good("dsse", r);
        Assert.Equal(T0s, r.Core!["signed_time"]);
        Assert.Equal(7L, r.Core["rekor_log_index"]);
        Assert.Equal("v1", r.Core["rekor"]);
        Assert.Equal(Identity, r.Core["identity"]);
        Assert.Equal(Issuer, r.Core["oidc_issuer"]);
        Good("intoto", Run(new Fx { Kind = "intoto" }));
        var v2 = Run(V2());
        Good("hashedrekord", v2);
        Assert.Equal("v2", v2.Core!["rekor"]);
        Assert.Equal(0L, v2.Core["rekor_log_index"]);
        var p384 = new Fx { Signer = Leaf384Key, Hash = HashAlgorithmName.SHA384, LeafDer = Leaf(req: new CertificateRequest("CN=leaf", Leaf384Key, HashAlgorithmName.SHA256)) };
        Good("dsse P-384", Run(p384));
        var p384v2 = V2();
        p384v2.Signer = Leaf384Key;
        p384v2.Hash = HashAlgorithmName.SHA384;
        p384v2.LeafDer = p384.LeafDer;
        Good("hashedrekord P-384", Run(p384v2));
        var facts = Sigstore.VerifySigstoreBundle(new Fx().Bundle(), new Fx().Roots());
        Assert.True(facts.Ok, facts.Detail);
    }

    [Fact]
    public void EarlyRefusals()
    {
        (string Name, Action<D> Edit, string Code, string Detail)[] rows =
        {
            ("media type", b => b["mediaType"] = "x", "media_type", "unsupported media type x"),
            ("media type null", b => b["mediaType"] = null, "media_type", "unsupported media type null"),
            ("media type absent", b => b.Remove("mediaType"), "media_type", "unsupported media type undefined"),
            ("no certificate", b => Vm(b).Remove("certificate"), "not_keyless", "no Fulcio certificate (public-key bundles are not supported)"),
            ("no envelope", b => b.Remove("dsseEnvelope"), "envelope", "not a DSSE bundle"),
            ("message signature", b => b["messageSignature"] = new D(), "envelope", "not a DSSE bundle"),
            ("payload type", b => Env(b)["payloadType"] = "x", "envelope", "payloadType is not application/vnd.in-toto+json"),
            ("no signature", b => Env(b)["signatures"] = new L(), "envelope", "a DSSE envelope must carry exactly one signature"),
            ("payload", b => Env(b)["payload"] = "!", "malformed", "fail closed: not base64"),
            ("certificate bytes", b => Dig(Vm(b), "certificate")["rawBytes"] = "!", "cert_parse", "fail closed: not base64"),
            ("no entries", b => Vm(b)["tlogEntries"] = new L(), "tlog_count", "exactly one transparency log entry is required"),
            ("no kindVersion", b => Entry(b).Remove("kindVersion"), "tlog_kind", "unsupported entry "),
            ("kind not a string", b => Dig(Entry(b), "kindVersion")["kind"] = 5L, "tlog_kind", "unsupported entry "),
            ("version not a string", b => Dig(Entry(b), "kindVersion")["version"] = 5L, "tlog_kind", "unsupported entry "),
            ("kind", b => Dig(Entry(b), "kindVersion")["kind"] = "x", "tlog_kind", "unsupported entry x/0.0.1"),
            ("log not pinned", b => Dig(Entry(b), "logId")["keyId"] = B64(new byte[32]), "tlog_key", "the entry names a log the verifier did not pin"),
            ("v2 entry on a v1 log", b => Entry(b)["kindVersion"] = new D { ["kind"] = "hashedrekord", ["version"] = "0.0.2" }, "tlog_key", "the entry type does not match the log version"),
            ("SET", b => Dig(Entry(b), "inclusionPromise")["signedEntryTimestamp"] = B64(B(1)), "tlog_set", "signed entry timestamp invalid"),
            ("no time", b => Entry(b).Remove("inclusionPromise"), "no_verified_time", "no verified time: no RFC 3161 timestamp and no Rekor v1 signed entry timestamp"),
            ("no inclusion proof", b => Entry(b).Remove("inclusionProof"), "tlog_inclusion", "no inclusion proof"),
            ("inclusion hashes", b => Proof(b)["hashes"] = new L { B64(new byte[32]) }, "tlog_inclusion", "the inclusion proof does not lead to the root"),
            ("checkpoint envelope", b => Dig(Proof(b), "checkpoint")["envelope"] = 5L, "tlog_checkpoint", "the checkpoint envelope is not a string"),
        };
        foreach (var (name, edit, code, detail) in rows) No(name, Run(new Fx(), edit), code, detail);
        var ok = new Fx();
        No("no roots", Sigstore.VerifySigstoreBundleCore(ok.Bundle(), null), "malformed", "not a bundle");
        No("the log key's window", Run(new Fx { LogStart = T0 + 1 }), "tlog_key", "the log key was not valid at a signing time");
    }

    [Fact]
    public void CertificatePathRefusals()
    {
        var badCa = new SigstorePinnedCa(new[] { Issued("ca", MidKey, "ca", MidKey, ca: true) }, 0, long.MaxValue);
        No("not issued", Run(new Fx { Cas = new[] { badCa } }), "cert_chain", "no pinned CA issued the certificate, valid at every signing time");
        No("leaf is a CA", Run(new Fx { LeafDer = Leaf(q => q.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true))) }), "cert_chain", "the leaf is a CA certificate");
        No("leaf window", Run(new Fx { LeafDer = Leaf(nb: S(T0s - 7200), na: S(T0s - 3600)) }), "cert_time", "the certificate was not valid at a signing time");
        No("no EKU", Run(new Fx { LeafDer = Leaf(eku: false) }), "cert_eku", "the certificate lacks the code-signing EKU");

        // the pin window is inclusive at its start
        Good("CA window starts at the time", Run(new Fx { Cas = new[] { new SigstorePinnedCa(new[] { CaCert }, T0, long.MaxValue) } }));

        // a pinned CA with no chain throws inside the stage: the refusal still names it. The first CA that fits ends the search.
        var empty = new SigstorePinnedCa(Array.Empty<X509Certificate2>(), 0, long.MaxValue);
        var thrown = Run(new Fx { Cas = new[] { empty } });
        Assert.False(thrown.Ok);
        Assert.Equal("cert_chain", thrown.Code);
        Assert.StartsWith("fail closed: ", thrown.Detail);
        Good("first CA wins", Run(new Fx { Cas = new[] { new SigstorePinnedCa(new[] { CaCert }, 0, long.MaxValue), empty } }));
    }

    [Fact]
    public void TheChainMustHoldAtEveryVerifiedTime()
    {
        // TSA time T0 + 1000 s, SET time T0: the CA certificate ends in between, the leaf covers both
        var shortCa = new SigstorePinnedCa(new[] { MakeCa(Nb, S(T0s + 500)) }, 0, long.MaxValue);
        var f = new Fx { Cas = new[] { shortCa } };
        f.TsaTimes.Add(T0 + 1_000_000);
        No("one time out", Run(f), "cert_chain", "no pinned CA issued the certificate, valid at every signing time");
        var control = new Fx();
        control.TsaTimes.Add(T0 + 1_000_000);
        var r = Run(control);
        Good("both times in", r);
        Assert.Equal(T0s, r.Core!["signed_time"]);
    }

    [Fact]
    public void SctStageNamesItsRefusals()
    {
        var malformed = new Fx { LeafDer = Leaf(q => q.CertificateExtensions.Add(new X509Extension(OidSct, B(4, 5), false))) };
        malformed.Ctlogs.Add(CtLog);
        No("thrown inside", Run(malformed), "sct", "fail closed: DER overrun");
        var none = new Fx();
        none.Ctlogs.Add(CtLog);
        No("no SCT", Run(none), "sct", "no embedded SCT");
    }

    [Fact]
    public void EntryBodyRefusals()
    {
        const string Payload = "the entry names another payload", Sig = "the entry names another signature", Cert = "the entry names another certificate", One = "the entry must name exactly one signature", Kind = "the entry body is not the kind the bundle names";
        static D Spec(D b) => (D)b["spec"]!;
        static D In(D b) => Dig(b, "spec", "content");
        static D H(D b) => Dig(b, "spec", "hashedRekordV002");
        var other = B64(new byte[8]);
        (string Name, string BundleKind, Action<Fx, D> Edit, string Detail)[] rows =
        {
            ("kind", "dsse", (f, b) => b["kind"] = "intoto", Kind),
            ("no kind", "dsse", (f, b) => b.Remove("kind"), Kind),
            ("no apiVersion", "dsse", (f, b) => b.Remove("apiVersion"), Kind),
            ("kind not a string", "dsse", (f, b) => b["kind"] = 5L, Kind),
            ("apiVersion not a string", "dsse", (f, b) => b["apiVersion"] = 5L, Kind),
            ("apiVersion", "dsse", (f, b) => b["apiVersion"] = "9", Kind),

            ("dsse hash alg", "dsse", (f, b) => Dig(b, "spec", "payloadHash")["algorithm"] = "sha512", Payload),
            ("dsse hash", "dsse", (f, b) => Dig(b, "spec", "payloadHash")["value"] = "00", Payload),
            ("dsse no signature", "dsse", (f, b) => Spec(b)["signatures"] = new L(), One),
            ("dsse signature", "dsse", (f, b) => First(Spec(b), "signatures")["signature"] = other, Sig),
            ("dsse verifier", "dsse", (f, b) => First(Spec(b), "signatures")["verifier"] = other, Cert),

            ("intoto hash alg", "intoto", (f, b) => Dig(b, "spec", "content", "payloadHash")["algorithm"] = "sha512", Payload),
            ("intoto hash", "intoto", (f, b) => Dig(b, "spec", "content", "payloadHash")["value"] = "00", Payload),
            ("intoto no signature", "intoto", (f, b) => Dig(In(b), "envelope")["signatures"] = new L(), One),
            ("intoto signature", "intoto", (f, b) => First(Dig(In(b), "envelope"), "signatures")["sig"] = B64(U(other)), Sig),
            ("intoto key", "intoto", (f, b) => First(Dig(In(b), "envelope"), "signatures")["publicKey"] = other, Cert),

            ("rekor2 algorithm", "hashedrekord", (f, b) => Dig(H(b), "data")["algorithm"] = "SHA2_512", "the entry digest algorithm is not the signing key's"),
            ("rekor2 algorithm of another key", "hashedrekord", (f, b) => Dig(H(b), "data")["algorithm"] = "SHA2_384", "the entry digest algorithm is not the signing key's"),
            ("rekor2 no algorithm", "hashedrekord", (f, b) => Dig(H(b), "data")["algorithm"] = "", "the entry digest algorithm is not the signing key's"),
            ("rekor2 digest", "hashedrekord", (f, b) => Dig(H(b), "data")["digest"] = other, "the entry names another envelope"),
            ("rekor2 content", "hashedrekord", (f, b) => Dig(H(b), "signature")["content"] = other, Sig),
            ("rekor2 verifier", "hashedrekord", (f, b) => Dig(H(b), "signature", "verifier", "x509Certificate")["rawBytes"] = other, Cert),
        };
        foreach (var (name, kind, edit, detail) in rows)
        {
            var f = kind == "hashedrekord" ? V2() : new Fx { Kind = kind };
            f.BodyEdit = edit;
            No(name, Run(f), "tlog_body", detail);
        }
    }

    [Fact]
    public void SignatureAndLeafKeyRefusals()
    {
        // the signature of another message, named by the entry (the log saw it), under the right key
        var other = new Fx { SigOverride = LeafKey.SignData(U("other"), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence) };
        No("DSSE", Run(other), "signature", "DSSE signature invalid");
        var rsa = new Fx { SigOverride = B(1), LeafDer = Leaf(req: new CertificateRequest("CN=leaf", RsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) };
        No("RSA leaf", Run(rsa), "signature", "unsupported leaf key type");
    }

    [Fact]
    public void ALeafCurveTheReferenceDoesNotNameIsRefused()
    {
        // FAIL-OPEN regression: the key SIZE used to choose the hash, so any 256-bit curve verified. The reference names P-256 and P-384 only.
        Assert.Equal("sha256", Sigstore.HashOfCurve(Convert.FromHexString("06082A8648CE3D030107")));
        Assert.Equal("sha384", Sigstore.HashOfCurve(Convert.FromHexString("06052B81040022")));
        Assert.Null(Sigstore.HashOfCurve(Convert.FromHexString("06092B2403030208010107"))); // brainpoolP256r1
        Assert.Null(Sigstore.HashOfCurve(Convert.FromHexString("06052B8104000A"))); // secp256k1
        Assert.Null(Sigstore.HashOfCurve(Array.Empty<byte>()));
        if (!OperatingSystem.IsLinux()) return; // macOS has no brainpool keys; the end-to-end refusal runs where the key can be made
        using var key = ECDsa.Create(ECCurve.NamedCurves.brainpoolP256r1);
        var f = new Fx { Signer = key, LeafDer = Leaf(req: new CertificateRequest("CN=leaf", key, HashAlgorithmName.SHA256)) };
        No("brainpoolP256r1", Run(f), "signature", "unsupported leaf key type");
    }

    static readonly byte[] P256Oid = Convert.FromHexString("06082A8648CE3D030107");

    [Fact]
    public void AnRsaLeafWithCurveParametersHasNoHash()
    {
        // sigstore.ts:472: the key TYPE decides first, so curve parameters on a non-EC key name no hash
        var spki = E(0x30, E(0x30, O("1.2.840.113549.1.1.1"), P256Oid), E(3, B(0), RsaKey.ExportRSAPublicKey()));
        X509Certificate2 c;
        try { c = new X509Certificate2(C(Ver, Ser, A256, Nm, Val, Nm, spki)); }
        catch (CryptographicException) when (!OperatingSystem.IsLinux()) { return; } // shortcut: only OpenSSL's lenient load is known for this odd SPKI, and mutation runs on Linux
        Assert.Equal(P256Oid, c.GetKeyAlgorithmParameters());
        Assert.Null(Call("LeafHashAlg", c));
    }

    [Fact]
    public void AKeyAgreementOnlyLeafIsNotASigningKey()
    {
        // stricter than sigstore.ts:472-474, which reads no key usage: the platform refuses this key as ECDSA, so nothing verifies under it
        static byte[] WithUsage(X509KeyUsageFlags u) => Leaf(q => q.CertificateExtensions.Add(new X509KeyUsageExtension(u, true)));
        var agreement = new X509Certificate2(WithUsage(X509KeyUsageFlags.KeyAgreement));
        Assert.Equal(P256Oid, agreement.GetKeyAlgorithmParameters());
        Assert.Null(Call("LeafHashAlg", agreement));
        Assert.Equal("sha256", Call("LeafHashAlg", new X509Certificate2(WithUsage(X509KeyUsageFlags.KeyAgreement | X509KeyUsageFlags.DigitalSignature))));
        No("key agreement", Run(new Fx { LeafDer = WithUsage(X509KeyUsageFlags.KeyAgreement) }), "signature", "unsupported leaf key type");
    }

    [Fact]
    public void AnEd25519LeafHasNoHashAndNoParameters()
    {
        // sigstore.ts:472; absent parameters read as empty, they do not throw
        var c = new X509Certificate2(C(Ver, Ser, A256, Nm, Val, Nm, Cat(EdPrefix, EdRaw)));
        Assert.Empty(c.GetKeyAlgorithmParameters());
        Assert.Null(Call("LeafHashAlg", c));
    }

    [Fact]
    public void IdentityRefusals()
    {
        No("no issuer", Run(new Fx { LeafDer = Leaf(iss: false) }), "identity", "no OIDC issuer extension");
        var two = Leaf(q => q.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.57264.1.1", U("https://other.example"), false)));
        No("issuers disagree", Run(new Fx { LeafDer = two }), "identity", "the two issuer extensions disagree");
    }

    [Fact]
    public void StatementRefusals()
    {
        var subject = new L { new D { ["digest"] = new D { ["sha256"] = "aa" } } };
        (string Name, D Statement, string Detail)[] rows =
        {
            ("type", new D { ["_type"] = "x" }, "not an in-toto Statement v1"),
            ("no subject", new D { ["_type"] = ProvenanceGate.IntotoStatementV1 }, "no subject"),
            ("no digest", new D { ["_type"] = ProvenanceGate.IntotoStatementV1, ["subject"] = new L { new D() } }, "no sha256/sha512 subject digest (or more than 64)"),
            ("no predicate type", new D { ["_type"] = ProvenanceGate.IntotoStatementV1, ["subject"] = subject }, "no predicateType"),
        };
        foreach (var (name, st, detail) in rows) No(name, Run(new Fx { Payload = U(J(st)) }), "statement", detail);
    }

    [Fact]
    public void PredicateRefusals()
    {
        SigstoreResult R(string statement)
        {
            var f = new Fx { Payload = U(statement) };
            return Sigstore.VerifySigstoreBundle(f.Bundle(), f.Roots());
        }
        var other = R(Statement("x"));
        Assert.Equal("predicate", other.Code);
        Assert.Equal("predicate x is not SLSA provenance v1", other.Detail);
        var empty = R(Statement(predicate: new D()));
        Assert.Equal("predicate", empty.Code);
        Assert.Equal("buildType, externalParameters and builder.id are required (SLSA Build L1)", empty.Detail);
    }
}
