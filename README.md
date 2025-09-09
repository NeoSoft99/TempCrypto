using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.Anssi;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Crypto.Parameters;

public static class EcCurveCatalog
{
    public sealed class CurveInfo
    {
        public string CanonicalName { get; init; }
        public DerObjectIdentifier Oid { get; init; }
        public X9ECParameters X9 { get; init; }
        public ECDomainParameters Domain { get; init; }

        public IReadOnlyCollection<string> Aliases => _aliases;
        public IReadOnlyCollection<string> Sources => _sources;

        internal readonly HashSet<string> _aliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        internal readonly HashSet<string> _sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public override string ToString()
        {
            return $"{CanonicalName} (OID {Oid?.Id})";
        }
    }

    /// <summary>
    /// Build a unique set of EC curves across all known Bouncy Castle registries.
    /// Deduplication is by OID. The chosen CanonicalName is the first name encountered.
    /// </summary>
    public static IReadOnlyDictionary<string, CurveInfo> LoadUniqueByCanonicalName()
    {
        var byOid = new Dictionary<string, CurveInfo>(StringComparer.Ordinal);

        void AddRegistry(
            string source,
            IEnumerable names,
            Func<string, DerObjectIdentifier> getOid,
            Func<DerObjectIdentifier, X9ECParameters> getByOid)
        {
            if (names == null)
            {
                return;
            }

            foreach (var obj in names)
            {
                var name = obj?.ToString();
                if (string.IsNullOrWhiteSpace(name))
                {
                    continue;
                }

                var oid = getOid(name);
                if (oid == null)
                {
                    continue;
                }

                // Prefer optimized/custom implementations if available.
                var x9 = Sec.CustomNamedCurves.GetByOid(oid) ?? getByOid(oid);
                if (x9 == null)
                {
                    continue;
                }

                var key = oid.Id;
                if (!byOid.TryGetValue(key, out var entry))
                {
                    var domain = new ECDomainParameters(x9.Curve, x9.G, x9.N, x9.H, x9.GetSeed());

                    entry = new CurveInfo
                    {
                        CanonicalName = name,
                        Oid = oid,
                        X9 = x9,
                        Domain = domain
                    };
                    entry._aliases.Add(name);
                    entry._sources.Add(source);

                    byOid[key] = entry;
                }
                else
                {
                    entry._aliases.Add(name);
                    entry._sources.Add(source);
                }
            }
        }

        // Enumerate all primary registries
        AddRegistry("X9.62", X962NamedCurves.Names, X962NamedCurves.GetOid, X962NamedCurves.GetByOid);
        AddRegistry("SEC (SECG)", SecNamedCurves.Names, SecNamedCurves.GetOid, SecNamedCurves.GetByOid);
        AddRegistry("NIST", NistNamedCurves.Names, NistNamedCurves.GetOid, NistNamedCurves.GetByOid);
        AddRegistry("TeleTrusT (brainpool)", TeleTrusTNamedCurves.Names, TeleTrusTNamedCurves.GetOid, TeleTrusTNamedCurves.GetByOid);
        AddRegistry("ANSSI (FRP)", AnssiNamedCurves.Names, AnssiNamedCurves.GetOid, AnssiNamedCurves.GetByOid);
        AddRegistry("GM (SM2)", GMNamedCurves.Names, GMNamedCurves.GetOid, GMNamedCurves.GetByOid);
        AddRegistry("GOST R 34.10-2001 (CryptoPro)", ECGost3410NamedCurves.Names, ECGost3410NamedCurves.GetOid, ECGost3410NamedCurves.GetByOid);
        AddRegistry("GOST R 34.10-2012 (Rosstandart/TC26)", RosstandartNamedCurves.Names, RosstandartNamedCurves.GetOid, RosstandartNamedCurves.GetByOid);

        // Also sweep the generic table to collect extra aliases like "P-256", "P-384", etc.
        AddRegistry("ECNamedCurveTable (aliases)", ECNamedCurveTable.Names, ECNamedCurveTable.GetOid, ECNamedCurveTable.GetByOid);

        // Return keyed by the canonical name we recorded first for each OID
        var result = new Dictionary<string, CurveInfo>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in byOid.Values)
        {
            result[e.CanonicalName] = e;
        }
        return result;
    }

    /// <summary>
    /// Resolve an EC curve by any known alias (case-insensitive).
    /// </summary>
    public static bool TryGetDomainByAnyName(string name, out ECDomainParameters domain, out CurveInfo info)
    {
        domain = null;
        info = null;
        if (string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        var unique = LoadUniqueByCanonicalName();

        // Check canonical names first
        if (unique.TryGetValue(name, out var hit))
        {
            info = hit;
            domain = hit.Domain;
            return true;
        }

        // Fall back to alias search
        foreach (var e in unique.Values)
        {
            if (e.Aliases.Contains(name))
            {
                info = e;
                domain = e.Domain;
                return true;
            }
        }

        return false;
    }
}

// ------------------------
// Usage examples
// ------------------------

// Build the unique catalog once (deduplicated by OID).
var catalog = EcCurveCatalog.LoadUniqueByCanonicalName();

// Example: secp256k1 (only one entry even though multiple registries know about it)
if (EcCurveCatalog.TryGetDomainByAnyName("secp256k1", out var k1Domain, out var k1Info))
{
    // k1Domain is Org.BouncyCastle.Crypto.Parameters.ECDomainParameters
    // k1Info.Aliases might include: "secp256k1"
}

// Example: brainpoolP384r1
if (EcCurveCatalog.TryGetDomainByAnyName("brainpoolP384r1", out var bp384Domain, out var bp384Info))
{
    // Use bp384Domain
}

// Example: SM2
if (EcCurveCatalog.TryGetDomainByAnyName("sm2p256v1", out var sm2Domain, out var sm2Info))
{
    // Use sm2Domain
}

// Example: GOST CryptoPro A
if (EcCurveCatalog.TryGetDomainByAnyName("GostR3410-2001-CryptoPro-A", out var gpDomain, out var gpInfo))
{
    // Use gpDomain
}

// Example: TC26 GOST 2012 256 set A
if (EcCurveCatalog.TryGetDomainByAnyName("Tc26-Gost-3410-12-256-paramSetA", out var tc26Domain, out var tc26Info))
{
    // Use tc26Domain
}

// Optional: enumerate everything (unique, no duplicates like P-256/prime256v1/secp256r1).
foreach (var entry in catalog.Values.OrderBy(e => e.CanonicalName, StringComparer.OrdinalIgnoreCase))
{
    Console.WriteLine($"{entry.CanonicalName} | OID={entry.Oid.Id} | Bits={entry.X9.Curve.FieldSize}");
}
