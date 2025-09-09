# TempCrypto
Temporary 
using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Asn1.Anssi;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto.Parameters;

public static class BcCurveExampleEmitter
{
    public static void Main()
    {
        // 1) Generic EC lookup examples (ECNamedCurveTable + CustomNamedCurves)
        EmitHeader("Generic EC (ECNamedCurveTable + CustomNamedCurves)");
        EmitGenericEcExamples();

        // 2) Per-registry EC examples
        EmitHeader("SEC (prime & binary) via SecNamedCurves");
        EmitRegistryExamples("Org.BouncyCastle.Asn1.Sec.SecNamedCurves", SecNamedCurves.Names.Cast<string>(),
            n => SecNamedCurves.GetByName(n));

        EmitHeader("NIST via NistNamedCurves");
        EmitRegistryExamples("Org.BouncyCastle.Asn1.Nist.NistNamedCurves", NistNamedCurves.Names.Cast<string>(),
            n => NistNamedCurves.GetByName(n));

        EmitHeader("X9.62 via X962NamedCurves");
        EmitRegistryExamples("Org.BouncyCastle.Asn1.X9.X962NamedCurves", X962NamedCurves.Names.Cast<string>(),
            n => X962NamedCurves.GetByName(n));

        EmitHeader("Brainpool via TeleTrusTNamedCurves");
        EmitRegistryExamples("Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTNamedCurves", TeleTrusTNamedCurves.Names.Cast<string>(),
            n => TeleTrusTNamedCurves.GetByName(n));

        EmitHeader("ANSSI via AnssiNamedCurves");
        EmitRegistryExamples("Org.BouncyCastle.Asn1.Anssi.AnssiNamedCurves", AnssiNamedCurves.Names.Cast<string>(),
            n => AnssiNamedCurves.GetByName(n));

        // 3) SM2 (GM)
        EmitHeader("SM2 via GMNamedCurves");
        EmitSm2Examples();

        // 4) GOST sets
        EmitHeader("GOST 2001 via ECGost3410NamedCurves");
        EmitGost2001Examples();

        EmitHeader("GOST 2012 (TC26) via RosstandartNamedCurves");
        EmitGost2012Examples();

        // 5) Bonus: fixed-curve (no named-curve lookup)
        EmitHeader("Bonus: fixed-curve examples (no named-curve registries)");
        EmitFixedCurveExamples();
    }

    private static void EmitHeader(string title)
    {
        Console.WriteLine();
        Console.WriteLine(new string('-', 80));
        Console.WriteLine("// " + title);
        Console.WriteLine(new string('-', 80));
        Console.WriteLine();
    }

    private static void EmitGenericEcExamples()
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string n in ECNamedCurveTable.Names) names.Add(n);
        foreach (string n in CustomNamedCurves.Names) names.Add(n);

        foreach (var name in names.OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
        {
            Console.WriteLine($"// {name}");
            Console.WriteLine($"var x9 = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName(\"{name}\")");
            Console.WriteLine($"         ?? Org.BouncyCastle.Asn1.Sec.CustomNamedCurves.GetByName(\"{name}\");");
            Console.WriteLine("var domain = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(");
            Console.WriteLine("    x9.Curve, x9.G, x9.N, x9.H, x9.GetSeed());");
            Console.WriteLine();
        }
    }

    private static void EmitRegistryExamples(string registryClassName, IEnumerable<string> names, Func<string, X9ECParameters> getByName)
    {
        foreach (var name in names.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
        {
            // Resolve now just to ensure the curve exists in this build
            var x9 = getByName(name);
            if (x9 == null)
                continue;

            Console.WriteLine($"// {name}");
            Console.WriteLine($"var x9 = {registryClassName}.GetByName(\"{name}\");");
            Console.WriteLine("var domain = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(");
            Console.WriteLine("    x9.Curve, x9.G, x9.N, x9.H, x9.GetSeed());");
            Console.WriteLine();
        }
    }

    private static void EmitSm2Examples()
    {
        foreach (var name in GMNamedCurves.Names.Cast<string>().OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
        {
            var x9 = GMNamedCurves.GetByName(name);
            if (x9 == null)
                continue;

            Console.WriteLine($"// {name}");
            Console.WriteLine($"var sm2 = Org.BouncyCastle.Asn1.GM.GMNamedCurves.GetByName(\"{name}\");");
            Console.WriteLine("var domain = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(");
            Console.WriteLine("    sm2.Curve, sm2.G, sm2.N, sm2.H, sm2.GetSeed());");
            Console.WriteLine();
        }
    }

    private static void EmitGost2001Examples()
    {
        foreach (var name in ECGost3410NamedCurves.Names.Cast<string>().OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
        {
            var x9 = ECGost3410NamedCurves.GetByName(name);
            if (x9 == null)
                continue;

            Console.WriteLine($"// {name}");
            Console.WriteLine($"var gp = Org.BouncyCastle.Asn1.CryptoPro.ECGost3410NamedCurves.GetByName(\"{name}\");");
            Console.WriteLine("var domain = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(");
            Console.WriteLine("    gp.Curve, gp.G, gp.N, gp.H, gp.GetSeed());");
            Console.WriteLine();
        }
    }

    private static void EmitGost2012Examples()
    {
        foreach (var name in RosstandartNamedCurves.Names.Cast<string>().OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
        {
            var x9 = RosstandartNamedCurves.GetByName(name);
            if (x9 == null)
                continue;

            Console.WriteLine($"// {name}");
            Console.WriteLine($"var tc26 = Org.BouncyCastle.Asn1.Rosstandart.RosstandartNamedCurves.GetByName(\"{name}\");");
            Console.WriteLine("var domain = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(");
            Console.WriteLine("    tc26.Curve, tc26.G, tc26.N, tc26.H, tc26.GetSeed());");
            Console.WriteLine();
        }
    }

    private static void EmitFixedCurveExamples()
    {
        Console.WriteLine("// Ed25519 (fixed curve)");
        Console.WriteLine("var ed25519Priv = new Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters(new Org.BouncyCastle.Security.SecureRandom());");
        Console.WriteLine("var ed25519Pub  = ed25519Priv.GeneratePublicKey();");
        Console.WriteLine();

        Console.WriteLine("// Ed448 (fixed curve)");
        Console.WriteLine("var ed448Priv = new Org.BouncyCastle.Crypto.Parameters.Ed448PrivateKeyParameters(new Org.BouncyCastle.Security.SecureRandom());");
        Console.WriteLine("var ed448Pub  = ed448Priv.GeneratePublicKey();");
        Console.WriteLine();

        Console.WriteLine("// X25519 (ECDH, fixed curve)");
        Console.WriteLine("var x25519Priv = new Org.BouncyCastle.Crypto.Parameters.X25519PrivateKeyParameters(new Org.BouncyCastle.Security.SecureRandom());");
        Console.WriteLine("var x25519Pub  = x25519Priv.GeneratePublicKey();");
        Console.WriteLine();

        Console.WriteLine("// X448 (ECDH, fixed curve)");
        Console.WriteLine("var x448Priv = new Org.BouncyCastle.Crypto.Parameters.X448PrivateKeyParameters(new Org.BouncyCastle.Security.SecureRandom());");
        Console.WriteLine("var x448Pub  = x448Priv.GeneratePublicKey();");
        Console.WriteLine();
    }
}
