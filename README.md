// SaltRegexTemplates.cs
// Regex strings only, grouped by reusable templates with parameter arrays.
// Build your Regex objects with IgnoreCase | CultureInvariant (and Singleline if desired).

using System;
using System.Collections.Generic;

public static class SaltRegexTemplates
{
    public static readonly string[] Patterns;

    static SaltRegexTemplates()
    {
        var list = new List<string>();

        // --- Templates ---
        string tpl_InitWithSaltAndIters = @"\b{CLASS}\b[\s\S]*?\.Init\s*\(\s*[^,]+,\s*[^,]+,\s*\d+";
        string tpl_InitWithSaltOnly     = @"\b{CLASS}\b[\s\S]*?\.Init\s*\(\s*[^,]+,\s*[^)]+\)";
        string tpl_NewCtor              = @"\bnew\s+{CLASS}\s*\(";
        string tpl_StaticCall           = @"\b{CLASS}\.{METHOD}\s*\(";
        string tpl_ClassMethod          = @"\b{CLASS}\b[\s\S]*?{METHOD}\s*\(";

        // --- Parameter sets ---

        // Generators that call Init(password, salt, iterations)
        string[] classes_InitWithSaltAndIters =
        {
            "PbeParametersGenerator",
            "Pkcs5S2ParametersGenerator",
            "Pkcs5S1ParametersGenerator",
            "Pkcs12ParametersGenerator"
        };

        // Generators that call Init(password, salt)
        string[] classes_InitWithSaltOnly =
        {
            "OpenSSLPBEParametersGenerator"
        };

        // Constructors whose mere presence implies salt-capable context
        string[] classes_NewCtor =
        {
            "PssSigner",
            "Iso9796d2PssSigner",
            "Blake2bDigest",
            "Blake2sDigest",
            "S2k",
            "Pbkdf2Params",
            "PbeParameter",
            "Pkcs12PbeParams",
            "HKDFParameters",
            "CmsPbeKey",
            "Srp6Client",
            "Srp6Server"
        };

        // Static calls of interest: Class.Method(
        string[] pairs_StaticCall =
        {
            "SCrypt|Generate",
            "OpenBSDBCrypt|Generate",
            "OpenBSDBCrypt|GenerateSalt",
            "Srp6Utilities|GenerateSalt",
            "Srp6Utilities|GenerateVerifier"
        };

        // Class … Method(  (may appear on same or different lines)
        string[] pairs_ClassMethod =
        {
            "HKDFBytesGenerator|Init",
            "Argon2BytesGenerator|Init",
            "SkeinDigest|Init",
            "CmsEnvelopedDataGenerator|AddPasswordRecipient",
            "CmsAuthenticatedDataGenerator|AddPasswordRecipient"
        };

        // --- Expand templates with parameters ---

        foreach (var cls in classes_InitWithSaltAndIters)
        {
            list.Add(tpl_InitWithSaltAndIters.Replace("{CLASS}", cls));
        }

        foreach (var cls in classes_InitWithSaltOnly)
        {
            list.Add(tpl_InitWithSaltOnly.Replace("{CLASS}", cls));
        }

        foreach (var cls in classes_NewCtor)
        {
            list.Add(tpl_NewCtor.Replace("{CLASS}", cls));
        }

        foreach (var pair in pairs_StaticCall)
        {
            var parts = pair.Split('|');
            list.Add(tpl_StaticCall.Replace("{CLASS}", parts[0]).Replace("{METHOD}", parts[1]));
        }

        foreach (var pair in pairs_ClassMethod)
        {
            var parts = pair.Split('|');
            list.Add(tpl_ClassMethod.Replace("{CLASS}", parts[0]).Replace("{METHOD}", parts[1]));
        }

        // --- Standalone signatures (kept as literals to minimize template count) ---
        list.Add(@"\bsaltLength\s*:");                                // RSA-PSS named arg
        list.Add(@"\bSkeinParameters\b[\s\S]*?PARAM_SALT");           // Skein salt parameter
        list.Add(@"\bArgon2Parameters\b[\s\S]*?WithSalt\s*\(");       // Argon2 builder WithSalt(...)
        list.Add(@"\bOrg\.BouncyCastle\.Bcpg\.S2k\b");                // Fully-qualified OpenPGP S2K

        Patterns = list.ToArray();
    }
}
