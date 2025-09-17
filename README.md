// Single-file snippet: (1) one-line BouncyCastle IV/nonce usage examples; (2) C# regex templates to detect them.
// NOTE: This compiles (given BouncyCastle & System.Text.RegularExpressions references) but is not meant to run.

using System;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace BcIvScannerSignatures
{
    public static class Signatures
    {
        // --------------------------
        // (1) ONE-LINE EXAMPLES
        // --------------------------
        public static void ExampleIvUsages()
        {
            // Dummy inputs just to keep code compilable
            byte[] key = new byte[32];
            byte[] iv = new byte[16];
            byte[] nonce = new byte[12];
            byte[] aad = Array.Empty<byte>();
            int macBits = 128;

            // ---- Classic block cipher modes (IV via ParametersWithIV) ----
            CipherUtilities.GetCipher("AES/CBC/PKCS7").Init(true,  new ParametersWithIV(new KeyParameter(key), iv));
            CipherUtilities.GetCipher("DES/CBC/PKCS7").Init(false, new ParametersWithIV(new KeyParameter(key), iv));
            CipherUtilities.GetCipher("DESEDE/CBC/PKCS7").Init(true, new ParametersWithIV(new KeyParameter(key), iv));
            CipherUtilities.GetCipher("RC2/CBC/PKCS7").Init(true,  new ParametersWithIV(new KeyParameter(key), iv));
            CipherUtilities.GetCipher("BLOWFISH/CBC/PKCS7").Init(true, new ParametersWithIV(new KeyParameter(key), iv));
            CipherUtilities.GetCipher("AES/CFB/NoPadding").Init(true,  new ParametersWithIV(new KeyParameter(key), iv));
            CipherUtilities.GetCipher("AES/OFB/NoPadding").Init(true,  new ParametersWithIV(new KeyParameter(key), iv));
            CipherUtilities.GetCipher("AES/CTR/NoPadding").Init(true,  new ParametersWithIV(new KeyParameter(key), iv)); // CTR a.k.a. SIC

            // Explicit mode classes (also IV via ParametersWithIV)
            new BufferedBlockCipher(new CbcBlockCipher(new AesEngine())).Init(true, new ParametersWithIV(new KeyParameter(key), iv));
            new BufferedBlockCipher(new CfbBlockCipher(new AesEngine(), 128)).Init(true, new ParametersWithIV(new KeyParameter(key), iv));
            new BufferedBlockCipher(new OfbBlockCipher(new AesEngine(), 128)).Init(true, new ParametersWithIV(new KeyParameter(key), iv));
            new BufferedBlockCipher(new SicBlockCipher(new AesEngine())).Init(true, new ParametersWithIV(new KeyParameter(key), iv));

            // Other block algorithms with CBC (IV via ParametersWithIV)
            new BufferedBlockCipher(new CbcBlockCipher(new CamelliaEngine())).Init(true, new ParametersWithIV(new KeyParameter(key), iv));
            new BufferedBlockCipher(new CbcBlockCipher(new TwofishEngine())).Init(true, new ParametersWithIV(new KeyParameter(key), iv));
            new BufferedBlockCipher(new CbcBlockCipher(new Cast5Engine())).Init(true, new ParametersWithIV(new KeyParameter(key), iv));

            // ---- AEAD modes (nonce via AeadParameters) ----
            new GcmBlockCipher(new AesEngine()).Init(true, new AeadParameters(new KeyParameter(key), macBits, nonce, aad));
            new CcmBlockCipher(new AesEngine()).Init(true, new AeadParameters(new KeyParameter(key), macBits, nonce, aad));
            new EaxBlockCipher(new AesEngine()).Init(true, new AeadParameters(new KeyParameter(key), macBits, nonce, aad));
            CipherUtilities.GetCipher("AES/GCM/NoPadding").Init(true, new AeadParameters(new KeyParameter(key), macBits, nonce, aad));

            // ---- Stream ciphers that take IV/nonce via ParametersWithIV ----
            new ChaChaEngine().Init(true, new ParametersWithIV(new KeyParameter(key), nonce));
            new ChaCha7539Engine().Init(true, new ParametersWithIV(new KeyParameter(key), nonce));
            new Salsa20Engine().Init(true, new ParametersWithIV(new KeyParameter(key), nonce));

            // ---- PBE generators that RETURN key+IV (ParametersWithIV) ----
            new Pkcs12ParametersGenerator(new Sha256Digest()).GenerateDerivedParameters("AES", 256, 128);
            new Pkcs5S2ParametersGenerator().GenerateDerivedParameters("AES", 256, 128);
            new OpenSslPbeParametersGenerator().GenerateDerivedParameters("AES", 256, 128);

            // ---- Wrapping IV inside ParametersWithRandom (common pattern) ----
            new ParametersWithRandom(new ParametersWithIV(new KeyParameter(key), iv), new SecureRandom());
        }

        // --------------------------
        // (2) C# REGEX SCANNER TEMPLATES
        // --------------------------
        // These patterns aim to detect the constructs above.
        // Use RegexOptions.IgnoreCase when helpful; most are case-sensitive to reduce false positives.
        public static readonly Regex[] IvUsageRegexes = new Regex[]
        {
            // Direct creation of an IV-bearing parameter
            new Regex(@"\bnew\s+ParametersWithIV\s*\(", RegexOptions.Compiled),

            // AEAD nonce-bearing parameter
            new Regex(@"\bnew\s+AeadParameters\s*\(", RegexOptions.Compiled),

            // Init(...) with ParametersWithIV
            new Regex(@"\.Init\s*\(\s*(?:true|false)\s*,\s*new\s+ParametersWithIV\s*\(", RegexOptions.Compiled),

            // Init(...) with AeadParameters
            new Regex(@"\.Init\s*\(\s*(?:true|false)\s*,\s*new\s+AeadParameters\s*\(", RegexOptions.Compiled),

            // CipherUtilities with IV/nonce-relevant modes
            new Regex(@"CipherUtilities\.GetCipher\(\s*""[^""]*/(?:CBC|CFB|OFB|CTR|SIC|GCM|EAX|CCM)[^""]*""\s*\)", RegexOptions.Compiled | RegexOptions.IgnoreCase),

            // Explicit block mode classes that require IV
            new Regex(@"\bnew\s+(?:Cbc|Cfb|Ofb|Sic)BlockCipher\s*\(", RegexOptions.Compiled),

            // Explicit AEAD block mode classes
            new Regex(@"\bnew\s+(?:Gcm|Ccm|Eax)BlockCipher\s*\(", RegexOptions.Compiled),

            // Stream engines that use ParametersWithIV for nonce/IV
            new Regex(@"\bnew\s+(?:ChaCha7539Engine|ChaChaEngine|Salsa20Engine)\s*\(\s*\)", RegexOptions.Compiled),

            // ParametersWithRandom wrapping ParametersWithIV (common wrap pattern)
            new Regex(@"\bnew\s+ParametersWithRandom\s*\(\s*new\s+ParametersWithIV\s*\(", RegexOptions.Compiled),

            // PBE generators that produce ParametersWithIV (key+IV) via two-size overloads
            new Regex(@"\bnew\s+(?:Pkcs12ParametersGenerator|Pkcs5S2ParametersGenerator|OpenSslPbeParametersGenerator)\s*\([^)]*\)\s*\.GenerateDerivedParameters\s*\(\s*(?:""[^""]+""\s*,\s*)?\d+\s*,\s*\d+\s*\)", RegexOptions.Compiled),

            // (Optional) Tighter catch: ParametersWithIV constructed directly from a KeyParameter
            new Regex(@"\bParametersWithIV\s*\(\s*new\s+KeyParameter\b", RegexOptions.Compiled)
        };
    }
}

// Single file: SaltUsageExamplesAndScanner.cs
// Purpose:
//  1) One-line, compilable examples showing where BouncyCastle APIs use salt.
//  2) C# Regex templates to detect those usages in source code.
//
// Notes:
//  - This compiles as-is assuming a reference to BouncyCastle.
//  - Lines are "usage signatures" (may be no-ops) intended for scanners.
//  - Brace style follows standard C# conventions (opening { on a new line).

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

// BouncyCastle namespaces
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Agreement.Srp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Math;

namespace SaltSignatures
{
    public static class SaltUsageExamples
    {
        #pragma warning disable CS0219, CS0168, CS0414 // suppress unused locals for demo lines
        public static void OneLineExamples()
        {
            // --- Dummy inputs (minimal to keep the examples compilable) ---
            byte[] password = Array.Empty<byte>();
            byte[] salt     = Array.Empty<byte>();
            byte[] ikm      = Array.Empty<byte>();
            byte[] info     = Array.Empty<byte>();
            byte[] identity = Array.Empty<byte>();
            char[] passwordChars = Array.Empty<char>();
            var random = new SecureRandom();
            var group  = new Srp6GroupParameters(BigInteger.One, new BigInteger("2"));
            // ----------------------------------------------------------------

            // 1) PBE / PBKDFs (salt is explicit)
            new Pkcs5S2ParametersGenerator().Init(password, salt, 100_000);                              // PBKDF2
            new Pkcs5S1ParametersGenerator(new Sha1Digest()).Init(password, salt, 1_000);               // PKCS#5 v1.5
            new Pkcs12ParametersGenerator(new Sha256Digest()).Init(password, salt, 2_048);              // PKCS#12
            new OpenSSLPBEParametersGenerator().Init(password, salt);                                    // OpenSSL EVP_BytesToKey-style

            // 2) Modern password hashing / KDFs
            var scrypt = SCrypt.Generate(password, salt, 16_384, 8, 1, 32);                              // scrypt(salt)
            new Argon2BytesGenerator().Init(new Argon2Parameters.Builder(2 /* Argon2id */).WithSalt(salt).Build()); // Argon2(..., WithSalt)
            new HkdfBytesGenerator(new Sha256Digest()).Init(new HkdfParameters(ikm, salt, info));        // HKDF(salt optional but supported)

            // 3) Signature schemes with salt
            new PssSigner(new RsaEngine(), new Sha256Digest(), new Sha256Digest(), 32);                  // RSA-PSS (saltLength=32)
            new Iso9796d2PssSigner(new RsaEngine(), new Sha256Digest(), 32);                             // ISO9796-2 PSS (has saltLength)

            // 4) Hash families that accept salt
            new Blake2bDigest(32, null, salt, null);                                                      // BLAKE2b(salt=...)
            new Blake2sDigest(32, null, salt, null);                                                      // BLAKE2s(salt=...)
            new SkeinDigest(256, 256).Init(new SkeinParameters.Builder().Set(SkeinParameters.PARAM_SALT, salt).Build()); // Skein(salt)

            // 5) OpenPGP S2K (string-to-key) carries salt
            new S2k(HashAlgorithmTag.Sha256, salt, 96);                                                   // S2K with salt + iteration

            // 6) SRP (salted verifier)
            Srp6Utilities.GenerateSalt(random, 16);                                                       // SRP: explicit salt generation
            Srp6Utilities.GenerateVerifier(group, new Sha256Digest(), salt, identity, password);         // SRP: verifier uses salt

            // 7) CMS password recipients / PKCS ASN.1 params (salt is embedded in params)
            new CmsEnvelopedDataGenerator().AddPasswordRecipient(new CmsPbeKey(passwordChars));           // CMS PasswordRecipient (PBKDF2 salt in params)
            new CmsAuthenticatedDataGenerator().AddPasswordRecipient(new CmsPbeKey(passwordChars));       // CMS AuthenticatedData password recipient
            new Pbkdf2Params(salt, 10_000);                                                               // ASN.1: PBKDF2 parameters (salt)
            new PbeParameter(salt, 2_048);                                                                // ASN.1: PKCS#5 PBE params (salt)
            new Pkcs12PbeParams(salt, 2_048);                                                             // ASN.1: PKCS#12 PBE params (salt)
        }
        #pragma warning restore CS0219, CS0168, CS0414
    }

    public static class SaltScannerTemplates
    {
        // C# Regex templates (use RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)
        // Designed to match common salt-using API constructions seen above (allowing whitespace/args flexibility).
        public static readonly string[] Patterns = new[]
        {
            // ---- PBKDF/PBE ----
            @"\bPkcs5S2ParametersGenerator\b.*\.Init\s*\(\s*[^,]+,\s*[^,]+,\s*\d+",          // PBKDF2.Init(password, salt, iter)
            @"\bPkcs5S1ParametersGenerator\b.*\.Init\s*\(\s*[^,]+,\s*[^,]+,\s*\d+",          // PKCS#5 v1.5
            @"\bPkcs12ParametersGenerator\b.*\.Init\s*\(\s*[^,]+,\s*[^,]+,\s*\d+",           // PKCS#12
            @"\bOpenSSL?PBEParametersGenerator\b.*\.Init\s*\(\s*[^,]+,\s*[^)]+\)",           // OpenSSL PBE (Init(password, salt))

            // ---- Modern KDFs ----
            @"\bSCrypt\.Generate\s*\(",                                                      // scrypt Generate(..., salt, ...)
            @"\bArgon2Parameters\b.*WithSalt\s*\(",                                          // Argon2Parameters.Builder(...).WithSalt(salt)
            @"\bArgon2BytesGenerator\b",                                                     // Argon2BytesGenerator
            @"\bH[kK]dfBytesGenerator\b.*\.Init\s*\(",                                       // HkdfBytesGenerator.Init(...)
            @"\bH[kK]dfParameters\b\s*\(",                                                   // HkdfParameters(ikm, salt, info)

            // ---- Signature with salt ----
            @"\bPssSigner\b\s*\(",                                                           // new PssSigner(..., saltLength)
            @"\bIso9796d2PssSigner\b\s*\(",                                                  // new Iso9796d2PssSigner(..., saltLength)
            @"\bsaltLength\s*:",                                                             // named arg: saltLength: 32

            // ---- Hash families that accept salt ----
            @"\bBlake2[bs]Digest\s*\(",                                                      // new Blake2bDigest(..., salt, ...) / Blake2sDigest
            @"\bSkeinParameters\b.*PARAM_SALT",                                              // SkeinParameters.Builder().Set(PARAM_SALT, salt)

            // ---- OpenPGP S2K ----
            @"\bOrg\.BouncyCastle\.Bcpg\.S2k\b",                                             // fully qualified S2k
            @"\bnew\s+S2k\s*\(",                                                             // new S2k(...)

            // ---- SRP ----
            @"\bSrp6Utilities\.GenerateSalt\s*\(",                                           // SRP salt generation
            @"\bSrp6Utilities\.GenerateVerifier\s*\(",                                       // SRP salted verifier
            @"\bSrp6(?:Client|Server)\b",                                                    // presence of SRP classes

            // ---- CMS / ASN.1 PBE params ----
            @"\bCmsEnvelopedDataGenerator\b.*AddPasswordRecipient\s*\(",                     // CMS password recipient
            @"\bCmsAuthenticatedDataGenerator\b.*AddPasswordRecipient\s*\(",                 // CMS authenticated data (password recipient)
            @"\bCmsPbeKey\b",                                                                // CmsPbeKey (password-based)
            @"\bPbkdf2Params\b",                                                             // ASN.1 PBKDF2 params (has salt)
            @"\bPbeParameter\b",                                                             // ASN.1 PKCS#5 PBE params (has salt)
            @"\bPkcs12PbeParams\b"                                                           // ASN.1 PKCS#12 PBE params (has salt)
        };

        // Helper to build compiled Regex objects if you want to consume them directly.
        public static IEnumerable<Regex> BuildRegexes()
        {
            foreach (var p in Patterns)
            {
                yield return new Regex(p, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }
        }
    }
}
