using System;
using System.Text.RegularExpressions;

// ===================== PARAMETERIZED REGEX (non‑approved only) =====================
// 1) Class-only (no mode): className ∈ { "Arc4","Aes","Camellia","ChaCha","Seed","Serpent","TripleDes" }
Func<string,string> BuildNonApprovedClassOnly =
    className => $@"\b(?:Org\.BouncyCastle\.Crypto\.General\.)?{Regex.Escape(className)}\b";

// 2) Class + Mode (same line): use className/mode pairs from General operation table, or "FipsAes"/"Ff3_1"
Func<string,string,string> BuildNonApprovedClassAndMode =
    (className, mode) => $@"^[^\n]*\b(?:Org\.BouncyCastle\.Crypto\.(?:General|Fips)\.)?{Regex.Escape(className)}\s*\.\s*{Regex.Escape(mode)}\b[^\n]*$";

// ===================== ONE-LINE SAMPLES (CLASS-ONLY, no mode) =====================
System.Type T_Arc4      = typeof(Org.BouncyCastle.Crypto.General.Arc4);
System.Type T_Aes       = typeof(Org.BouncyCastle.Crypto.General.Aes);
System.Type T_Camellia  = typeof(Org.BouncyCastle.Crypto.General.Camellia);
System.Type T_ChaCha    = typeof(Org.BouncyCastle.Crypto.General.ChaCha);
System.Type T_Seed      = typeof(Org.BouncyCastle.Crypto.General.Seed);
System.Type T_Serpent   = typeof(Org.BouncyCastle.Crypto.General.Serpent);
System.Type T_TripleDes = typeof(Org.BouncyCastle.Crypto.General.TripleDes);

// ===================== ONE-LINE SAMPLES (CLASS + MODE on the same line) =====================
// AES (general-operation modes)
var Aes_OpenPGPCFB  = Org.BouncyCastle.Crypto.General.Aes.OpenPGPCFB;                        // non‑approved AES mode
var Aes_FF3_1       = Org.BouncyCastle.Crypto.Fips.FipsAes.Ff3_1;                            // FF3‑1 FPE (exposed under FipsAes)

// Camellia (CBC/CCM/CFB8/CFB128/CTR/ECB/GCM/OCB/OFB/OpenPGPCFB)
var Cam_Cbc         = Org.BouncyCastle.Crypto.General.Camellia.Cbc;
var Cam_Ccm         = Org.BouncyCastle.Crypto.General.Camellia.Ccm;
var Cam_Cfb8        = Org.BouncyCastle.Crypto.General.Camellia.Cfb8;
var Cam_Cfb128      = Org.BouncyCastle.Crypto.General.Camellia.Cfb128;
var Cam_Ctr         = Org.BouncyCastle.Crypto.General.Camellia.Ctr;
var Cam_Ecb         = Org.BouncyCastle.Crypto.General.Camellia.Ecb;
var Cam_Gcm         = Org.BouncyCastle.Crypto.General.Camellia.Gcm;
var Cam_Ocb         = Org.BouncyCastle.Crypto.General.Camellia.Ocb;
var Cam_Ofb         = Org.BouncyCastle.Crypto.General.Camellia.Ofb;
var Cam_OpenPGPCFB  = Org.BouncyCastle.Crypto.General.Camellia.OpenPGPCFB;

// ChaCha (e.g., IETF/RFC 7539 variant)
var Cha_Ietf        = Org.BouncyCastle.Crypto.General.ChaCha.Ietf;                           // non‑approved stream cipher (example shows IETF)  [oai_citation:1‡downloads.bouncycastle.org](https://downloads.bouncycastle.org/fips-csharp/docs/BC-FNA-UserGuide-1.0.2.pdf)

// SEED (CBC/CCM/CFB8/CFB128/CTR/ECB/GCM/OFB)
var Seed_Cbc        = Org.BouncyCastle.Crypto.General.Seed.Cbc;
var Seed_Ccm        = Org.BouncyCastle.Crypto.General.Seed.Ccm;
var Seed_Cfb8       = Org.BouncyCastle.Crypto.General.Seed.Cfb8;
var Seed_Cfb128     = Org.BouncyCastle.Crypto.General.Seed.Cfb128;
var Seed_Ctr        = Org.BouncyCastle.Crypto.General.Seed.Ctr;
var Seed_Ecb        = Org.BouncyCastle.Crypto.General.Seed.Ecb;
var Seed_Gcm        = Org.BouncyCastle.Crypto.General.Seed.Gcm;
var Seed_Ofb        = Org.BouncyCastle.Crypto.General.Seed.Ofb;

// Serpent (CBC/CCM/CFB8/CFB128/CTR/ECB/GCM/OFB)
var Serp_Cbc        = Org.BouncyCastle.Crypto.General.Serpent.Cbc;
var Serp_Ccm        = Org.BouncyCastle.Crypto.General.Serpent.Ccm;
var Serp_Cfb8       = Org.BouncyCastle.Crypto.General.Serpent.Cfb8;
var Serp_Cfb128     = Org.BouncyCastle.Crypto.General.Serpent.Cfb128;
var Serp_Ctr        = Org.BouncyCastle.Crypto.General.Serpent.Ctr;
var Serp_Ecb        = Org.BouncyCastle.Crypto.General.Serpent.Ecb;
var Serp_Gcm        = Org.BouncyCastle.Crypto.General.Serpent.Gcm;
var Serp_Ofb        = Org.BouncyCastle.Crypto.General.Serpent.Ofb;

// TripleDES (OpenPGPCFB in general operation)
var Tdes_OpenPGPCFB = Org.BouncyCastle.Crypto.General.TripleDes.OpenPGPCFB;
