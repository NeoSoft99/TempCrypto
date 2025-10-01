using System;
using System.Text.RegularExpressions;

// ===================== REGEX BUILDERS =====================

// 1) CLASS-ONLY (no modes on the same line)
//    Pass className: "Aes", "Camellia", "ChaCha", "Seed", "Serpent", "TripleDes", "Arc4"
string BuildFipsModuleClassOnly(string className) =>
    $@"\b(?:Org\.BouncyCastle\.Crypto\.General\.)?{Regex.Escape(className)}\b(?!\s*\.\s*(?:Cbc|Ccm|Cfb8|Cfb128|Ctr|Ecb|Gcm|Ocb|Ofb|OpenPGPCFB|Ietf|eStream|Ff3_1|FF3_1))";

// 2) CLASS + MODE (algorithm and mode appear on the same physical line)
//    Pass className and mode (e.g., ("Camellia","Cbc"), ("Aes","OpenPGPCFB"), ("FipsAes","Ff3_1"), ("ChaCha","Ietf"))
//    Note: allows either General.* (usual case) or Fips.* (needed for Ff3_1).
string BuildFipsModuleClassAndMode(string className, string mode) =>
    $@"^[^\n]*\b(?:Org\.BouncyCastle\.Crypto\.(?:General|Fips)\.)?(?<alg>{Regex.Escape(className)})\s*\.\s*(?<mode>{Regex.Escape(mode)})\b[^\n]*$";


// ===================== CLASS-ONLY (no mode) – one-liners =====================
System.Type G_Arc4_Type       = typeof(Org.BouncyCastle.Crypto.General.Arc4);
System.Type G_Aes_Type        = typeof(Org.BouncyCastle.Crypto.General.Aes);
System.Type G_Camellia_Type   = typeof(Org.BouncyCastle.Crypto.General.Camellia);
System.Type G_ChaCha_Type     = typeof(Org.BouncyCastle.Crypto.General.ChaCha);
System.Type G_Seed_Type       = typeof(Org.BouncyCastle.Crypto.General.Seed);
System.Type G_Serpent_Type    = typeof(Org.BouncyCastle.Crypto.General.Serpent);
System.Type G_TripleDes_Type  = typeof(Org.BouncyCastle.Crypto.General.TripleDes);

// ===================== CLASS + MODE (same line) – one-liners =====================
// AES (general-operation modes)
var GAes_OpenPGPCFB = Org.BouncyCastle.Crypto.General.Aes.OpenPGPCFB;  // AES/OpenPGPCFB (general)
var FAes_FF3_1      = Org.BouncyCastle.Crypto.Fips.FipsAes.Ff3_1;      // FF3-1 (FPE; general-op; lives under FipsAes)

// Camellia (general-operation modes)
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

// ChaCha (general-operation variants)
var Cha_Ietf        = Org.BouncyCastle.Crypto.General.ChaCha.Ietf;     // RFC 7539 IETF variant

// SEED (general-operation modes)
var Seed_Cbc        = Org.BouncyCastle.Crypto.General.Seed.Cbc;
var Seed_Ccm        = Org.BouncyCastle.Crypto.General.Seed.Ccm;
var Seed_Cfb8       = Org.BouncyCastle.Crypto.General.Seed.Cfb8;
var Seed_Cfb128     = Org.BouncyCastle.Crypto.General.Seed.Cfb128;
var Seed_Ctr        = Org.BouncyCastle.Crypto.General.Seed.Ctr;
var Seed_Ecb        = Org.BouncyCastle.Crypto.General.Seed.Ecb;
var Seed_Gcm        = Org.BouncyCastle.Crypto.General.Seed.Gcm;
var Seed_Ofb        = Org.BouncyCastle.Crypto.General.Seed.Ofb;

// Serpent (general-operation modes)
var Serp_Cbc        = Org.BouncyCastle.Crypto.General.Serpent.Cbc;
var Serp_Ccm        = Org.BouncyCastle.Crypto.General.Serpent.Ccm;
var Serp_Cfb8       = Org.BouncyCastle.Crypto.General.Serpent.Cfb8;
var Serp_Cfb128     = Org.BouncyCastle.Crypto.General.Serpent.Cfb128;
var Serp_Ctr        = Org.BouncyCastle.Crypto.General.Serpent.Ctr;
var Serp_Ecb        = Org.BouncyCastle.Crypto.General.Serpent.Ecb;
var Serp_Gcm        = Org.BouncyCastle.Crypto.General.Serpent.Gcm;
var Serp_Ofb        = Org.BouncyCastle.Crypto.General.Serpent.Ofb;

// TripleDES (general-operation mode)
var Tdes_OpenPGPCFB = Org.BouncyCastle.Crypto.General.TripleDes.OpenPGPCFB;
