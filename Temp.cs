// ------------ Regex builders (non-FIPS / classic BC API) -------------
// 1) CLASS-ONLY (no modes) — param: className (e.g., "AesEngine", "BlowfishEngine")
string BuildNonFipsClassOnly(string className) =>
    $@"\b(?:Org\.BouncyCastle\.Crypto\.Engines\.)?{System.Text.RegularExpressions.Regex.Escape(className)}\b";

// 2) CLASS + MODE (same line) — params: className (engine) + modeClassName (e.g., "CbcBlockCipher", "GcmBlockCipher")
// Use with RegexOptions.Multiline when scanning whole files.
string BuildNonFipsClassAndMode(string className, string modeClassName) =>
    $@"^[^\n]*\b(?:new\s+)?(?:Org\.BouncyCastle\.Crypto\.Modes\.)?(?<mode>{System.Text.RegularExpressions.Regex.Escape(modeClassName)})\s*\(\s*(?:new\s+)?(?:Org\.BouncyCastle\.Crypto\.Engines\.)?(?<alg>{System.Text.RegularExpressions.Regex.Escape(className)})\b[^\n]*$";


// ------------------------- CLASS-ONLY targets -------------------------
// (Engines only; no mode on the line)
var E_Aes        = new Org.BouncyCastle.Crypto.Engines.AesEngine();
var E_DesEde     = new Org.BouncyCastle.Crypto.Engines.DesEdeEngine();
var E_Des        = new Org.BouncyCastle.Crypto.Engines.DesEngine();
var E_Blowfish   = new Org.BouncyCastle.Crypto.Engines.BlowfishEngine();
var E_Camellia   = new Org.BouncyCastle.Crypto.Engines.CamelliaEngine();
var E_Cast5      = new Org.BouncyCastle.Crypto.Engines.Cast5Engine();
var E_Cast6      = new Org.BouncyCastle.Crypto.Engines.Cast6Engine();
var E_Idea       = new Org.BouncyCastle.Crypto.Engines.IdeaEngine();
var E_RC2        = new Org.BouncyCastle.Crypto.Engines.RC2Engine();
var E_RC4        = new Org.BouncyCastle.Crypto.Engines.RC4Engine();
var E_Seed       = new Org.BouncyCastle.Crypto.Engines.SeedEngine();
var E_Serpent    = new Org.BouncyCastle.Crypto.Engines.SerpentEngine();
var E_Skipjack   = new Org.BouncyCastle.Crypto.Engines.SkipjackEngine();
var E_Twofish    = new Org.BouncyCastle.Crypto.Engines.TwofishEngine();


// --------------------- CLASS + MODE (same line) -----------------------
// (Mode wrapper + engine on the SAME line; realistic pairings shown)

// --- CBC / CFB / OFB / CTR(SIC) ---
var M_Aes_Cbc        = new Org.BouncyCastle.Crypto.Modes.CbcBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine());
var M_3Des_Cbc       = new Org.BouncyCastle.Crypto.Modes.CbcBlockCipher(new Org.BouncyCastle.Crypto.Engines.DesEdeEngine());
var M_Blowfish_Cbc   = new Org.BouncyCastle.Crypto.Modes.CbcBlockCipher(new Org.BouncyCastle.Crypto.Engines.BlowfishEngine());
var M_Camellia_Cbc   = new Org.BouncyCastle.Crypto.Modes.CbcBlockCipher(new Org.BouncyCastle.Crypto.Engines.CamelliaEngine());
var M_Serpent_Cfb    = new Org.BouncyCastle.Crypto.Modes.CfbBlockCipher(new Org.BouncyCastle.Crypto.Engines.SerpentEngine(), 128);
var M_Twofish_Ofb    = new Org.BouncyCastle.Crypto.Modes.OfbBlockCipher(new Org.BouncyCastle.Crypto.Engines.TwofishEngine(), 128);
var M_Cast5_Cfb      = new Org.BouncyCastle.Crypto.Modes.CfbBlockCipher(new Org.BouncyCastle.Crypto.Engines.Cast5Engine(), 64);
var M_Idea_Ofb       = new Org.BouncyCastle.Crypto.Modes.OfbBlockCipher(new Org.BouncyCastle.Crypto.Engines.IdeaEngine(), 64);
var M_Aes_Ctr        = new Org.BouncyCastle.Crypto.Modes.SicBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine());          // CTR = SIC in BC
var M_Seed_Ctr       = new Org.BouncyCastle.Crypto.Modes.SicBlockCipher(new Org.BouncyCastle.Crypto.Engines.SeedEngine());

// --- AEAD (GCM / CCM / EAX / OCB) — typically with AES engines ---
var M_Aes_Gcm        = new Org.BouncyCastle.Crypto.Modes.GcmBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine());
var M_Aes_Ccm        = new Org.BouncyCastle.Crypto.Modes.CcmBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine());
var M_Aes_Eax        = new Org.BouncyCastle.Crypto.Modes.EaxBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine());
var M_Aes_Ocb        = new Org.BouncyCastle.Crypto.Modes.OcbBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine(), new Org.BouncyCastle.Crypto.Engines.AesEngine());

// --- ECB-ish (engine without explicit mode usually wrapped by a buffered cipher) — optional examples ---
// (kept to one-liners with explicit mode wrappers above to align with “mode present on the same line”)
