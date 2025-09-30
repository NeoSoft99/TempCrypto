string BuildClassOnly(string className) =>
    $@"\b(?:Org\.BouncyCastle\.Crypto\.Fips\.)?{Regex.Escape(className)}\b(?!\s*\.\s*(?:Cbc|Ctr|Cfb|Ofb|Ecb|Gcm|Ccm))";



string BuildClassAndMode(string className, string mode) =>
    $@"^[^\n]*\b(?:Org\.BouncyCastle\.Crypto\.Fips\.)?(?<alg>{Regex.Escape(className)})\s*\.\s*(?<mode>{Regex.Escape(mode)})\b[^\n]*$";



// --- CLASS-ONLY (no mode) ---
System.Type T_Aes_TypeOnly = typeof(Org.BouncyCastle.Crypto.Fips.FipsAes);
var K_Aes_KeyOnly = new Org.BouncyCastle.Crypto.Fips.FipsAes.Key(new byte[16]);
System.Type T_Tdes_TypeOnly = typeof(Org.BouncyCastle.Crypto.Fips.FipsTripleDes);
var K_Tdes_KeyOnly = new Org.BouncyCastle.Crypto.Fips.FipsTripleDes.Key(new byte[24]);

// --- CLASS + MODE (same line) ---
var P_Aes_Cbc = Org.BouncyCastle.Crypto.Fips.FipsAes.Cbc.WithIV(new byte[16]);
var P_Aes_Ctr = Org.BouncyCastle.Crypto.Fips.FipsAes.Ctr.WithIV(new byte[16]);
var P_Aes_Cfb = Org.BouncyCastle.Crypto.Fips.FipsAes.Cfb.WithIV(new byte[16]);
var P_Aes_Ofb = Org.BouncyCastle.Crypto.Fips.FipsAes.Ofb.WithIV(new byte[16]);
var P_Aes_Ecb = Org.BouncyCastle.Crypto.Fips.FipsAes.Ecb;
var P_Aes_Gcm = Org.BouncyCastle.Crypto.Fips.FipsAes.Gcm.WithIV(new byte[12]);
var P_Aes_Ccm = Org.BouncyCastle.Crypto.Fips.FipsAes.Ccm.WithIV(new byte[13]);
var P_Tdes_Cbc = Org.BouncyCastle.Crypto.Fips.FipsTripleDes.Cbc.WithIV(new byte[8]);
var P_Tdes_Ecb = Org.BouncyCastle.Crypto.Fips.FipsTripleDes.Ecb;
