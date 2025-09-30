string BuildClassOnly(string className) =>
    $@"\b(?:Org\.BouncyCastle\.Crypto\.Fips\.)?{Regex.Escape(className)}\b(?!\s*\.\s*(?:Cbc|Ctr|Cfb|Ofb|Ecb|Gcm|Ccm))";



string BuildClassAndMode(string className, string mode) =>
    $@"^[^\n]*\b(?:Org\.BouncyCastle\.Crypto\.Fips\.)?(?<alg>{Regex.Escape(className)})\s*\.\s*(?<mode>{Regex.Escape(mode)})\b[^\n]*$";
