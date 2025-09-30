string BuildClassOnly_KeyUsage(string className) =>
    $@"\b(?:Org\.BouncyCastle\.Crypto\.Fips\.)?{Regex.Escape(className)}\s*\.\s*Key\b";



    string BuildClassAndMode(string className, string mode) =>
    $@"^[^\n]*\b(?:Org\.BouncyCastle\.Crypto\.Fips\.)?(?<alg>{Regex.Escape(className)})\s*\.\s*(?<mode>{Regex.Escape(mode)})\b[^\n]*$";


    
