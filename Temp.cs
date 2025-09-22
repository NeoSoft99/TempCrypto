// 1) KeyParameter(<setter>)
@"\bnew\s+(?:Org\.BouncyCastle\.)?(?:Crypto\.)?(?:Parameters\.)?KeyParameter\s*\(\s*<setter>\s*\)"

// 2) *.Init(..., new KeyParameter(<setter>))
@"\.\s*Init\s*\([^,]*,\s*new\s+(?:Org\.BouncyCastle\.)?(?:Crypto\.)?(?:Parameters\.)?KeyParameter\s*\(\s*<setter>\s*\)\s*\)"

// 3) ParametersWithIV(new KeyParameter(<setter>), ...
@"\bnew\s+(?:Org\.BouncyCastle\.)?(?:Crypto\.)?(?:Parameters\.)?ParametersWithIV\s*\(\s*new\s+(?:Org\.BouncyCastle\.)?(?:Crypto\.)?(?:Parameters\.)?KeyParameter\s*\(\s*<setter>\s*\)\s*,"

// 4) AeadParameters(new KeyParameter(<setter>), ...
@"\bnew\s+(?:Org\.BouncyCastle\.)?(?:Crypto\.)?(?:Parameters\.)?AeadParameters\s*\(\s*new\s+(?:Org\.BouncyCastle\.)?(?:Crypto\.)?(?:Parameters\.)?KeyParameter\s*\(\s*<setter>\s*\)\s*,"

// 5) ParameterUtilities.CreateKeyParameter("ALG", <setter>)
@"\b(?:Org\.BouncyCastle\.)?Security\.ParameterUtilities\s*\.\s*CreateKeyParameter\s*\(\s*""[^""]+""\s*,\s*<setter>\s*\)"

// 6) DesEdeParameters(<setter>)
@"\bnew\s+(?:Org\.BouncyCastle\.)?(?:Crypto\.)?(?:Parameters\.)?DesEdeParameters\s*\(\s*<setter>\s*\)"

// 7) DesParameters(<setter>)
@"\bnew\s+(?:Org\.BouncyCastle\.)?(?:Crypto\.)?(?:Parameters\.)?DesParameters\s*\(\s*<setter>\s*\)"

// 8) RC2Parameters(<setter>[, bits])
@"\bnew\s+(?:Org\.BouncyCastle\.)?(?:Crypto\.)?(?:Parameters\.)?RC2Parameters\s*\(\s*<setter>\s*(?:,\s*\d+\s*)?\)"

// 9) RC5Parameters(<setter>[, rounds])
@"\bnew\s+(?:Org\.BouncyCastle\.)?(?:Crypto\.)?(?:Parameters\.)?RC5Parameters\s*\(\s*<setter>\s*(?:,\s*\d+\s*)?\)"

// 10) RsaKeyParameters(true, modulus, <setter>)
@"\bnew\s+(?:Org\.BouncyCastle\.)?(?:Crypto\.)?(?:Parameters\.)?RsaKeyParameters\s*\(\s*(?:true|True)\s*,\s*[^,]+,\s*<setter>\s*\)"

// 11) RsaPrivateCrtKeyParameters(..., <setter>, ...)
@"\bnew\s+(?:Org\.BouncyCastle\.)?(?:Crypto\.)?(?:Parameters\.)?RsaPrivateCrtKeyParameters\s*\(\s*[^,]+,\s*[^,]+,\s*<setter>\s*,"

// 12) ECPrivateKeyParameters(<setter>, ...)
@"\bnew\s+(?:Org\.BouncyCastle\.)?(?:Crypto\.)?(?:Parameters\.)?ECPrivateKeyParameters\s*\(\s*<setter>\s*,"

// 13) Ed25519PrivateKeyParameters(<setter>, ...)
@"\bnew\s+(?:Org\.BouncyCastle\.)?(?:Crypto\.)?(?:Parameters\.)?Ed25519PrivateKeyParameters\s*\(\s*<setter>\s*,"

// 14) X25519PrivateKeyParameters(<setter>, ...)
@"\bnew\s+(?:Org\.BouncyCastle\.)?(?:Crypto\.)?(?:Parameters\.)?X25519PrivateKeyParameters\s*\(\s*<setter>\s*,"

// 15) DHPrivateKeyParameters(<setter>, ...)
@"\bnew\s+(?:Org\.BouncyCastle\.)?(?:Crypto\.)?(?:Parameters\.)?DHPrivateKeyParameters\s*\(\s*<setter>\s*,"

// 16) PrivateKeyFactory.CreateKey(<setter>)
@"\b(?:Org\.BouncyCastle\.)?Security\.PrivateKeyFactory\s*\.\s*CreateKey\s*\(\s*<setter>\s*\)"
