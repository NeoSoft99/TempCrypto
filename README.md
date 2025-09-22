// [R01] new KeyParameter(<setter>)
@"new\s+(?:[\w\.]+\.)?KeyParameter\s*\(\s*(?<setter>(?>[^()]+|\((?<DEPTH>)|\)(?<-DEPTH>))*(?(DEPTH)(?!)))\s*\)"

// [R02] cipher or mac .Init(..., new KeyParameter(<setter>))
@"\.\s*Init\s*\(\s*[^,]*,\s*new\s+(?:[\w\.]+\.)?KeyParameter\s*\(\s*(?<setter>(?>[^()]+|\((?<DEPTH>)|\)(?<-DEPTH>))*(?(DEPTH)(?!)))\s*\)\s*\)"

// [R03] ParametersWithIV(new KeyParameter(<setter>), <iv>)
@"new\s+(?:[\w\.]+\.)?ParametersWithIV\s*\(\s*new\s+(?:[\w\.]+\.)?KeyParameter\s*\(\s*(?<setter>(?>[^()]+|\((?<DEPTH>)|\)(?<-DEPTH>))*(?(DEPTH)(?!)))\s*\)\s*,"

// [R04] AeadParameters(new KeyParameter(<setter>), macBits, nonce[, aad])
@"new\s+(?:[\w\.]+\.)?AeadParameters\s*\(\s*new\s+(?:[\w\.]+\.)?KeyParameter\s*\(\s*(?<setter>(?>[^()]+|\((?<DEPTH>)|\)(?<-DEPTH>))*(?(DEPTH)(?!)))\s*\)\s*,\s*\d+\s*,"

// [R05] ParameterUtilities.CreateKeyParameter("ALG", <setter>)
@"ParameterUtilities\s*\.\s*CreateKeyParameter\s*\(\s*""[^""]+""\s*,\s*(?<setter>(?>[^()]+|\((?<DEPTH>)|\)(?<-DEPTH>))*(?(DEPTH)(?!)))\s*\)"

// [R06] DesEdeParameters(<setter>)
@"new\s+(?:[\w\.]+\.)?DesEdeParameters\s*\(\s*(?<setter>(?>[^()]+|\((?<DEPTH>)|\)(?<-DEPTH>))*(?(DEPTH)(?!)))\s*\)"

// [R07] DesParameters(<setter>)
@"new\s+(?:[\w\.]+\.)?DesParameters\s*\(\s*(?<setter>(?>[^()]+|\((?<DEPTH>)|\)(?<-DEPTH>))*(?(DEPTH)(?!)))\s*\)"

// [R08] RC2Parameters(<setter>[, bits])
@"new\s+(?:[\w\.]+\.)?RC2Parameters\s*\(\s*(?<setter>(?>[^(),]+|\((?<DEPTH>)|\)(?<-DEPTH>))*(?(DEPTH)(?!)))\s*(?:,\s*\d+\s*)?\)"

// [R09] RC5Parameters(<setter>[, rounds])
@"new\s+(?:[\w\.]+\.)?RC5Parameters\s*\(\s*(?<setter>(?>[^(),]+|\((?<DEPTH>)|\)(?<-DEPTH>))*(?(DEPTH)(?!)))\s*(?:,\s*\d+\s*)?\)"

// [R10] RSA basic private: RsaKeyParameters(true, modulus, <setter>)
@"new\s+(?:[\w\.]+\.)?RsaKeyParameters\s*\(\s*(?:true|True)\s*,\s*[^,]+,\s*(?<setter>[^)\r\n]+?)\s*\)"

// [R11] RSA CRT private: RsaPrivateCrtKeyParameters(..., <setter>, ...)
@"new\s+(?:[\w\.]+\.)?RsaPrivateCrtKeyParameters\s*\(\s*[^,]+,\s*[^,]+,\s*(?<setter>[^,]+)\s*,"

// [R12] EC private scalar: ECPrivateKeyParameters(<setter>, ...)
@"new\s+(?:[\w\.]+\.)?ECPrivateKeyParameters\s*\(\s*(?<setter>[^,]+)\s*,"

// [R13] Ed25519 private: Ed25519PrivateKeyParameters(<setter>, ...)
@"new\s+(?:[\w\.]+\.)?Ed25519PrivateKeyParameters\s*\(\s*(?<setter>(?>[^(),]+|\((?<DEPTH>)|\)(?<-DEPTH>))*(?(DEPTH)(?!)))\s*,"

// [R14] X25519 private: X25519PrivateKeyParameters(<setter>, ...)
@"new\s+(?:[\w\.]+\.)?X25519PrivateKeyParameters\s*\(\s*(?<setter>(?>[^(),]+|\((?<DEPTH>)|\)(?<-DEPTH>))*(?(DEPTH)(?!)))\s*,"

// [R15] DH private: DHPrivateKeyParameters(<setter>, ...)
@"new\s+(?:[\w\.]+\.)?DHPrivateKeyParameters\s*\(\s*(?<setter>[^,]+)\s*,"

// [R16] Load key from raw bytes/stream: PrivateKeyFactory.CreateKey(<setter>)
@"(?:^|[^\w])(?:Org\.BouncyCastle\.Security\.)?PrivateKeyFactory\s*\.\s*CreateKey\s*\(\s*(?<setter>(?>[^()]+|\((?<DEPTH>)|\)(?<-DEPTH>))*(?(DEPTH)(?!)))\s*\)"
