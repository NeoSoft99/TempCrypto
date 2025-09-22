// Symmetric keys (KeyParameter)
ICipherParameters p01 = new KeyParameter(Org.BouncyCastle.Utilities.Encoders.Hex.Decode("00112233445566778899AABBCCDDEEFF"));
ICipherParameters p02 = new KeyParameter(Convert.FromBase64String("AABBCCDDEEFF00112233445566778899AABBCCDDEEE="));
ICipherParameters p03 = new KeyParameter(Encoding.UTF8.GetBytes("My32ByteSecretKeyValue________"));

// With IV / AEAD wrappers
ICipherParameters p04 = new ParametersWithIV(new KeyParameter(Hex.Decode("000102030405060708090A0B0C0D0E0F")), Hex.Decode("1A1B1C1D1E1F2021"));
ICipherParameters p05 = new AeadParameters(new KeyParameter(Hex.Decode("FEFFE9928665731C6D6A8F9467308308")), 128, Hex.Decode("CAFEBABECAFEBABECAFEBABE"));

// Init calls that pass a KeyParameter inline
var gcm = new Org.BouncyCastle.Crypto.Modes.GcmBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine());
gcm.Init(true, new AeadParameters(new KeyParameter(Encoding.ASCII.GetBytes("Sixteen byte key")), 128, Hex.Decode("000102030405060708090A0B")));

var hmac = new Org.BouncyCastle.Crypto.Macs.HMac(new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
hmac.Init(new KeyParameter(Hex.Decode("0F0E0D0C0B0A09080706050403020100")));

// Other symmetric parameter classes
ICipherParameters p08 = new DesEdeParameters(Hex.Decode("0123456789ABCDEFFEDCBA98765432100123456789ABCDEF"));
ICipherParameters p09 = new DesParameters(Hex.Decode("133457799BBCDFF1"));
ICipherParameters p10 = new RC2Parameters(Hex.Decode("300102030405060708090A0B0C0D0E0F"), 128);
ICipherParameters p11 = new RC5Parameters(Encoding.ASCII.GetBytes("rc5-key-material"), 16);

// Asymmetric key parameters (private)
AsymmetricKeyParameter k12 = new RsaKeyParameters(true, new Org.BouncyCastle.Math.BigInteger("C9F9A7D1B2C3", 16), new Org.BouncyCastle.Math.BigInteger("6B8B4567", 16));
AsymmetricKeyParameter k13 = new RsaPrivateCrtKeyParameters(new BigInteger("DCBA",16), new BigInteger("010001",16), new BigInteger("1234",16), new BigInteger("F1",16), new BigInteger("E1",16), new BigInteger("D1",16), new BigInteger("C1",16), new BigInteger("B1",16));
AsymmetricKeyParameter k14 = new ECPrivateKeyParameters(new BigInteger("1F1E1D1C1B1A19181716151413121110", 16), null);
AsymmetricKeyParameter k15 = new Ed25519PrivateKeyParameters(Hex.Decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"), 0);
AsymmetricKeyParameter k16 = new X25519PrivateKeyParameters(Convert.FromBase64String("d3B5dHByaXZrZXlzdGVzdGtleXNlZWQxMjM0NTY3ODkwMTIzNA=="), 0);
AsymmetricKeyParameter k17 = new DHPrivateKeyParameters(new BigInteger("1A2B3C4D5E6F", 16), null);

// Factory helpers
ICipherParameters p18 = Org.BouncyCastle.Security.ParameterUtilities.CreateKeyParameter("AES", Hex.Decode("00112233445566778899AABBCCDDEEFF"));
AsymmetricKeyParameter k19 = Org.BouncyCastle.Security.PrivateKeyFactory.CreateKey(File.ReadAllBytes("my-private-key.der"));
new Org.BouncyCastle.Crypto.Macs.CMac(new Org.BouncyCastle.Crypto.Engines.AesEngine()).Init(new KeyParameter(Hex.Decode("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF")));
