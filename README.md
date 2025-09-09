// secp256k1
var x9_secp256k1 = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName("secp256k1")
         ?? Org.BouncyCastle.Asn1.Sec.CustomNamedCurves.GetByName("secp256k1");
var domain_secp256k1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_secp256k1.Curve, x9_secp256k1.G, x9_secp256k1.N, x9_secp256k1.H, x9_secp256k1.GetSeed());

// brainpoolP384r1
var x9_brainpoolP384r1 = Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTNamedCurves.GetByName("brainpoolP384r1");
var domain_brainpoolP384r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_brainpoolP384r1.Curve, x9_brainpoolP384r1.G, x9_brainpoolP384r1.N, x9_brainpoolP384r1.H, x9_brainpoolP384r1.GetSeed());

// sm2p256v1
var x9_sm2p256v1 = Org.BouncyCastle.Asn1.GM.GMNamedCurves.GetByName("sm2p256v1");
var domain_sm2p256v1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sm2p256v1.Curve, x9_sm2p256v1.G, x9_sm2p256v1.N, x9_sm2p256v1.H, x9_sm2p256v1.GetSeed());

// GostR3410-2001-CryptoPro-A
var x9_GostR3410_2001_CryptoPro_A = Org.BouncyCastle.Asn1.CryptoPro.ECGost3410NamedCurves.GetByName("GostR3410-2001-CryptoPro-A");
var domain_GostR3410_2001_CryptoPro_A = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_GostR3410_2001_CryptoPro_A.Curve, x9_GostR3410_2001_CryptoPro_A.G, x9_GostR3410_2001_CryptoPro_A.N, x9_GostR3410_2001_CryptoPro_A.H, x9_GostR3410_2001_CryptoPro_A.GetSeed());

// Tc26-Gost-3410-12-256-paramSetA
var x9_Tc26_Gost_3410_12_256_paramSetA = Org.BouncyCastle.Asn1.Rosstandart.RosstandartNamedCurves.GetByName("Tc26-Gost-3410-12-256-paramSetA");
var domain_Tc26_Gost_3410_12_256_paramSetA = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_Tc26_Gost_3410_12_256_paramSetA.Curve, x9_Tc26_Gost_3410_12_256_paramSetA.G, x9_Tc26_Gost_3410_12_256_paramSetA.N, x9_Tc26_Gost_3410_12_256_paramSetA.H, x9_Tc26_Gost_3410_12_256_paramSetA.GetSeed());

// ---------------------------
// NIST P-curves
// ---------------------------

// P-192
var x9_P_192 = Org.BouncyCastle.Asn1.Nist.NistNamedCurves.GetByName("P-192");
var domain_P_192 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_P_192.Curve, x9_P_192.G, x9_P_192.N, x9_P_192.H, x9_P_192.GetSeed());

// P-224
var x9_P_224 = Org.BouncyCastle.Asn1.Nist.NistNamedCurves.GetByName("P-224");
var domain_P_224 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_P_224.Curve, x9_P_224.G, x9_P_224.N, x9_P_224.H, x9_P_224.GetSeed());

// P-256
var x9_P_256 = Org.BouncyCastle.Asn1.Nist.NistNamedCurves.GetByName("P-256");
var domain_P_256 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_P_256.Curve, x9_P_256.G, x9_P_256.N, x9_P_256.H, x9_P_256.GetSeed());

// P-384
var x9_P_384 = Org.BouncyCastle.Asn1.Nist.NistNamedCurves.GetByName("P-384");
var domain_P_384 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_P_384.Curve, x9_P_384.G, x9_P_384.N, x9_P_384.H, x9_P_384.GetSeed());

// P-521
var x9_P_521 = Org.BouncyCastle.Asn1.Nist.NistNamedCurves.GetByName("P-521");
var domain_P_521 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_P_521.Curve, x9_P_521.G, x9_P_521.N, x9_P_521.H, x9_P_521.GetSeed());

// ---------------------------
// SEC prime curves (secp*), excluding r1 aliases of NIST and existing secp256k1
// ---------------------------

// secp112r1
var x9_secp112r1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp112r1");
var domain_secp112r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_secp112r1.Curve, x9_secp112r1.G, x9_secp112r1.N, x9_secp112r1.H, x9_secp112r1.GetSeed());

// secp112r2
var x9_secp112r2 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp112r2");
var domain_secp112r2 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_secp112r2.Curve, x9_secp112r2.G, x9_secp112r2.N, x9_secp112r2.H, x9_secp112r2.GetSeed());

// secp128r1
var x9_secp128r1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp128r1");
var domain_secp128r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_secp128r1.Curve, x9_secp128r1.G, x9_secp128r1.N, x9_secp128r1.H, x9_secp128r1.GetSeed());

// secp128r2
var x9_secp128r2 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp128r2");
var domain_secp128r2 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_secp128r2.Curve, x9_secp128r2.G, x9_secp128r2.N, x9_secp128r2.H, x9_secp128r2.GetSeed());

// secp160k1
var x9_secp160k1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp160k1");
var domain_secp160k1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_secp160k1.Curve, x9_secp160k1.G, x9_secp160k1.N, x9_secp160k1.H, x9_secp160k1.GetSeed());

// secp160r1
var x9_secp160r1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp160r1");
var domain_secp160r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_secp160r1.Curve, x9_secp160r1.G, x9_secp160r1.N, x9_secp160r1.H, x9_secp160r1.GetSeed());

// secp160r2
var x9_secp160r2 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp160r2");
var domain_secp160r2 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_secp160r2.Curve, x9_secp160r2.G, x9_secp160r2.N, x9_secp160r2.H, x9_secp160r2.GetSeed());

// secp192k1
var x9_secp192k1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp192k1");
var domain_secp192k1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_secp192k1.Curve, x9_secp192k1.G, x9_secp192k1.N, x9_secp192k1.H, x9_secp192k1.GetSeed());

// secp224k1
var x9_secp224k1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp224k1");
var domain_secp224k1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_secp224k1.Curve, x9_secp224k1.G, x9_secp224k1.N, x9_secp224k1.H, x9_secp224k1.GetSeed());

// secp239k1
var x9_secp239k1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp239k1");
var domain_secp239k1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_secp239k1.Curve, x9_secp239k1.G, x9_secp239k1.N, x9_secp239k1.H, x9_secp239k1.GetSeed());

// ---------------------------
// SEC binary curves (sect*)
// ---------------------------

// sect113r1
var x9_sect113r1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect113r1");
var domain_sect113r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect113r1.Curve, x9_sect113r1.G, x9_sect113r1.N, x9_sect113r1.H, x9_sect113r1.GetSeed());

// sect113r2
var x9_sect113r2 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect113r2");
var domain_sect113r2 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect113r2.Curve, x9_sect113r2.G, x9_sect113r2.N, x9_sect113r2.H, x9_sect113r2.GetSeed());

// sect131r1
var x9_sect131r1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect131r1");
var domain_sect131r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect131r1.Curve, x9_sect131r1.G, x9_sect131r1.N, x9_sect131r1.H, x9_sect131r1.GetSeed());

// sect131r2
var x9_sect131r2 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect131r2");
var domain_sect131r2 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect131r2.Curve, x9_sect131r2.G, x9_sect131r2.N, x9_sect131r2.H, x9_sect131r2.GetSeed());

// sect163k1
var x9_sect163k1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect163k1");
var domain_sect163k1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect163k1.Curve, x9_sect163k1.G, x9_sect163k1.N, x9_sect163k1.H, x9_sect163k1.GetSeed());

// sect163r1
var x9_sect163r1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect163r1");
var domain_sect163r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect163r1.Curve, x9_sect163r1.G, x9_sect163r1.N, x9_sect163r1.H, x9_sect163r1.GetSeed());

// sect163r2
var x9_sect163r2 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect163r2");
var domain_sect163r2 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect163r2.Curve, x9_sect163r2.G, x9_sect163r2.N, x9_sect163r2.H, x9_sect163r2.GetSeed());

// sect193r1
var x9_sect193r1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect193r1");
var domain_sect193r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect193r1.Curve, x9_sect193r1.G, x9_sect193r1.N, x9_sect193r1.H, x9_sect193r1.GetSeed());

// sect193r2
var x9_sect193r2 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect193r2");
var domain_sect193r2 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect193r2.Curve, x9_sect193r2.G, x9_sect193r2.N, x9_sect193r2.H, x9_sect193r2.GetSeed());

// sect233k1
var x9_sect233k1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect233k1");
var domain_sect233k1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect233k1.Curve, x9_sect233k1.G, x9_sect233k1.N, x9_sect233k1.H, x9_sect233k1.GetSeed());

// sect233r1
var x9_sect233r1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect233r1");
var domain_sect233r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect233r1.Curve, x9_sect233r1.G, x9_sect233r1.N, x9_sect233r1.H, x9_sect233r1.GetSeed());

// sect239k1
var x9_sect239k1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect239k1");
var domain_sect239k1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect239k1.Curve, x9_sect239k1.G, x9_sect239k1.N, x9_sect239k1.H, x9_sect239k1.GetSeed());

// sect283k1
var x9_sect283k1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect283k1");
var domain_sect283k1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect283k1.Curve, x9_sect283k1.G, x9_sect283k1.N, x9_sect283k1.H, x9_sect283k1.GetSeed());

// sect283r1
var x9_sect283r1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect283r1");
var domain_sect283r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect283r1.Curve, x9_sect283r1.G, x9_sect283r1.N, x9_sect283r1.H, x9_sect283r1.GetSeed());

// sect409k1
var x9_sect409k1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect409k1");
var domain_sect409k1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect409k1.Curve, x9_sect409k1.G, x9_sect409k1.N, x9_sect409k1.H, x9_sect409k1.GetSeed());

// sect409r1
var x9_sect409r1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect409r1");
var domain_sect409r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect409r1.Curve, x9_sect409r1.G, x9_sect409r1.N, x9_sect409r1.H, x9_sect409r1.GetSeed());

// sect571k1
var x9_sect571k1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect571k1");
var domain_sect571k1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect571k1.Curve, x9_sect571k1.G, x9_sect571k1.N, x9_sect571k1.H, x9_sect571k1.GetSeed());

// sect571r1
var x9_sect571r1 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("sect571r1");
var domain_sect571r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_sect571r1.Curve, x9_sect571r1.G, x9_sect571r1.N, x9_sect571r1.H, x9_sect571r1.GetSeed());

// ---------------------------
// ANSI X9.62 additional curves (skip aliases like prime256v1/prime192v1)
// ---------------------------

// prime192v2
var x9_prime192v2 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("prime192v2");
var domain_prime192v2 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_prime192v2.Curve, x9_prime192v2.G, x9_prime192v2.N, x9_prime192v2.H, x9_prime192v2.GetSeed());

// prime192v3
var x9_prime192v3 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("prime192v3");
var domain_prime192v3 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_prime192v3.Curve, x9_prime192v3.G, x9_prime192v3.N, x9_prime192v3.H, x9_prime192v3.GetSeed());

// prime239v1
var x9_prime239v1 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("prime239v1");
var domain_prime239v1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_prime239v1.Curve, x9_prime239v1.G, x9_prime239v1.N, x9_prime239v1.H, x9_prime239v1.GetSeed());

// prime239v2
var x9_prime239v2 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("prime239v2");
var domain_prime239v2 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_prime239v2.Curve, x9_prime239v2.G, x9_prime239v2.N, x9_prime239v2.H, x9_prime239v2.GetSeed());

// prime239v3
var x9_prime239v3 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("prime239v3");
var domain_prime239v3 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_prime239v3.Curve, x9_prime239v3.G, x9_prime239v3.N, x9_prime239v3.H, x9_prime239v3.GetSeed());

// c2pnb163v1
var x9_c2pnb163v1 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("c2pnb163v1");
var domain_c2pnb163v1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_c2pnb163v1.Curve, x9_c2pnb163v1.G, x9_c2pnb163v1.N, x9_c2pnb163v1.H, x9_c2pnb163v1.GetSeed());

// c2pnb163v2
var x9_c2pnb163v2 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("c2pnb163v2");
var domain_c2pnb163v2 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_c2pnb163v2.Curve, x9_c2pnb163v2.G, x9_c2pnb163v2.N, x9_c2pnb163v2.H, x9_c2pnb163v2.GetSeed());

// c2pnb163v3
var x9_c2pnb163v3 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("c2pnb163v3");
var domain_c2pnb163v3 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_c2pnb163v3.Curve, x9_c2pnb163v3.G, x9_c2pnb163v3.N, x9_c2pnb163v3.H, x9_c2pnb163v3.GetSeed());

// c2pnb176w1
var x9_c2pnb176w1 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("c2pnb176w1");
var domain_c2pnb176w1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_c2pnb176w1.Curve, x9_c2pnb176w1.G, x9_c2pnb176w1.N, x9_c2pnb176w1.H, x9_c2pnb176w1.GetSeed());

// c2pnb208w1
var x9_c2pnb208w1 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("c2pnb208w1");
var domain_c2pnb208w1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_c2pnb208w1.Curve, x9_c2pnb208w1.G, x9_c2pnb208w1.N, x9_c2pnb208w1.H, x9_c2pnb208w1.GetSeed());

// c2tnb191v1
var x9_c2tnb191v1 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("c2tnb191v1");
var domain_c2tnb191v1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_c2tnb191v1.Curve, x9_c2tnb191v1.G, x9_c2tnb191v1.N, x9_c2tnb191v1.H, x9_c2tnb191v1.GetSeed());

// c2tnb191v2
var x9_c2tnb191v2 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("c2tnb191v2");
var domain_c2tnb191v2 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_c2tnb191v2.Curve, x9_c2tnb191v2.G, x9_c2tnb191v2.N, x9_c2tnb191v2.H, x9_c2tnb191v2.GetSeed());

// c2tnb191v3
var x9_c2tnb191v3 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("c2tnb191v3");
var domain_c2tnb191v3 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_c2tnb191v3.Curve, x9_c2tnb191v3.G, x9_c2tnb191v3.N, x9_c2tnb191v3.H, x9_c2tnb191v3.GetSeed());

// c2tnb239v1
var x9_c2tnb239v1 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("c2tnb239v1");
var domain_c2tnb239v1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_c2tnb239v1.Curve, x9_c2tnb239v1.G, x9_c2tnb239v1.N, x9_c2tnb239v1.H, x9_c2tnb239v1.GetSeed());

// c2tnb239v2
var x9_c2tnb239v2 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("c2tnb239v2");
var domain_c2tnb239v2 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_c2tnb239v2.Curve, x9_c2tnb239v2.G, x9_c2tnb239v2.N, x9_c2tnb239v2.H, x9_c2tnb239v2.GetSeed());

// c2tnb239v3
var x9_c2tnb239v3 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("c2tnb239v3");
var domain_c2tnb239v3 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_c2tnb239v3.Curve, x9_c2tnb239v3.G, x9_c2tnb239v3.N, x9_c2tnb239v3.H, x9_c2tnb239v3.GetSeed());

// c2tnb359v1
var x9_c2tnb359v1 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("c2tnb359v1");
var domain_c2tnb359v1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_c2tnb359v1.Curve, x9_c2tnb359v1.G, x9_c2tnb359v1.N, x9_c2tnb359v1.H, x9_c2tnb359v1.GetSeed());

// c2tnb431r1
var x9_c2tnb431r1 = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByName("c2tnb431r1");
var domain_c2tnb431r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_c2tnb431r1.Curve, x9_c2tnb431r1.G, x9_c2tnb431r1.N, x9_c2tnb431r1.H, x9_c2tnb431r1.GetSeed());

// ---------------------------
// TeleTrusT / brainpool (excluding the one already added: brainpoolP384r1)
// ---------------------------

// brainpoolP160r1
var x9_brainpoolP160r1 = Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTNamedCurves.GetByName("brainpoolP160r1");
var domain_brainpoolP160r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_brainpoolP160r1.Curve, x9_brainpoolP160r1.G, x9_brainpoolP160r1.N, x9_brainpoolP160r1.H, x9_brainpoolP160r1.GetSeed());

// brainpoolP160t1
var x9_brainpoolP160t1 = Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTNamedCurves.GetByName("brainpoolP160t1");
var domain_brainpoolP160t1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_brainpoolP160t1.Curve, x9_brainpoolP160t1.G, x9_brainpoolP160t1.N, x9_brainpoolP160t1.H, x9_brainpoolP160t1.GetSeed());

// brainpoolP192r1
var x9_brainpoolP192r1 = Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTNamedCurves.GetByName("brainpoolP192r1");
var domain_brainpoolP192r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_brainpoolP192r1.Curve, x9_brainpoolP192r1.G, x9_brainpoolP192r1.N, x9_brainpoolP192r1.H, x9_brainpoolP192r1.GetSeed());

// brainpoolP192t1
var x9_brainpoolP192t1 = Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTNamedCurves.GetByName("brainpoolP192t1");
var domain_brainpoolP192t1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_brainpoolP192t1.Curve, x9_brainpoolP192t1.G, x9_brainpoolP192t1.N, x9_brainpoolP192t1.H, x9_brainpoolP192t1.GetSeed());

// brainpoolP224r1
var x9_brainpoolP224r1 = Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTNamedCurves.GetByName("brainpoolP224r1");
var domain_brainpoolP224r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_brainpoolP224r1.Curve, x9_brainpoolP224r1.G, x9_brainpoolP224r1.N, x9_brainpoolP224r1.H, x9_brainpoolP224r1.GetSeed());

// brainpoolP224t1
var x9_brainpoolP224t1 = Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTNamedCurves.GetByName("brainpoolP224t1");
var domain_brainpoolP224t1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_brainpoolP224t1.Curve, x9_brainpoolP224t1.G, x9_brainpoolP224t1.N, x9_brainpoolP224t1.H, x9_brainpoolP224t1.GetSeed());

// brainpoolP256r1
var x9_brainpoolP256r1 = Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTNamedCurves.GetByName("brainpoolP256r1");
var domain_brainpoolP256r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_brainpoolP256r1.Curve, x9_brainpoolP256r1.G, x9_brainpoolP256r1.N, x9_brainpoolP256r1.H, x9_brainpoolP256r1.GetSeed());

// brainpoolP256t1
var x9_brainpoolP256t1 = Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTNamedCurves.GetByName("brainpoolP256t1");
var domain_brainpoolP256t1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_brainpoolP256t1.Curve, x9_brainpoolP256t1.G, x9_brainpoolP256t1.N, x9_brainpoolP256t1.H, x9_brainpoolP256t1.GetSeed());

// brainpoolP320r1
var x9_brainpoolP320r1 = Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTNamedCurves.GetByName("brainpoolP320r1");
var domain_brainpoolP320r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_brainpoolP320r1.Curve, x9_brainpoolP320r1.G, x9_brainpoolP320r1.N, x9_brainpoolP320r1.H, x9_brainpoolP320r1.GetSeed());

// brainpoolP320t1
var x9_brainpoolP320t1 = Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTNamedCurves.GetByName("brainpoolP320t1");
var domain_brainpoolP320t1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_brainpoolP320t1.Curve, x9_brainpoolP320t1.G, x9_brainpoolP320t1.N, x9_brainpoolP320t1.H, x9_brainpoolP320t1.GetSeed());

// brainpoolP384t1
var x9_brainpoolP384t1 = Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTNamedCurves.GetByName("brainpoolP384t1");
var domain_brainpoolP384t1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_brainpoolP384t1.Curve, x9_brainpoolP384t1.G, x9_brainpoolP384t1.N, x9_brainpoolP384t1.H, x9_brainpoolP384t1.GetSeed());

// brainpoolP512r1
var x9_brainpoolP512r1 = Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTNamedCurves.GetByName("brainpoolP512r1");
var domain_brainpoolP512r1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_brainpoolP512r1.Curve, x9_brainpoolP512r1.G, x9_brainpoolP512r1.N, x9_brainpoolP512r1.H, x9_brainpoolP512r1.GetSeed());

// brainpoolP512t1
var x9_brainpoolP512t1 = Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTNamedCurves.GetByName("brainpoolP512t1");
var domain_brainpoolP512t1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_brainpoolP512t1.Curve, x9_brainpoolP512t1.G, x9_brainpoolP512t1.N, x9_brainpoolP512t1.H, x9_brainpoolP512t1.GetSeed());

// ---------------------------
// ANSSI (FRP)
// ---------------------------

// FRP256v1
var x9_FRP256v1 = Org.BouncyCastle.Asn1.Anssi.AnssiNamedCurves.GetByName("FRP256v1");
var domain_FRP256v1 = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_FRP256v1.Curve, x9_FRP256v1.G, x9_FRP256v1.N, x9_FRP256v1.H, x9_FRP256v1.GetSeed());

// ---------------------------
// GOST R 34.10-2001 (CryptoPro) — additional sets
// ---------------------------

// GostR3410-2001-CryptoPro-B
var x9_GostR3410_2001_CryptoPro_B = Org.BouncyCastle.Asn1.CryptoPro.ECGost3410NamedCurves.GetByName("GostR3410-2001-CryptoPro-B");
var domain_GostR3410_2001_CryptoPro_B = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_GostR3410_2001_CryptoPro_B.Curve, x9_GostR3410_2001_CryptoPro_B.G, x9_GostR3410_2001_CryptoPro_B.N, x9_GostR3410_2001_CryptoPro_B.H, x9_GostR3410_2001_CryptoPro_B.GetSeed());

// GostR3410-2001-CryptoPro-C
var x9_GostR3410_2001_CryptoPro_C = Org.BouncyCastle.Asn1.CryptoPro.ECGost3410NamedCurves.GetByName("GostR3410-2001-CryptoPro-C");
var domain_GostR3410_2001_CryptoPro_C = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_GostR3410_2001_CryptoPro_C.Curve, x9_GostR3410_2001_CryptoPro_C.G, x9_GostR3410_2001_CryptoPro_C.N, x9_GostR3410_2001_CryptoPro_C.H, x9_GostR3410_2001_CryptoPro_C.GetSeed());

// GostR3410-2001-CryptoPro-XchA
var x9_GostR3410_2001_CryptoPro_XchA = Org.BouncyCastle.Asn1.CryptoPro.ECGost3410NamedCurves.GetByName("GostR3410-2001-CryptoPro-XchA");
var domain_GostR3410_2001_CryptoPro_XchA = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_GostR3410_2001_CryptoPro_XchA.Curve, x9_GostR3410_2001_CryptoPro_XchA.G, x9_GostR3410_2001_CryptoPro_XchA.N, x9_GostR3410_2001_CryptoPro_XchA.H, x9_GostR3410_2001_CryptoPro_XchA.GetSeed());

// GostR3410-2001-CryptoPro-XchB
var x9_GostR3410_2001_CryptoPro_XchB = Org.BouncyCastle.Asn1.CryptoPro.ECGost3410NamedCurves.GetByName("GostR3410-2001-CryptoPro-XchB");
var domain_GostR3410_2001_CryptoPro_XchB = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_GostR3410_2001_CryptoPro_XchB.Curve, x9_GostR3410_2001_CryptoPro_XchB.G, x9_GostR3410_2001_CryptoPro_XchB.N, x9_GostR3410_2001_CryptoPro_XchB.H, x9_GostR3410_2001_CryptoPro_XchB.GetSeed());

// ---------------------------
// GOST R 34.10-2012 (Rosstandart / TC26) — additional sets
// ---------------------------

// Tc26-Gost-3410-12-256-paramSetB
var x9_Tc26_Gost_3410_12_256_paramSetB = Org.BouncyCastle.Asn1.Rosstandart.RosstandartNamedCurves.GetByName("Tc26-Gost-3410-12-256-paramSetB");
var domain_Tc26_Gost_3410_12_256_paramSetB = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_Tc26_Gost_3410_12_256_paramSetB.Curve, x9_Tc26_Gost_3410_12_256_paramSetB.G, x9_Tc26_Gost_3410_12_256_paramSetB.N, x9_Tc26_Gost_3410_12_256_paramSetB.H, x9_Tc26_Gost_3410_12_256_paramSetB.GetSeed());

// Tc26-Gost-3410-12-256-paramSetC
var x9_Tc26_Gost_3410_12_256_paramSetC = Org.BouncyCastle.Asn1.Rosstandart.RosstandartNamedCurves.GetByName("Tc26-Gost-3410-12-256-paramSetC");
var domain_Tc26_Gost_3410_12_256_paramSetC = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_Tc26_Gost_3410_12_256_paramSetC.Curve, x9_Tc26_Gost_3410_12_256_paramSetC.G, x9_Tc26_Gost_3410_12_256_paramSetC.N, x9_Tc26_Gost_3410_12_256_paramSetC.H, x9_Tc26_Gost_3410_12_256_paramSetC.GetSeed());

// Tc26-Gost-3410-12-512-paramSetA
var x9_Tc26_Gost_3410_12_512_paramSetA = Org.BouncyCastle.Asn1.Rosstandart.RosstandartNamedCurves.GetByName("Tc26-Gost-3410-12-512-paramSetA");
var domain_Tc26_Gost_3410_12_512_paramSetA = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_Tc26_Gost_3410_12_512_paramSetA.Curve, x9_Tc26_Gost_3410_12_512_paramSetA.G, x9_Tc26_Gost_3410_12_512_paramSetA.N, x9_Tc26_Gost_3410_12_512_paramSetA.H, x9_Tc26_Gost_3410_12_512_paramSetA.GetSeed());

// Tc26-Gost-3410-12-512-paramSetB
var x9_Tc26_Gost_3410_12_512_paramSetB = Org.BouncyCastle.Asn1.Rosstandart.RosstandartNamedCurves.GetByName("Tc26-Gost-3410-12-512-paramSetB");
var domain_Tc26_Gost_3410_12_512_paramSetB = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_Tc26_Gost_3410_12_512_paramSetB.Curve, x9_Tc26_Gost_3410_12_512_paramSetB.G, x9_Tc26_Gost_3410_12_512_paramSetB.N, x9_Tc26_Gost_3410_12_512_paramSetB.H, x9_Tc26_Gost_3410_12_512_paramSetB.GetSeed());

// Tc26-Gost-3410-12-512-paramSetC
var x9_Tc26_Gost_3410_12_512_paramSetC = Org.BouncyCastle.Asn1.Rosstandart.RosstandartNamedCurves.GetByName("Tc26-Gost-3410-12-512-paramSetC");
var domain_Tc26_Gost_3410_12_512_paramSetC = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
    x9_Tc26_Gost_3410_12_512_paramSetC.Curve, x9_Tc26_Gost_3410_12_512_paramSetC.G, x9_Tc26_Gost_3410_12_512_paramSetC.N, x9_Tc26_Gost_3410_12_512_paramSetC.H, x9_Tc26_Gost_3410_12_512_paramSetC.GetSeed());
