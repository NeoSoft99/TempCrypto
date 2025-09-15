// BC 1.8.9 — RNG init one‑liners (drop inside any method in a test project)

// Namespaces you’ll need:
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Prng.Drbg;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

// ---- CSPRNGs (SecureRandom and builders) ----
var rngSecureDefault   = new SecureRandom();
var rngSecureCryptoApi = new SecureRandom(new CryptoApiRandomGenerator());
var rngSecureDigestGen = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));

var rngSp800Hash = new SP800SecureRandomBuilder().BuildHash(new Sha256Digest(), new byte[16], false);
var rngSp800Hmac = new SP800SecureRandomBuilder().BuildHMac(new HMac(new Sha256Digest()), new byte[16], false);
var rngSp800Ctr  = new SP800SecureRandomBuilder().BuildCtr(new AesEngine(), 256, new byte[32], false);

var rngX931Aes   = new X931SecureRandomBuilder().Build(new AesEngine(), new KeyParameter(new byte[16]), false);

// ---- Non‑secure PRNGs (IRandomGenerator and wrappers) ----
var genDigest    = new DigestRandomGenerator(new Sha256Digest());
var genVmpc      = new VmpcRandomGenerator();
var genReversed  = new ReversedWindowGenerator(new DigestRandomGenerator(new Sha256Digest()), 16);

// ---- Seeder (not an RNG, but frequently used with RNGs) ----
var seedFromThreads = new ThreadedSeedGenerator().GenerateSeed(32, true);

// ---- Raw SP800‑90A DRBGs (standalone; implement ISP80090Drbg) ----
var drbgCtr  = new CtrSP800Drbg(new AesEngine(), 256, 256, new BasicEntropySourceProvider(new SecureRandom(), true).Get(256), new byte[0], new byte[16]);
var drbgHash = new HashSP800Drbg(new Sha256Digest(), 256, new BasicEntropySourceProvider(new SecureRandom(), true).Get(256), new byte[0], new byte[16]);
var drbgHmac = new HMacSP800Drbg(new HMac(new Sha256Digest()), 256, new BasicEntropySourceProvider(new SecureRandom(), true).Get(256), new byte[0], new byte[16]);
