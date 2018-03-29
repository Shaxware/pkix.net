using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace PKI.Utils.CLRExtensions {
    static class PublicKeyExtensions {
        const Int32 RSA_MAGIC        = 0x31415352;
        const Int32 DSA_V1_MAGIC     = 0x42505344; // 512-1024 bit, legacy
        const Int32 DSA_V2_MAGIC     = 0x32425044; // larger than 1024, CNG
        const Int32 ECDSA_P256_MAGIC = 0x31534345;
        const Int32 ECDSA_P384_MAGIC = 0x33534345;
        const Int32 ECDSA_P521_MAGIC = 0x35534345;

        public static Byte[] GetCryptBlob(this PublicKey publicKey) {
            List<Byte> blob = new List<Byte>();
            switch (publicKey.Oid.Value) {
                // RSA
                case "1.2.840.113549.1.1.1":
                    readRsaHeader(blob, publicKey);
                    break;
                // DSA
                case "1.2.840.10040.4.1":
                    // DSA has two formats, legacy and new. Legacy DSA keys are up to 1024 bit and support
                    // SHA1 hash algorithm only. Larger keys support up to 2048? bit keys and new hashing algorithms,
                    // SHA1, SHA256 and SHA512. SHA384 somehow is missing, see bcrypt.h file for
                    // HASHALGORITHM_ENUM
                    // so check the key size and read appropriate header
                    if (publicKey.Key.KeySize <= 1024) {
                        readDsaV1Header(blob, publicKey);
                    } else {
                        readDsaV2Header(blob, publicKey);
                    }
                    break;
                // ECC/ECDSA
                case "1.2.840.10045.2.1":
                    readEcdsaHeader(blob, publicKey);
                    break;
            }
            return blob.ToArray();
        }

        static void readRsaHeader(List<Byte> blob, PublicKey publicKey) {
            /*
            typedef struct _BCRYPT_RSAKEY_BLOB {
              ULONG Magic;          -- 0x31415352
              ULONG BitLength       -- bitLen
              ULONG cbPublicExp;    -- const 3
              ULONG cbModulus;      -- bitLen/8
              ULONG cbPrime1;       -- const 0
              ULONG cbPrime2;       -- const 0
            } BCRYPT_RSAKEY_BLOB; -- public key only
            */
            Int32 pubKeyLength = publicKey.Key.KeySize;
            blob.AddRange(BitConverter.GetBytes(RSA_MAGIC));        // Magic
            blob.AddRange(BitConverter.GetBytes(pubKeyLength));     // bitLen
            blob.AddRange(BitConverter.GetBytes(3));                // cbPublicExp
            blob.AddRange(BitConverter.GetBytes(pubKeyLength / 8)); // cbModulus
            blob.AddRange(new Byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });   // zero length primes
            blob.AddRange(publicKey.EncodedKeyValue.RawData);
        }
        static void readDsaV1Header(List<Byte> blob, PublicKey publicKey) {
            /*
            typedef struct _BCRYPT_DSA_KEY_BLOB {
                ULONG dwMagic;
                ULONG cbKey;
                UCHAR Count[4];
                UCHAR Seed[20];
                UCHAR q[20];
            } BCRYPT_DSA_KEY_BLOB, *PBCRYPT_DSA_KEY_BLOB; -- public key only
            */
            blob.AddRange(BitConverter.GetBytes(DSA_V1_MAGIC));
            blob.AddRange(BitConverter.GetBytes(publicKey.Key.KeySize));
            DSAParameters parameters = ((DSACryptoServiceProvider)publicKey.Key).ExportParameters(false);
            if (parameters.Seed == null) {
                // fill count and seed values with 0xff
                for (Int32 index = 0; index < 24; index++) {
                    blob.Add(0xff);
                }
            } else {
                // seed is exactly 20 bytes long
                if (parameters.Seed.Length != 20) {
                    throw new ArgumentException("Seed parameter is incorrect.");
                }
                blob.AddRange(BitConverter.GetBytes(parameters.Counter));
                blob.AddRange(parameters.Seed);
            }
            blob.AddRange(parameters.Q);
            /*
            BCRYPT_DSA_KEY_BLOB
            Modulus[cbKey]    // Big-endian.
            Generator[cbKey]  // Big-endian.
            Public[cbKey]     // Big-endian.
            */
            blob.AddRange(parameters.P);
            blob.AddRange(parameters.G);
            blob.AddRange(parameters.Y);
        }
        static void readDsaV2Header(List<Byte> blob, PublicKey publicKey) {
            /*
            typedef struct _BCRYPT_DSA_KEY_BLOB_V2 {
                ULONG               dwMagic;
                ULONG               cbKey;
                HASHALGORITHM_ENUM  hashAlgorithm;      -- SHA1 - 0, SHA256 - 1, SHA512 - 2
                DSAFIPSVERSION_ENUM standardVersion;    -- DSA_FIPS186_2 - 0, 
                ULONG               cbSeedLength;
                ULONG               cbGroupSize;
                UCHAR               Count[4];
            } BCRYPT_DSA_KEY_BLOB_V2, *PBCRYPT_DSA_KEY_BLOB_V2;
            according to: https://msdn.microsoft.com/en-us/library/windows/desktop/jj670561(v=vs.85).aspx
            this struct is available only starting with Windows 8/Windows Server 2012
            */
            Version version = Environment.OSVersion.Version;
            if ((version.Major != 6 || version.Minor < 2) && version.Major <= 6) {
                throw new PlatformNotSupportedException("DSAv2 keys are supported on systems started with Windows 8/Windows Server 2012.");
            }
            blob.AddRange(BitConverter.GetBytes(DSA_V2_MAGIC));
            blob.AddRange(BitConverter.GetBytes(publicKey.Key.KeySize));
            DSAParameters parameters = ((DSACryptoServiceProvider)publicKey.Key).ExportParameters(false);
            switch (parameters.Q.Length) {
                case 20:
                    blob.AddRange(BitConverter.GetBytes((Int32)BCRYPT_HASHALGORITHM_ENUM.DSA_HASH_ALGORITHM_SHA1));
                    break;
                case 32:
                    blob.AddRange(BitConverter.GetBytes((Int32)BCRYPT_HASHALGORITHM_ENUM.DSA_HASH_ALGORITHM_SHA256));
                    break;
                case 64:
                    blob.AddRange(BitConverter.GetBytes((Int32)BCRYPT_HASHALGORITHM_ENUM.DSA_HASH_ALGORITHM_SHA512));
                    break;
                default:
                    throw new ArgumentException("Q-parameter is invalid");
            }
            blob.AddRange(BitConverter.GetBytes((Int32)BCRYPT_DSAFIPSVERSION_ENUM.DSA_FIPS186_3));
            if (parameters.Seed == null) {
                // fill cbSeedLength with 0xff
                for (Int32 index = 0; index < parameters.Q.Length + 4; index++) {
                    blob.Add(0xff);
                }
            } else {
                blob.AddRange(BitConverter.GetBytes(parameters.Seed.Length));
                blob.AddRange(BitConverter.GetBytes(parameters.Q.Length));
                blob.AddRange(BitConverter.GetBytes(parameters.Counter));
                blob.AddRange(parameters.Seed);
            }

            blob.AddRange(parameters.Q);
            /*
            BCRYPT_DSA_KEY_BLOB
            Modulus[cbKey]    // Big-endian.
            Generator[cbKey]  // Big-endian.
            Public[cbKey]     // Big-endian.
            */
            blob.AddRange(parameters.P);
            blob.AddRange(parameters.G);
            blob.AddRange(parameters.Y);
        }
        static void readEcdsaHeader(List<Byte> blob, PublicKey publicKey) {
            /*
            typedef struct _BCRYPT_ECCKEY_BLOB {
              ULONG Magic;
              ULONG cbKey;
            } BBCRYPT_ECCKEY_BLOB, *PBCRYPT_ECCKEY_BLOB; -- public key only
            */
            // headers from bcrypt.h
            switch (Asn1Utils.DecodeObjectIdentifier(publicKey.EncodedParameters.RawData).Value) {
                // ECDH_P256/ECDSA_P256
                case "1.2.840.10045.3.1.7":
                    blob.AddRange(BitConverter.GetBytes(ECDSA_P256_MAGIC));
                    blob.AddRange(BitConverter.GetBytes(256 / 8));
                    break;
                // ECDH_P384/ECDSA_P384
                case "1.3.132.0.34":
                    blob.AddRange(BitConverter.GetBytes(ECDSA_P384_MAGIC));
                    blob.AddRange(BitConverter.GetBytes(384 / 8));
                    break;
                // ECDH_P521/ECDSA_P521
                case "1.3.132.0.35":
                    blob.AddRange(BitConverter.GetBytes(ECDSA_P521_MAGIC));
                    blob.AddRange(BitConverter.GetBytes(528 / 8));
                    break;
                default:
                    throw new CryptographicException("Specified ellyptic curve is not supported.");
            }
            // skip first byte, it is always 0X04 for ECDSA public key
            blob.AddRange(publicKey.EncodedKeyValue.RawData.Skip(1));
        }

        enum BCRYPT_HASHALGORITHM_ENUM {
            DSA_HASH_ALGORITHM_SHA1 = 0,
            DSA_HASH_ALGORITHM_SHA256 = 1,
            DSA_HASH_ALGORITHM_SHA512 = 2
        }

        enum BCRYPT_DSAFIPSVERSION_ENUM {
            DSA_FIPS186_2 = 0,
            DSA_FIPS186_3 = 1
        }
    }
}
