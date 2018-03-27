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
                case "1.2.840.10040.4.1": break;
                // ECC/ECDSA
                case "1.2.840.10045.2.1":
                    readEcdsaHeader(blob, publicKey);
                    break;
            }
            return blob.ToArray();
        }

        static void readRsaHeader(List<Byte> blob, PublicKey publicKey) {
            Int32 pubKeyLength = publicKey.Key.KeySize;
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
            blob.AddRange(BitConverter.GetBytes(RSA_MAGIC));        // Magic
            blob.AddRange(BitConverter.GetBytes(pubKeyLength));     // bitLen
            blob.AddRange(BitConverter.GetBytes(3));                // cbPublicExp
            blob.AddRange(BitConverter.GetBytes(pubKeyLength / 8)); // cbModulus
            blob.AddRange(new Byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });   // zero length primes
            blob.AddRange(publicKey.EncodedKeyValue.RawData);
        }
        static void readDsaHeader(List<Byte> blob, PublicKey publicKey) {

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
    }
}
