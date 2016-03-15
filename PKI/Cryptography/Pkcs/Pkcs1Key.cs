using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using PKI.Utils.CLRExtensions;
using SysadminsLV.Asn1Parser;

namespace PKI.Cryptography.Pkcs {
    public class Pkcs1Key {
        Int32 version;
        BigInteger modulus, pubExponent, privateExponent, prime1, prime2, exp1, exp2, coefficient;
        Byte[] privateKeyMagic = { 0x07,0x02,0x00,0x00,0x00,0x24,0x00,0x00,0x52,0x53,0x41,0x32,0x00 };


        public Pkcs1Key(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException("rawData"); }
            decodePrivate(rawData);
        }
        protected Pkcs1Key(Byte[] rawData, Boolean pkcs8) {

        }

        public Int32 Version {
            get { return version + 1; }
            
        }
        public KeyType Type { get; protected set; }
        public Byte[] RawData { get; protected set; }

        void decodePrivate(Byte[] rawData) {
            Asn1Reader asn = new Asn1Reader(rawData);
            if (asn.Tag != 48) { throw new ArgumentException("The data is invalid ASN message."); }
            if (asn.GetNestedNodeCount() > 10) {
                throw new ArgumentException("The data is too big.");
            }
            asn.MoveNext();
            version = asn.GetPayload()[0];
            if (!asn.MoveNext()) {
                
            }
            modulus = new BigInteger(getNormalizedArray(asn.GetPayload()));
            if (!asn.MoveNext()) {
                
            }
            pubExponent = new BigInteger(getNormalizedArray(asn.GetPayload()));
            if (!asn.MoveNext()) {
                
            }
            privateExponent = new BigInteger(getNormalizedArray(asn.GetPayload()));
            if (!asn.MoveNext()) {
                
            }
            prime1 = new BigInteger(getNormalizedArray(asn.GetPayload()));
            if (!asn.MoveNext()) {
                
            }
            prime2 = new BigInteger(getNormalizedArray(asn.GetPayload()));
            if (!asn.MoveNext()) {
                
            }
            exp1 = new BigInteger(getNormalizedArray(asn.GetPayload()));
            if (!asn.MoveNext()) {
                
            }
            exp2 = new BigInteger(getNormalizedArray(asn.GetPayload()));
            if (!asn.MoveNext()) {
                
            }
            coefficient = new BigInteger(getNormalizedArray(asn.GetPayload()));

            Type = KeyType.Private;
            RawData = rawData;
        }
        void decodePublic(Byte[] rawData) {
            Type = KeyType.Public;
            RawData = rawData;
        }
        protected static Byte[] getNormalizedArray(Byte[] rawData) {
            var padding = rawData.Length % 8;
            return padding == 0 ? rawData : rawData.Skip(padding).ToArray();
        }

        /// <summary>
        /// Attaches current object to an <see cref="X509Certificate2"/> object.
        /// </summary>
        /// <param name="cert"></param>
        /// <exception cref="InvalidOperationException">
        /// Current key is public key. This method is applicable only for private key objects
        /// </exception>
        public void Attach(X509Certificate2 cert) {
            if (Type != KeyType.Private) {
                throw new InvalidOperationException("The current key type do not allow this operation.");
            }
        }
        public virtual String Format() {
            return "-----BEGIN RSA PRIVATE KEY-----" +
                Environment.NewLine +
                AsnFormatter.BinaryToString(RawData, EncodingType.Base64) +
                "-----End RSA PRIVATE KEY-----";
        }
    }
}
