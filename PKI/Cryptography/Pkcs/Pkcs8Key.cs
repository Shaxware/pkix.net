using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using SysadminsLV.Asn1Parser;

namespace PKI.Cryptography.Pkcs {
    sealed class Pkcs8Key {
		// PrivateKeyInfo::= SEQUENCE {
		//    version Version,
		//    privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
		//    privateKey PrivateKey,
		//    attributes [0] Attributes OPTIONAL }
		// Version::= INTEGER {v1(0)} (v1,...)
		// PrivateKey::= OCTET STRING
		// Attributes::= SET OF Attribute
		public Pkcs8Key(Byte[] rawData) {
            
        }

		public Int32 Version => 1;
		public Oid KeyAlgorithm { get; private set; }
		public X509AttributeCollection Attributes { get; }
		public Byte[] RawData { get; private set; }

        public string Format() {
            return "-----BEGIN PRIVATE KEY-----" +
                Environment.NewLine +
                AsnFormatter.BinaryToString(RawData, EncodingType.Base64) +
                "-----End PRIVATE KEY-----";
        }
    }
}
