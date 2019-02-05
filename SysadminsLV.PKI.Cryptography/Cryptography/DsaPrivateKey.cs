using System;
using System.Security.Cryptography;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography {
    public sealed class DsaPrivateKey : AsymmetricKeyPair {
        const String ALG_ERROR = "Private key is not DSA.";
        static readonly Oid _oid = new Oid(AlgorithmOids.DSA);
        DSAParameters dsaParameters;
        DSA dsaKey;

        public DsaPrivateKey(Byte[] rawData) : base(_oid, false) {
            if (rawData == null) {
                throw new ArgumentNullException(nameof(rawData));
            }
            decode(rawData);
        }

        void decode(Byte[] rawData) {
            var asn = new Asn1Reader(rawData);
            // version. Must be 0
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
            // algID
            asn.MoveNextAndExpectTags(0x30);
            decodeAlgID(asn.GetTagRawData());
            // PrivateKey
            asn.MoveNextCurrentLevelAndExpectTags((Byte)Asn1Type.OCTET_STRING);
            decodePrivateKey(asn.GetPayload());
        }
        void decodeAlgID(Byte[] rawData) {
            var asn = new Asn1Reader(rawData);
            // DSA oid
            asn.MoveNextAndExpectTags((Byte)Asn1Type.OBJECT_IDENTIFIER);
            Oid oid = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value;
            if (oid.Value != _oid.Value) {
                throw new ArgumentException(ALG_ERROR);
            }
            decodeParams(asn);
        }
        void decodeParams(Asn1Reader asn) {
            // params
            asn.MoveNextAndExpectTags(0x30);
            // modulus p
            asn.MoveNextAndExpectTags((Byte) Asn1Type.INTEGER);
            dsaParameters.P = GetPositiveInteger(asn.GetPayload());
            // modulus q
            asn.MoveNextAndExpectTags((Byte) Asn1Type.INTEGER);
            dsaParameters.Q = GetPositiveInteger(asn.GetPayload());
            // base g
            asn.MoveNextAndExpectTags((Byte) Asn1Type.INTEGER);
            dsaParameters.G = GetPositiveInteger(asn.GetPayload());
        }
        void decodePrivateKey(Byte[] rawData) {
            var asn = new Asn1Reader(rawData);
            dsaParameters.X = GetPositiveInteger(asn.GetPayload());
        }

        public override AsymmetricAlgorithm GetAsymmetricKey() {
            if (dsaKey != null) {
                return dsaKey;
            }
            dsaKey = DSA.Create();
            dsaKey.ImportParameters(dsaParameters);
            return dsaKey;
        }

        /// <inheritdoc />
        public override void Dispose() {
            dsaKey?.Dispose();
        }
    }
}
/*
PrivateKeyInfo ::= SEQUENCE {
  version Version,
  algorithm AlgorithmIdentifier,
  PrivateKey OCTETSTRING
}

AlgorithmIdentifier ::= SEQUENCE {
  algorithm ALGORITHM.id,
  parameters Dss-Parms
}

Dss-Parms ::= SEQUENCE {
  p INTEGER,
  q INTEGER,
  g INTEGER
}

DSAPrivateKey ::= OCTETSTRING {
  privateExponent INTEGER
}
 */
