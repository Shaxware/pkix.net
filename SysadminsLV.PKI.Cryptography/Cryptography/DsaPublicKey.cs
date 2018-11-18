using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography {
    class DsaPublicKey : RawPublicKey {
        static readonly Oid _oid = new Oid(AlgorithmOids.DSA);
        DSAParameters dsaParams;
        DSA dsa;

        public DsaPublicKey(PublicKey publicKey) : base(_oid) {
            if (publicKey == null) {
                throw new ArgumentNullException(nameof(publicKey));
            }
            if (publicKey.Oid.Value != Oid.Value) {
                throw new ArgumentException("Public key algorithm is not DSA.");
            }
            decodeFromPublicKey(publicKey);
        }
        public DsaPublicKey(Byte[] rawData) : base(_oid) {
            if (rawData == null) {
                throw new ArgumentNullException(nameof(rawData));
            }
            decodeFromFullKey(rawData);
        }

        void decodeFromPublicKey(PublicKey publicKey) {
            dsaParams.Y = publicKey.EncodedKeyValue.RawData[0] == 0
                ? publicKey.EncodedKeyValue.RawData.Skip(1).ToArray()
                : publicKey.EncodedKeyValue.RawData;
            decodeParams(publicKey.EncodedParameters.RawData);
        }
        void decodeFromFullKey(Byte[] rawData) {
            var asn = new Asn1Reader(rawData);
            asn.MoveNextAndExpectTags(0x30);
            Int32 offset = asn.Offset;
            asn.MoveNextAndExpectTags((Byte)Asn1Type.OBJECT_IDENTIFIER);
            Oid oid = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value;
            if (oid.Value != _oid.Value) {
                throw new ArgumentException("Public key algorithm is not DSA.");
            }
            asn.MoveNextAndExpectTags(0x30);
            decodeParams(asn.GetTagRawData());
            asn.MoveToPoisition(offset);
            asn.MoveNextCurrentLevelAndExpectTags((Byte)Asn1Type.BIT_STRING);
            var bitString = (Asn1BitString)asn.GetTagObject();
            dsaParams.Y = bitString.Value[0] == 0
                ? bitString.Value.Skip(1).ToArray()
                : bitString.Value;
        }
        void decodeParams(Byte[] paramBytes) {
            var asn = new Asn1Reader(paramBytes);
            // P
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
            Byte[] bytes = asn.GetPayload();
            dsaParams.P = bytes[0] == 0
                ? bytes.Skip(0).ToArray()
                : bytes;
            // Q
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
            bytes = asn.GetPayload();
            dsaParams.Q = bytes[0] == 0
                ? bytes.Skip(0).ToArray()
                : bytes;
            // G
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
            bytes = asn.GetPayload();
            dsaParams.G = bytes[0] == 0
                ? bytes.Skip(0).ToArray()
                : bytes;
        }

        public override AsymmetricAlgorithm GetAsymmetricKey() {
            dsa = DSA.Create();
            dsa.ImportParameters(dsaParams);
            return dsa;
        }
        public override void Dispose() {
            dsa?.Dispose();
        }
    }
}
