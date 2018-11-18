using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography {
    class ECDsaPublicKey : RawPublicKey {
        static readonly Oid _oid = new Oid(AlgorithmOids.ECC);
        ECDsa ecdsa;

        public ECDsaPublicKey(PublicKey publicKey) : base(_oid) {
            if (publicKey == null) {
                throw new ArgumentNullException(nameof(publicKey));
            }
            if (publicKey.Oid.Value != Oid.Value) {
                throw new ArgumentException("Public key algorithm is not EC.");
            }
            decodeFromPublicKey(publicKey);
        }
        public ECDsaPublicKey(Byte[] rawData) : base(_oid) {
            if (rawData == null) {
                throw new ArgumentNullException(nameof(rawData));
            }
            decodeFromFullKey(rawData);
        }

        public Oid CurveOid { get; private set; }
        public Byte[] CoordinateX { get; private set; }
        public Byte[] CoordinateY { get; private set; }

        void decodeFromPublicKey(PublicKey publicKey) {
            // skip first byte as it is always 0x04 for ECDSA keys
            Byte[] key = publicKey.EncodedKeyValue.RawData.Skip(1).ToArray();
            // coordinates are halves of concatenated encoded key value
            // X is first half
            // Y is second half
            CoordinateX = key.Take(key.Length / 2).ToArray();
            CoordinateY = key.Skip(key.Length / 2).ToArray();
            CurveOid = new Asn1ObjectIdentifier(publicKey.EncodedParameters.RawData).Value;
        }
        void decodeFromFullKey(Byte[] rawData) {
            var asn = new Asn1Reader(rawData);
            asn.MoveNextAndExpectTags(0x30);
            asn.MoveNextAndExpectTags((Byte)Asn1Type.OBJECT_IDENTIFIER);
            Oid oid = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value;
            if (oid.Value != AlgorithmOids.ECC) {
                throw new ArgumentException("Public key algorithm is not EC.");
            }
            asn.MoveNextAndExpectTags((Byte)Asn1Type.OBJECT_IDENTIFIER);
            CurveOid = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value;
            asn.MoveNextAndExpectTags((Byte)Asn1Type.BIT_STRING);
            var bitString = (Asn1BitString)asn.GetTagObject();
            Byte[] key = bitString.Value.Skip(1).ToArray();
            // coordinates are halves of concatenated encoded key value
            // X is first half
            // Y is second half
            CoordinateX = key.Take(key.Length / 2).ToArray();
            CoordinateY = key.Skip(key.Length / 2).ToArray();
        }

        public override AsymmetricAlgorithm GetAsymmetricKey() {
            if (ecdsa != null) {
                return ecdsa;
            }
            var ecdsaParams = new ECParameters {
                Q = {
                        X = CoordinateX,
                        Y = CoordinateY
                    },
                Curve = ECCurve.CreateFromOid(CurveOid)
            };
            ecdsa = ECDsa.Create();
            ecdsa.ImportParameters(ecdsaParams);
            return ecdsa;
        }

        /// <inheritdoc />
        public override void Dispose() {
            ecdsa?.Dispose();
        }
    }
}
