﻿using System;
using System.Security.Cryptography;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography {
    public sealed class RsaPrivateKey : AsymmetricKeyPair {
        const String ALG_ERROR = "Private key algorithm is not RSA.";
        static readonly Oid _oid = new Oid(AlgorithmOids.RSA);
        RSAParameters rsaParameters;
        RSA rsaKey;

        public RsaPrivateKey(Byte[] rawData) : base(_oid, false) {
            if (rawData == null) {
                throw new ArgumentNullException(nameof(rawData));
            }
            selectFormat(rawData);
        }

        public KeyPkcsFormat KeyFormat { get; private set; }

        void selectFormat(Byte[] rawData) {
            var asn = new Asn1Reader(rawData);
            // version
            asn.MoveNext();
            // algID
            asn.MoveNext();
            if (asn.Tag == 0x30) {
                KeyFormat = KeyPkcsFormat.Pkcs8;
                decodePkcs8(rawData);
            } else {
                KeyFormat = KeyPkcsFormat.Pkcs1;
                decodePkcs1(rawData);
            }
        }
        void decodePkcs8(Byte[] rawData) {
            var asn = new Asn1Reader(rawData);
            // version
            asn.MoveNext();
            // algID
            asn.MoveNext();
            Int32 offset = asn.Offset;
            asn.MoveNextAndExpectTags((Byte)Asn1Type.OBJECT_IDENTIFIER);
            Oid oid = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value;
            if (oid.Value != Oid.Value) {
                throw new ArgumentException(ALG_ERROR);
            }
            asn.MoveToPosition(offset);
            asn.MoveNextCurrentLevelAndExpectTags((Byte)Asn1Type.OCTET_STRING);
            decodePkcs1(asn.GetPayload());
        }
        void decodePkcs1(Byte[] rawData) {
            var asn = new Asn1Reader(rawData);
            // version. Must be 0
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
            // modulus: Modulus
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
            rsaParameters.Modulus = GetPositiveInteger(asn.GetPayload());
            // publicExponent: Exponent
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
            rsaParameters.Exponent = asn.GetPayload();
            // privateExponent: D
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
            rsaParameters.D = GetPositiveInteger(asn.GetPayload());
            // prime1: P
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
            rsaParameters.P = GetPositiveInteger(asn.GetPayload());
            // prime2: Q
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
            rsaParameters.Q = GetPositiveInteger(asn.GetPayload());
            // exponent1: DP
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
            rsaParameters.DP = GetPositiveInteger(asn.GetPayload());
            // exponent2: DQ
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
            rsaParameters.DQ = GetPositiveInteger(asn.GetPayload());
            // coefficient: InverseQ
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
            rsaParameters.InverseQ = GetPositiveInteger(asn.GetPayload());
            rsaKey = RSA.Create();
            rsaKey.ImportParameters(rsaParameters);
        }

        public override AsymmetricAlgorithm GetAsymmetricKey() {
            return rsaKey;
        }
        public override void Dispose() {
            rsaKey?.Dispose();
        }
    }
}
/*
PKCS#8
------
PrivateKeyInfo ::= SEQUENCE {
  version         Version,
  algorithm       AlgorithmIdentifier,
  PrivateKey      OCTET STRING
}

PKCS#1
------
RSAPrivateKey ::= SEQUENCE {
     version Version,
     modulus INTEGER, -- n
     publicExponent INTEGER, -- e
     privateExponent INTEGER, -- d
     prime1 INTEGER, -- p
     prime2 INTEGER, -- q
     exponent1 INTEGER, -- d mod (p-1)
     exponent2 INTEGER, -- d mod (q-1)
     coefficient INTEGER -- (inverse of q) mod p }

   Version ::= INTEGER

*/
