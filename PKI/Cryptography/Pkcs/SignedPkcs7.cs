using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography.Pkcs {
    /*
    RFC2315 https://tools.ietf.org/html/rfc2315
    SignedData ::= SEQUENCE {
        version             Version,
        digestAlgorithms    DigestAlgorithmIdentifiers,
        contentInfo         ContentInfo,
        certificates [0]    IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
        crls         [1]    IMPLICIT CertificateRevocationLists OPTIONAL,
        signerInfos         SignerInfos
    }
    */
    /// <summary>
    /// Represents base class for any sort of PKCS #7 signed message.
    /// </summary>
    /// <typeparam name="T">Any reference type that represents the contents of signed message.</typeparam>
    /// <remarks>This class is <strong>abstract</strong> and cannot be instantiated.</remarks>
    public abstract class SignedPkcs7<T> where T : class {
        readonly List<AlgorithmIdentifier> _digestAlgorithms    = new List<AlgorithmIdentifier>();
        readonly List<X509CRL2> _crls                           = new List<X509CRL2>();
        readonly List<PkcsSignerInfo> _signerInfos              = new List<PkcsSignerInfo>();

        /// <summary>
        /// Initializes a new instance of <strong>SignedPkcs7</strong> message from ASN.1-encoded PKCS# signed message.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array that represent PKCS# signed message</param>
        protected SignedPkcs7(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            decode(rawData);
        }

        /// <summary>
        /// Gets the version of the CMS/PKCS#7 message.
        /// </summary>
        public Int32 Version { get; set; }
        /// <summary>
        /// Gets the object identifier that identifies the content type stored in <see cref="Content"/> member.
        /// </summary>
        public Oid ContentType { get; private set; }
        /// <summary>
        /// Gets the content of the current signed message. Object type is determined by implementer based on
        /// <see cref="ContentType"/> information.
        /// </summary>
        public T Content { get; protected set; }
        /// <summary>
        /// Gets a collection of hashing algorithms.
        /// </summary>
        public AlgorithmIdentifier[] DigestAlgorithms => _digestAlgorithms.ToArray();
        /// <summary>
        /// Gets a collection of certificates contained in signed message.
        /// </summary>
        public X509Certificate2Collection Certificates { get; } = new X509Certificate2Collection();
        /// <summary>
        /// Gets an array of certificate revocation lists contained in the message.
        /// </summary>
        public X509CRL2[] RevocationLists => _crls.ToArray();
        /// <summary>
        /// Gets a collection of tagged attributes associated with the message.
        /// </summary>
        public X509AttributeCollection Attributes { get; } = new X509AttributeCollection();
        /// <summary>
        /// Gets an array of signer information that were used to sign the message.
        /// </summary>
        public PkcsSignerInfo[] SignerInfos => _signerInfos.ToArray();
        /// <summary>
        /// Gets the ASN.1-encoded byte array that represents current object.
        /// </summary>
        public Byte[] RawData { get; private set; }

        void decode(Byte[] rawData) {
            Asn1Reader asn = new Asn1Reader(rawData);
            asn.MoveNext();
            ContentType = new Asn1ObjectIdentifier(asn.GetTagRawData()).Value;
            asn.MoveNextAndExpectTags(0xa0); // [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL, 0xa0
            asn.MoveNextAndExpectTags(0x30); // SEQUENCE OF ANY
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER); // version
            Version = (Int32)new Asn1Integer(asn.GetTagRawData()).Value;
            asn.MoveNextCurrentLevelAndExpectTags(0x31);
            decodeDigestAlgorithms(asn);
            asn.MoveNextCurrentLevelAndExpectTags(0x30); // ContentInfo
            Byte[] content = extractContent(asn);
            while (asn.MoveNextCurrentLevel()) {
                switch (asn.Tag) {
                    case 0xa0:
                        decodeCertificates(asn);
                        break;
                    case 0xa1:
                        decodeCrls(asn);
                        break;
                    case 0x31:
                        decodeSignerInfos(asn);
                        break;
                    default:
                        throw new ArgumentException("Invalid type.");
                }
            }
            RawData = rawData;
            DecodeContent(content);
        }
        void decodeDigestAlgorithms(Asn1Reader asn) {
            // asn tag -> SET (0x31)
            Int32 offset = asn.Offset;
            if (asn.PayloadLength == 0) { return; }
            asn.MoveNext();
            do {
                _digestAlgorithms.Add(new AlgorithmIdentifier(asn.GetTagRawData()));
            } while (asn.MoveNextCurrentLevel());

            asn.MoveToPoisition(offset);
        }
        Byte[] extractContent(Asn1Reader asn) {
            Int32 offset = asn.Offset;
            asn.MoveNext();
            Byte[] payload = null;
            ContentType = new Asn1ObjectIdentifier(asn.GetTagRawData()).Value;
            if (asn.MoveNextCurrentLevel()) { // content [0] EXPLICIT ANY DEFINED BY contentType
                asn.MoveNextAndExpectTags((Byte)Asn1Type.OCTET_STRING, 48); // octet string
                payload = asn.GetPayload();
            }
            asn.MoveToPoisition(offset);
            return payload;
        }
        void decodeCertificates(Asn1Reader asn) {
            if (asn.PayloadLength == 0) { return; }
            Int32 offset = asn.Offset;
            asn.MoveNext();
            do {
                Certificates.Add(new X509Certificate2(asn.GetTagRawData()));
            } while (asn.MoveNextCurrentLevel());
            asn.MoveToPoisition(offset);
        }
        void decodeCrls(Asn1Reader asn) {
            if (asn.PayloadLength == 0) { return; }
            Int32 offset = asn.Offset;
            asn.MoveNext();
            do {
                _crls.Add(new X509CRL2(asn.GetTagRawData()));
            } while (asn.MoveNextCurrentLevel());
            asn.MoveToPoisition(offset);
        }
        void decodeSignerInfos(Asn1Reader asn) {
            if (asn.PayloadLength == 0) { return; }
            Int32 offset = asn.Offset;
            asn.MoveNext();
            do {
                _signerInfos.Add(new PkcsSignerInfo(asn.GetTagRawData()));
            } while (asn.MoveNextCurrentLevel());
            asn.MoveToPoisition(offset);
        }

        /// <summary>
        /// Implementers use this method to decode content of the signed message and set it in
        /// <see cref="Content"/> member.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded array that represents signed message's content. Can be null.</param>
        /// <remarks> This method is invoked after entire PKCS #7 structure is decoded.</remarks>
        protected abstract void DecodeContent(Byte[] rawData);
    }
}
