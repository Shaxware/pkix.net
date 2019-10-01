using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Tools.MessageOperations;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace SysadminsLV.PKI.Cryptography.Pkcs {
    /// <summary>
    /// Contains properties and members to construct and (optionally) sign PKCS#7/CMS message.
    /// </summary>
    public sealed class SignedCmsBuilder {
        readonly Oid _contentType;
        readonly Byte[] _content;
        readonly PkcsSignerInfoCollection _signerInfos = new PkcsSignerInfoCollection();

        /// <summary>
        ///     Initializes a new instance of <strong>SignedCmsBuilder</strong> from content type identifier and optional content.
        /// </summary>
        /// <param name="contentType">An object identifier that identifies the content type stored in PKCS#7 message.</param>
        /// <param name="content">
        ///     Content embedded in the PKCS#7 message. This parameter is optional.
        /// </param>
        /// <remarks>
        ///     If <strong>content</strong> parameter is null, signing operation will fail. Only message encoding is allowed.
        ///     <para>
        ///     If <strong>content</strong> parameter is presented, the content must be properly encoded without outer SEQUENCE type.
        ///     </para>
        /// </remarks>
        public SignedCmsBuilder(Oid contentType, Byte[] content = null) {
            _contentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
            _content = content;
        }

        /// <summary>
        /// Gets the version of the CMS/PKCS#7 message. Currently, only version 1 is defined.
        /// </summary>
        public Int32 Version { get; } = 1;
        /// <summary>
        /// Gets the object identifier that identifies the content type stored in current object.
        /// </summary>
        public Oid ContentType => new Oid(_contentType);
        /// <summary>
        /// Gets a collection of hashing algorithms.
        /// </summary>
        public AlgorithmIdentifierCollection DigestAlgorithms { get; } = new AlgorithmIdentifierCollection();
        /// <summary>
        /// Gets a collection of certificates contained in signed message.
        /// </summary>
        public X509Certificate2Collection Certificates { get; } = new X509Certificate2Collection();
        /// <summary>
        /// Gets an array of certificate revocation lists contained in the message.
        /// </summary>
        public X509CRL2Collection RevocationLists { get; } = new X509CRL2Collection();
        /// <summary>
        /// Gets a collection of signer infos. This collection is read-only and populated automatically by signing current object.
        /// </summary>
        public PkcsSignerInfoCollection SignerInfos => new PkcsSignerInfoCollection(_signerInfos);

        Byte[] encodeSignedData() {
            // initialize with Version
            var rawData = new List<Byte>(new Asn1Integer(1).RawData);
            // digestAlgorithms
            rawData.AddRange(DigestAlgorithms.Encode());
            // contentInfo
            rawData.AddRange(encodeContentInfo());
            // certificates
            if (Certificates.Count > 0) {
                rawData.AddRange(encodeCertificates());
            }
            // CRLs
            if (RevocationLists.Count > 0) {
                rawData.AddRange(encodeCRLs());
            }
            rawData.AddRange(_signerInfos.Encode());
            return Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        IEnumerable<Byte> encodeContentInfo() {
            var rawData = new List<Byte>(new Asn1ObjectIdentifier(_contentType).RawData);
            if (_content != null) {
                switch (ContentType.Value) {
                    case "1.3.6.1.5.5.7.12.2": // CMC Data. For CMC: content [0] EXPLICIT OCTET STRING OPTIONAL
                        rawData.AddRange(Asn1Utils.Encode(Asn1Utils.Encode(_content, (Byte)Asn1Type.OCTET_STRING), 0xa0));
                        break;
                    default: // everything else. Suggested: content [0] EXPLICIT SEQUENCE OF ANY OPTIONAL
                        rawData.AddRange(Asn1Utils.Encode(Asn1Utils.Encode(_content, 48), 0xa0));
                        break;
                }
            }

            return Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        IEnumerable<Byte> encodeCertificates() {
            return Certificates.Encode(0xa0);
        }
        IEnumerable<Byte> encodeCRLs() {
            var rawData = new List<Byte>();
            foreach (X509CRL2 crl in RevocationLists) {
                rawData.AddRange(crl.RawData);
            }
            return Asn1Utils.Encode(rawData.ToArray(), 0xa1);
        }
        // we use this method to add signing certificates to Certificates collection.
        void addCerts(IEnumerable<X509Certificate2> signingCerts) {
            if (Certificates.Count == 0) {
                Certificates.AddRange(signingCerts.ToArray());
            } else {
                // we exclude possible certificate duplicates.
                foreach (X509Certificate2 signingCert in signingCerts) {
                    Int32 index = Certificates.IndexOf(signingCert);
                    if (index >= 0) {
                        Certificates.RemoveAt(index);
                    }
                    Certificates.Insert(0, signingCert);
                }
            }
        }
        Byte[] wrapEnvelope() {
            var rawData = new List<Byte>(new Asn1ObjectIdentifier("1.2.840.113549.1.7.2").RawData);
            rawData.AddRange(Asn1Utils.Encode(encodeSignedData(), 0xa0));
            return Asn1Utils.Encode(rawData.ToArray(), 48);
        }

        /// <summary>
        ///     Signs current PKCS#7 message and adds a new signer information to <see cref="SignerInfos"/> collection.
        ///     Certificates specified in <strong>chain</strong> parameter are added to <see cref="Certificates"/> collection.
        /// </summary>
        /// <param name="signer">signing object that contains public certificate, private key and signing configuration.</param>
        /// <param name="chain">
        ///     Signing certificate chain to add to CMS. This parameter is optional. If not specified, only leaf (signing) certificate
        ///     is added to <see cref="Certificates"/> collection and signed message.
        /// </param>
        /// <exception cref="InvalidOperationException">
        ///     No data to sign was passed in the constructor.
        /// </exception>
        /// <returns>
        ///     An instance of <see cref="DefaultSignedPkcs7"/> class that represents signed CMS message.
        /// </returns>
        /// <remarks>
        ///     You can call this method multiple times to attach multiple signatures to signed CMS message.
        /// </remarks>
        public DefaultSignedPkcs7 Sign(MessageSigner signer, X509Certificate2Collection chain = null) {
            if (_content == null || _content.Length == 0) {
                throw new InvalidOperationException("There is no data to sign.");
            }
            var asn = new Asn1Reader(Asn1Utils.Encode(_content, 48));
            var builder = new PkcsSignerInfoBuilder(signer) {
                ContentType = ContentType
            };
            _signerInfos.Add(builder.EncodeAndSign(asn.GetPayload()));
            var certs = new List<X509Certificate2>(new[] { signer.SignerCertificate });
            if (chain != null) {
                certs.AddRange(chain.Cast<X509Certificate2>());
            }
            addCerts(certs);
            return new DefaultSignedPkcs7(wrapEnvelope());
        }
        /// <summary>
        /// Encodes CMS without signing. 
        /// </summary>
        /// <returns>
        ///     An instance of <see cref="DefaultSignedPkcs7"/> class that represents signed CMS message.
        /// </returns>
        public DefaultSignedPkcs7 Encode() {
            return new DefaultSignedPkcs7(wrapEnvelope());
        }
    }
}
