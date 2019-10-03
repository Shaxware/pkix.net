using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Tools.MessageOperations;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace SysadminsLV.PKI.Cryptography.Pkcs {
    public sealed class PkcsSignerInfoBuilder {
        readonly X509AttributeCollection _authAttributes = new X509AttributeCollection();
        readonly X509AttributeCollection _unauthAttributes = new X509AttributeCollection();
        readonly MessageSigner _signer;

        public PkcsSignerInfoBuilder(MessageSigner signerInfo) {
            if (signerInfo.PaddingScheme == SignaturePadding.PSS) {
                throw new CryptographicException("PSS padding scheme is not supported.");
            }
            _signer = signerInfo;
        }

        /// <summary>
        ///		Gets the signer information version. Default version Version 1.
        /// </summary>
        /// <remarks>
        ///		The version determines whether the message is a PKCS #7 message or a Cryptographic Message Syntax (CMS)
        ///		message. CMS is a newer superset of PKCS #7.
        /// </remarks>
        public Int32 Version { get; set; } = 1;
        /// <summary>
        ///     Gets or sets the subject identifier type used to identify the signer in signer info element. Default value is
        /// <strong>IssuerAndSerialNumber</strong>.
        /// </summary>
        public SubjectIdentifierType SubjectIdentifier { get; set; } = SubjectIdentifierType.IssuerAndSerialNumber;
        /// <summary>
        ///     Gets or sets the object identifier that identifies the content type.
        /// </summary>
        public Oid ContentType { get; set; }
        /// <summary>
        ///		Gets the <see cref="X509AttributeCollection"/> collection of signed attributes that is associated with
        ///		the signer information. Signed attributes are signed along with the rest of the message content.
        /// </summary>
        public X509AttributeCollection AuthenticatedAttributes => new X509AttributeCollection(_authAttributes);
        /// <summary>
        ///		Gets the <see cref="X509AttributeCollection"/> collection of unsigned attributes that is associated with
        ///		the <see cref="PkcsSignerInfo"/> content. Unsigned attributes can be modified without invalidating the
        ///		signature.
        /// </summary>
        public X509AttributeCollection UnauthenticatedAttributes => new X509AttributeCollection(_unauthAttributes);

        static void addUniqueAttribute(IList<X509Attribute> referenceList, X509Attribute attribute) {
            // if there is already same attribute (with same OID), remove old attribute and add new attribute
            // to avoid duplicates.
            for (Int32 index = 0; index < referenceList.Count; index++) {
                if (referenceList[index].Oid.Value == attribute.Oid.Value) {
                    referenceList.RemoveAt(index);
                    break;
                }
            }
            referenceList.Add(attribute);
        }

        void prepareSigning(Byte[] content) {
            addContentInfoAttribute();
            addMessageDigestAttribute(content);
        }
        void addContentInfoAttribute() {
            AddAuthenticatedAttribute(new X509Attribute(new Oid("1.2.840.113549.1.9.3"), new Asn1ObjectIdentifier(ContentType).RawData));
        }
        void addMessageDigestAttribute(Byte[] content) {
            using (var hasher = HashAlgorithm.Create(_signer.HashingAlgorithm.FriendlyName)) {
                if (hasher == null) {
                    throw new ArgumentException("Specified hash algorithm is not valid hashing algorithm");
                }
                var attrValue = Asn1Utils.Encode(hasher.ComputeHash(content), (Byte)Asn1Type.OCTET_STRING);
                AddAuthenticatedAttribute(new X509Attribute(new Oid("1.2.840.113549.1.9.4"), attrValue));
            }
        }

        /// <summary>
        /// Adds authenticated attribute. Authenticated attribute will be protected from tampering by digitally signing its contents.
        /// </summary>
        /// <param name="attribute">
        /// An attribute that must be protected by digital signature.
        /// </param>
        /// <remarks>
        /// If same attribute (with same object identifier) is already presented in collection, it will be overwritten with attribute in the
        /// <strong>attribute</strong> parameter.
        /// </remarks>
        public void AddAuthenticatedAttribute(X509Attribute attribute) {
            if (attribute == null) {
                throw new ArgumentNullException(nameof(attribute));
            }
            addUniqueAttribute(_authAttributes, attribute);
        }
        /// <summary>
        /// Adds unauthenticated attribute. Unlike authenticated attribute, unauthenticated attributes are not protected by signer's signature.
        /// Unauthenticated attributes are replaceable. Such attributes are counter-signing and timestamp. These attributes are informative or
        /// provide their own integrity mechanisms.
        /// </summary>
        /// <param name="attribute">
        /// An attribute that must be protected by digital signature.
        /// </param>
        /// <remarks>
        /// If same attribute (with same object identifier) is already presented in collection, it will be overwritten with attribute in the
        /// <strong>attribute</strong> parameter.
        /// </remarks>
        public void AddUnauthenticatedAttribute(X509Attribute attribute) {
            if (attribute == null) {
                throw new ArgumentNullException(nameof(attribute));
            }
            addUniqueAttribute(_unauthAttributes, attribute);
        }

        /// <summary>
        ///     Encodes and signs the content using the signer object used in 
        /// </summary>
        /// <param name="content">
        ///     Content to sign and associate with the resulted signer info element.
        /// </param>
        /// <returns>
        ///     An instance of <see cref="PkcsSignerInfo"/> class.
        /// </returns>
        /// <remarks>
        ///     Before signing, the method adds two authenticated attributes: content type and message digest. Authenticated attributes are then
        ///     signed with signer's private key.
        /// </remarks>
        public PkcsSignerInfo EncodeAndSign(Byte[] content) {
            // add mandatory attributes: content type and message digest.
            prepareSigning(content);
            // version
            var bigInt = new BigInteger(Version);
            var rawData = new List<Byte>(Asn1Utils.Encode(bigInt.ToLittleEndianByteArray(), (byte)Asn1Type.INTEGER));
            // signerIdentifier
            var signerID = new SubjectIdentifier2(_signer.SignerCertificate, SubjectIdentifier);
            rawData.AddRange(signerID.Encode());
            // digestAlgorithm
            rawData.AddRange(new AlgorithmIdentifier(_signer.HashingAlgorithm.ToOid()).RawData);
            // authenticatedAttributes
            if (_authAttributes.Any()) {
                rawData.AddRange(_authAttributes.Encode(0xa0));
            }
            // digestEncryptionAlgorithm
            rawData.AddRange(new AlgorithmIdentifier(_signer.PublicKeyAlgorithm).RawData);
            // encryptedDigest
            SignedContentBlob signedBlob;
            if (_authAttributes.Any()) {
                // auth attributes are encoded as IMPLICIT (OPTIONAL), but RFC2315 §9.3 requires signature computation for SET
                signedBlob = new SignedContentBlob(_authAttributes.Encode(0x31), ContentBlobType.ToBeSignedBlob);
            } else {
                if (content == null) {
                    throw new ArgumentException("'content' parameter cannot be null if no authenticated attributes present.");
                }
                signedBlob = new SignedContentBlob(content, ContentBlobType.ToBeSignedBlob);
            }
            signedBlob.Sign(_signer);
            rawData.AddRange(Asn1Utils.Encode(signedBlob.Signature.Value, (Byte)Asn1Type.OCTET_STRING));
            // unauthenticatedAttributes
            if (_unauthAttributes.Any()) {
                var attrBytes = AuthenticatedAttributes.Encode();
                attrBytes[0] = 0xa1;
                rawData.AddRange(attrBytes);
            }

            // wrap
            rawData = new List<Byte>(Asn1Utils.Encode(rawData.ToArray(), 48));
            return new PkcsSignerInfo(rawData.ToArray());
        }
    }
}
