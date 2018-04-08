using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PKI.Structs;
using PKI.Utils.CLRExtensions;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Tools.MessageOperations;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace SysadminsLV.PKI.Cryptography.X509CertificateRequests {
    /// <summary>
    /// Represents a managed PKCS #10 request.
    /// </summary>
    public class X509CertificateRequestPkcs10 {

        protected X509CertificateRequestPkcs10() { }
        /// <summary>
        /// Initializes a new instance of <strong>X509CertificateRequestPkcs10</strong> class from ASN.1-encoded
        /// byte array that represents PKCS #10 certificate request.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        public X509CertificateRequestPkcs10(Byte[] rawData) {
            Decode(rawData);
        }

        /// <summary>
        /// Gets the X.509 format version of a certificate request.
        /// </summary>
        /// <remarks>
        /// Currently only version 1 is defined.
        /// </remarks>
        public Int32 Version { get; protected set; }
        /// <summary>
        /// Gets the distinguished name of the request subject.
        /// </summary>
        public X500DistinguishedName SubjectName { get; protected set; }
        /// <summary>
        /// Gets textual form of the distinguished name of the request subject.
        /// </summary>
        public String Subject => SubjectName?.Name;
        /// <summary>
        /// Gets a <see cref="PublicKey"/> object associated with a certificate
        /// </summary>
        /// <remarks>
        /// <para>
        /// This property returns a PublicKey object, which contains the object identifier (Oid) representing the public key
        /// algorithm, the ASN.1-encoded parameters, and the ASN.1-encoded key value.</para>
        /// <para>You can also obtain the key as an <see cref="AsymmetricAlgorithm"/> object by referencing the <strong>PublicKey</strong> property.
        /// This property supports only RSA or DSA keys, so it returns either an <see cref="RSACryptoServiceProvider"/> or a
        /// <see cref="DSACryptoServiceProvider"/> object that represents the public key.</para>
        /// </remarks>
        public PublicKey PublicKey { get; protected set; }
        /// <summary>
        /// Gets a collection of <see cref="X509Extension"/> objects included in the request.
        /// </summary>
        public X509ExtensionCollection Extensions { get; } = new X509ExtensionCollection();
        /// <summary>
        /// Gets <see cref="X509AttributeCollection"/> object that contains a collection of attributes
        /// associated with the certificate request.
        /// </summary>
        public X509AttributeCollection Attributes { get; } = new X509AttributeCollection();
        /// <summary>
        /// Gets the algorithm used to create the signature of a certificate request.
        /// </summary>
        /// <remarks>The object identifier <see cref="Oid">(Oid)</see> identifies the type of signature
        /// algorithm used by the certificate request.</remarks>
        public Oid SignatureAlgorithm { get; protected set; }
        /// <summary>
        /// Gets request signature status. Returns <strong>True</strong> if signature is valid, <strong>False</strong> otherwise.
        /// </summary>
        public Boolean SignatureIsValid { get; protected set; }
        /// <summary>
        /// Gets the raw data of a certificate request.
        /// </summary>
        public Byte[] RawData { get; private set; }

        protected void Decode(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            var blob = new SignedContentBlob(rawData, ContentBlobType.SignedBlob);
            // at this point we can set signature algorithm and populate RawData
            SignatureAlgorithm = blob.SignatureAlgorithm.AlgorithmId;
            Asn1Reader asn = new Asn1Reader(blob.ToBeSignedData);
            getVersion(asn);
            getSubject(asn);
            getPublicKey(asn);
            // if we reach this far, then we can verify request attribute.
            SignatureIsValid = MessageSigner.VerifyData(blob, PublicKey);
            asn.MoveNextCurrentLevel();
            if (asn.Tag == 0xa0) {
                getAttributes(asn);
            }
            RawData = rawData;
        }
        void getVersion(Asn1Reader asn) {
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
            Version = (Int32)(Asn1Utils.DecodeInteger(asn.GetTagRawData()) + 1);
        }
        void getSubject(Asn1Reader asn) {
            asn.MoveNextCurrentLevelAndExpectTags(0x30);
            if (asn.PayloadLength != 0) {
                SubjectName = new X500DistinguishedName(asn.GetTagRawData());
            }
        }
        void getPublicKey(Asn1Reader asn) {
            asn.MoveNextCurrentLevel();
            PublicKey = PublicKeyExtensions.FromRawData(asn.GetTagRawData());
        }
        void getAttributes(Asn1Reader asn) {
            asn.MoveNext();
            if (asn.PayloadLength == 0) { return; }
            do {
                X509Attribute attribute = X509Attribute.Decode(asn.GetTagRawData());
                if (attribute.Oid.Value == X509CertExtensions.X509CertificateExtensions) {
                    //Extensions
                    Extensions.Decode(attribute.RawData);
                } else {
                    Attributes.Add(attribute);
                }
            } while (asn.MoveNextCurrentLevel());
        }

        public virtual String Format() {
            var SB = new StringBuilder();
            var blob = new SignedContentBlob(RawData, ContentBlobType.SignedBlob);
            SB.Append(
$@"PKCS10 Certificate Request:
Version: {Version}
Subject:
    {Subject ?? "EMPTY"}

{PublicKey.Format().TrimEnd()}
Request attributes (Count={Attributes.Count}):{formatAttributes().TrimEnd()}
Request extensions (Count={Extensions.Count}):{formatExtensons().TrimEnd()}
{blob.SignatureAlgorithm.ToString().TrimEnd()}    
Signature: Unused bits={blob.Signature.UnusedBits}
    {AsnFormatter.BinaryToString(blob.Signature.Value.ToArray(), EncodingType.HexAddress).Replace("\r\n", "\r\n    ")}
Signature matches Public Key: {SignatureIsValid}
");

            return SB.ToString();
        }
        String formatAttributes() {
            StringBuilder sb = new StringBuilder();
            if (Attributes.Count == 0) {
                return sb.ToString();
            }

            sb.AppendLine("");
            for (Int32 index = 0; index < Attributes.Count; index++) {
                var attribute = Attributes[index];
                sb.AppendLine(
                    $"  Attribute[{index}], Length={attribute.RawData.Length} ({attribute.RawData.Length:x2}):");
                sb.AppendLine($"    {attribute.Format(true).Replace("\r\n", "\r\n    ")}");
            }
            return sb.ToString();
        }
        String formatExtensons() {
            StringBuilder sb = new StringBuilder();
            if (Extensions.Count == 0) {
                return sb.ToString();
            }

            sb.AppendLine("");
            foreach (X509Extension extension in Extensions) {
                sb.AppendLine($"    {extension.Oid.Format(true)}, Critial={extension.Critical}, Length={extension.RawData.Length:x2}:");
                sb.AppendLine($"        {extension.Format(true).Replace("\r\n", "\r\n        ")}");
            }
            return sb.ToString();
        }
    }
}