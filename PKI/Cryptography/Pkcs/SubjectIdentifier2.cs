using System;
using System.Security.Cryptography.Pkcs;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.Pkcs {
    /// <summary>
    /// The <strong>SubjectIdentifier2</strong> class defines the type of the identifier of a subject, such as
    /// a <see cref="PkcsSignerInfo"/>. The subject can be identified by the certificate issuer and serial number
    /// or the subject key.
    /// </summary>
    /// <remarks>This class is a replacement for for a .NET native <see cref="SubjectIdentifier"/> class.</remarks>
    public sealed class SubjectIdentifier2 {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="rawData"></param>
        public SubjectIdentifier2(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            decode(rawData);
        }

        /// <summary>
        /// Gets the type of the of subject identifier. The subject can be identified by the certificate issuer and
        /// serial number or the subject key.
        /// <para>
        /// The following table displays mappings between subject identifier type and object type stored in the
        /// <see cref="Value"/> property:
        /// <list type="table">
        ///		<listheader>
        ///			<term>Identifier type</term>
        ///			<description>Object type</description>
        ///		</listheader>
        ///		<item>
        ///			<term><strong>IssuerAndSerialNumber</strong></term>
        ///			<description>An instance of <see cref="X509IssuerSerial"/> class.</description>
        ///		</item>
        ///		<item>
        ///			<term><strong>SubjectKeyIdentifier</strong></term>
        ///			<description>
        ///				A string that represents subject key identifier value (cryptographic hash calculated
        ///				over a public key).
        ///			</description>
        ///		</item>
        ///		<item>
        ///			<term><strong>Sha1Hash</strong></term>
        ///			<description>A SHA1 hash of the certificate to be used as a unique identifier of the certificate.</description>
        ///		</item>
        ///		<item>
        ///			<term><strong>Unknown</strong></term>
        ///			<description>NULL</description>
        ///		</item>
        /// </list>
        /// </para>
        /// </summary>
        public SubjectIdentifierType Type { get; private set; }
        /// <summary>
        /// Contains the value of the subject identifier. Object type and it's description depends on <see cref="Type"/>
        /// property value.
        /// <para>
        /// The following table displays mappings between subject identifier type and object type stored in the
        /// property:
        /// <list type="table">
        ///		<listheader>
        ///			<term>Identifier type</term>
        ///			<description>Object type</description>
        ///		</listheader>
        ///		<item>
        ///			<term><strong>IssuerAndSerialNumber</strong></term>
        ///			<description>An instance of <see cref="X509IssuerSerial"/> class.</description>
        ///		</item>
        ///		<item>
        ///			<term><strong>SubjectKeyIdentifier</strong></term>
        ///			<description>
        ///				A string that represents subject key identifier value (cryptographic hash calculated
        ///				over a public key).
        ///			</description>
        ///		</item>
        ///		<item>
        ///			<term><strong>NoSignature</strong></term>
        ///			<description>A string that contains hash value of external message.</description>
        ///		</item>
        ///		<item>
        ///			<term><strong>Unknown</strong></term>
        ///			<description>NULL.</description>
        ///		</item>
        /// </list>
        /// </para>
        /// </summary>
        public Object Value { get; private set; }

        void decode(Byte[] rawData) {
            Asn1Reader asn = new Asn1Reader(rawData);
            switch (asn.Tag) {
                case 48:
                    Type = SubjectIdentifierType.IssuerAndSerialNumber;
                    Value = new X509IssuerSerial(asn.GetTagRawData());
                    break;
                case 0x80:
                    Type = SubjectIdentifierType.SubjectKeyIdentifier;
                    Value = AsnFormatter.BinaryToString(asn, EncodingType.HexRaw, EncodingFormat.NOCRLF);
                    break;
                default: throw new ArgumentException("Invalid CMS issuer identifier type.");
            }
        }
    }
}
