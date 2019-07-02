using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Exceptions;

namespace SysadminsLV.PKI.Helpers.CLRExtensions {
    /// <summary>
    /// Contains extension methods for <see cref="X509Extension"/> class.
    /// </summary>
    public static class X509ExtensionExtensions {
        /// <summary>
        /// Encodes current extension to ASN.1-encoded byte array.
        /// </summary>
        /// <param name="extension">Extension to encode.</param>
        /// <exception cref="ArgumentNullException"><strong>extension</strong> parameter is null.</exception>
        /// <exception cref="UninitializedObjectException">Extension object is not properly initialized.</exception>
        /// <returns></returns>
        public static Byte[] Encode(this X509Extension extension) {
            if (extension == null) {
                throw new ArgumentNullException(nameof(extension));
            }
            if (String.IsNullOrEmpty(extension.Oid.Value)) {
                throw new UninitializedObjectException();
            }
            var rawData = new List<Byte>(Asn1Utils.EncodeObjectIdentifier(extension.Oid));
            if (extension.Critical) {
                rawData.AddRange(Asn1Utils.EncodeBoolean(true));
            }

            rawData.AddRange(Asn1Utils.Encode(extension.RawData, (Byte)Asn1Type.OCTET_STRING));
            return Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        /// <summary>
        /// Decodes ASN.1-encoded byte array to an instance of <see cref="X509Extension"/> class.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array that represents full extension information.</param>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null.</exception>
        /// <exception cref="Asn1InvalidTagException">Decoder encountered an unexpected ASN.1 type identifier.</exception>
        /// <returns>Decoded extension object.</returns>
        public static X509Extension Decode(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }

            Asn1Reader asn = new Asn1Reader(rawData);
            if (asn.Tag != 48) { throw new Asn1InvalidTagException(asn.Offset); }

            asn.MoveNext();
            if (asn.Tag != (Byte)Asn1Type.OBJECT_IDENTIFIER) { throw new Asn1InvalidTagException(asn.Offset); }

            Oid oid = new Asn1ObjectIdentifier(asn).Value;
            Boolean critical = false;
            asn.MoveNext();
            if (asn.Tag == (Byte)Asn1Type.BOOLEAN) {
                critical = Asn1Utils.DecodeBoolean(asn.GetTagRawData());
                asn.MoveNext();
            }
            if (asn.Tag != (Byte)Asn1Type.OCTET_STRING) { throw new Asn1InvalidTagException(asn.Offset); }

            return new X509Extension(oid, asn.GetPayload(), critical).ConvertExtension();
        }
        /// <summary>
        /// Converts default instance of <see cref="X509Extension"/> class to a specific extension implementation object.
        /// </summary>
        /// <param name="extension">Default instance of <see cref="X509Extension"/> class.</param>
        /// <returns>Explicit extension implementation if defined, otherwise, the same object is returned.</returns>
        public static X509Extension ConvertExtension(this X509Extension extension) {
            var asnData = new AsnEncodedData(extension.Oid, extension.RawData);
            switch (extension.Oid.Value) {
                case X509ExtensionOidMap.X509CertTemplateName:
                    return new X509CertificateTemplateNameExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509CAVersion:
                    return new X509CAVersionExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509NextCRLPublish:
                    return new X509NextCRLPublishExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509CertificateTemplate:
                    return new X509CertificateTemplateExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509ApplicationPolicies:
                    return new X509ApplicationPoliciesExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509ApplicationPolicyMappings:
                    return new X509ApplicationPolicyMappingsExtension(asnData);
                case X509ExtensionOidMap.X509ApplicationPolicyConstraints:
                    return new X509ApplicationPolicyConstraintsExtension(asnData);
                case X509ExtensionOidMap.X509PublishedCrlLocations:
                    return new X509PublishedCrlLocationsExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509AuthorityInformationAccess:
                    return new X509AuthorityInformationAccessExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509OcspNonce:
                    return new X509NonceExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509OcspCRLReference:
                    return new X509CRLReferenceExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509ArchiveCutoff:
                    return new X509ArchiveCutoffExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509ServiceLocator:
                    return new X509ServiceLocatorExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509SubjectKeyIdentifier:
                    return new X509SubjectKeyIdentifierExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509KeyUsage:
                    return new X509KeyUsageExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509SubjectAlternativeNames:
                    return new X509SubjectAlternativeNamesExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509IssuerAlternativeNames:
                    return new X509IssuerAlternativeNamesExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509BasicConstraints:
                    return new X509BasicConstraintsExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509CRLNumber:
                    return new X509CRLNumberExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509NameConstraints:
                    return new X509NameConstraintsExtension(asnData);
                case X509ExtensionOidMap.X509CRLDistributionPoints:
                    return new X509CRLDistributionPointsExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509CertificatePolicies:
                    return new X509CertificatePoliciesExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509CertificatePolicyMappings:
                    return new X509CertificatePolicyMappingsExtension(asnData);
                case X509ExtensionOidMap.X509AuthorityKeyIdentifier:
                    return new X509AuthorityKeyIdentifierExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509CertificatePolicyConstraints:
                    return new X509CertificatePolicyConstraintsExtension(asnData);
                case X509ExtensionOidMap.X509EnhancedKeyUsage:
                    return new X509EnhancedKeyUsageExtension(asnData, extension.Critical);
                case X509ExtensionOidMap.X509FreshestCRL:
                    return new X509FreshestCRLExtension(asnData, extension.Critical);
                default:
                    return extension;
            }
        }
    }
}
