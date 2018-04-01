using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PKI.Structs;

namespace PKI.Utils {
    public static class CryptographyUtils {
        public static X509Extension ConvertExtension(X509Extension extension) {
            AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
            switch (extension.Oid.Value) {
                case X509CertExtensions.X509NextCRLPublish:
                    return new X509NextCRLPublishExtension(asndata, extension.Critical);
                case X509CertExtensions.X509CertificateTemplate:
                    return new X509CertificateTemplateExtension(asndata, extension.Critical);
                case X509CertExtensions.X509ApplicationPolicies:
                    return new X509ApplicationPoliciesExtension(asndata, extension.Critical);
                case X509CertExtensions.X509ApplicationPolicyMappings:
                    return new X509ApplicationPolicyMappingsExtension(asndata);
                case X509CertExtensions.X509ApplicationPolicyConstraints:
                    return new X509ApplicationPolicyConstraintsExtension(asndata);
                case X509CertExtensions.X509AuthorityInformationAccess:
                    return new X509AuthorityInformationAccessExtension(asndata, extension.Critical);
                case X509CertExtensions.X509OcspNonce:
                    return new X509NonceExtension(asndata, extension.Critical);
                case X509CertExtensions.X509OcspCRLReference:
                    return new X509CRLReferenceExtension(asndata, extension.Critical);
                case X509CertExtensions.X509ArchiveCutoff:
                    return new X509ArchiveCutoffExtension(asndata, extension.Critical);
                case X509CertExtensions.X509ServiceLocator:
                    return new X509ServiceLocatorExtension(asndata, extension.Critical);
                case X509CertExtensions.X509SubjectKeyIdentifier:
                    return new X509SubjectKeyIdentifierExtension(asndata, extension.Critical);
                case X509CertExtensions.X509KeyUsage:
                    return new X509KeyUsageExtension(asndata, extension.Critical);
                case X509CertExtensions.X509SubjectAlternativeNames:
                    return new X509SubjectAlternativeNamesExtension(asndata, extension.Critical);
                case X509CertExtensions.X509IssuerAlternativeNames:
                    return new X509IssuerAlternativeNamesExtension(asndata, extension.Critical);
                case X509CertExtensions.X509BasicConstraints:
                    return new X509BasicConstraintsExtension(asndata, extension.Critical);
                case X509CertExtensions.X509CRLNumber:
                    return new X509CRLNumberExtension(asndata, extension.Critical);
                case X509CertExtensions.X509NameConstraints:
                    return new X509NameConstraintsExtension(asndata);
                case X509CertExtensions.X509CRLDistributionPoints:
                    return new X509CRLDistributionPointsExtension(asndata, extension.Critical);
                case X509CertExtensions.X509CertificatePolicies:
                    return new X509CertificatePoliciesExtension(asndata, extension.Critical);
                case X509CertExtensions.X509CertificatePolicyMappings:
                    return new X509CertificatePolicyMappingsExtension(asndata);
                case X509CertExtensions.X509AuthorityKeyIdentifier:
                    return new X509AuthorityKeyIdentifierExtension(asndata, extension.Critical);
                case X509CertExtensions.X509CertificatePolicyConstraints:
                    return new X509CertificatePolicyConstraintsExtension(asndata);
                case X509CertExtensions.X509EnhancedKeyUsage:
                    return new X509EnhancedKeyUsageExtension(asndata, extension.Critical);
                case X509CertExtensions.X509FreshestCRL:
                    return new X509FreshestCRLExtension(asndata, extension.Critical);
                default:
                    return extension;
            }
        }
        public static X509Attribute ConvertAttribute(X509Attribute attribute) {
            // reserved for future use
            switch (attribute.Oid.Value) {
                default:
                    return attribute;
            }
        }
        public static Boolean TestCNGCompat() {
            return Environment.OSVersion.Version.Major >= 6;
        }
        public static Boolean TestOleCompat() {
            if (Environment.OSVersion.Version.Major < 6) { return false; }
            return Environment.OSVersion.Version.Major != 6 || Environment.OSVersion.Version.Minor >= 3;
        }
        public static Boolean TestCepCompat() {
            if (Environment.OSVersion.Version.Major < 6) { return false; }
            return Environment.OSVersion.Version.Major != 6 || Environment.OSVersion.Version.Minor != 0;
        }
        public static void ReleaseCom(Object ComObject) {
            Marshal.FinalReleaseComObject(ComObject);
        }
        public static Byte[] DecodeDerString(String str) {
            if (String.IsNullOrEmpty(str)) {
                throw new ArgumentNullException(nameof(str));
            }
            return Encoding.Unicode.GetBytes(str);
        }
        public static String EncodeDerString(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            if (rawData.Length == 0) { throw new ArgumentException("The vlue is empty"); }
            List<Byte> rawBytes;
            if (rawData.Length % 2 > 0) {
                rawBytes = new List<Byte>(rawData.Length + 1);
                rawBytes.AddRange(rawData);
                rawBytes.Add(0);
            } else {
                rawBytes = new List<Byte>(rawData);
            }
            var sb = new StringBuilder(rawBytes.Count / 2);
            for (Int32 index = 0; index < rawBytes.Count; index += 2) {
                sb.Append(Convert.ToChar(rawBytes[index + 1] << 8 | rawBytes[index]));
            }
            return sb.ToString();
        }
        public static IEnumerable<X509Extension> DecodeX509ExtensionCollection2(Wincrypt.CERT_EXTENSIONS extstruct) {
            return decode_extstruct(extstruct).ToArray();
        }

        static List<X509Extension> decode_extstruct(Wincrypt.CERT_EXTENSIONS extstruct) {
            List<X509Extension> extensions = new List<X509Extension>();
            if (extstruct.cExtension > 0) {
                IntPtr rgExtension = extstruct.rgExtension;
                for (UInt32 index = 0; index < extstruct.cExtension; index++) {
                    Wincrypt.CERT_EXTENSION ExtEntry = (Wincrypt.CERT_EXTENSION)Marshal.PtrToStructure(rgExtension, typeof(Wincrypt.CERT_EXTENSION));
                    Byte[] rawData = new Byte[ExtEntry.Value.cbData];
                    Marshal.Copy(ExtEntry.Value.pbData, rawData, 0, rawData.Length);
                    extensions.Add(ConvertExtension(new X509Extension(ExtEntry.pszObjId, rawData, ExtEntry.fCritical)));
                    rgExtension = rgExtension + Marshal.SizeOf(typeof(Wincrypt.CERT_EXTENSION));
                }
            }
            return extensions;
        }
    }
}
