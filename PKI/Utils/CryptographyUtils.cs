using PKI.Structs;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PKI.Utils {
    static class CryptographyUtils {
		public static X509Extension ConvertExtension(X509Extension extension) {
			AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
			switch (extension.Oid.Value) {
				case "1.3.6.1.4.1.311.21.7":
					return new X509CertificateTemplateExtension(asndata, extension.Critical);
				case "1.3.6.1.4.1.311.21.10":
					return new X509ApplicationPoliciesExtension(asndata, extension.Critical);
                case "1.3.6.1.4.1.311.21.11":
                    return new X509ApplicationPolicyMappingsExtension(asndata);
                case "1.3.6.1.4.1.311.21.12":
                    return new X509ApplicationPolicyConstraintsExtension(asndata);
                case "1.3.6.1.5.5.7.1.1":
					return new X509AuthorityInformationAccessExtension(asndata, extension.Critical);
				case "1.3.6.1.5.5.7.48.1.2":
					return new X509NonceExtension(asndata, extension.Critical);
				case "1.3.6.1.5.5.7.48.1.3":
					return new X509CRLReferenceExtension(asndata, extension.Critical);
				case "1.3.6.1.5.5.7.48.1.6":
					return new X509ArchiveCutoffExtension(asndata, extension.Critical);
				case "1.3.6.1.5.5.7.48.1.7":
					return new X509ServiceLocatorExtension(asndata, extension.Critical);
				case "2.5.29.14":
					return new X509SubjectKeyIdentifierExtension(asndata, extension.Critical);
				case "2.5.29.15":
					return new X509KeyUsageExtension(asndata, extension.Critical);
				case "2.5.29.17":
					return new X509SubjectAlternativeNamesExtension(asndata, extension.Critical);
				case "2.5.29.18":
					return new X509IssuerAlternativeNamesExtension(asndata, extension.Critical);
				case "2.5.29.19":
					return new X509BasicConstraintsExtension(asndata, extension.Critical);
				case "2.5.29.20":
					return new X509CRLNumberExtension(asndata, extension.Critical);
                case "2.5.29.30":
                    return new X509NameConstraintsExtension(asndata);
                case "2.5.29.31":
					return new X509CRLDistributionPointsExtension(asndata, extension.Critical);
				case "2.5.29.32":
					return new X509CertificatePoliciesExtension(asndata, extension.Critical);
                case "2.5.29.33":
                    return new X509CertificatePolicyMappingsExtension(asndata);
                case "2.5.29.36":
                    return new X509CertificatePolicyConstraintsExtension(asndata);
                case "2.5.29.37":
					return new X509EnhancedKeyUsageExtension(asndata, extension.Critical);
				case "2.5.29.46":
					return new X509FreshestCRLExtension(asndata, extension.Critical);
				default:
					return extension;
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
                throw new ArgumentNullException("str");
            }
            return Encoding.Unicode.GetBytes(str);
		}
		public static String EncodeDerString(Byte[] rawData) {
			if (rawData == null) { throw new ArgumentNullException(); }
            if (rawData.Length == 0) { throw new ArgumentException("The vlue is empty"); }
            List<Byte> rawBytes;
            if (rawData.Length % 2 > 0) {
                rawBytes = new List<Byte>(rawData.Length + 1);
                rawBytes.AddRange(rawData);
                rawBytes.Add(0);
            } else {
                rawBytes = new List<Byte>(rawData);
            }
            return Encoding.Unicode.GetString(rawBytes.ToArray());
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
