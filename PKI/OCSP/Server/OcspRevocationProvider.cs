using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using CERTADMINLib;

namespace PKI.OCSP.Server {
	/// <summary>
	/// Represents revocation provider and its settings for OCSP configuration.
	/// </summary>
	public class OcspRevocationProvider {
		/// <summary>
		/// Intitializes a new instance of <strong>OcspRevocationProvider</strong> class.
		/// </summary>
		public OcspRevocationProvider() { }
		internal OcspRevocationProvider(IOCSPCAConfiguration ocspconfig) {
			m_initialize(ocspconfig);
		}

		/// <summary>
		/// Gets configured URL or URLs to retrieve Base CRL. If multiple URLs are specified, they must point to the same CRL file.
		/// </summary>
		public String[] BaseCrlUrls { get; set; }
		/// <summary>
		/// Gets configured URL or URLs to retrieve Delta CRL. If multiple URLs are specified, they must point to the same Delta CRL file.
		/// </summary>
		/// <remarks>If CA server is not confgired to use Delta CRLs, this property is set to <strong>null</strong>.</remarks>
		public String[] DeltaCrlUrls { get; set; }
		/// <summary>
		/// Gets local CRL cache lifetime in minutes. If the value is zero, then CRL cache is valid while CRLs are valid.
		/// </summary>
		public Int32 RefreshInterval { get; set; }
		/// <summary>
		/// Gets the time-out in seconds that the revocation provider must wait before it times out while trying
		/// to retrieve the CRL for which it is configured.
		/// </summary>
		public Int32 CrlUrlTimeout { get; set; }
		/// <summary>
		/// Gets explicitly configured Base CRL. This property can be set to <strong>null</strong>.
		/// </summary>
		public X509CRL2 BaseCrl { get; set; }
		/// <summary>
		/// Gets explicitly configured Delta CRL. This property can be set to <strong>null</strong>.
		/// </summary>
		public X509CRL2 DeltaCrl { get; set; }
		/// <summary>
		/// Gets local CRL. You can put revoked serial numbers without revoking them on the CA server.
		/// </summary>
		public X509CRL2 LocalCrl { get; set; }
		/// <summary>
		/// Gets hash algorithm used to sign OCSP responses. It is recommended to use SHA1 (default).
		/// </summary>
		/// <remarks><see href="http://tools.ietf.org/html/rfc5019.html">RFC5019</see> supports only SHA1 algorithm.</remarks>
		public String HashAlgorithm { get; private set; }
		/// <summary>
		/// Indicates whether one or more properties were changed.
		/// </summary>
		public Boolean IsModified { get; private set; }
		/// <summary>
		/// Gets revocation provider status code. Any non-zero value means error. Exact error text is stored
		/// in <see cref="StatusMessage"/> property.
		/// </summary>
		public Int32 StatusCode { get; private set; }
		/// <summary>
		/// Gets revocation provider status message.
		/// </summary>
		public String StatusMessage => StatusCode == 0 ? "Ok" : new Win32Exception(StatusCode).Message;

		void m_initialize(IOCSPCAConfiguration ocspconfig) {
			Object[,] props = (Object[,])ocspconfig.ProviderProperties;
			Int32 count = props.Length / 2;
			for (Int32 index = 0; index < count; index++) {
				Int32 length;
				switch ((String)props[index,0]) {
					case "BaseCrl": BaseCrl = new X509CRL2((Byte[])props[index, 1]); break;
					case "DeltaCrl": DeltaCrl = new X509CRL2((Byte[])props[index, 1]); break;
					case "BaseCrlUrls":
						length = ((Object[])props[index, 1]).Length;
						BaseCrlUrls = new String[length];
						Array.Copy((Object[])props[index, 1], BaseCrlUrls, length);
						break;
					case "DeltaCrlUrls":
						length = ((Object[])props[index, 1]).Length;
						DeltaCrlUrls = new String[length];
						Array.Copy((Object[])props[index, 1], DeltaCrlUrls, length);
						break;
					case "CrlUrlTimeout": CrlUrlTimeout = (Int32)props[index, 1] / 1000; break;
					case "RefreshTimeOut": RefreshInterval = (Int32)props[index, 1] / 60000; break;
					case "RevocationErrorCode": StatusCode = (Int32)props[index, 1]; break;
				}
			}
		}

		/// <summary>
		/// Sets CRL cache validity interval in minutes. If the <paramref name="minutes"/> is set to zero,
		/// CRLs are valid until they expire.
		/// </summary>
		/// <param name="minutes">CRL cache validity interval in minutes.</param>
		/// <returns><strong>True</strong> if the property was successfully updated, otherwise <strong>False</strong>.</returns>
		public Boolean SetRefreshInterval(Int32 minutes) {
			if (RefreshInterval != minutes) {
				RefreshInterval = minutes;
				IsModified = true;
				return true;
			}
			return false;
		}
		/// <summary>
		/// Sets hash algorithm to use to sign OCSP responses. By default SHA1 algorithm is used.
		/// </summary>
		/// <param name="hashAlgorithm">Hash algorithm to use.</param>
		/// <returns><strong>True</strong> if the property was successfully updated, otherwise <strong>False</strong>.</returns>
		public Boolean SetHashAlgorithm(String hashAlgorithm) {
			if (!String.IsNullOrEmpty(hashAlgorithm)) {
				List<String> supportedAlgs = new List<String>(new [] { "sha1", "md5", "md4", "md2" });
				if (supportedAlgs.Contains(hashAlgorithm.ToLower())) {
					if (HashAlgorithm != hashAlgorithm) {
						HashAlgorithm = hashAlgorithm;
						IsModified = true;
						return true;
					}
					return false;
				}
				throw new ArgumentException("Specified hash algorithm is not supported.");
			}
			throw new ArgumentNullException(nameof(hashAlgorithm));
		}
	}
}
