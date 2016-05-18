using System.Security.Cryptography.X509Certificates;

namespace PKI.Utils.CLRExtensions {
	/// <summary>
	/// Contains extension methods for <see cref="X509Certificate2"/> class.
	/// </summary>
	public static class X509Certificate2Extensions {
		/// <summary>
		/// Converts generic X.509 extension objects to specialized certificate extension objects
		/// inherited from <see cref="X509Extension"/> class that provide extension-specific information.
		/// </summary>
		/// <param name="cert">Certificate.</param>
		/// <returns>A collection of certificate extensions</returns>
		/// <remarks>
		/// This method can transform the following X.509 certificate extensions:
		/// <list type="bullet">
		/// <item><description><see cref="X509CertificateTemplateExtension"/></description></item>
		/// <item><description><see cref="X509ApplicationPoliciesExtension"/></description></item>
		/// <item><description><see cref="X509ApplicationPolicyMappingsExtension"/></description></item>
		/// <item><description><see cref="X509ApplicationPolicyConstraintsExtension"/></description></item>
		/// <item><description><see cref="X509AuthorityInformationAccessExtension"/></description></item>
		/// <item><description><see cref="X509NonceExtension"/></description></item>
		/// <item><description><see cref="X509CRLReferenceExtension"/></description></item>
		/// <item><description><see cref="X509ArchiveCutoffExtension"/></description></item>
		/// <item><description><see cref="X509ServiceLocatorExtension"/></description></item>
		/// <item><description><see cref="X509SubjectKeyIdentifierExtension"/></description></item>
		/// <item><description><see cref="X509KeyUsageExtension"/></description></item>
		/// <item><description><see cref="X509SubjectAlternativeNamesExtension"/></description></item>
		/// <item><description><see cref="X509IssuerAlternativeNamesExtension"/></description></item>
		/// <item><description><see cref="X509BasicConstraintsExtension"/></description></item>
		/// <item><description><see cref="X509CRLNumberExtension"/></description></item>
		/// <item><description><see cref="X509NameConstraintsExtension"/></description></item>
		/// <item><description><see cref="X509CRLDistributionPointsExtension"/></description></item>
		/// <item><description><see cref="X509CertificatePoliciesExtension"/></description></item>
		/// <item><description><see cref="X509CertificatePolicyMappingsExtension"/></description></item>
		/// <item><description><see cref="X509AuthorityKeyIdentifierExtension"/></description></item>
		/// <item><description><see cref="X509CertificatePolicyConstraintsExtension"/></description></item>
		/// <item><description><see cref="X509EnhancedKeyUsageExtension"/></description></item>
		/// <item><description><see cref="X509FreshestCRLExtension"/></description></item>
		/// </list>
		/// Non-supported extensions will be returned as an <see cref="X509Extension"/> object.
		/// </remarks>
		public static X509ExtensionCollection ResolveExtensions (this X509Certificate2 cert) {
			if (cert.Extensions.Count == 0) { return cert.Extensions; }
			X509ExtensionCollection extensions = new X509ExtensionCollection();
			foreach (var ext in cert.Extensions) {
				extensions.Add(CryptographyUtils.ConvertExtension(ext));
			}
			return extensions;
		}
	}
}
