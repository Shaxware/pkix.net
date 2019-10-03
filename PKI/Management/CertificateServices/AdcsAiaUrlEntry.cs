﻿using System;
using System.Text.RegularExpressions;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents an AuthorityInformationAccess URL object. An object contains URL information and URL publication settings.
    /// An URL indicates how clients can obtain presented certificate's issuer certificate, or how to locate authoritative OCSP responder. These URLs
    /// are generally used for certificate chain building purposes to determine whether the presented certificate came from trusted CA.
    /// </summary>
    public class AdcsAiaUrlEntry {
        /// <summary>Initializes a new instance of the <strong>AIA</strong> class using URL string.</summary>
        /// <param name="regUri">An URL that is formatted as follows: Flags:protocol/ActualURL/options.
        /// See <see cref="RegURI">RegURI</see> property for variable replacement tokens
        /// and <see cref="Flags">Flags</see> property for detailed information about publication Flags.</param>
        /// <exception cref="ArgumentNullException">The <strong>regUri</strong> parameter is null or empty.</exception>
        /// <exception cref="FormatException">The string in the <strong>regUri</strong> parameter does not match required pattern.</exception>
        /// <remarks>
        /// <p>Only absolute (local), UNC paths and LDAP:// URLs are supported for CRT file publishing.</p>
        /// <p>Only LDAP:// and HTTP:// URLs are supported for CRT file retrieval.</p>
        /// </remarks>
        public AdcsAiaUrlEntry(String regUri) {
            if (String.IsNullOrEmpty(regUri)) { throw new ArgumentNullException(nameof(regUri)); }
            RegURI = regUri;
            m_initialize();
        }

        /// <summary>
        /// Gets an URL that is formatted as follows: Flags:protocol/ActualURL/options.
        /// <p>for example, an URL can be: 3:http://pki.company.com/AIA/%2_%3%4.crt </p>
        /// See <strong>Remarks</strong> for detailed URL structure.
        /// </summary>
        /// <remarks>The following replacement tokens are defined for AIA URL variables:
        /// <p>%1 -  &lt;ServerDNSName&gt; (The DNS name of the certification authority server).</p>
        /// <p>%2 -  &lt;ServerShortName&gt; (The NetBIOS name of the certification authority server).</p>
        /// <p>%3 -  &lt;CaName&gt; (The name of the certification authority);</p>
        /// <p>%4 -  &lt;CertificateName&gt; (The renewal extension of the certification authority).</p>
        /// <p>%6 -  &lt;ConfigurationContainer&gt; (The location of the Configuration container in Active Directory).</p>
        /// <p>%7 -  &lt;CATruncatedName&gt; (The "sanitized" name of the certification authority, truncated to 32 characters with a hash on the end).</p>
        /// <p>%11 - &lt;CAObjectClass&gt; - (The object class identifier for a certification authority, used when publishing to an LDAP URL).</p>
        /// <p>See <see cref="Flags">Flags</see> property for flag definitions.</p>
        /// </remarks>
        public String RegURI { get; }
        /// <summary>
        /// Gets an URL representation that is shown in Certification Authority MMC snap-in Extensions tab. See <see cref="RegURI"> for detailed variable token
        /// replacement rules.</see></summary>
        public String ConfigURI { get; private set; }
        /// <summary>
        /// Gets the protocol scheme used by this object.
        /// </summary>
        public UrlProtocolScheme UrlScheme { get; private set; }
        /// <summary>
        /// Gets URL publication Flags.
        /// </summary>
        /// <remarks>Windows Server 2003 and higher: you cannot define custom CRT file publication local path.</remarks>
        public AdcsAiaUrlFlag Flags { get; private set; }
        /// <summary>
        /// Gets True if specified URL is configured to publish the CRT file to the specified location.
        /// </summary>
        /// <remarks>Only absolute (local), UNC and LDAP:// paths are supported.</remarks>
        public Boolean ServerPublish => (Flags & AdcsAiaUrlFlag.CertPublish) > 0;
        /// <summary>
        /// Gets True if specified URL is configured to include specified URL to all issued certificate's Authority Information Access extension.
        /// </summary>
        /// <remarks>Only HTTP:// and LDAP:// paths are supported.</remarks>
        public Boolean AddToCertAia => (Flags & AdcsAiaUrlFlag.AddToCertAiaIssuer) > 0;
        /// <summary>
        /// Gets True if specified URL is configured to include specified URL to all issued certificate's Authority Information Access extension as a OCSP Locator.
        /// </summary>
        /// <remarks>HTTP:// paths are supported.</remarks>
        public Boolean OCSP => (Flags & AdcsAiaUrlFlag.AddToCertAiaOcsp) > 0;

        void m_initialize() {
            var regex = new Regex(@"^\d+");
            Match match = regex.Match(RegURI);
            if (match.Success) {
                Int16 matches = Convert.ToInt16(match.Value);
                Flags = (AdcsAiaUrlFlag)matches;
            } else { throw new FormatException(); }
            ConfigURI = RegURI
                .Replace("%11", "<CAObjectClass>")
                .Replace("%1", "<ServerDNSName>")
                .Replace("%2", "<ServerShortName>")
                .Replace("%3", "<CaName>")
                .Replace("%4", "<CertificateName>")
                .Replace("%6", "<ConfigurationContainer>")
                .Replace("%7", "<CATruncatedName>");
            getUrlScheme();
        }
        void getUrlScheme() {
            var regex = new Regex(@"([a-z]:\\(?:[^\\:]+\\)*(?:[^:\\]+\.\w+))", RegexOptions.Compiled | RegexOptions.IgnoreCase);
            String regUri = RegURI.ToLower();
            if (regex.IsMatch(regUri)) {
                UrlScheme = UrlProtocolScheme.Local;
            } else if (regUri.Contains("file://") || regUri.Contains(@"\\")) {
                UrlScheme = UrlProtocolScheme.UNC;
            } else if (regUri.Contains("http://") || regUri.Contains("https://")) {
                UrlScheme = UrlProtocolScheme.HTTP;
            } else if (regUri.Contains("ldap://")) {
                UrlScheme = UrlProtocolScheme.LDAP;
            } else if (regUri.Contains("ftp://")) {
                UrlScheme = UrlProtocolScheme.FTP;
            } else {
                UrlScheme = UrlProtocolScheme.Unknown;
            }
        }
        /// <summary>
        /// Returns a string representation of the current AIA object. (Overrides Object.ToString().)
        /// </summary>
        /// <returns>A string representation of the current AIA object.</returns>
        public override String ToString() {
            return ConfigURI;
        }
    }
}
