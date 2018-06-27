using System;
using System.IO;
using System.Text.RegularExpressions;

namespace SysadminsLV.PKI.Management.CertificateServices.Configuration {
    /// <summary>
    /// Represents an AuthorityInformationAccess URL object. An object contains URL information and URL publication settings.
    /// An URL indicates how clients can obtain presented certificate's issuer certificate, or how to locate authoritative OCSP responder. These URLs
    /// are generally used for certificate chain building purposes to determine whether the presented certificate came from trusted CA.
    /// </summary>
    public class AuthorityInformationAccessConfigUri {
        readonly Regex _regex = new Regex("(1|2|32):(.+)", RegexOptions.Compiled);

        /// <summary>
        /// Initializes a new instance of the <strong>AuthorityInformationAccessConfigUri</strong> class.
        /// </summary>
        public AuthorityInformationAccessConfigUri() { }
        /// <summary>
        /// Initializes a new instance of the <strong>AuthorityInformationAccessConfigUri</strong> class
        /// using URL string.
        /// </summary>
        /// <param name="uri">An URL that points to a publication location including file name.
        /// See <see cref="URI"/> property for variable replacement tokens
        /// </param>
        /// <exception cref="ArgumentNullException">The <strong>uri</strong> parameter is null or empty.</exception>
        /// <remarks>
        /// <p>Only absolute (local), UNC paths and LDAP:// URLs are supported for CRT file publishing.</p>
        /// <p>Only LDAP:// and HTTP:// URLs are supported for CRT file retrieval.</p>
        /// </remarks>
        public AuthorityInformationAccessConfigUri(String uri) {
            if (String.IsNullOrWhiteSpace(uri)) {
                throw new ArgumentNullException(nameof(uri));
            }
            Match match = _regex.Match(uri);
            if (match.Success) {
                var flag = Convert.ToInt32(match.Groups[1].Value);
                URI = match.Groups[2].Value;
                if ((flag & 1) > 0) {
                    ServerPublish = true;
                }
                if ((flag & 2) > 0) {
                    IncludeToExtension = true;
                }
                if ((flag & 32) > 0) {
                    OCSP = true;
                }
            } else {
                URI = uri;
            }

        }

        /// <summary>
        /// Gets or sets a publication URL. Can be local path, UNC, LDAP or HTTP path.
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
        /// </remarks>
        public String URI { get; set; }
        /// <summary>
        /// Gets an URL representation that is shown in Certification Authority MMC snap-in Extensions tab. See
        /// <see cref="URI"/> for detailed variable token replacement rules.
        /// </summary>
        public String ConfigURI {
            get {
                if (String.IsNullOrWhiteSpace(URI)) { return String.Empty; }
                return URI
                    .Replace("%11", "<CAObjectClass>")
                    .Replace("%1", "<ServerDNSName>")
                    .Replace("%2", "<ServerShortName>")
                    .Replace("%3", "<CaName>")
                    .Replace("%4", "<CertificateName>")
                    .Replace("%6", "<ConfigurationContainer>")
                    .Replace("%7", "<CATruncatedName>");
            }
        }
        /// <summary>
        /// Gets or sets the value if specified URL is configured to publish the CRT file to the specified location.
        /// </summary>
        /// <remarks>Only absolute (local), UNC and LDAP paths are supported.</remarks>
        public Boolean ServerPublish { get; set; }
        /// <summary>
        /// Gets or sets the value if the URL is configured to include specified URL to all issued
        /// certificate's Authority Information Access extension.
        /// </summary>
        /// <remarks>Only HTTP and LDAP paths are supported.</remarks>
        public Boolean IncludeToExtension { get; set; }
        /// <summary>
        /// Gets or sets if the URL is configured to include specified URL to all issued certificate's
        /// Authority Information Access extension as a OCSP Locator.
        /// </summary>
        /// <remarks>Only HTTP paths are supported.</remarks>
        public Boolean OCSP { get; set; }

        public String GetConfigUri() {
            if (String.IsNullOrWhiteSpace(URI)) {
                throw new InvalidDataException("The URI is null or empty.");
            }
            Int32 flag = 0;
            if (ServerPublish) {
                flag |= 1;
            }

            if (IncludeToExtension) {
                flag |= 2;
            }

            if (OCSP) {
                flag |= 32;
            }

            return $"{flag}:{URI}";
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
