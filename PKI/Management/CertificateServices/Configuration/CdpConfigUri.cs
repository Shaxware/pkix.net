using System;
using System.IO;
using System.Text.RegularExpressions;
using PKI.CertificateServices;

namespace PKI.Management.CertificateServices.Configuration {
    /// <summary>
    /// Represents CRLDistributionPoint URL object. An object contains URL information and URL publication settings.
    /// </summary>
    public class CrlDistributionPointConfigUri {
        readonly Regex _regex = new Regex("(1|2|4|8|64|128):(.+)", RegexOptions.Compiled);
        String uri;

        /// <summary>
        /// Initializes a new instance of <strong>CrlDistributionPointConfigUri</strong> class.
        /// </summary>
        public CrlDistributionPointConfigUri() { }
        /// <summary>
        /// Initializes a new instance of the <strong>CrlDistributionPointConfigUri</strong> class
        /// using URL string.
        /// </summary>
        /// <param name="uri">
        /// An URL that points to a publication location including file name.
        /// See <see cref="URI"/> property for variable replacement tokens.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <strong>uri</strong> parameter is null or empty string.
        /// </exception>
        public CrlDistributionPointConfigUri(String uri) {
            if (String.IsNullOrWhiteSpace(uri)) {
                throw new ArgumentNullException(nameof(uri));
            }
            Match match = _regex.Match(uri);
            if (match.Success) {
                Int32 flag       = Convert.ToInt32(match.Groups[1].Value);
                URI              = match.Groups[2].Value;
                CRLPublish       = (flag & 1) > 0;
                AddToCertCDP     = (flag & 2) > 0;
                AddToFreshestCRL = (flag & 4) > 0;
                AddToCrlcdp      = (flag & 8) > 0;
                DeltaCRLPublish  = (flag & 64) > 0;
                IDP              = (flag & 128) > 0;
            } else {
                URI = uri;
            }
        }

        /// <summary>
        /// Gets or sets a publication URL. Can be local path, UNC, LDAP or HTTP path.
        /// See <strong>Remarks</strong> for detailed URL structure.
        /// </summary>
        /// <remarks>
        /// The following replacement tokens are defined for CDP URL variables:
        /// <list type="table">
        ///     <listheader>
        ///         <term>Registry Variable</term>
        ///         <term>Config Variable</term>
        ///         <description>Description</description>
        ///     </listheader>
        ///     <item>
        ///         <term>%1</term>
        ///         <term>&lt;ServerDNSName&gt;</term>
        ///         <description>DNS name of the certification authority server</description>
        ///     </item>
        ///     <item>
        ///         <term>%2</term>
        ///         <term>&lt;ServerShortName&gt;</term>
        ///         <description>NetBIOS name of the certification authority server</description>
        ///     </item>
        ///     <item>
        ///         <term>%3</term>
        ///         <term>&lt;CaName&gt;</term>
        ///         <description>Name of the certification authority</description>
        ///     </item>
        ///     <item>
        ///         <term>%6</term>
        ///         <term>&lt;ConfigurationContainer&gt;</term>
        ///         <description>Location of the Configuration container in Active Directory</description>
        ///     </item>
        ///     <item>
        ///         <term>%7</term>
        ///         <term>&lt;CATruncatedName&gt;</term>
        ///         <description>"sanitized" name of the certification authority, truncated to 32 characters with a hash on the end</description>
        ///     </item>
        ///     <item>
        ///         <term>%8</term>
        ///         <term>&lt;CRLNameSuffix&gt;</term>
        ///         <description>Inserts a name suffix at the end of the file name when publishing a CRL to a file or URL location</description>
        ///     </item>
        ///     <item>
        ///         <term>%9</term>
        ///         <term>&lt;DeltaCRLAllowed&gt;</term>
        ///         <description>When Delta CRL is published, this replaces the CRLNameSuffix with a separate suffix to distinguish the delta CRL</description>
        ///     </item>
        ///     <item>
        ///         <term>%10</term>
        ///         <term>&lt;CDPObjectClass&gt;</term>
        ///         <description>Active Directory object class identifier for CRL distribution points used when publishing to an LDAP URL</description>
        ///     </item>
        ///     <item>
        ///         <term>%11</term>
        ///         <term>&lt;CAObjectClass&gt;</term>
        ///         <description>Active Directory object class identifier for a certification authority, used when publishing to an LDAP URL</description>
        ///     </item>
        /// </list>
        /// </remarks>
        public String URI {
            get => uri;
            set {
                uri = value;
                getUrlScheme();
            }
        }
        /// <summary>
        /// Gets the protocol scheme used by this object.
        /// </summary>
        public UrlProtocolSchemes UrlScheme { get; private set; }
        /// <summary>
        /// Gets an URL representation that is shown in Certification Authority MMC snap-in Extensions tab. See
        /// <see cref="URI"/> for detailed variable token replacement rules.
        /// </summary>
        public String ConfigURI {
            get {
                if (String.IsNullOrWhiteSpace(URI)) { return String.Empty; }
                return URI
                    .Replace("%11", "<CAObjectClass>")
                    .Replace("%10", "<CDPObjectClass>")
                    .Replace("%1", "<ServerDNSName>")
                    .Replace("%2", "<ServerShortName>")
                    .Replace("%3", "<CaName>")
                    .Replace("%6", "<ConfigurationContainer>")
                    .Replace("%7", "<CATruncatedName>")
                    .Replace("%8", "<CRLNameSuffix>")
                    .Replace("%9", "<DeltaCRLAllowed>");
            }
        }

        /// <summary>
        /// Gets True if provided URL is configured to publish CRLs to this location.
        /// </summary>
        /// <remarks>Only absolute (local), UNC and LDAP paths are supported.</remarks>
        public Boolean CRLPublish { get; set; }
        /// <summary>
        /// Gets True if provided URL is configured to publish Delta CRLs to this location.
        /// </summary>
        /// <remarks>Only absolute (local), UNC and LDAP paths are supported.</remarks>
        public Boolean DeltaCRLPublish { get; set; }
        /// <summary>
        /// Gets True if provided URL is configured to publish specified URL to all issued certificates' CDP extension.
        /// </summary>
        /// <remarks>Only HTTP and LDAP paths are supported.</remarks>
        public Boolean AddToCertCDP { get; set; }
        /// <summary>
        /// Gets True if provided URL is configured to publish specified URL Base CRL CDP extension.
        /// This extension is used to locate Delta CRL locations.
        /// </summary>
        /// <remarks>Only HTTP and LDAP paths are supported.</remarks>
        public Boolean AddToFreshestCRL { get; set; }
        /// <summary>
        /// Gets True if provided URL is configured to publish provided URL to CRLs.
        /// </summary>
        /// <remarks>Only LDAP paths are supported.</remarks>
        public Boolean AddToCrlcdp { get; set; }
        /// <summary>
        /// Gets True if provided URL is configured to publish CRLs to CRLs' IDP (Issuing Distribution Point) extension.
        /// </summary>
        /// <remarks>Only HTTP and LDAP paths are supported.</remarks>
        public Boolean IDP { get; set; }

        void getUrlScheme() {
            Regex regex = new Regex(@"([a-z]:\\(?:[^\\:]+\\)*(?:[^:\\]+\.\w+))");
            if (regex.IsMatch(URI)) {
                UrlScheme = UrlProtocolSchemes.Local;
            } else if (URI.ToLower().Contains("file://") || URI.Contains(@"\\")) {
                UrlScheme = UrlProtocolSchemes.UNC;
            } else if (URI.ToLower().Contains("http://")) {
                UrlScheme = UrlProtocolSchemes.HTTP;
            } else if (URI.ToLower().Contains("ldap://")) {
                UrlScheme = UrlProtocolSchemes.LDAP;
            } else {
                UrlScheme = UrlProtocolSchemes.Unknown;
            }
        }

        public String GetConfigUri() {
            if (String.IsNullOrWhiteSpace(URI)) {
                throw new InvalidDataException("The URI is null or empty.");
            }
            Int32 flag = 0;
            if (CRLPublish) {
                flag |= 1;
            }
            if (AddToCertCDP) {
                flag |= 2;
            }
            if (AddToFreshestCRL) {
                flag |= 4;
            }
            if (AddToCrlcdp) {
                flag |= 8;
            }
            if (DeltaCRLPublish) {
                flag |= 64;
            }
            if (IDP) {
                flag |= 128;
            }
            return $"{flag}:{URI}";
        }
        /// <summary>
        /// Returns a string representation of the current CDP URI object.
        /// </summary>
        /// <returns>A string representation of the current CDP URI object.</returns>
        public override String ToString() {
            return ConfigURI;
        }
    }
}
